//! Recoverable publication of a plain object file and its metadata sidecar.
//!
//! A store-wide advisory lock protects cooperating readers and writers across processes.
//! A durable redo journal is published only after both replacement files are synced.
//! Recovery completes an interrupted publication before any API operation can read it.
//! Storage roots must be exclusively managed by VSR (not writable by untrusted processes).

use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Component, Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
struct Journal {
    object: PathBuf,
    metadata: PathBuf,
    delete: bool,
}

/// Exclusive local storage transaction; dropping it releases the OS lock.
pub struct LocalTransaction {
    root: PathBuf,
    dir: PathBuf,
    _lock: File,
}

impl LocalTransaction {
    /// Lock a storage root and recover any interrupted publication.
    pub fn lock(root: &Path) -> io::Result<Self> {
        let root = fs::canonicalize(root)?;
        let dir = root.join(".vsr-meta/.vsr-transaction");
        safe_path(&root, &dir.join("lock"), true)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join("lock"))?;
        lock.lock()?;
        let tx = Self {
            root,
            dir,
            _lock: lock,
        };
        tx.recover()?;
        Ok(tx)
    }

    /// Reject symlinks and non-normal paths; optionally create missing parents.
    pub fn validate(&self, path: &Path, create_parents: bool) -> io::Result<()> {
        safe_path(&self.root, path, create_parents)
    }

    fn prepare(
        &self,
        object: &Path,
        metadata: &Path,
        data: Option<(&[u8], &[u8])>,
    ) -> io::Result<()> {
        self.validate(object, true)?;
        self.validate(metadata, true)?;
        let relative = |path: &Path| {
            path.strip_prefix(&self.root)
                .map(Path::to_path_buf)
                .map_err(|_| io::Error::other("storage path outside root"))
        };
        let journal = Journal {
            object: relative(object)?,
            metadata: relative(metadata)?,
            delete: data.is_none(),
        };
        if let Some((body, meta)) = data {
            self.write_stage("body", body)?;
            self.write_stage("metadata", meta)?;
        }
        let bytes = serde_json::to_vec(&journal)?;
        self.write_stage("next-journal", &bytes)?;
        fs::rename(self.dir.join("next-journal"), self.dir.join("journal"))?;
        sync_dir(&self.dir)
    }

    fn write_stage(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        let path = self.dir.join(name);
        self.validate(&path, false)?;
        let mut file = File::create(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }

    /// Publish a complete new pair. An error after journal publication is an uncertain
    /// commit: the next operation rolls it forward, never serves a mismatched pair.
    pub fn put(&self, object: &Path, metadata: &Path, body: &[u8], meta: &[u8]) -> io::Result<()> {
        self.recover()?;
        self.prepare(object, metadata, Some((body, meta)))?;
        self.recover()
    }

    /// Delete a pair with the same recoverable commit protocol.
    pub fn delete(&self, object: &Path, metadata: &Path) -> io::Result<()> {
        self.recover()?;
        self.prepare(object, metadata, None)?;
        self.recover()
    }

    fn recover(&self) -> io::Result<()> {
        let path = self.dir.join("journal");
        self.validate(&path, false)?;
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        let journal: Journal = serde_json::from_slice(&bytes)?;
        for (stage, relative) in [("body", journal.object), ("metadata", journal.metadata)] {
            let destination = self.root.join(relative);
            self.validate(&destination, false)?;
            if journal.delete {
                match fs::remove_file(&destination) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            } else {
                let staged = self.dir.join(stage);
                self.validate(&staged, false)?;
                match fs::rename(&staged, &destination) {
                    Ok(()) => {}
                    Err(error)
                        if error.kind() == io::ErrorKind::NotFound && destination.is_file() => {}
                    Err(error) => return Err(error),
                }
            }
            sync_dir(
                destination
                    .parent()
                    .ok_or_else(|| io::Error::other("missing parent"))?,
            )?;
            sync_dir(&self.dir)?;
        }
        fs::remove_file(path)?;
        sync_dir(&self.dir)
    }
}

fn safe_path(root: &Path, path: &Path, create_parents: bool) -> io::Result<()> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| io::Error::other("storage path outside root"))?;
    let mut components = relative.components().peekable();
    if components.peek().is_none() {
        return Err(io::Error::other("storage path is the root"));
    }
    let mut current = root.to_path_buf();
    while let Some(component) = components.next() {
        let Component::Normal(segment) = component else {
            return Err(io::Error::other("non-normal storage path"));
        };
        current.push(segment);
        let parent = components.peek().is_some();
        match fs::symlink_metadata(&current) {
            Ok(meta)
                if meta.file_type().is_symlink()
                    || (parent && !meta.is_dir())
                    || (!parent && !meta.is_file()) =>
            {
                return Err(io::Error::other(
                    "storage path contains a symbolic link or unexpected file type",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if parent && create_parents {
                    match fs::create_dir(&current) {
                        Ok(()) => sync_dir(
                            current
                                .parent()
                                .ok_or_else(|| io::Error::other("missing parent"))?,
                        )?,
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                            let meta = fs::symlink_metadata(&current)?;
                            if meta.file_type().is_symlink() || !meta.is_dir() {
                                return Err(error);
                            }
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn sync_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()
    }
    // Windows rename is atomic, but std does not expose a portable directory fsync.
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn root() -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "vsr-pair-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::canonicalize(root).unwrap()
    }

    #[test]
    fn recovers_each_publication_boundary_and_preserves_old_data_on_prepare_failure() {
        for completed_renames in 0..=2 {
            let root = root();
            let object = root.join("object");
            let metadata = root.join(".vsr-meta/object.json");
            let tx = LocalTransaction::lock(&root).unwrap();
            tx.put(&object, &metadata, b"old", b"old-meta").unwrap();
            assert!(
                tx.put(&object, &root.join("../escape"), b"bad", b"bad")
                    .is_err()
            );
            assert_eq!(fs::read(&object).unwrap(), b"old");
            tx.prepare(&object, &metadata, Some((b"new", b"new-meta")))
                .unwrap();
            if completed_renames >= 1 {
                fs::rename(tx.dir.join("body"), &object).unwrap();
            }
            if completed_renames >= 2 {
                fs::rename(tx.dir.join("metadata"), &metadata).unwrap();
            }
            drop(tx);
            let tx = LocalTransaction::lock(&root).unwrap();
            assert_eq!(fs::read(&object).unwrap(), b"new");
            assert_eq!(fs::read(&metadata).unwrap(), b"new-meta");
            tx.prepare(&object, &metadata, None).unwrap();
            fs::remove_file(&object).unwrap();
            drop(tx);
            let tx = LocalTransaction::lock(&root).unwrap();
            assert!(!metadata.exists());
            drop(tx);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn independent_readers_and_writers_observe_complete_pairs() {
        let root = root();
        let object = root.join("object");
        let metadata = root.join(".vsr-meta/object.json");
        LocalTransaction::lock(&root)
            .unwrap()
            .put(&object, &metadata, b"0", b"0")
            .unwrap();
        std::thread::scope(|scope| {
            for _ in 0..3 {
                scope.spawn(|| {
                    for n in 1..15 {
                        let tx = LocalTransaction::lock(&root).unwrap();
                        let bytes = n.to_string();
                        tx.put(&object, &metadata, bytes.as_bytes(), bytes.as_bytes())
                            .unwrap();
                    }
                });
            }
            for _ in 0..40 {
                let _tx = LocalTransaction::lock(&root).unwrap();
                assert_eq!(fs::read(&object).unwrap(), fs::read(&metadata).unwrap());
            }
        });
        fs::remove_dir_all(root).unwrap();
    }
}
