use std::{
    env, fs,
    io::{Error, ErrorKind, Result},
};

pub fn load_secret_from_env_or_file(var_name: &str, label: &str) -> Result<String> {
    if let Ok(value) = env::var(var_name) {
        if value.trim().is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("{label} `{var_name}` resolved to an empty value"),
            ));
        }
        return Ok(value);
    }

    let file_var = format!("{var_name}_FILE");
    let path = env::var(&file_var).map_err(|_| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("{label} references missing environment variable `{var_name}` or `{file_var}`"),
        )
    })?;

    if path.trim().is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("{label} `{file_var}` resolved to an empty value"),
        ));
    }

    let secret = fs::read_to_string(&path).map_err(|error| {
        Error::new(
            error.kind(),
            format!("{label} `{file_var}` points to unreadable file `{path}`: {error}"),
        )
    })?;
    let secret = secret.trim().to_owned();

    if secret.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("{label} file `{path}` resolved to an empty value"),
        ));
    }

    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::load_secret_from_env_or_file;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn unique_secret_path(prefix: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic enough")
            .as_nanos();
        std::env::temp_dir().join(format!("vsr_secret_{prefix}_{nanos}.txt"))
    }

    #[test]
    fn prefers_inline_secret_env_var() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::set_var("VSR_TEST_SECRET", "inline-secret");
            std::env::remove_var("VSR_TEST_SECRET_FILE");
        }

        let secret = load_secret_from_env_or_file("VSR_TEST_SECRET", "test secret")
            .expect("env secret should load");
        assert_eq!(secret, "inline-secret");

        unsafe {
            std::env::remove_var("VSR_TEST_SECRET");
        }
    }

    #[test]
    fn loads_secret_from_mounted_file_path() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        let path = unique_secret_path("file");
        std::fs::write(&path, "file-secret\n").expect("secret file should write");

        unsafe {
            std::env::remove_var("VSR_TEST_SECRET");
            std::env::set_var("VSR_TEST_SECRET_FILE", path.as_os_str());
        }

        let secret = load_secret_from_env_or_file("VSR_TEST_SECRET", "test secret")
            .expect("file-backed secret should load");
        assert_eq!(secret, "file-secret");

        unsafe {
            std::env::remove_var("VSR_TEST_SECRET_FILE");
        }
        let _ = std::fs::remove_file(path);
    }
}
