//! Compatibility facade for configuration secret resolution in `vsr-runtime`.

pub use vsr_runtime::config_secret::{
    SecretRef, describe_secret_ref, describe_secret_source, has_secret,
    has_secret_from_env_or_file, load_optional_secret, load_optional_secret_from_env_or_file,
    load_secret, load_secret_from_env_or_file,
};
#[cfg(test)]
// Legacy environment fixtures; this exception is confined to tests.
#[allow(unsafe_code)]
mod tests {
    use super::{
        SecretRef, describe_secret_source, has_secret_from_env_or_file,
        load_optional_secret_from_env_or_file, load_secret_from_env_or_file,
    };
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

    #[test]
    fn optional_loader_returns_none_when_binding_is_absent() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::remove_var("VSR_TEST_SECRET");
            std::env::remove_var("VSR_TEST_SECRET_FILE");
        }

        let secret = load_optional_secret_from_env_or_file("VSR_TEST_SECRET", "test secret")
            .expect("missing binding should not error");
        assert_eq!(secret, None);
        assert!(!has_secret_from_env_or_file("VSR_TEST_SECRET"));
    }

    #[test]
    fn describe_source_prefers_inline_env_then_file_binding() {
        let _guard = env_lock().lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            std::env::set_var("VSR_TEST_SECRET", "inline-secret");
            std::env::remove_var("VSR_TEST_SECRET_FILE");
        }
        assert_eq!(
            describe_secret_source("VSR_TEST_SECRET").as_deref(),
            Some("`VSR_TEST_SECRET`")
        );

        unsafe {
            std::env::remove_var("VSR_TEST_SECRET");
            std::env::set_var("VSR_TEST_SECRET_FILE", "/run/secrets/test");
        }
        assert_eq!(
            describe_secret_source("VSR_TEST_SECRET").as_deref(),
            Some("`VSR_TEST_SECRET_FILE`")
        );

        unsafe {
            std::env::remove_var("VSR_TEST_SECRET_FILE");
        }
    }

    #[test]
    fn secret_ref_helpers_build_expected_variants() {
        assert_eq!(
            SecretRef::env("JWT_SECRET"),
            SecretRef::Env {
                var_name: "JWT_SECRET".to_owned()
            }
        );
        assert_eq!(
            SecretRef::env_or_file("JWT_SECRET"),
            SecretRef::EnvOrFile {
                var_name: "JWT_SECRET".to_owned()
            }
        );
    }
}
