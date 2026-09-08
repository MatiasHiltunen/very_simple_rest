use std::path::Path;

pub fn database_url(path: &Path) -> String {
    // AnyConnectOptions parses a URL before SQLite sees it. An authority would
    // turn a Windows drive letter into a host; encode the path as opaque data.
    let encoded = percent_encoding::utf8_percent_encode(
        path.to_str().expect("test database path must be UTF-8"),
        percent_encoding::NON_ALPHANUMERIC,
    );
    format!("sqlite:{encoded}?mode=rwc")
}

#[cfg(test)]
mod tests {
    use super::database_url;
    use sqlx::{ConnectOptions, any::AnyConnectOptions, sqlite::SqliteConnectOptions};
    use std::path::Path;

    #[test]
    fn sqlite_paths_survive_any_url_parsing() {
        for path in [
            r"C:\Users\runneradmin\AppData\Local\Temp\accounts.sqlite",
            "C:/Users/runneradmin/AppData/Local/Temp/accounts.sqlite",
            r"\\?\C:\Temp\accounts.sqlite",
            r"\\server\share\accounts.sqlite",
            "/tmp/space # percent% question?/accounts.sqlite",
            "relative/space # percent% question?.sqlite",
        ] {
            let any: AnyConnectOptions = database_url(Path::new(path)).parse().unwrap();
            let sqlite = SqliteConnectOptions::from_url(&any.database_url).unwrap();
            assert_eq!(sqlite.get_filename(), Path::new(path));
        }
    }

    #[tokio::test]
    async fn sqlite_opens_the_exact_encoded_filename() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("space # percent%25.sqlite");
        sqlx::any::install_default_drivers();
        let pool = sqlx::AnyPool::connect(&database_url(&path)).await.unwrap();
        sqlx::raw_sql("CREATE TABLE path_probe (id INTEGER PRIMARY KEY)")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        assert!(path.is_file());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
        directory.close().unwrap();
    }
}
