use env_logger::{Builder, Env};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize)]
pub enum LogTimestampPrecision {
    None,
    #[default]
    Seconds,
    Millis,
    Micros,
    Nanos,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_filter_env")]
    pub filter_env: String,
    #[serde(default = "default_log_default_filter")]
    pub default_filter: String,
    #[serde(default)]
    pub timestamp: LogTimestampPrecision,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            filter_env: default_log_filter_env(),
            default_filter: default_log_default_filter(),
            timestamp: LogTimestampPrecision::default(),
        }
    }
}

fn default_log_filter_env() -> String {
    "RUST_LOG".to_owned()
}

fn default_log_default_filter() -> String {
    "info".to_owned()
}

impl LoggingConfig {
    pub fn build_env_logger(&self) -> Builder {
        let env = Env::default().filter_or(self.filter_env.as_str(), self.default_filter.as_str());
        let mut builder = Builder::from_env(env);

        match self.timestamp {
            LogTimestampPrecision::None => {
                builder.format_timestamp(None);
            }
            LogTimestampPrecision::Seconds => {
                builder.format_timestamp_secs();
            }
            LogTimestampPrecision::Millis => {
                builder.format_timestamp_millis();
            }
            LogTimestampPrecision::Micros => {
                builder.format_timestamp_micros();
            }
            LogTimestampPrecision::Nanos => {
                builder.format_timestamp_nanos();
            }
        }

        builder
    }

    pub fn init_env_logger(&self) {
        self.build_env_logger().init();
    }
}
