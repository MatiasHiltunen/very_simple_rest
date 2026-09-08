//! Strict launcher configuration; paths are relative to this EON file.
use crate::Error;
use serde::Deserialize;
use std::{
    collections::HashSet,
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
pub enum Backend {
    Axum,
    Actix,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationKey {
    pub kid: String,
    pub pem_file: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub backend: Backend,
    pub listen: SocketAddr,
    pub database: PathBuf,
    pub verification_keys: Vec<VerificationKey>,
    pub allowed_origins: Vec<String>,
    pub request_timeout_seconds: u64,
    pub shutdown_timeout_seconds: u64,
    pub max_in_flight: usize,
    pub max_string_chars: usize,
    pub max_page_size: u32,
    #[serde(default)]
    pub tls: Option<Tls>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let mut config: Self = eon::from_str(&std::fs::read_to_string(path)?)?;
        let base = path.parent().unwrap_or(Path::new("."));
        config.database = base.join(&config.database);
        for key in &mut config.verification_keys {
            key.pem_file = base.join(&key.pem_file);
        }
        if let Some(tls) = &mut config.tls {
            tls.cert_file = base.join(&tls.cert_file);
            tls.key_file = base.join(&tls.key_file);
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if !self.listen.ip().is_loopback() && self.tls.is_none() {
            return Err("non-loopback listeners require TLS".into());
        }
        if !(1..=120).contains(&self.request_timeout_seconds)
            || !(1..=120).contains(&self.shutdown_timeout_seconds)
            || !(1..=1024).contains(&self.max_in_flight)
            || !(1..=65536).contains(&self.max_string_chars)
            || !(1..=100).contains(&self.max_page_size)
            || self.database.as_os_str().is_empty()
        {
            return Err("invalid bounded server configuration".into());
        }
        let mut ids = HashSet::new();
        if self.verification_keys.is_empty() {
            return Err("verification keys are required".into());
        }
        for key in &self.verification_keys {
            if key.kid.is_empty() || key.kid.len() > 128 || !ids.insert(&key.kid) {
                return Err("verification key IDs must be nonempty and unique".into());
            }
        }
        Ok(())
    }
}
