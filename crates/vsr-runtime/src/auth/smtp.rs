//! SMTP [`Mailer`] implementation powered by [`lettre`].
//!
//! Connect to any SMTP server (including local dev servers such as
//! [MailHog](https://github.com/mailhog/MailHog) or
//! [Mailpit](https://github.com/axllent/mailpit)) via a standard SMTP URL.
//!
//! # URL format
//!
//! ```text
//! smtp://user:password@host:port
//! smtps://user:password@host:465         # implicit TLS
//! smtp+starttls://user:password@host:587 # STARTTLS
//! ```
//!
//! The URL is loaded from an environment variable or a secret reference at
//! construction time (see [`SmtpMailer::from_url`]).
//!
//! # Capture mode
//!
//! When the environment variable `VSR_EMAIL_CAPTURE_DIR` is set, outgoing
//! emails are **not** sent via SMTP. Instead each message is written as a
//! JSON file in that directory. This is useful for integration tests and
//! local development without a real SMTP server.

use lettre::{
    AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
    message::{Mailbox, Message, MultiPart, header::ContentType},
};
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use vsr_core::error::{VsrError, VsrResult};

use super::{MailMessage, Mailer};

/// Environment variable that enables capture mode.
pub const EMAIL_CAPTURE_DIR_ENV: &str = "VSR_EMAIL_CAPTURE_DIR";

// ── SmtpMailer ────────────────────────────────────────────────────────────────

/// SMTP-backed [`Mailer`] using an async `lettre` transport.
///
/// Construct with [`SmtpMailer::from_url`], then share via `Arc<SmtpMailer>`.
#[derive(Clone)]
pub struct SmtpMailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl SmtpMailer {
    /// Create a mailer connected to the SMTP server described by `url`.
    ///
    /// # Errors
    ///
    /// Returns an error if `url` is not a valid SMTP URL.
    pub fn from_url(url: &str) -> VsrResult<Self> {
        let transport = AsyncSmtpTransport::<Tokio1Executor>::from_url(url)
            .map_err(|e| {
                VsrError::Config {
                    message: format!("invalid SMTP URL: {e}"),
                    key: Some("SMTP_URL".to_owned()),
                }
            })?
            .build();
        Ok(Self { transport })
    }
}

impl Mailer for SmtpMailer {
    async fn send(&self, message: MailMessage) -> VsrResult<()> {
        // Capture mode: write to a directory instead of sending.
        if let Some(dir) = capture_dir()? {
            return write_capture(&dir, &message);
        }

        let email = build_lettre_message(&message)?;
        self.transport
            .send(email)
            .await
            .map_err(|e| VsrError::Other(format!("SMTP delivery failed: {e}").into()))?;
        Ok(())
    }
}

impl std::fmt::Debug for SmtpMailer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpMailer").finish_non_exhaustive()
    }
}

// ── Capture mode ──────────────────────────────────────────────────────────────

fn capture_dir() -> VsrResult<Option<PathBuf>> {
    let Ok(dir) = std::env::var(EMAIL_CAPTURE_DIR_ENV) else {
        return Ok(None);
    };
    let dir = dir.trim();
    if dir.is_empty() {
        return Err(VsrError::Config {
            message: format!("{EMAIL_CAPTURE_DIR_ENV} must not be empty"),
            key: Some(EMAIL_CAPTURE_DIR_ENV.to_owned()),
        });
    }
    Ok(Some(PathBuf::from(dir)))
}

fn write_capture(dir: &PathBuf, message: &MailMessage) -> VsrResult<()> {
    std::fs::create_dir_all(dir).map_err(|e| {
        VsrError::Io(e)
    })?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| VsrError::Other(format!("system clock error: {e}").into()))?
        .as_millis();
    let uuid_part: u64 = rand_u64();
    let file_name = format!("{stamp}-{uuid_part:016x}.json");
    let path = dir.join(file_name);
    let payload = serde_json::json!({
        "from": message.from,
        "to": message.to,
        "subject": message.subject,
        "text_body": message.text_body,
        "html_body": message.html_body,
    });
    let bytes = serde_json::to_vec_pretty(&payload).map_err(|e| {
        VsrError::Other(format!("failed to serialize captured email: {e}").into())
    })?;
    std::fs::write(&path, bytes).map_err(VsrError::Io)
}

/// Poor-man's random u64 without a rand dep: mix time nanos with a counter.
fn rand_u64() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let count = CTR.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    nanos.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(count)
}

// ── Message builder ───────────────────────────────────────────────────────────

fn build_lettre_message(message: &MailMessage) -> VsrResult<Message> {
    let from = parse_mailbox(&message.from)?;
    let to = parse_mailbox(&message.to)?;
    let builder = Message::builder()
        .from(from)
        .to(to)
        .subject(&message.subject);

    match &message.html_body {
        Some(html) => builder
            .header(ContentType::TEXT_HTML)
            .multipart(MultiPart::alternative_plain_html(
                message.text_body.clone(),
                html.clone(),
            ))
            .map_err(|e| VsrError::Other(format!("failed to build MIME message: {e}").into())),
        None => builder
            .header(ContentType::TEXT_PLAIN)
            .body(message.text_body.clone())
            .map_err(|e| VsrError::Other(format!("failed to build MIME message: {e}").into())),
    }
}

fn parse_mailbox(address: &str) -> VsrResult<Mailbox> {
    address.parse::<Mailbox>().map_err(|e| {
        VsrError::Other(format!("invalid email address `{address}`: {e}").into())
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::auth::MailMessage;

    fn temp_capture_dir(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("vsr_email_capture_{label}_{stamp}"))
    }

    fn sample_message() -> MailMessage {
        MailMessage {
            from: "noreply@example.com".to_owned(),
            to: "user@example.com".to_owned(),
            subject: "Test email".to_owned(),
            text_body: "Hello, world!".to_owned(),
            html_body: Some("<p>Hello, world!</p>".to_owned()),
        }
    }

    #[test]
    fn capture_mode_writes_json_file() {
        let dir = temp_capture_dir("write");
        // Call write_capture directly — env-var routing is in capture_dir()
        // which cannot be unit-tested without unsafe set_var (forbidden in
        // this crate by #![forbid(unsafe_code)]).
        let result = write_capture(&dir, &sample_message());
        assert!(result.is_ok(), "capture write should succeed: {result:?}");

        let entries: Vec<_> = fs::read_dir(&dir)
            .expect("dir should exist")
            .filter_map(Result::ok)
            .collect();
        assert_eq!(entries.len(), 1, "exactly one file should be written");

        let content = fs::read_to_string(entries[0].path()).expect("file should be readable");
        let parsed: serde_json::Value =
            serde_json::from_str(&content).expect("captured file should be valid JSON");
        assert_eq!(parsed["from"], "noreply@example.com");
        assert_eq!(parsed["to"], "user@example.com");
        assert_eq!(parsed["subject"], "Test email");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn capture_mode_writes_multiple_files() {
        let dir = temp_capture_dir("multi");

        write_capture(&dir, &sample_message()).expect("first write should succeed");
        write_capture(&dir, &sample_message()).expect("second write should succeed");

        let count = fs::read_dir(&dir)
            .expect("dir should exist")
            .filter_map(Result::ok)
            .count();
        assert_eq!(count, 2, "each call should produce a distinct file");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_message_with_html_succeeds() {
        let msg = sample_message();
        let result = build_lettre_message(&msg);
        assert!(result.is_ok(), "should build multipart message: {result:?}");
    }

    #[test]
    fn build_message_text_only_succeeds() {
        let msg = MailMessage {
            html_body: None,
            ..sample_message()
        };
        let result = build_lettre_message(&msg);
        assert!(result.is_ok(), "should build plain-text message: {result:?}");
    }

    #[test]
    fn build_message_invalid_address_errors() {
        let msg = MailMessage {
            from: "not-an-email".to_owned(),
            ..sample_message()
        };
        let result = build_lettre_message(&msg);
        assert!(result.is_err(), "invalid address should produce an error");
    }
}
