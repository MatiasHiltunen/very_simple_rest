use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "auth-email")]
use lettre::message::{Mailbox, Message, header::ContentType};
#[cfg(feature = "auth-email")]
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
#[cfg(feature = "auth-email")]
use reqwest::Client;
use serde_json::json;
use uuid::Uuid;

use crate::auth::{AuthEmailProvider, AuthEmailSettings};
#[cfg(feature = "auth-email")]
use crate::secret::load_secret;

pub const AUTH_EMAIL_CAPTURE_DIR_ENV: &str = "VSR_AUTH_EMAIL_CAPTURE_DIR";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthEmailMessage {
    pub to_email: String,
    pub to_name: Option<String>,
    pub subject: String,
    pub text_body: String,
    pub html_body: String,
}

pub async fn send_auth_email(
    settings: &AuthEmailSettings,
    message: &AuthEmailMessage,
) -> Result<(), String> {
    if capture_outgoing_email(settings, message)? {
        return Ok(());
    }
    send_via_provider(settings, message).await
}

/// Dispatches email delivery to the configured provider.
///
/// This implementation is compiled only when the `auth-email` feature is enabled.
#[cfg(feature = "auth-email")]
async fn send_via_provider(
    settings: &AuthEmailSettings,
    message: &AuthEmailMessage,
) -> Result<(), String> {
    match &settings.provider {
        AuthEmailProvider::Resend {
            api_key,
            api_base_url,
        } => {
            let api_key =
                load_secret(api_key, "Resend API key").map_err(|error| error.to_string())?;
            send_via_resend(
                settings,
                message,
                &api_key,
                api_base_url.as_deref().unwrap_or("https://api.resend.com"),
            )
            .await
        }
        AuthEmailProvider::Smtp { connection_url } => {
            let connection_url = load_secret(connection_url, "SMTP connection URL")
                .map_err(|error| error.to_string())?;
            send_via_smtp(settings, message, &connection_url).await
        }
    }
}

/// Stub used when the `auth-email` feature is disabled.
#[cfg(not(feature = "auth-email"))]
async fn send_via_provider(
    _settings: &AuthEmailSettings,
    _message: &AuthEmailMessage,
) -> Result<(), String> {
    Err("Email delivery requires the `auth-email` feature to be enabled".to_owned())
}

fn capture_outgoing_email(
    settings: &AuthEmailSettings,
    message: &AuthEmailMessage,
) -> Result<bool, String> {
    let Ok(dir) = std::env::var(AUTH_EMAIL_CAPTURE_DIR_ENV) else {
        return Ok(false);
    };
    if dir.trim().is_empty() {
        return Err(format!(
            "{AUTH_EMAIL_CAPTURE_DIR_ENV} resolved to an empty directory path"
        ));
    }

    let target_dir = PathBuf::from(dir);
    std::fs::create_dir_all(&target_dir)
        .map_err(|error| format!("failed to create email capture dir: {error}"))?;

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock error: {error}"))?
        .as_millis();
    let file_name = format!("{stamp}-{}.json", Uuid::new_v4());
    let path = target_dir.join(file_name);
    let payload = json!({
        "provider": match &settings.provider {
            AuthEmailProvider::Resend { .. } => "resend",
            AuthEmailProvider::Smtp { .. } => "smtp",
        },
        "from": format_mailbox(settings.from_name.as_deref(), &settings.from_email),
        "reply_to": settings.reply_to,
        "to": format_mailbox(message.to_name.as_deref(), &message.to_email),
        "subject": message.subject,
        "text_body": message.text_body,
        "html_body": message.html_body,
    });
    let body = serde_json::to_vec_pretty(&payload)
        .map_err(|error| format!("failed to serialize captured email: {error}"))?;
    std::fs::write(&path, body).map_err(|error| {
        format!(
            "failed to write captured email to `{}`: {error}",
            path.display()
        )
    })?;
    Ok(true)
}

#[cfg(feature = "auth-email")]
async fn send_via_resend(
    settings: &AuthEmailSettings,
    message: &AuthEmailMessage,
    api_key: &str,
    api_base_url: &str,
) -> Result<(), String> {
    let endpoint = format!("{}/emails", api_base_url.trim_end_matches('/'));
    let client = Client::new();
    let payload = json!({
        "from": format_mailbox(settings.from_name.as_deref(), &settings.from_email),
        "to": [format_mailbox(message.to_name.as_deref(), &message.to_email)],
        "reply_to": settings.reply_to,
        "subject": message.subject,
        "text": message.text_body,
        "html": message.html_body,
    });
    let response = client
        .post(endpoint)
        .bearer_auth(api_key)
        .json(&payload)
        .send()
        .await
        .map_err(|error| format!("failed to send email via Resend: {error}"))?;

    if response.status().is_success() {
        Ok(())
    } else {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unavailable>".to_owned());
        Err(format!(
            "Resend email delivery failed with status {status}: {body}"
        ))
    }
}

#[cfg(feature = "auth-email")]
async fn send_via_smtp(
    settings: &AuthEmailSettings,
    message: &AuthEmailMessage,
    connection_url: &str,
) -> Result<(), String> {
    let email = build_message(settings, message)?;
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::from_url(connection_url)
        .map_err(|error| format!("invalid SMTP connection URL: {error}"))?
        .build();
    mailer
        .send(email)
        .await
        .map_err(|error| format!("SMTP email delivery failed: {error}"))?;
    Ok(())
}

#[cfg(feature = "auth-email")]
fn build_message(
    settings: &AuthEmailSettings,
    message: &AuthEmailMessage,
) -> Result<Message, String> {
    let from = parse_mailbox(settings.from_name.as_deref(), &settings.from_email)?;
    let to = parse_mailbox(message.to_name.as_deref(), &message.to_email)?;
    let mut builder = Message::builder()
        .from(from)
        .to(to)
        .subject(&message.subject);

    if let Some(reply_to) = settings.reply_to.as_deref() {
        builder = builder.reply_to(parse_mailbox(None, reply_to)?);
    }

    let multipart = lettre::message::MultiPart::alternative_plain_html(
        message.text_body.clone(),
        message.html_body.clone(),
    );
    builder
        .header(ContentType::TEXT_HTML)
        .multipart(multipart)
        .map_err(|error| format!("failed to build email message: {error}"))
}

#[cfg(feature = "auth-email")]
fn parse_mailbox(name: Option<&str>, email: &str) -> Result<Mailbox, String> {
    let address = email
        .parse()
        .map_err(|error| format!("invalid email address `{email}`: {error}"))?;
    Ok(Mailbox::new(
        name.filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned),
        address,
    ))
}

fn format_mailbox(name: Option<&str>, email: &str) -> String {
    match name.filter(|value| !value.trim().is_empty()) {
        Some(name) => format!("{name} <{email}>"),
        None => email.to_owned(),
    }
}
