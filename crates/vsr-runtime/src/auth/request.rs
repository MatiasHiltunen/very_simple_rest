//! Transport-independent request authentication and failure responses.

use std::{future::Future, sync::Arc};

use super::AuthenticatedIdentity;
use crate::http::{Handler, HeaderFields, ResponseEnvelope, make_handler};

/// Public failures never carry tokens, password material, SQL or key errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailure {
    /// No supported credential was supplied.
    MissingToken,
    /// Invalid or ambiguous credentials.
    InvalidToken,
    /// The live account no longer matches the token.
    RevokedToken,
    /// A cookie-authenticated mutation failed its CSRF check.
    InvalidCsrf,
    /// The account dependency failed; never treat this as anonymous access.
    AccountValidation,
    /// All bounded password workers are occupied.
    Busy,
    /// The blocking password task could not complete.
    PasswordWorker,
    /// The password algorithm rejected an operation.
    PasswordOperation,
}

impl AuthFailure {
    /// HTTP status shared by native and neutral handlers.
    pub const fn status(self) -> u16 {
        match self {
            Self::MissingToken | Self::InvalidToken | Self::RevokedToken => 401,
            Self::InvalidCsrf => 403,
            Self::AccountValidation | Self::PasswordWorker | Self::PasswordOperation => 500,
            Self::Busy => 503,
        }
    }

    /// Stable legacy-compatible error code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::MissingToken => "missing_token",
            Self::InvalidToken => "invalid_token",
            Self::RevokedToken => "revoked_token",
            Self::InvalidCsrf => "invalid_csrf",
            Self::AccountValidation | Self::PasswordWorker | Self::PasswordOperation => {
                "internal_error"
            }
            Self::Busy => "auth_busy",
        }
    }

    /// Stable, non-sensitive client message.
    pub const fn message(self) -> &'static str {
        match self {
            Self::MissingToken => "Missing token",
            Self::InvalidToken => "Invalid token",
            Self::RevokedToken => "Account changed; log in again",
            Self::InvalidCsrf => "Missing or invalid CSRF token",
            Self::AccountValidation => "Account validation failed",
            Self::Busy => "Authentication is busy; retry later",
            Self::PasswordWorker => "Password worker failed",
            Self::PasswordOperation => "Password operation failed",
        }
    }

    /// Render the same JSON schema used by existing VSR clients.
    pub fn response(self) -> ResponseEnvelope {
        let mut response = ResponseEnvelope::json(serde_json::json!({
            "code": self.code(), "message": self.message(),
        }));
        response.status = self.status();
        if self.status() == 401 {
            response
                .headers
                .append("www-authenticate", "Bearer")
                .expect("static header");
        }
        response
    }
}

impl std::fmt::Display for AuthFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for AuthFailure {}

/// Authenticate every protected request, including live revocation checks.
/// Deliberately narrower than the still-unmigrated account lifecycle API.
pub trait RequestAuthenticator: Send + Sync + 'static {
    /// Never trust identity supplied by earlier request processing.
    fn authenticate(
        &self,
        method: &str,
        headers: &HeaderFields,
    ) -> impl Future<Output = Result<AuthenticatedIdentity, AuthFailure>> + Send;
}

/// Wrap a protected handler identically for Actix and Axum. Authentication is
/// not authorization: the handler must still enforce operation and row policy.
pub fn require_authentication<A: RequestAuthenticator>(auth: Arc<A>, handler: Handler) -> Handler {
    make_handler(move |mut request| {
        let auth = auth.clone();
        let handler = handler.clone();
        async move {
            request.identity = None;
            match auth
                .authenticate(&request.method.to_string(), &request.headers)
                .await
            {
                Ok(identity) => {
                    request.identity = Some(identity);
                    handler(request).await
                }
                Err(error) => error.response(),
            }
        }
    })
}
