//! Shared admission policy for login/registration, separate from authentication.

use crate::{
    http::{Handler, ResponseEnvelope, make_handler},
    rate_limit::{RateLimitDecision, RateLimitKey, RateLimitStore},
};
use std::{net::IpAddr, sync::Arc, time::Duration};

/// Existing login/registration quota configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthRateLimitRule {
    /// Maximum accepted attempts in the sliding window.
    pub requests: u32,
    /// Window duration in seconds.
    pub window_seconds: u64,
}

/// Independent budgets for credential endpoints, not arbitrary request paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthRateLimitScope {
    /// Login attempts.
    Login,
    /// Registration attempts.
    Register,
}

impl AuthRateLimitScope {
    /// Stable public scope name used in keys and error messages.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Register => "register",
        }
    }
}

/// Public failures omit key data and private store errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthAdmissionError {
    /// Quota exhausted; refused attempts do not extend the window.
    Limited {
        /// Credential endpoint whose quota was exhausted.
        scope: AuthRateLimitScope,
        /// Seconds until retry, rounded up by the store.
        retry_after_secs: u64,
    },
    /// Missing, exhausted or failed configured store. Never bypass enforcement.
    Unavailable,
    /// Zero requests or window is an invalid rule, not disabled enforcement.
    Configuration,
}

impl AuthAdmissionError {
    /// Preserve 429/error JSON and Retry-After; store failures return 503.
    pub fn response(self) -> ResponseEnvelope {
        let (status, code, message, retry) = match self {
            Self::Limited {
                scope,
                retry_after_secs,
            } => (
                429,
                "rate_limited",
                format!("Too many {} attempts. Try again later.", scope.as_str()),
                Some(retry_after_secs.max(1)),
            ),
            Self::Unavailable => (
                503,
                "auth_rate_limit_unavailable",
                "Authentication rate limiting is unavailable".into(),
                Some(1),
            ),
            Self::Configuration => (
                500,
                "internal_error",
                "Invalid authentication rate-limit configuration".into(),
                None,
            ),
        };
        let mut response =
            ResponseEnvelope::json(serde_json::json!({"code":code,"message":message}));
        response.status = status;
        if let Some(retry) = retry {
            // The decimal representation is always a valid field value.
            if response
                .headers
                .append("retry-after", retry.to_string())
                .is_err()
            {
                return ResponseEnvelope::status(500);
            }
        }
        response
    }
}

fn validate(rule: AuthRateLimitRule) -> Result<(), AuthAdmissionError> {
    if rule.requests == 0 || rule.window_seconds == 0 {
        Err(AuthAdmissionError::Configuration)
    } else {
        Ok(())
    }
}

/// Atomically admit one attempt. The IP must come from the direct socket peer or
/// an explicitly verified proxy chain, never an arbitrary request header/body.
/// Missing peer identity shares a conservative `unknown` bucket.
pub async fn check_auth_rate_limit<S: RateLimitStore>(
    store: &S,
    scope: AuthRateLimitScope,
    client_ip: Option<IpAddr>,
    rule: AuthRateLimitRule,
) -> Result<(), AuthAdmissionError> {
    validate(rule)?;
    let client = client_ip.map_or_else(|| "unknown".into(), |ip| ip.to_string());
    let key = RateLimitKey::Custom(format!("auth:{}:{client}", scope.as_str()));
    match store
        .check_and_increment(
            &key,
            rule.requests,
            Duration::from_secs(rule.window_seconds),
        )
        .await
        .map_err(|_| AuthAdmissionError::Unavailable)?
    {
        RateLimitDecision::Allowed { .. } => Ok(()),
        RateLimitDecision::Denied { retry_after_secs } => Err(AuthAdmissionError::Limited {
            scope,
            retry_after_secs,
        }),
    }
}

/// Reusable handler wrapper for both transports. This default uses only the
/// direct socket peer; forwarding headers and supplied identities cannot change
/// the bucket. Proxy-aware consumers must explicitly resolve trust before using
/// `check_auth_rate_limit`. Place outside extraction to charge malformed attempts.
pub fn rate_limit_authentication<S: RateLimitStore>(
    store: Arc<S>,
    scope: AuthRateLimitScope,
    rule: AuthRateLimitRule,
    handler: Handler,
) -> Result<Handler, AuthAdmissionError> {
    validate(rule)?;
    Ok(make_handler(move |request| {
        let store = store.clone();
        let handler = handler.clone();
        async move {
            match check_auth_rate_limit(
                store.as_ref(),
                scope,
                request.peer_addr.map(|peer| peer.ip()),
                rule,
            )
            .await
            {
                Ok(()) => handler(request).await,
                Err(error) => error.response(),
            }
        }
    }))
}

#[cfg(test)]
#[path = "admission_tests.rs"]
mod tests;
