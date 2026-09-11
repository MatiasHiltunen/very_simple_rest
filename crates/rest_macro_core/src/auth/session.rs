//! Configuration bridge for framework-neutral login/logout presentation.

use super::{AuthSettings, SessionCookieSameSite, SessionCookieSettings};
use vsr_runtime::auth::{
    accounts::AccountError,
    session::{SessionCookiePolicy, SessionPresentation, SessionSameSite},
};

pub(crate) fn cookie_policy(settings: &SessionCookieSettings) -> SessionCookiePolicy {
    SessionCookiePolicy {
        request: super::runtime::cookie_policy(settings),
        path: settings.path.clone(),
        secure: settings.secure,
        same_site: match settings.same_site {
            SessionCookieSameSite::Lax => SessionSameSite::Lax,
            SessionCookieSameSite::None => SessionSameSite::None,
            SessionCookieSameSite::Strict => SessionSameSite::Strict,
        },
    }
}

/// Compose shared session presentation from existing EON/programmatic settings.
/// This bridge still links Actix; the returned policy has no framework dependency.
pub fn builtin_session_presentation(
    settings: &AuthSettings,
) -> Result<SessionPresentation, AccountError> {
    SessionPresentation::new(settings.session_cookie.as_ref().map(cookie_policy))
}
