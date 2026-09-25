//! Compatibility facade for authentication configuration in `vsr-runtime`.

pub use vsr_runtime::auth::settings::{
    AuthClaimMapping, AuthClaimType, AuthEmailProvider, AuthEmailSettings, AuthJwtAlgorithm,
    AuthJwtSettings, AuthJwtVerificationKey, AuthSettings, AuthUiPageSettings,
    SessionCookieSameSite, SessionCookieSettings, auth_jwt_signing_secret_ref,
};
