use actix_web::web;

use crate::db::DbPool;
use crate::errors;

use super::handlers::{
    account, account_portal_page, admin_dashboard_page, change_password, confirm_password_reset,
    create_managed_user, delete_managed_user, list_managed_users, login_with_request, logout,
    managed_user, me, password_reset_page, register_with_request, resend_account_verification,
    resend_managed_user_verification, resend_verification, request_password_reset,
    update_managed_user, verify_email_page, verify_email_token,
};
use super::jwt::jwks;
use super::settings::AuthSettings;
use super::user::AuthRateLimiter;

pub fn auth_routes(cfg: &mut web::ServiceConfig, db: impl Into<DbPool>) {
    auth_routes_with_settings(cfg, db, AuthSettings::default());
}

pub fn public_auth_discovery_routes(cfg: &mut web::ServiceConfig) {
    public_auth_discovery_routes_with_settings(cfg, AuthSettings::default());
}

pub fn public_auth_discovery_routes_with_settings(
    cfg: &mut web::ServiceConfig,
    settings: AuthSettings,
) {
    let settings = web::Data::new(settings);
    cfg.app_data(settings.clone());
    if public_jwks_enabled(settings.get_ref()) {
        cfg.route("/.well-known/jwks.json", web::get().to(jwks));
    }
}

pub fn public_jwks_enabled(settings: &AuthSettings) -> bool {
    settings
        .jwt
        .as_ref()
        .is_some_and(|jwt| !jwt.algorithm.is_symmetric() && !jwt.verification_keys.is_empty())
}

pub fn auth_routes_with_settings(
    cfg: &mut web::ServiceConfig,
    db: impl Into<DbPool>,
    settings: AuthSettings,
) {
    public_auth_discovery_routes_with_settings(cfg, settings.clone());
    auth_api_routes_with_settings(cfg, db, settings);
}

/// Registers the account portal and admin dashboard HTML pages at their
/// configured absolute paths. These pages are meant to be loaded directly by a
/// browser, so they must be mounted OUTSIDE any scope guarded by the anonymous
/// client middleware. Safe to call at the `App::configure` level.
pub fn register_builtin_auth_html_pages(cfg: &mut web::ServiceConfig, settings: AuthSettings) {
    let portal = settings.portal.clone();
    let admin_dashboard = settings.admin_dashboard.clone();
    cfg.app_data(web::Data::new(settings));

    if let Some(portal) = portal {
        cfg.route(portal.path.as_str(), web::get().to(account_portal_page));
    }
    if let Some(dashboard) = admin_dashboard {
        cfg.route(dashboard.path.as_str(), web::get().to(admin_dashboard_page));
    }
}

pub fn auth_api_routes_with_settings(
    cfg: &mut web::ServiceConfig,
    db: impl Into<DbPool>,
    settings: AuthSettings,
) {
    let db = web::Data::new(db.into());
    let settings = web::Data::new(settings);
    let limiter = web::Data::new(AuthRateLimiter::default());
    errors::configure_extractor_errors(cfg);
    cfg.app_data(db.clone());
    cfg.app_data(settings.clone());
    cfg.app_data(limiter);

    cfg.route("/auth/register", web::post().to(register_with_request));
    cfg.route("/auth/login", web::post().to(login_with_request));
    cfg.route("/auth/logout", web::post().to(logout));
    cfg.route("/auth/me", web::get().to(me));
    cfg.route("/auth/account", web::get().to(account));
    cfg.route("/auth/account/password", web::post().to(change_password));
    cfg.route(
        "/auth/account/verification",
        web::post().to(resend_account_verification),
    );
    cfg.route("/auth/verify-email", web::get().to(verify_email_page));
    cfg.route("/auth/verify-email", web::post().to(verify_email_token));
    cfg.route(
        "/auth/verification/resend",
        web::post().to(resend_verification),
    );
    cfg.route("/auth/password-reset", web::get().to(password_reset_page));
    cfg.route(
        "/auth/password-reset/request",
        web::post().to(request_password_reset),
    );
    cfg.route(
        "/auth/password-reset/confirm",
        web::post().to(confirm_password_reset),
    );
    cfg.route("/auth/admin/users", web::get().to(list_managed_users));
    cfg.route("/auth/admin/users", web::post().to(create_managed_user));
    cfg.route("/auth/admin/users/{id}", web::get().to(managed_user));
    cfg.route(
        "/auth/admin/users/{id}",
        web::patch().to(update_managed_user),
    );
    cfg.route(
        "/auth/admin/users/{id}",
        web::delete().to(delete_managed_user),
    );
    cfg.route(
        "/auth/admin/users/{id}/verification",
        web::post().to(resend_managed_user_verification),
    );
}
