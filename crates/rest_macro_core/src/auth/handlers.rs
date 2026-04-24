use actix_web::{HttpRequest, HttpResponse, Responder, web};
use actix_web::cookie::{Cookie, time::Duration as CookieDuration};
use bcrypt::{hash, verify};
use chrono::{Duration, Utc};
use jsonwebtoken::encode;

use crate::{db::{DbPool, query}, errors};

use super::admin::resolve_managed_claim_updates;
use super::db_ops::{
    account_info_from_user, delete_user_row, detect_auth_backend,
    initialize_user_management_timestamps, list_authenticated_users_with_settings,
    load_authenticated_user_by_email_with_settings,
    load_authenticated_user_by_email_with_settings_for_backend,
    load_authenticated_user_by_id, load_authenticated_user_by_id_with_settings,
    mark_user_email_verified, update_managed_user_row, update_user_password, user_table_columns,
};
use super::email::{configured_auth_email, send_password_reset_email_for_user, send_verification_email_for_user};
use super::helpers::{
    auth_api_base_path_for_page, auth_settings_from_request, enforce_auth_rate_limit,
    generate_ephemeral_secret, is_missing_auth_management_schema,
    is_unique_violation, missing_auth_management_schema_response, normalize_auth_email,
    normalize_auth_role, now_timestamp_string, same_site_from_settings,
    scope_prefix_from_request, user_is_admin, user_roles, validate_auth_password, validate_cookie_csrf,
};
use super::jwt::{Claims, configured_jwt_signer};
use super::migrations::auth_user_table_ident;
use super::pages::{
    render_account_portal_page, render_admin_dashboard_page, render_message_page,
    render_password_reset_page,
};
use super::settings::{AuthSettings, SessionCookieSettings};
use super::tokens::{TokenActionOutcome, apply_email_verification_token, apply_password_reset_token};
use super::user::{
    AdminListQuery, AuthRateLimitScope, AuthTokenQuery, ChangePasswordInput,
    CreateManagedUserInput, LoginInput, PasswordResetConfirmInput, PasswordResetRequestInput,
    RegisterInput, UpdateManagedUserInput, UserContext, VerificationResendInput, VerifyEmailInput,
};

pub async fn register(input: web::Json<RegisterInput>, db: web::Data<DbPool>) -> impl Responder {
    register_with_settings(None, input, db, AuthSettings::default()).await
}

pub(crate) async fn register_with_settings(
    request: Option<&HttpRequest>,
    input: web::Json<RegisterInput>,
    db: web::Data<DbPool>,
    settings: AuthSettings,
) -> HttpResponse {
    let backend = match detect_auth_backend(db.get_ref()).await {
        Ok(backend) => backend,
        Err(_) => return errors::internal_error("Database error"),
    };
    let email = match normalize_auth_email(&input.email) {
        Ok(email) => email,
        Err(response) => return response,
    };
    if let Err(response) = validate_auth_password(&input.password) {
        return response;
    }
    let password_hash = match hash(&input.password, 12) {
        Ok(h) => h,
        Err(_) => return errors::internal_error("Hashing error"),
    };

    let tx = match db.begin().await {
        Ok(tx) => tx,
        Err(_) => return errors::internal_error("Database error"),
    };
    let result = query(&format!(
        "INSERT INTO {} (email, password_hash, role) VALUES (?, ?, ?)",
        auth_user_table_ident(backend)
    ))
    .bind(&email)
    .bind(&password_hash)
    .bind("user")
    .execute(&tx)
    .await;

    match result {
        Ok(_) => {}
        Err(error) if is_unique_violation(&error) => {
            let _ = tx.rollback().await;
            return errors::conflict("duplicate_email", "A user with that email already exists");
        }
        Err(error) => {
            let _ = tx.rollback().await;
            if is_missing_auth_management_schema(&error) {
                return missing_auth_management_schema_response();
            }
            return errors::internal_error("Database error");
        }
    };

    let user = match load_authenticated_user_by_email_with_settings_for_backend(
        &tx, backend, &email, &settings,
    )
    .await
    {
        Ok(Some(user)) => user,
        Ok(None) => {
            let _ = tx.rollback().await;
            return errors::internal_error("Failed to load registered account");
        }
        Err(error) => {
            let _ = tx.rollback().await;
            if is_missing_auth_management_schema(&error) {
                return missing_auth_management_schema_response();
            }
            return errors::internal_error("Database error");
        }
    };
    let now = now_timestamp_string();
    if let Err(error) = initialize_user_management_timestamps(&tx, backend, user.id, &now).await
        && (settings.email.is_some() || settings.require_email_verification)
    {
        let _ = tx.rollback().await;
        if is_missing_auth_management_schema(&error) {
            return missing_auth_management_schema_response();
        }
        return errors::internal_error("Database error");
    }

    if settings.email.is_some() {
        if let Err(response) =
            send_verification_email_for_user(&tx, request, &settings, &user, "/auth/register").await
        {
            let _ = tx.rollback().await;
            return response;
        }
    } else if let Err(error) = mark_user_email_verified(&tx, backend, user.id, &now).await
        && !is_missing_auth_management_schema(&error)
    {
        let _ = tx.rollback().await;
        return errors::internal_error("Database error");
    }

    if tx.commit().await.is_err() {
        return errors::internal_error("Database error");
    }

    HttpResponse::Created().finish()
}

pub async fn register_with_request(
    req: HttpRequest,
    input: web::Json<RegisterInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    if let Some(response) = enforce_auth_rate_limit(&req, AuthRateLimitScope::Register) {
        return response;
    }
    let settings = auth_settings_from_request(&req);
    register_with_settings(Some(&req), input, db, settings).await
}

pub async fn login(input: web::Json<LoginInput>, db: web::Data<DbPool>) -> impl Responder {
    login_with_settings(input, db, AuthSettings::default()).await
}

pub(crate) async fn login_with_settings(
    input: web::Json<LoginInput>,
    db: web::Data<DbPool>,
    settings: AuthSettings,
) -> HttpResponse {
    let email = match normalize_auth_email(&input.email) {
        Ok(email) => email,
        Err(response) => return response,
    };
    let user = match load_authenticated_user_by_email_with_settings(db.get_ref(), &email, &settings)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return errors::unauthorized("invalid_credentials", "Invalid credentials"),
        Err(error) => {
            if is_missing_auth_management_schema(&error) {
                return missing_auth_management_schema_response();
            }
            return errors::internal_error("Database error");
        }
    };

    if verify(&input.password, &user.password_hash).unwrap_or(false) {
        if settings.require_email_verification && user.email_verified_at.is_none() {
            if !user.has_auth_management_schema() {
                return missing_auth_management_schema_response();
            }
            return errors::forbidden(
                "email_not_verified",
                "Email address must be verified before logging in",
            );
        }
        let claims = Claims {
            sub: user.id,
            roles: user_roles(&user.role),
            iss: settings.issuer.clone(),
            aud: settings.audience.clone(),
            exp: (Utc::now() + Duration::seconds(settings.access_token_ttl_seconds)).timestamp()
                as usize,
            extra: user.claims,
        };
        let (header, encoding_key) = match configured_jwt_signer(&settings) {
            Ok(signer) => signer,
            Err(message) => return errors::internal_error(message),
        };

        match encode(&header, &claims, encoding_key.as_ref()) {
            Ok(token) => {
                if let Some(cookie_settings) = &settings.session_cookie {
                    issue_cookie_login_response(
                        &token,
                        cookie_settings,
                        settings.access_token_ttl_seconds,
                    )
                } else {
                    HttpResponse::Ok().json(serde_json::json!({ "token": token }))
                }
            }
            Err(_) => errors::internal_error("Token generation failed"),
        }
    } else {
        errors::unauthorized("invalid_credentials", "Invalid credentials")
    }
}

pub async fn login_with_request(
    req: HttpRequest,
    input: web::Json<LoginInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    if let Some(response) = enforce_auth_rate_limit(&req, AuthRateLimitScope::Login) {
        return response;
    }
    let settings = auth_settings_from_request(&req);
    login_with_settings(input, db, settings).await
}

pub(crate) fn issue_cookie_login_response(
    token: &str,
    settings: &SessionCookieSettings,
    ttl_seconds: i64,
) -> HttpResponse {
    let csrf_token = generate_ephemeral_secret(32);
    let same_site = same_site_from_settings(settings.same_site);
    let max_age = CookieDuration::seconds(ttl_seconds.max(1));

    let session_cookie = Cookie::build(settings.name.clone(), token.to_owned())
        .path(settings.path.clone())
        .http_only(true)
        .secure(settings.secure)
        .same_site(same_site)
        .max_age(max_age)
        .finish();
    let csrf_cookie = Cookie::build(settings.csrf_cookie_name.clone(), csrf_token.clone())
        .path(settings.path.clone())
        .http_only(false)
        .secure(settings.secure)
        .same_site(same_site)
        .max_age(max_age)
        .finish();

    HttpResponse::Ok()
        .cookie(session_cookie)
        .cookie(csrf_cookie)
        .json(serde_json::json!({
            "token": token,
            "csrf_token": csrf_token,
        }))
}

pub(crate) fn clear_session_cookie_response(settings: &SessionCookieSettings) -> HttpResponse {
    let same_site = same_site_from_settings(settings.same_site);
    let expired_session = Cookie::build(settings.name.clone(), "")
        .path(settings.path.clone())
        .http_only(true)
        .secure(settings.secure)
        .same_site(same_site)
        .max_age(CookieDuration::seconds(0))
        .finish();
    let expired_csrf = Cookie::build(settings.csrf_cookie_name.clone(), "")
        .path(settings.path.clone())
        .http_only(false)
        .secure(settings.secure)
        .same_site(same_site)
        .max_age(CookieDuration::seconds(0))
        .finish();

    HttpResponse::NoContent()
        .cookie(expired_session)
        .cookie(expired_csrf)
        .finish()
}

pub async fn me(user: UserContext) -> impl Responder {
    HttpResponse::Ok().json(user)
}

pub async fn logout(req: HttpRequest) -> impl Responder {
    let settings = auth_settings_from_request(&req);
    let Some(cookie_settings) = settings.session_cookie.as_ref() else {
        return HttpResponse::NoContent().finish();
    };

    if req.cookie(&cookie_settings.name).is_some()
        && let Err(response) = validate_cookie_csrf(&req, cookie_settings)
    {
        return response;
    }

    clear_session_cookie_response(cookie_settings)
}

pub async fn account(req: HttpRequest, user: UserContext, db: web::Data<DbPool>) -> impl Responder {
    let settings = auth_settings_from_request(&req);
    match load_authenticated_user_by_id_with_settings(db.get_ref(), user.id, &settings).await {
        Ok(Some(user)) => HttpResponse::Ok().json(account_info_from_user(user)),
        Ok(None) => errors::unauthorized("invalid_token", "Authenticated user not found"),
        Err(_) => errors::internal_error("Database error"),
    }
}

pub async fn change_password(
    user: UserContext,
    input: web::Json<ChangePasswordInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    let backend = match detect_auth_backend(db.get_ref()).await {
        Ok(backend) => backend,
        Err(_) => return errors::internal_error("Database error"),
    };
    if let Err(response) = validate_auth_password(&input.new_password) {
        return response;
    }

    let account = match load_authenticated_user_by_id(db.get_ref(), user.id).await {
        Ok(Some(account)) => account,
        Ok(None) => return errors::unauthorized("invalid_token", "Authenticated user not found"),
        Err(_) => return errors::internal_error("Database error"),
    };

    if !verify(&input.current_password, &account.password_hash).unwrap_or(false) {
        return errors::unauthorized("invalid_credentials", "Current password is incorrect");
    }

    let password_hash = match hash(&input.new_password, 12) {
        Ok(hash) => hash,
        Err(_) => return errors::internal_error("Hashing error"),
    };
    let now = now_timestamp_string();

    match update_user_password(db.get_ref(), backend, user.id, &password_hash, &now).await {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(error) if is_missing_auth_management_schema(&error) => {
            match query(&format!(
                "UPDATE {} SET password_hash = ? WHERE id = ?",
                auth_user_table_ident(backend)
            ))
            .bind(password_hash)
            .bind(user.id)
            .execute(db.get_ref())
            .await
            {
                Ok(_) => HttpResponse::NoContent().finish(),
                Err(_) => errors::internal_error("Database error"),
            }
        }
        Err(_) => errors::internal_error("Database error"),
    }
}

pub async fn verify_email_token(
    input: web::Json<VerifyEmailInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    let token = input.token.trim();
    if token.is_empty() {
        return errors::validation_error("token", "Verification token cannot be empty");
    }

    match apply_email_verification_token(db.get_ref(), token).await {
        Ok(TokenActionOutcome::Applied) => HttpResponse::NoContent().finish(),
        Ok(TokenActionOutcome::Invalid) => {
            errors::bad_request("invalid_token", "Verification token is invalid")
        }
        Ok(TokenActionOutcome::Expired) => {
            errors::bad_request("expired_token", "Verification token has expired")
        }
        Err(error) if is_missing_auth_management_schema(&error) => {
            missing_auth_management_schema_response()
        }
        Err(_) => errors::internal_error("Database error"),
    }
}

pub async fn verify_email_page(
    query: web::Query<AuthTokenQuery>,
    db: web::Data<DbPool>,
) -> impl Responder {
    let Some(token) = query
        .token
        .as_deref()
        .map(str::trim)
        .filter(|token| !token.is_empty())
    else {
        return render_message_page(
            "Verify Email",
            "Verification link is missing a token.",
            "Ask the application to resend the verification email and open the new link.",
        );
    };

    match apply_email_verification_token(db.get_ref(), token).await {
        Ok(TokenActionOutcome::Applied) => render_message_page(
            "Email Verified",
            "Your email address has been verified.",
            "You can return to the app and continue signing in.",
        ),
        Ok(TokenActionOutcome::Invalid) => render_message_page(
            "Invalid Link",
            "This verification link is invalid.",
            "Request a new verification email from the account portal or sign-up flow.",
        ),
        Ok(TokenActionOutcome::Expired) => render_message_page(
            "Expired Link",
            "This verification link has expired.",
            "Request a new verification email from the account portal or sign-up flow.",
        ),
        Err(error) if is_missing_auth_management_schema(&error) => render_message_page(
            "Migration Required",
            "The built-in auth management schema is missing.",
            "Apply the built-in auth migration again to add email verification support.",
        ),
        Err(_) => render_message_page(
            "Unexpected Error",
            "Email verification failed because of a server error.",
            "Try again later or contact the application administrator.",
        ),
    }
}

pub async fn resend_verification(
    req: HttpRequest,
    input: web::Json<VerificationResendInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    let settings = auth_settings_from_request(&req);
    if let Err(response) = configured_auth_email(&settings) {
        return response;
    }

    let email = match normalize_auth_email(&input.email) {
        Ok(email) => email,
        Err(response) => return response,
    };
    let user = match load_authenticated_user_by_email_with_settings(db.get_ref(), &email, &settings)
        .await
    {
        Ok(user) => user,
        Err(_) => return errors::internal_error("Database error"),
    };
    let Some(user) = user else {
        return HttpResponse::Accepted().finish();
    };
    if user.email_verified_at.is_some() {
        return HttpResponse::Accepted().finish();
    }

    let tx = match db.begin().await {
        Ok(tx) => tx,
        Err(_) => return errors::internal_error("Database error"),
    };
    if let Err(response) = send_verification_email_for_user(
        &tx,
        Some(&req),
        &settings,
        &user,
        "/auth/verification/resend",
    )
    .await
    {
        let _ = tx.rollback().await;
        return response;
    }
    if tx.commit().await.is_err() {
        return errors::internal_error("Database error");
    }

    HttpResponse::Accepted().finish()
}

pub async fn resend_account_verification(
    req: HttpRequest,
    user: UserContext,
    db: web::Data<DbPool>,
) -> impl Responder {
    let settings = auth_settings_from_request(&req);
    if let Err(response) = configured_auth_email(&settings) {
        return response;
    }

    let account =
        match load_authenticated_user_by_id_with_settings(db.get_ref(), user.id, &settings).await {
            Ok(Some(account)) => account,
            Ok(None) => {
                return errors::unauthorized("invalid_token", "Authenticated user not found");
            }
            Err(_) => return errors::internal_error("Database error"),
        };
    if account.email_verified_at.is_some() {
        return HttpResponse::NoContent().finish();
    }

    let tx = match db.begin().await {
        Ok(tx) => tx,
        Err(_) => return errors::internal_error("Database error"),
    };
    if let Err(response) = send_verification_email_for_user(
        &tx,
        Some(&req),
        &settings,
        &account,
        "/auth/account/verification",
    )
    .await
    {
        let _ = tx.rollback().await;
        return response;
    }
    if tx.commit().await.is_err() {
        return errors::internal_error("Database error");
    }

    HttpResponse::Accepted().finish()
}

pub async fn request_password_reset(
    req: HttpRequest,
    input: web::Json<PasswordResetRequestInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    let settings = auth_settings_from_request(&req);
    if let Err(response) = configured_auth_email(&settings) {
        return response;
    }

    let email = match normalize_auth_email(&input.email) {
        Ok(email) => email,
        Err(response) => return response,
    };
    let user = match load_authenticated_user_by_email_with_settings(db.get_ref(), &email, &settings)
        .await
    {
        Ok(user) => user,
        Err(_) => return errors::internal_error("Database error"),
    };
    let Some(user) = user else {
        return HttpResponse::Accepted().finish();
    };

    let tx = match db.begin().await {
        Ok(tx) => tx,
        Err(_) => return errors::internal_error("Database error"),
    };
    if let Err(response) =
        send_password_reset_email_for_user(&tx, Some(&req), &settings, &user).await
    {
        let _ = tx.rollback().await;
        return response;
    }
    if tx.commit().await.is_err() {
        return errors::internal_error("Database error");
    }

    HttpResponse::Accepted().finish()
}

pub async fn confirm_password_reset(
    input: web::Json<PasswordResetConfirmInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    let token = input.token.trim();
    if token.is_empty() {
        return errors::validation_error("token", "Reset token cannot be empty");
    }
    if let Err(response) = validate_auth_password(&input.new_password) {
        return response;
    }

    let password_hash = match hash(&input.new_password, 12) {
        Ok(hash) => hash,
        Err(_) => return errors::internal_error("Hashing error"),
    };

    match apply_password_reset_token(db.get_ref(), token, &password_hash).await {
        Ok(TokenActionOutcome::Applied) => HttpResponse::NoContent().finish(),
        Ok(TokenActionOutcome::Invalid) => {
            errors::bad_request("invalid_token", "Password reset token is invalid")
        }
        Ok(TokenActionOutcome::Expired) => {
            errors::bad_request("expired_token", "Password reset token has expired")
        }
        Err(error) if is_missing_auth_management_schema(&error) => {
            missing_auth_management_schema_response()
        }
        Err(_) => errors::internal_error("Database error"),
    }
}

pub async fn password_reset_page(
    req: HttpRequest,
    query: web::Query<AuthTokenQuery>,
) -> impl Responder {
    let auth_base = auth_api_base_path_for_page(&req, None);
    let page = render_password_reset_page(&auth_base, query.token.as_deref());
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(page)
}

pub async fn create_managed_user(
    req: HttpRequest,
    user: UserContext,
    input: web::Json<CreateManagedUserInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    if !user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    let settings = auth_settings_from_request(&req);
    let backend = match detect_auth_backend(db.get_ref()).await {
        Ok(backend) => backend,
        Err(_) => return errors::internal_error("Database error"),
    };
    let email = match normalize_auth_email(&input.email) {
        Ok(email) => email,
        Err(response) => return response,
    };
    if let Err(response) = validate_auth_password(&input.password) {
        return response;
    }
    let role = match normalize_auth_role(input.role.as_deref(), "user") {
        Ok(role) => role,
        Err(response) => return response,
    };
    if input.email_verified == Some(true) && input.send_verification_email == Some(true) {
        return errors::bad_request(
            "invalid_invite_state",
            "A verified user does not need a verification email",
        );
    }
    if input.send_verification_email == Some(true)
        && let Err(response) = configured_auth_email(&settings)
    {
        return response;
    }

    let password_hash = match hash(&input.password, 12) {
        Ok(hash) => hash,
        Err(_) => return errors::internal_error("Hashing error"),
    };

    let tx = match db.begin().await {
        Ok(tx) => tx,
        Err(_) => return errors::internal_error("Database error"),
    };
    let insert_result = query(&format!(
        "INSERT INTO {} (email, password_hash, role) VALUES (?, ?, ?)",
        auth_user_table_ident(backend)
    ))
    .bind(&email)
    .bind(&password_hash)
    .bind(&role)
    .execute(&tx)
    .await;

    match insert_result {
        Ok(_) => {}
        Err(error) if is_unique_violation(&error) => {
            let _ = tx.rollback().await;
            return errors::conflict("duplicate_email", "A user with that email already exists");
        }
        Err(error) => {
            let _ = tx.rollback().await;
            if is_missing_auth_management_schema(&error) {
                return missing_auth_management_schema_response();
            }
            return errors::internal_error("Database error");
        }
    }

    let Some(created_user) = (match load_authenticated_user_by_email_with_settings_for_backend(
        &tx, backend, &email, &settings,
    )
    .await
    {
        Ok(user) => user,
        Err(error) => {
            let _ = tx.rollback().await;
            if is_missing_auth_management_schema(&error) {
                return missing_auth_management_schema_response();
            }
            return errors::internal_error("Database error");
        }
    }) else {
        let _ = tx.rollback().await;
        return errors::internal_error("Failed to load created user");
    };

    let now = now_timestamp_string();
    if let Err(error) =
        initialize_user_management_timestamps(&tx, backend, created_user.id, &now).await
    {
        let _ = tx.rollback().await;
        if is_missing_auth_management_schema(&error) {
            return missing_auth_management_schema_response();
        }
        return errors::internal_error("Database error");
    }

    if input.email_verified.unwrap_or(false) {
        if let Err(error) = mark_user_email_verified(&tx, backend, created_user.id, &now).await {
            let _ = tx.rollback().await;
            if is_missing_auth_management_schema(&error) {
                return missing_auth_management_schema_response();
            }
            return errors::internal_error("Database error");
        }
    } else if input.send_verification_email.unwrap_or(false)
        && let Err(response) = send_verification_email_for_user(
            &tx,
            Some(&req),
            &settings,
            &created_user,
            "/auth/admin/users",
        )
        .await
    {
        let _ = tx.rollback().await;
        return response;
    }

    if tx.commit().await.is_err() {
        return errors::internal_error("Database error");
    }

    match load_authenticated_user_by_email_with_settings(db.get_ref(), &email, &settings).await {
        Ok(Some(account)) => {
            let scope_prefix = scope_prefix_from_request(&req, Some("/auth/admin/users"));
            let location = if scope_prefix.is_empty() {
                format!("/auth/admin/users/{}", account.id)
            } else {
                format!(
                    "{}/auth/admin/users/{}",
                    scope_prefix.trim_end_matches('/'),
                    account.id
                )
            };
            HttpResponse::Created()
                .append_header(("Location", location))
                .json(account_info_from_user(account))
        }
        Ok(None) => errors::internal_error("Failed to load created user"),
        Err(error) if is_missing_auth_management_schema(&error) => {
            missing_auth_management_schema_response()
        }
        Err(_) => errors::internal_error("Database error"),
    }
}

pub async fn list_managed_users(
    req: HttpRequest,
    user: UserContext,
    query_params: web::Query<AdminListQuery>,
    db: web::Data<DbPool>,
) -> impl Responder {
    if !user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    let limit = query_params.limit.unwrap_or(50).clamp(1, 100);
    let offset = query_params.offset.unwrap_or(0);
    let email_filter = query_params
        .email
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let settings = auth_settings_from_request(&req);
    let backend = match detect_auth_backend(db.get_ref()).await {
        Ok(backend) => backend,
        Err(_) => return errors::internal_error("Database error"),
    };
    match list_authenticated_users_with_settings(
        db.get_ref(),
        backend,
        limit,
        offset,
        email_filter,
        &settings,
    )
    .await
    {
        Ok(items) => HttpResponse::Ok().json(serde_json::json!({
            "items": items,
            "limit": limit,
            "offset": offset,
        })),
        Err(_) => errors::internal_error("Database error"),
    }
}

pub async fn managed_user(
    req: HttpRequest,
    user: UserContext,
    path: web::Path<i64>,
    db: web::Data<DbPool>,
) -> impl Responder {
    if !user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    let settings = auth_settings_from_request(&req);
    match load_authenticated_user_by_id_with_settings(db.get_ref(), path.into_inner(), &settings)
        .await
    {
        Ok(Some(user)) => HttpResponse::Ok().json(account_info_from_user(user)),
        Ok(None) => errors::not_found("User not found"),
        Err(_) => errors::internal_error("Database error"),
    }
}

pub async fn update_managed_user(
    req: HttpRequest,
    user: UserContext,
    path: web::Path<i64>,
    input: web::Json<UpdateManagedUserInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    if !user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }
    if input
        .role
        .as_deref()
        .is_some_and(|role| role.trim().is_empty())
    {
        return errors::validation_error("role", "Role cannot be empty");
    }

    let user_id = path.into_inner();
    let now = now_timestamp_string();
    let settings = auth_settings_from_request(&req);
    let backend = match detect_auth_backend(db.get_ref()).await {
        Ok(backend) => backend,
        Err(_) => return errors::internal_error("Database error"),
    };
    let claim_updates = if input.claims.is_empty() {
        Vec::new()
    } else {
        let user_columns = match user_table_columns(db.get_ref(), backend).await {
            Ok(columns) => columns,
            Err(_) => return errors::internal_error("Database error"),
        };
        match resolve_managed_claim_updates(&user_columns, &settings.claims, &input.claims) {
            Ok(updates) => updates,
            Err(response) => return response,
        }
    };
    if input.role.is_none() && input.email_verified.is_none() && claim_updates.is_empty() {
        return errors::bad_request(
            "missing_changes",
            "Provide `role`, `email_verified`, and/or `claims` to update the user",
        );
    }
    match update_managed_user_row(db.get_ref(), backend, user_id, &input, &claim_updates, &now)
        .await
    {
        Ok(true) => {
            match load_authenticated_user_by_id_with_settings(db.get_ref(), user_id, &settings)
                .await
            {
                Ok(Some(user)) => HttpResponse::Ok().json(account_info_from_user(user)),
                Ok(None) => errors::not_found("User not found"),
                Err(_) => errors::internal_error("Database error"),
            }
        }
        Ok(false) => errors::not_found("User not found"),
        Err(error) if is_missing_auth_management_schema(&error) => {
            missing_auth_management_schema_response()
        }
        Err(_) => errors::internal_error("Database error"),
    }
}

pub async fn delete_managed_user(
    user: UserContext,
    path: web::Path<i64>,
    db: web::Data<DbPool>,
) -> impl Responder {
    if !user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    let user_id = path.into_inner();
    if user.id == user_id {
        return errors::bad_request(
            "cannot_delete_self",
            "Admins cannot delete their own account from the admin dashboard",
        );
    }

    let backend = match detect_auth_backend(db.get_ref()).await {
        Ok(backend) => backend,
        Err(_) => return errors::internal_error("Database error"),
    };
    match delete_user_row(db.get_ref(), backend, user_id).await {
        Ok(true) => HttpResponse::NoContent().finish(),
        Ok(false) => errors::not_found("User not found"),
        Err(_) => errors::internal_error("Database error"),
    }
}

pub async fn resend_managed_user_verification(
    req: HttpRequest,
    user: UserContext,
    path: web::Path<i64>,
    db: web::Data<DbPool>,
) -> impl Responder {
    if !user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }
    let settings = auth_settings_from_request(&req);
    if let Err(response) = configured_auth_email(&settings) {
        return response;
    }

    let Some(account) = (match load_authenticated_user_by_id_with_settings(
        db.get_ref(),
        path.into_inner(),
        &settings,
    )
    .await
    {
        Ok(account) => account,
        Err(_) => return errors::internal_error("Database error"),
    }) else {
        return errors::not_found("User not found");
    };
    if account.email_verified_at.is_some() {
        return HttpResponse::NoContent().finish();
    }

    let tx = match db.begin().await {
        Ok(tx) => tx,
        Err(_) => return errors::internal_error("Database error"),
    };
    if let Err(response) = send_verification_email_for_user(
        &tx,
        Some(&req),
        &settings,
        &account,
        "/auth/admin/users/verification",
    )
    .await
    {
        let _ = tx.rollback().await;
        return response;
    }
    if tx.commit().await.is_err() {
        return errors::internal_error("Database error");
    }

    HttpResponse::Accepted().finish()
}

pub async fn account_portal_page(req: HttpRequest) -> impl Responder {
    let settings = auth_settings_from_request(&req);
    let Some(portal) = settings.portal.as_ref() else {
        return errors::not_found("Account portal is not enabled");
    };
    let auth_base = auth_api_base_path_for_page(&req, Some(portal.path.as_str()));
    let csrf_cookie_name = settings
        .session_cookie
        .as_ref()
        .map(|cookie| cookie.csrf_cookie_name.as_str())
        .unwrap_or("vsr_csrf");
    let csrf_header_name = settings
        .session_cookie
        .as_ref()
        .map(|cookie| cookie.csrf_header_name.as_str())
        .unwrap_or("x-csrf-token");

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(render_account_portal_page(
            &portal.title,
            &auth_base,
            csrf_cookie_name,
            csrf_header_name,
        ))
}

pub async fn admin_dashboard_page(req: HttpRequest, user: UserContext) -> impl Responder {
    if !user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    let settings = auth_settings_from_request(&req);
    let Some(dashboard) = settings.admin_dashboard.as_ref() else {
        return errors::not_found("Admin dashboard is not enabled");
    };
    let auth_base = auth_api_base_path_for_page(&req, Some(dashboard.path.as_str()));
    let csrf_cookie_name = settings
        .session_cookie
        .as_ref()
        .map(|cookie| cookie.csrf_cookie_name.as_str())
        .unwrap_or("vsr_csrf");
    let csrf_header_name = settings
        .session_cookie
        .as_ref()
        .map(|cookie| cookie.csrf_header_name.as_str())
        .unwrap_or("x-csrf-token");

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(render_admin_dashboard_page(
            &dashboard.title,
            &auth_base,
            csrf_cookie_name,
            csrf_header_name,
        ))
}
