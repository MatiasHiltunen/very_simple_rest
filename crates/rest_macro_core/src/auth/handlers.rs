use actix_web::{HttpRequest, HttpResponse, Responder, web};

use crate::{db::DbPool, errors};

use super::helpers::{
    auth_api_base_path_for_page, auth_settings_from_request, enforce_auth_rate_limit,
    scope_prefix_from_request, user_is_admin,
};
use super::pages::{
    render_account_portal_page, render_admin_dashboard_page, render_message_page,
    render_password_reset_page,
};
use super::settings::AuthSettings;
use super::tokens::{TokenActionOutcome, apply_email_verification_token};
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
    let verification_url = if settings.email.is_some() {
        match super::email::action_url(
            request,
            &settings,
            super::user::AuthTokenPurpose::EmailVerification,
            Some("/auth/register"),
        ) {
            Ok(url) => Some(url),
            Err(error) => return super::accounts::error_response(error),
        }
    } else {
        None
    };
    let service = match super::registration::builtin_registration_service(
        db.get_ref().clone(),
        &settings,
        verification_url.as_deref(),
    ) {
        Ok(service) => service,
        Err(error) => return super::accounts::error_response(error),
    };
    match service.register(&input.email, &input.password).await {
        Ok(()) => HttpResponse::Created().finish(),
        Err(error) => super::accounts::error_response(error),
    }
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
    let presentation = match super::session::builtin_session_presentation(&settings) {
        Ok(presentation) => presentation,
        Err(error) => return super::accounts::error_response(error),
    };
    let service = match super::accounts::builtin_account_service(
        db.get_ref().clone(),
        settings.clone(),
    ) {
        Ok(service) => service,
        Err(error) => return super::accounts::error_response(error),
    };
    match service.login(&input.email, &input.password).await {
        Ok(token) => match presentation.login(&token, settings.access_token_ttl_seconds) {
            Ok(response) => super::accounts::response(response),
            Err(error) => super::accounts::error_response(error),
        },
        Err(error) => super::accounts::error_response(error),
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

pub async fn me(user: UserContext) -> impl Responder {
    HttpResponse::Ok().json(user)
}

pub async fn logout(req: HttpRequest) -> impl Responder {
    let settings = auth_settings_from_request(&req);
    let presentation = match super::session::builtin_session_presentation(&settings) {
        Ok(presentation) => presentation,
        Err(error) => return super::accounts::error_response(error),
    };
    let headers = match super::runtime::request_headers(&req) {
        Ok(headers) => headers,
        Err(error) => return super::runtime::failure_response(error),
    };
    match presentation.logout(&headers) {
        Ok(response) => super::accounts::response(response),
        Err(error) => super::accounts::error_response(error),
    }
}

pub async fn account(req: HttpRequest, user: UserContext, db: web::Data<DbPool>) -> impl Responder {
    let service = match super::accounts::builtin_account_service(
        db.get_ref().clone(),
        auth_settings_from_request(&req),
    ) {
        Ok(service) => service,
        Err(error) => return super::accounts::error_response(error),
    };
    match service.account(user.id).await {
        Ok(account) => HttpResponse::Ok().json(account),
        Err(error) => super::accounts::error_response(error),
    }
}

pub async fn change_password(
    user: UserContext,
    input: web::Json<ChangePasswordInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    let service = match super::accounts::builtin_account_service(
        db.get_ref().clone(),
        AuthSettings::default(),
    ) {
        Ok(service) => service,
        Err(error) => return super::accounts::error_response(error),
    };
    match service
        .change_password(user.id, &input.current_password, &input.new_password)
        .await
    {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(error) => super::accounts::error_response(error),
    }
}

pub async fn verify_email_token(
    input: web::Json<VerifyEmailInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    match super::tokens::builtin_recovery_service(db.get_ref().clone())
        .verify_email(&input.token)
        .await
    {
        Ok(outcome) => super::accounts::response(
            outcome.response(super::user::AuthTokenPurpose::EmailVerification),
        ),
        Err(error) => super::accounts::error_response(error),
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
        Err(vsr_runtime::auth::accounts::AccountError::MissingSchema) => render_message_page(
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

async fn request_recovery_email(
    req: &HttpRequest,
    email: &str,
    db: &DbPool,
    purpose: super::user::AuthTokenPurpose,
    current_route_path: &str,
) -> HttpResponse {
    let settings = auth_settings_from_request(req);
    let url =
        match super::email::action_url(Some(req), &settings, purpose, Some(current_route_path)) {
            Ok(url) => url,
            Err(error) => return super::accounts::error_response(error),
        };
    let service = match super::recovery_email::builtin_recovery_email_service(
        db.clone(),
        &settings,
        &url,
        purpose,
    ) {
        Ok(service) => service,
        Err(error) => return super::accounts::error_response(error),
    };
    match service.request(email).await {
        Ok(()) => HttpResponse::Accepted().finish(),
        Err(error) => super::accounts::error_response(error),
    }
}

pub async fn resend_verification(
    req: HttpRequest,
    input: web::Json<VerificationResendInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    request_recovery_email(
        &req,
        &input.email,
        db.get_ref(),
        super::user::AuthTokenPurpose::EmailVerification,
        "/auth/verification/resend",
    )
    .await
}

pub async fn resend_account_verification(
    req: HttpRequest,
    user: UserContext,
    db: web::Data<DbPool>,
) -> impl Responder {
    resend_authenticated_verification(&req, &user, db.get_ref(), None).await
}

async fn resend_authenticated_verification(
    req: &HttpRequest,
    user: &UserContext,
    db: &DbPool,
    target: Option<i64>,
) -> HttpResponse {
    if target.is_some() && !user_is_admin(user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }
    let settings = auth_settings_from_request(req);
    let route = if target.is_some() {
        "/auth/admin/users/verification"
    } else {
        "/auth/account/verification"
    };
    let url = match super::email::action_url(
        Some(req),
        &settings,
        super::user::AuthTokenPurpose::EmailVerification,
        Some(route),
    ) {
        Ok(url) => url,
        Err(error) => return super::accounts::error_response(error),
    };
    let service = match super::management::builtin_provisioning_service(
        db.clone(),
        &settings,
        Some(&url),
    ) {
        Ok(service) => service,
        Err(error) => return super::accounts::response(error.response()),
    };
    let actor = user.management_identity();
    let result = if let Some(id) = target {
        service.resend_managed(&actor, id).await
    } else {
        service.resend_account(&actor).await
    };
    match result {
        Ok(outcome) => super::accounts::response(outcome.response()),
        Err(error) => super::accounts::response(error.response()),
    }
}

pub async fn request_password_reset(
    req: HttpRequest,
    input: web::Json<PasswordResetRequestInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    request_recovery_email(
        &req,
        &input.email,
        db.get_ref(),
        super::user::AuthTokenPurpose::PasswordReset,
        "/auth/password-reset/request",
    )
    .await
}

pub async fn confirm_password_reset(
    input: web::Json<PasswordResetConfirmInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    match super::tokens::builtin_recovery_service(db.get_ref().clone())
        .reset_password(&input.token, &input.new_password)
        .await
    {
        Ok(outcome) => super::accounts::response(
            outcome.response(super::user::AuthTokenPurpose::PasswordReset),
        ),
        Err(error) => super::accounts::error_response(error),
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
    let url = if input.send_verification_email == Some(true)
        && input.email_verified != Some(true)
        && settings.email.is_some()
    {
        match super::email::action_url(
            Some(&req),
            &settings,
            super::user::AuthTokenPurpose::EmailVerification,
            Some("/auth/admin/users"),
        ) {
            Ok(url) => Some(url),
            Err(error) => return super::accounts::error_response(error),
        }
    } else {
        None
    };
    let service = match super::management::builtin_provisioning_service(
        db.get_ref().clone(),
        &settings,
        url.as_deref(),
    ) {
        Ok(service) => service,
        Err(error) => return super::accounts::response(error.response()),
    };
    match service.create(&user.management_identity(), &input).await {
        Ok(account) => {
            let prefix = scope_prefix_from_request(&req, Some("/auth/admin/users"));
            let location = format!(
                "{}/auth/admin/users/{}",
                prefix.trim_end_matches('/'),
                account.id
            );
            HttpResponse::Created()
                .append_header(("Location", location))
                .json(account)
        }
        Err(error) => super::accounts::response(error.response()),
    }
}

pub async fn list_managed_users(
    req: HttpRequest,
    user: UserContext,
    query_params: web::Query<AdminListQuery>,
    db: web::Data<DbPool>,
) -> impl Responder {
    let service = super::management::builtin_management_service(
        db.get_ref().clone(),
        &auth_settings_from_request(&req),
    );
    match service
        .list(&user.management_identity(), &query_params)
        .await
    {
        Ok(page) => HttpResponse::Ok().json(page),
        Err(error) => super::accounts::response(error.response()),
    }
}

pub async fn managed_user(
    req: HttpRequest,
    user: UserContext,
    path: web::Path<i64>,
    db: web::Data<DbPool>,
) -> impl Responder {
    let service = super::management::builtin_management_service(
        db.get_ref().clone(),
        &auth_settings_from_request(&req),
    );
    match service
        .get(&user.management_identity(), path.into_inner())
        .await
    {
        Ok(account) => HttpResponse::Ok().json(account),
        Err(error) => super::accounts::response(error.response()),
    }
}

pub async fn update_managed_user(
    req: HttpRequest,
    user: UserContext,
    path: web::Path<i64>,
    input: web::Json<UpdateManagedUserInput>,
    db: web::Data<DbPool>,
) -> impl Responder {
    let service = super::management::builtin_management_service(
        db.get_ref().clone(),
        &auth_settings_from_request(&req),
    );
    match service
        .update(
            &user.management_identity(),
            path.into_inner(),
            input.into_inner(),
        )
        .await
    {
        Ok(account) => HttpResponse::Ok().json(account),
        Err(error) => super::accounts::response(error.response()),
    }
}

pub async fn delete_managed_user(
    user: UserContext,
    path: web::Path<i64>,
    db: web::Data<DbPool>,
) -> impl Responder {
    // Deletion needs only the live built-in role, not custom claim mappings.
    let service = super::management::builtin_management_service(
        db.get_ref().clone(),
        &AuthSettings::default(),
    );
    match service
        .delete(&user.management_identity(), path.into_inner())
        .await
    {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(error) => super::accounts::response(error.response()),
    }
}

pub async fn resend_managed_user_verification(
    req: HttpRequest,
    user: UserContext,
    path: web::Path<i64>,
    db: web::Data<DbPool>,
) -> impl Responder {
    resend_authenticated_verification(&req, &user, db.get_ref(), Some(path.into_inner())).await
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
