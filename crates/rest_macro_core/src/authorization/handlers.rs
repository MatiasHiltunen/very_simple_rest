use actix_web::{HttpResponse, Responder, web};

use crate::errors;
use crate::auth::UserContext;

use super::types::{
    AuthorizationRuntime, AuthorizationRuntimeAccessInput, AuthorizationScopedAssignmentCreateInput,
    AuthorizationScopedAssignmentListQuery, AuthorizationScopedAssignmentRenewInput,
    AuthorizationScopedAssignmentRevokeInput,
};

fn authorization_user_is_admin(user: &UserContext) -> bool {
    user.roles.iter().any(|role| role == "admin")
}

pub(super) async fn evaluate_runtime_access_endpoint(
    user: UserContext,
    input: web::Json<AuthorizationRuntimeAccessInput>,
    runtime: web::Data<AuthorizationRuntime>,
) -> impl Responder {
    let input = input.into_inner();
    let target_user_id = input.user_id.unwrap_or(user.id);
    if target_user_id != user.id && !authorization_user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    match runtime
        .evaluate_runtime_access_for_user(
            target_user_id,
            &input.resource,
            input.action,
            input.scope,
        )
        .await
    {
        Ok(result) => HttpResponse::Ok().json(result),
        Err(message)
            if message.contains("undeclared")
                || message.contains("not found")
                || message.contains("does not define") =>
        {
            errors::bad_request("invalid_runtime_access", message)
        }
        Err(message) => errors::internal_error(message),
    }
}

pub(super) async fn list_runtime_assignments_endpoint(
    user: UserContext,
    query: web::Query<AuthorizationScopedAssignmentListQuery>,
    runtime: web::Data<AuthorizationRuntime>,
) -> impl Responder {
    if !authorization_user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    match runtime.list_assignments_for_user(query.user_id).await {
        Ok(assignments) => HttpResponse::Ok().json(assignments),
        Err(message) => errors::internal_error(message),
    }
}

pub(super) async fn list_runtime_assignment_events_endpoint(
    user: UserContext,
    query: web::Query<AuthorizationScopedAssignmentListQuery>,
    runtime: web::Data<AuthorizationRuntime>,
) -> impl Responder {
    if !authorization_user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    match runtime.list_assignment_events_for_user(query.user_id).await {
        Ok(events) => HttpResponse::Ok().json(events),
        Err(message) => errors::internal_error(message),
    }
}

pub(super) async fn create_runtime_assignment_endpoint(
    user: UserContext,
    input: web::Json<AuthorizationScopedAssignmentCreateInput>,
    runtime: web::Data<AuthorizationRuntime>,
) -> impl Responder {
    if !authorization_user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    let record = match input.into_inner().into_record(Some(user.id)) {
        Ok(record) => record,
        Err(message) => return errors::bad_request("invalid_runtime_assignment", message),
    };

    match runtime.create_assignment(record).await {
        Ok(assignment) => HttpResponse::Created().json(assignment),
        Err(message) if message.contains("undeclared") || message.contains("only supports") => {
            errors::bad_request("invalid_runtime_assignment", message)
        }
        Err(message) => errors::internal_error(message),
    }
}

pub(super) async fn delete_runtime_assignment_endpoint(
    user: UserContext,
    path: web::Path<String>,
    runtime: web::Data<AuthorizationRuntime>,
) -> impl Responder {
    if !authorization_user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    match runtime
        .delete_assignment_with_audit(&path.into_inner(), Some(user.id), None)
        .await
    {
        Ok(true) => HttpResponse::NoContent().finish(),
        Ok(false) => errors::not_found("Runtime authorization assignment not found"),
        Err(message) => errors::internal_error(message),
    }
}

pub(super) async fn revoke_runtime_assignment_endpoint(
    user: UserContext,
    path: web::Path<String>,
    input: web::Json<AuthorizationScopedAssignmentRevokeInput>,
    runtime: web::Data<AuthorizationRuntime>,
) -> impl Responder {
    if !authorization_user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    match runtime
        .revoke_assignment_with_audit(&path.into_inner(), Some(user.id), input.into_inner().reason)
        .await
    {
        Ok(Some(assignment)) => HttpResponse::Ok().json(assignment),
        Ok(None) => errors::not_found("Runtime authorization assignment not found"),
        Err(message) if message.contains("already inactive") => {
            errors::bad_request("invalid_runtime_assignment", message)
        }
        Err(message) => errors::internal_error(message),
    }
}

pub(super) async fn renew_runtime_assignment_endpoint(
    user: UserContext,
    path: web::Path<String>,
    input: web::Json<AuthorizationScopedAssignmentRenewInput>,
    runtime: web::Data<AuthorizationRuntime>,
) -> impl Responder {
    if !authorization_user_is_admin(&user) {
        return errors::forbidden("forbidden", "Admin role is required");
    }

    let input = input.into_inner();
    match runtime
        .renew_assignment_with_audit(
            &path.into_inner(),
            &input.expires_at,
            Some(user.id),
            input.reason,
        )
        .await
    {
        Ok(Some(assignment)) => HttpResponse::Ok().json(assignment),
        Ok(None) => errors::not_found("Runtime authorization assignment not found"),
        Err(message)
            if message.contains("expires_at")
                || message.contains("already expires at or after") =>
        {
            errors::bad_request("invalid_runtime_assignment", message)
        }
        Err(message) => errors::internal_error(message),
    }
}


