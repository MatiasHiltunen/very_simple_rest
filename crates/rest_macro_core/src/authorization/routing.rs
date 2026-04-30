use actix_web::web;

use crate::errors;

use super::handlers::{
    create_runtime_assignment_endpoint, delete_runtime_assignment_endpoint,
    evaluate_runtime_access_endpoint, list_runtime_assignment_events_endpoint,
    list_runtime_assignments_endpoint, renew_runtime_assignment_endpoint,
    revoke_runtime_assignment_endpoint,
};
use super::types::DEFAULT_AUTHORIZATION_MANAGEMENT_MOUNT;

pub fn authorization_management_routes(cfg: &mut web::ServiceConfig) {
    authorization_management_routes_at(cfg, DEFAULT_AUTHORIZATION_MANAGEMENT_MOUNT);
}

pub fn authorization_management_routes_at(cfg: &mut web::ServiceConfig, mount: &str) {
    errors::configure_extractor_errors(cfg);
    let mount = normalize_management_mount(mount);
    cfg.route(
        &format!("{mount}/evaluate"),
        web::post().to(evaluate_runtime_access_endpoint),
    );
    cfg.route(
        &format!("{mount}/assignments"),
        web::get().to(list_runtime_assignments_endpoint),
    );
    cfg.route(
        &format!("{mount}/assignments"),
        web::post().to(create_runtime_assignment_endpoint),
    );
    cfg.route(
        &format!("{mount}/assignment-events"),
        web::get().to(list_runtime_assignment_events_endpoint),
    );
    cfg.route(
        &format!("{mount}/assignments/{{id}}"),
        web::delete().to(delete_runtime_assignment_endpoint),
    );
    cfg.route(
        &format!("{mount}/assignments/{{id}}/revoke"),
        web::post().to(revoke_runtime_assignment_endpoint),
    );
    cfg.route(
        &format!("{mount}/assignments/{{id}}/renew"),
        web::post().to(renew_runtime_assignment_endpoint),
    );
}

fn normalize_management_mount(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return DEFAULT_AUTHORIZATION_MANAGEMENT_MOUNT.to_owned();
    }
    if trimmed.ends_with('/') {
        trimmed.trim_end_matches('/').to_owned()
    } else {
        trimmed.to_owned()
    }
}
