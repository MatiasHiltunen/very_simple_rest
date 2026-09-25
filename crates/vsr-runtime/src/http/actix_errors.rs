//! Actix JSON error responses and extractor error configuration.

use actix_web::{
    HttpResponse,
    error::{JsonPayloadError, PathError, QueryPayloadError},
    http::StatusCode,
    web::{self, JsonConfig, PathConfig, QueryConfig},
};
use serde::Serialize;

/// Stable JSON error body for legacy Actix endpoints.
#[derive(Debug, Clone, Serialize)]
pub struct ApiErrorResponse {
    /// Machine-readable error code.
    pub code: &'static str,
    /// Human-readable error message.
    pub message: String,
    /// Optional field associated with validation failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

/// Build a JSON error response with an explicit status and code.
pub fn error_response(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> HttpResponse {
    HttpResponse::build(status).json(ApiErrorResponse {
        code,
        message: message.into(),
        field: None,
    })
}

/// Build a field-specific validation response.
pub fn validation_error(field: impl Into<String>, message: impl Into<String>) -> HttpResponse {
    HttpResponse::BadRequest().json(ApiErrorResponse {
        code: "validation_error",
        message: message.into(),
        field: Some(field.into()),
    })
}

/// Build a bad-request response.
pub fn bad_request(code: &'static str, message: impl Into<String>) -> HttpResponse {
    error_response(StatusCode::BAD_REQUEST, code, message)
}

/// Build a forbidden response.
pub fn forbidden(code: &'static str, message: impl Into<String>) -> HttpResponse {
    error_response(StatusCode::FORBIDDEN, code, message)
}

/// Build an unauthorized response.
pub fn unauthorized(code: &'static str, message: impl Into<String>) -> HttpResponse {
    error_response(StatusCode::UNAUTHORIZED, code, message)
}

/// Build a conflict response.
pub fn conflict(code: &'static str, message: impl Into<String>) -> HttpResponse {
    error_response(StatusCode::CONFLICT, code, message)
}

/// Build a rate-limit response.
pub fn too_many_requests(code: &'static str, message: impl Into<String>) -> HttpResponse {
    error_response(StatusCode::TOO_MANY_REQUESTS, code, message)
}

/// Build a not-found response.
pub fn not_found(message: impl Into<String>) -> HttpResponse {
    error_response(StatusCode::NOT_FOUND, "not_found", message)
}

/// Build an internal-error response.
pub fn internal_error(message: impl Into<String>) -> HttpResponse {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", message)
}

/// Convert a response into an Actix extractor error.
pub fn into_actix_error(response: HttpResponse) -> actix_web::Error {
    actix_web::error::InternalError::from_response("", response).into()
}

/// Configure JSON extraction errors and an optional body limit.
pub fn json_error_config(max_size: Option<usize>) -> JsonConfig {
    let mut config = web::JsonConfig::default();
    if let Some(max_size) = max_size {
        config = config.limit(max_size);
    }
    config.error_handler(|error, _request| into_actix_error(json_payload_error_response(&error)))
}

/// Configure path extraction errors.
pub fn path_error_config() -> PathConfig {
    web::PathConfig::default()
        .error_handler(|error, _request| into_actix_error(path_error_response(&error)))
}

/// Configure query extraction errors.
pub fn query_error_config() -> QueryConfig {
    web::QueryConfig::default()
        .error_handler(|error, _request| into_actix_error(query_error_response(&error)))
}

/// Install default extractor error handlers in an Actix scope.
pub fn configure_extractor_errors(cfg: &mut web::ServiceConfig) {
    configure_extractor_errors_with_limit(cfg, None);
}

/// Install extractor error handlers with an optional JSON size limit.
pub fn configure_extractor_errors_with_limit(
    cfg: &mut web::ServiceConfig,
    json_max_bytes: Option<usize>,
) {
    cfg.app_data(json_error_config(json_max_bytes));
    cfg.app_data(path_error_config());
    cfg.app_data(query_error_config());
}

/// Map an Actix JSON extraction failure into the stable error shape.
pub fn json_payload_error_response(error: &JsonPayloadError) -> HttpResponse {
    match error {
        JsonPayloadError::OverflowKnownLength { .. } | JsonPayloadError::Overflow { .. } => {
            error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "JSON payload is too large",
            )
        }
        JsonPayloadError::ContentType => error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "invalid_content_type",
            "Expected Content-Type: application/json",
        ),
        JsonPayloadError::Deserialize(_) => {
            bad_request("invalid_json", "Request body is not valid JSON")
        }
        JsonPayloadError::Payload(_) => {
            bad_request("invalid_json_payload", "Failed to read JSON request body")
        }
        JsonPayloadError::Serialize(_) => internal_error("Failed to serialize JSON payload"),
        _ => bad_request(
            "invalid_json_payload",
            "Failed to process JSON request body",
        ),
    }
}

/// Map a path extraction failure into the stable error shape.
pub fn path_error_response(_error: &PathError) -> HttpResponse {
    bad_request("invalid_path", "Path parameters are invalid")
}

/// Map a query extraction failure into the stable error shape.
pub fn query_error_response(_error: &QueryPayloadError) -> HttpResponse {
    bad_request("invalid_query", "Query parameters are invalid")
}

#[cfg(test)]
mod tests {
    use actix_web::{App, HttpResponse, http::StatusCode, test, web};

    use crate::security::{SecurityConfig, actix::configure_scope_security};

    #[actix_web::test]
    async fn security_scope_preserves_json_size_error() {
        let mut security = SecurityConfig::default();
        security.requests.json_max_bytes = Some(2);
        let app = test::init_service(App::new().service(web::scope("/api").configure(|cfg| {
            configure_scope_security(cfg, &security);
            cfg.route(
                "/items",
                web::post()
                    .to(|_: web::Json<serde_json::Value>| async { HttpResponse::Ok().finish() }),
            );
        })))
        .await;

        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/api/items")
                .insert_header(("content-type", "application/json"))
                .set_payload(r#"{"name":"too large"}"#)
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let body: serde_json::Value = test::read_body_json(response).await;
        assert_eq!(body["code"], "payload_too_large");
    }
}
