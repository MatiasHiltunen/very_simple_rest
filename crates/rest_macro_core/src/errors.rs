use actix_web::{
    HttpResponse,
    error::{JsonPayloadError, PathError, QueryPayloadError},
    http::StatusCode,
    web::{self, JsonConfig, PathConfig, QueryConfig},
};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ApiErrorResponse {
    pub code: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

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

pub fn validation_error(field: impl Into<String>, message: impl Into<String>) -> HttpResponse {
    HttpResponse::BadRequest().json(ApiErrorResponse {
        code: "validation_error",
        message: message.into(),
        field: Some(field.into()),
    })
}

pub fn bad_request(code: &'static str, message: impl Into<String>) -> HttpResponse {
    error_response(StatusCode::BAD_REQUEST, code, message)
}

pub fn forbidden(code: &'static str, message: impl Into<String>) -> HttpResponse {
    error_response(StatusCode::FORBIDDEN, code, message)
}

pub fn unauthorized(code: &'static str, message: impl Into<String>) -> HttpResponse {
    error_response(StatusCode::UNAUTHORIZED, code, message)
}

pub fn conflict(code: &'static str, message: impl Into<String>) -> HttpResponse {
    error_response(StatusCode::CONFLICT, code, message)
}

pub fn not_found(message: impl Into<String>) -> HttpResponse {
    error_response(StatusCode::NOT_FOUND, "not_found", message)
}

pub fn internal_error(message: impl Into<String>) -> HttpResponse {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", message)
}

pub fn into_actix_error(response: HttpResponse) -> actix_web::Error {
    actix_web::error::InternalError::from_response("", response).into()
}

pub fn json_error_config() -> JsonConfig {
    web::JsonConfig::default()
        .error_handler(|error, _request| into_actix_error(json_payload_error_response(&error)))
}

pub fn path_error_config() -> PathConfig {
    web::PathConfig::default()
        .error_handler(|error, _request| into_actix_error(path_error_response(&error)))
}

pub fn query_error_config() -> QueryConfig {
    web::QueryConfig::default()
        .error_handler(|error, _request| into_actix_error(query_error_response(&error)))
}

pub fn configure_extractor_errors(cfg: &mut web::ServiceConfig) {
    cfg.app_data(json_error_config());
    cfg.app_data(path_error_config());
    cfg.app_data(query_error_config());
}

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

pub fn path_error_response(_error: &PathError) -> HttpResponse {
    bad_request("invalid_path", "Path parameters are invalid")
}

pub fn query_error_response(_error: &QueryPayloadError) -> HttpResponse {
    bad_request("invalid_query", "Query parameters are invalid")
}
