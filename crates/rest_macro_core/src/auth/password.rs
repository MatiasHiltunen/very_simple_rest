//! Compatibility wrappers; bounded work is owned by the shared runtime.

use actix_web::HttpResponse;

pub(super) async fn hash(password: &str, cost: u32) -> Result<String, HttpResponse> {
    vsr_runtime::auth::password::hash(password, cost)
        .await
        .map_err(super::runtime::failure_response)
}
