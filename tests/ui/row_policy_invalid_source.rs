#![allow(dead_code)]

use very_simple_rest::RestApi;

#[derive(RestApi)]
#[row_policy(read = "tenant_id=session.tenant_id")]
struct InvalidPolicySource {
    id: Option<i64>,
    tenant_id: i64,
}

fn main() {}
