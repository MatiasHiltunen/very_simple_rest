#![allow(dead_code)]

use very_simple_rest::RestApi;

#[derive(RestApi)]
#[row_policy(read = "tenant:user_id")]
struct UnknownPolicyKind {
    id: Option<i64>,
    user_id: i64,
}

fn main() {}
