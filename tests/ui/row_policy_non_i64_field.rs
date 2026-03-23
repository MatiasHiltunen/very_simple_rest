#![allow(dead_code)]

use very_simple_rest::RestApi;

#[derive(RestApi)]
#[row_policy(read = "owner:user_id")]
struct InvalidPolicyFieldType {
    id: Option<i64>,
    user_id: f64,
}

fn main() {}
