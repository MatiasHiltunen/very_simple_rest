#![allow(dead_code)]

use very_simple_rest::RestApi;

#[derive(RestApi)]
#[row_policy(read = "owner:user_id")]
struct MissingPolicyField {
    id: Option<i64>,
    title: String,
}

fn main() {}
