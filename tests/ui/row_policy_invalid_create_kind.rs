#![allow(dead_code)]

use very_simple_rest::RestApi;

#[derive(RestApi)]
#[row_policy(create = "owner:user_id")]
struct InvalidCreatePolicy {
    id: Option<i64>,
    user_id: i64,
}

fn main() {}
