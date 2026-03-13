#![allow(dead_code)]

use very_simple_rest::RestApi;

#[derive(RestApi)]
struct InvalidRelationForeignKey {
    id: Option<i64>,
    #[relation(foreign_key = "post_fk", references = "post.id")]
    post_id: i64,
}

fn main() {}
