use very_simple_rest::rest_api_from_eon;

rest_api_from_eon!("tests/fixtures/blog_api.eon");
rest_api_from_eon!("tests/fixtures/owned_api.eon");
rest_api_from_eon!("tests/fixtures/tenant_api.eon");

#[test]
fn eon_macro_generates_models_dtos_and_configure_functions() {
    let post = blog_api::Post {
        id: Some(1),
        title: "Post".to_owned(),
        content: "Body".to_owned(),
        created_at: Some("2026-03-12T00:00:00Z".to_owned()),
        updated_at: Some("2026-03-12T00:00:00Z".to_owned()),
    };
    let create = blog_api::PostCreate {
        title: "Post".to_owned(),
        content: "Body".to_owned(),
    };
    let update = blog_api::PostUpdate {
        title: "Post".to_owned(),
        content: "Body".to_owned(),
    };
    let comment = blog_api::CommentCreate {
        title: "Comment".to_owned(),
        content: "Body".to_owned(),
        post_id: 1,
    };

    let _configure_service: fn(
        &mut very_simple_rest::actix_web::web::ServiceConfig,
        very_simple_rest::sqlx::AnyPool,
    ) = blog_api::configure;
    let _configure_post: fn(
        &mut very_simple_rest::actix_web::web::ServiceConfig,
        very_simple_rest::sqlx::AnyPool,
    ) = blog_api::Post::configure;

    let _ = (post, create, update, comment);
}

#[test]
fn eon_macro_owner_policies_trim_generated_dtos() {
    let post = owned_api::OwnedPost {
        id: Some(1),
        title: "Owned".to_owned(),
        user_id: 7,
        created_at: Some("2026-03-12T00:00:00Z".to_owned()),
        updated_at: Some("2026-03-12T00:00:00Z".to_owned()),
    };
    let create = owned_api::OwnedPostCreate {
        title: "Owned".to_owned(),
    };
    let update = owned_api::OwnedPostUpdate {
        title: "Updated".to_owned(),
    };

    let _configure_service: fn(
        &mut very_simple_rest::actix_web::web::ServiceConfig,
        very_simple_rest::sqlx::AnyPool,
    ) = owned_api::configure;
    let _configure_post: fn(
        &mut very_simple_rest::actix_web::web::ServiceConfig,
        very_simple_rest::sqlx::AnyPool,
    ) = owned_api::OwnedPost::configure;

    let _ = (post, create, update);
}

#[test]
fn eon_macro_claim_policies_trim_generated_dtos() {
    let post = tenant_api::TenantPost {
        id: Some(1),
        title: "Tenant".to_owned(),
        user_id: 3,
        tenant_id: 9,
        created_at: Some("2026-03-12T00:00:00Z".to_owned()),
        updated_at: Some("2026-03-12T00:00:00Z".to_owned()),
    };
    let create = tenant_api::TenantPostCreate {
        title: "Tenant".to_owned(),
    };
    let update = tenant_api::TenantPostUpdate {
        title: "Updated".to_owned(),
    };

    let _configure_service: fn(
        &mut very_simple_rest::actix_web::web::ServiceConfig,
        very_simple_rest::sqlx::AnyPool,
    ) = tenant_api::configure;
    let _configure_post: fn(
        &mut very_simple_rest::actix_web::web::ServiceConfig,
        very_simple_rest::sqlx::AnyPool,
    ) = tenant_api::TenantPost::configure;

    let _ = (post, create, update);
}
