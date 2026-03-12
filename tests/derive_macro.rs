use very_simple_rest::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, RestApi)]
#[rest_api(table = "article", id = "id", db = "sqlite")]
struct Article {
    id: Option<i64>,
    title: String,
    body: String,
    created_at: Option<String>,
    updated_at: Option<String>,
}

#[test]
fn derive_macro_generates_write_dtos() {
    let article = Article {
        id: Some(1),
        title: "Title".to_owned(),
        body: "Body".to_owned(),
        created_at: Some("2026-03-12T00:00:00Z".to_owned()),
        updated_at: Some("2026-03-12T00:00:00Z".to_owned()),
    };
    let create = ArticleCreate {
        title: "Title".to_owned(),
        body: "Body".to_owned(),
    };
    let update = ArticleUpdate {
        title: "Updated".to_owned(),
        body: "Body".to_owned(),
    };

    let _configure: fn(
        &mut very_simple_rest::actix_web::web::ServiceConfig,
        very_simple_rest::sqlx::AnyPool,
    ) = Article::configure;

    let _ = (article, create, update);
}
