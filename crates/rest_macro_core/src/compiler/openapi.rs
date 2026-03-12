use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::Span;
use serde_json::{Map, Value, json};

use super::model::{FieldSpec, GeneratedValue, ResourceSpec, ServiceSpec, is_optional_type};

#[derive(Clone, Debug)]
pub struct OpenApiSpecOptions {
    pub title: String,
    pub version: String,
    pub server_url: String,
    pub include_builtin_auth: bool,
}

impl OpenApiSpecOptions {
    pub fn new(
        title: impl Into<String>,
        version: impl Into<String>,
        server_url: impl Into<String>,
    ) -> Self {
        Self {
            title: title.into(),
            version: version.into(),
            server_url: server_url.into(),
            include_builtin_auth: false,
        }
    }

    pub fn with_builtin_auth(mut self, include_builtin_auth: bool) -> Self {
        self.include_builtin_auth = include_builtin_auth;
        self
    }
}

impl Default for OpenApiSpecOptions {
    fn default() -> Self {
        Self::new("very_simple_rest API", "1.0.0", "/api")
    }
}

pub fn render_service_openapi_json(
    service: &ServiceSpec,
    options: &OpenApiSpecOptions,
) -> syn::Result<String> {
    serde_json::to_string_pretty(&render_service_openapi_value(service, options)).map_err(|error| {
        syn::Error::new(
            Span::call_site(),
            format!("failed to serialize OpenAPI document: {error}"),
        )
    })
}

fn render_service_openapi_value(service: &ServiceSpec, options: &OpenApiSpecOptions) -> Value {
    let mut schemas = Map::new();
    let mut paths = Map::new();
    let mut tags = service
        .resources
        .iter()
        .map(|resource| {
            json!({
                "name": resource_name(resource),
            })
        })
        .collect::<Vec<_>>();

    for resource in &service.resources {
        let name = resource_name(resource);
        schemas.insert(
            name.clone(),
            object_schema(&resource.fields.iter().collect::<Vec<_>>()),
        );
        schemas.insert(
            format!("{name}Create"),
            object_schema(&create_payload_fields(resource)),
        );
        schemas.insert(
            format!("{name}Update"),
            object_schema(&update_payload_fields(resource)),
        );

        paths.insert(
            format!("/{}", resource.table_name),
            collection_path_item(resource),
        );
        paths.insert(
            format!("/{}/{{id}}", resource.table_name),
            item_path_item(resource),
        );

        for field in &resource.fields {
            let Some(relation) = field.relation.as_ref() else {
                continue;
            };
            if !relation.nested_route {
                continue;
            }
            paths.insert(
                format!(
                    "/{}/{{parent_id}}/{}",
                    relation.references_table, resource.table_name
                ),
                nested_collection_path_item(resource, &relation.references_table, &field.name()),
            );
        }
    }

    if options.include_builtin_auth {
        tags.push(json!({ "name": "Auth" }));
        append_builtin_auth_components(&mut schemas, &mut paths);
    }

    json!({
        "openapi": "3.0.3",
        "info": {
            "title": options.title,
            "version": options.version,
        },
        "servers": [
            {
                "url": options.server_url,
            }
        ],
        "tags": tags,
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT"
                }
            },
            "schemas": schemas,
        },
        "paths": paths,
    })
}

fn collection_path_item(resource: &ResourceSpec) -> Value {
    json!({
        "get": {
            "tags": [resource_name(resource)],
            "summary": format!("List {}", resource_name(resource)),
            "operationId": format!("list{}", resource_name(resource)),
            "security": bearer_security(),
            "responses": list_responses(resource),
        },
        "post": {
            "tags": [resource_name(resource)],
            "summary": format!("Create {}", resource_name(resource)),
            "operationId": format!("create{}", resource_name(resource)),
            "security": bearer_security(),
            "requestBody": json_request_body(format!("{}Create", resource_name(resource))),
            "responses": write_responses("Created"),
        },
    })
}

fn item_path_item(resource: &ResourceSpec) -> Value {
    let id_parameter = id_parameter("id", &resource.id_field);

    json!({
        "get": {
            "tags": [resource_name(resource)],
            "summary": format!("Get {}", resource_name(resource)),
            "operationId": format!("get{}", resource_name(resource)),
            "parameters": [id_parameter.clone()],
            "security": bearer_security(),
            "responses": get_one_responses(resource),
        },
        "put": {
            "tags": [resource_name(resource)],
            "summary": format!("Update {}", resource_name(resource)),
            "operationId": format!("update{}", resource_name(resource)),
            "parameters": [id_parameter.clone()],
            "security": bearer_security(),
            "requestBody": json_request_body(format!("{}Update", resource_name(resource))),
            "responses": write_responses("Updated"),
        },
        "delete": {
            "tags": [resource_name(resource)],
            "summary": format!("Delete {}", resource_name(resource)),
            "operationId": format!("delete{}", resource_name(resource)),
            "parameters": [id_parameter],
            "security": bearer_security(),
            "responses": write_responses("Deleted"),
        },
    })
}

fn nested_collection_path_item(
    resource: &ResourceSpec,
    parent_table: &str,
    relation_field: &str,
) -> Value {
    json!({
        "get": {
            "tags": [resource_name(resource)],
            "summary": format!("List {} by {}", resource_name(resource), parent_table),
            "operationId": format!("list{}By{}", resource_name(resource), parent_table.to_case(CaseKind::Pascal)),
            "parameters": [id_parameter("parent_id", relation_field)],
            "security": bearer_security(),
            "responses": list_responses(resource),
        }
    })
}

fn append_builtin_auth_components(
    schemas: &mut Map<String, Value>,
    paths: &mut Map<String, Value>,
) {
    schemas.insert(
        "RegisterInput".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "email": { "type": "string", "format": "email" },
                "password": { "type": "string" }
            },
            "required": ["email", "password"]
        }),
    );
    schemas.insert(
        "LoginInput".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "email": { "type": "string", "format": "email" },
                "password": { "type": "string" }
            },
            "required": ["email", "password"]
        }),
    );
    schemas.insert(
        "AuthTokenResponse".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "token": { "type": "string" }
            },
            "required": ["token"]
        }),
    );
    schemas.insert(
        "AuthMeResponse".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "integer", "format": "int64" },
                "roles": {
                    "type": "array",
                    "items": { "type": "string" }
                }
            },
            "required": ["id", "roles"],
            "additionalProperties": true
        }),
    );

    paths.insert(
        "/auth/register".to_owned(),
        json!({
            "post": {
                "tags": ["Auth"],
                "summary": "Register a new user",
                "operationId": "registerUser",
                "requestBody": json_request_body("RegisterInput"),
                "responses": {
                    "201": plain_response("Created"),
                    "500": plain_response("Internal server error")
                }
            }
        }),
    );
    paths.insert(
        "/auth/login".to_owned(),
        json!({
            "post": {
                "tags": ["Auth"],
                "summary": "Login and receive a JWT token",
                "operationId": "loginUser",
                "requestBody": json_request_body("LoginInput"),
                "responses": {
                    "200": json_response("OK", schema_ref("AuthTokenResponse")),
                    "401": plain_response("Invalid credentials"),
                    "500": plain_response("Internal server error")
                }
            }
        }),
    );
    paths.insert(
        "/auth/me".to_owned(),
        json!({
            "get": {
                "tags": ["Auth"],
                "summary": "Get the authenticated user context",
                "operationId": "getAuthenticatedUser",
                "security": bearer_security(),
                "responses": {
                    "200": json_response("OK", schema_ref("AuthMeResponse")),
                    "401": plain_response("Authentication required")
                }
            }
        }),
    );
}

fn list_responses(resource: &ResourceSpec) -> BTreeMap<&'static str, Value> {
    BTreeMap::from([
        (
            "200",
            json_response(
                "OK",
                json!({
                    "type": "array",
                    "items": schema_ref(resource_name(resource)),
                }),
            ),
        ),
        ("401", plain_response("Authentication required")),
        ("403", plain_response("Forbidden")),
        ("500", plain_response("Internal server error")),
    ])
}

fn get_one_responses(resource: &ResourceSpec) -> BTreeMap<&'static str, Value> {
    BTreeMap::from([
        (
            "200",
            json_response("OK", schema_ref(resource_name(resource))),
        ),
        ("401", plain_response("Authentication required")),
        ("403", plain_response("Forbidden")),
        ("404", plain_response("Not found")),
        ("500", plain_response("Internal server error")),
    ])
}

fn write_responses(success_description: &'static str) -> BTreeMap<&'static str, Value> {
    BTreeMap::from([
        (
            if success_description == "Created" {
                "201"
            } else {
                "200"
            },
            plain_response(success_description),
        ),
        ("401", plain_response("Authentication required")),
        ("403", plain_response("Forbidden")),
        ("404", plain_response("Not found")),
        ("500", plain_response("Internal server error")),
    ])
}

fn json_request_body(schema_name: impl Into<String>) -> Value {
    json!({
        "required": true,
        "content": {
            "application/json": {
                "schema": schema_ref(schema_name.into()),
            }
        }
    })
}

fn json_response(description: &'static str, schema: Value) -> Value {
    json!({
        "description": description,
        "content": {
            "application/json": {
                "schema": schema,
            }
        }
    })
}

fn plain_response(description: &'static str) -> Value {
    json!({
        "description": description,
    })
}

fn bearer_security() -> Value {
    json!([
        {
            "bearerAuth": []
        }
    ])
}

fn schema_ref(name: impl Into<String>) -> Value {
    json!({
        "$ref": format!("#/components/schemas/{}", name.into()),
    })
}

fn id_parameter(name: &str, description: &str) -> Value {
    json!({
        "name": name,
        "in": "path",
        "required": true,
        "description": format!("Path parameter for `{description}`"),
        "schema": {
            "type": "integer",
            "format": "int64"
        }
    })
}

fn object_schema(fields: &[&FieldSpec]) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();

    for field in fields {
        let field_name = field.name();
        properties.insert(field_name.clone(), field_schema(field));
        if !is_optional_type(&field.ty) {
            required.push(field_name);
        }
    }

    let mut schema = json!({
        "type": "object",
        "properties": properties,
    });
    if !required.is_empty() {
        schema["required"] = json!(required);
    }
    schema
}

fn field_schema(field: &FieldSpec) -> Value {
    let mut schema = match field.sql_type.as_str() {
        "INTEGER" => json!({
            "type": "integer",
            "format": "int64",
        }),
        "REAL" => json!({
            "type": "number",
            "format": "double",
        }),
        "BOOLEAN" => json!({
            "type": "boolean",
        }),
        _ => json!({
            "type": "string",
        }),
    };

    if matches!(
        field.generated,
        GeneratedValue::CreatedAt | GeneratedValue::UpdatedAt
    ) || field.name().ends_with("_at")
    {
        schema["format"] = json!("date-time");
    }

    if is_optional_type(&field.ty) {
        schema["nullable"] = json!(true);
    }

    schema
}

fn create_payload_fields(resource: &ResourceSpec) -> Vec<&FieldSpec> {
    resource
        .fields
        .iter()
        .filter(|field| {
            !field.generated.skip_insert()
                && !resource
                    .policies
                    .create
                    .iter()
                    .any(|policy| policy.field == field.name())
        })
        .collect()
}

fn update_payload_fields(resource: &ResourceSpec) -> Vec<&FieldSpec> {
    let controlled_fields = policy_controlled_fields(resource);
    resource
        .fields
        .iter()
        .filter(|field| {
            !field.is_id
                && !field.generated.skip_update_bind()
                && !controlled_fields.contains(&field.name())
        })
        .collect()
}

fn policy_controlled_fields(resource: &ResourceSpec) -> BTreeSet<String> {
    resource
        .policies
        .iter_filters()
        .map(|(_, policy)| policy.field.clone())
        .chain(
            resource
                .policies
                .iter_assignments()
                .map(|(_, policy)| policy.field.clone()),
        )
        .collect()
}

fn resource_name(resource: &ResourceSpec) -> String {
    resource.struct_ident.to_string()
}

enum CaseKind {
    Pascal,
}

trait CaseExt {
    fn to_case(&self, kind: CaseKind) -> String;
}

impl CaseExt for str {
    fn to_case(&self, kind: CaseKind) -> String {
        match kind {
            CaseKind::Pascal => self
                .split(['_', '-', ' '])
                .filter(|part| !part.is_empty())
                .map(|part| {
                    let mut chars = part.chars();
                    match chars.next() {
                        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                        None => String::new(),
                    }
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use serde_json::{Value, json};

    use super::{OpenApiSpecOptions, render_service_openapi_json};
    use crate::compiler::{load_derive_service_from_path, load_service_from_path};

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    fn temp_root(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("{name}_{stamp}"))
    }

    #[test]
    fn renders_openapi_for_eon_service_with_nested_routes_and_policy_trimmed_dtos() {
        let service =
            load_service_from_path(&fixture_path("tenant_api.eon")).expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("Tenant API", "1.0.0", "/api"),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");

        assert_eq!(document["openapi"], "3.0.3");
        assert_eq!(document["servers"][0]["url"], "/api");
        assert!(document["paths"]["/tenant_post"].is_object());
        assert!(document["paths"]["/tenant_post/{id}"].is_object());
        assert_eq!(
            document["paths"]["/tenant_post"]["get"]["security"][0]["bearerAuth"],
            json!([])
        );
        assert!(
            document["components"]["schemas"]["TenantPostCreate"]["properties"]["tenant_id"]
                .is_null()
        );
        assert!(
            document["components"]["schemas"]["TenantPostCreate"]["properties"]["user_id"]
                .is_null()
        );
    }

    #[test]
    fn renders_openapi_for_derive_service_directory() {
        let root = temp_root("derive_openapi");
        fs::create_dir_all(&root).expect("temp dir should exist");
        fs::write(
            root.join("main.rs"),
            r#"
            use very_simple_rest::prelude::*;

            #[derive(Debug, Clone, Serialize, Deserialize, FromRow, RestApi)]
            #[rest_api(table = "post", id = "id", db = "sqlite")]
            struct Post {
                id: Option<i64>,
                title: String,
                body: String,
            }
            "#,
        )
        .expect("main file should be written");

        let service = load_derive_service_from_path(&root).expect("derive service should load");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("Derive API", "1.0.0", "/api"),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");

        assert_eq!(
            document["components"]["schemas"]["Post"]["properties"]["title"]["type"],
            "string"
        );
        assert!(document["paths"]["/post"]["get"].is_object());
        assert!(document["paths"]["/post/{id}"]["put"].is_object());
    }

    #[test]
    fn renders_openapi_with_builtin_auth_routes_when_requested() {
        let service =
            load_service_from_path(&fixture_path("blog_api.eon")).expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("Blog API", "1.0.0", "/api").with_builtin_auth(true),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");

        assert!(document["paths"]["/auth/register"]["post"].is_object());
        assert!(document["paths"]["/auth/login"]["post"].is_object());
        assert!(document["paths"]["/auth/me"]["get"].is_object());
        assert!(document["components"]["schemas"]["AuthTokenResponse"].is_object());
        assert!(document["paths"]["/auth/login"]["post"]["security"].is_null());
        assert_eq!(
            document["paths"]["/auth/me"]["get"]["security"][0]["bearerAuth"],
            json!([])
        );
    }
}
