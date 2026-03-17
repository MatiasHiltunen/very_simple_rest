use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::Span;
use serde_json::{Map, Value, json};

use super::model::{
    FieldSpec, GeneratedValue, PolicyValueSource, ResourceSpec, ServiceSpec, is_optional_type,
};

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

    schemas.insert("ApiErrorResponse".to_owned(), api_error_schema());

    for resource in &service.resources {
        let name = resource_name(resource);
        schemas.insert(
            name.clone(),
            object_schema(&resource.fields.iter().collect::<Vec<_>>()),
        );
        schemas.insert(format!("{name}Create"), create_payload_schema(resource));
        schemas.insert(
            format!("{name}Update"),
            object_schema(&update_payload_fields(resource)),
        );
        schemas.insert(
            format!("{name}ListResponse"),
            list_response_schema(resource),
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
        tags.push(json!({ "name": "Account" }));
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
            "parameters": list_query_parameters(resource, None),
            "security": bearer_security(),
            "responses": list_responses(resource),
        },
        "post": {
            "tags": [resource_name(resource)],
            "summary": format!("Create {}", resource_name(resource)),
            "operationId": format!("create{}", resource_name(resource)),
            "security": bearer_security(),
            "requestBody": json_request_body(format!("{}Create", resource_name(resource))),
            "responses": create_responses(),
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
            "responses": update_responses(),
        },
        "delete": {
            "tags": [resource_name(resource)],
            "summary": format!("Delete {}", resource_name(resource)),
            "operationId": format!("delete{}", resource_name(resource)),
            "parameters": [id_parameter],
            "security": bearer_security(),
            "responses": delete_responses(),
        },
    })
}

fn nested_collection_path_item(
    resource: &ResourceSpec,
    parent_table: &str,
    relation_field: &str,
) -> Value {
    let mut parameters = vec![id_parameter("parent_id", relation_field)];
    parameters.extend(list_query_parameters(resource, Some(relation_field)));
    json!({
        "get": {
            "tags": [resource_name(resource)],
            "summary": format!("List {} by {}", resource_name(resource), parent_table),
            "operationId": format!("list{}By{}", resource_name(resource), parent_table.to_case(CaseKind::Pascal)),
            "parameters": parameters,
            "security": bearer_security(),
            "responses": nested_list_responses(resource),
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
                "token": { "type": "string" },
                "csrf_token": { "type": "string" }
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
                    "400": api_error_response("Invalid request body"),
                    "413": api_error_response("Payload too large"),
                    "415": api_error_response("Unsupported media type"),
                    "409": api_error_response("Email already exists"),
                    "500": api_error_response("Internal server error")
                }
            }
        }),
    );
    paths.insert(
        "/auth/login".to_owned(),
        json!({
            "post": {
                "tags": ["Auth"],
                "summary": "Login and receive a JWT token or configured session cookie",
                "operationId": "loginUser",
                "requestBody": json_request_body("LoginInput"),
                "responses": {
                    "200": json_response("OK", schema_ref("AuthTokenResponse")),
                    "400": api_error_response("Invalid request body"),
                    "413": api_error_response("Payload too large"),
                    "415": api_error_response("Unsupported media type"),
                    "401": api_error_response("Invalid credentials"),
                    "500": api_error_response("Internal server error")
                }
            }
        }),
    );
    paths.insert(
        "/auth/logout".to_owned(),
        json!({
            "post": {
                "tags": ["Account"],
                "summary": "Clear configured auth session cookies",
                "operationId": "logoutUser",
                "responses": {
                    "204": plain_response("Logged out"),
                    "403": api_error_response("Missing or invalid CSRF token")
                }
            }
        }),
    );
    paths.insert(
        "/auth/me".to_owned(),
        json!({
            "get": {
                "tags": ["Account"],
                "summary": "Get the authenticated account context",
                "operationId": "getAuthenticatedAccount",
                "security": bearer_security(),
                "responses": {
                    "200": json_response("OK", schema_ref("AuthMeResponse")),
                    "401": api_error_response("Authentication required")
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
                schema_ref(format!("{}ListResponse", resource_name(resource))),
            ),
        ),
        ("400", api_error_response("Invalid query parameters")),
        ("401", plain_response("Authentication required")),
        ("403", api_error_response("Forbidden")),
        ("500", api_error_response("Internal server error")),
    ])
}

fn get_one_responses(resource: &ResourceSpec) -> BTreeMap<&'static str, Value> {
    BTreeMap::from([
        (
            "200",
            json_response("OK", schema_ref(resource_name(resource))),
        ),
        ("400", api_error_response("Invalid path parameters")),
        ("401", plain_response("Authentication required")),
        ("403", api_error_response("Forbidden")),
        ("404", api_error_response("Not found")),
        ("500", api_error_response("Internal server error")),
    ])
}

fn nested_list_responses(resource: &ResourceSpec) -> BTreeMap<&'static str, Value> {
    let mut responses = list_responses(resource);
    responses.insert("400", api_error_response("Invalid path parameters"));
    responses
}

fn create_responses() -> BTreeMap<&'static str, Value> {
    BTreeMap::from([
        ("201", plain_response("Created")),
        (
            "400",
            api_error_response("Invalid request body or validation error"),
        ),
        ("413", api_error_response("Payload too large")),
        ("415", api_error_response("Unsupported media type")),
        ("401", plain_response("Authentication required")),
        ("403", api_error_response("Forbidden")),
        ("500", api_error_response("Internal server error")),
    ])
}

fn update_responses() -> BTreeMap<&'static str, Value> {
    BTreeMap::from([
        ("200", plain_response("Updated")),
        (
            "400",
            api_error_response("Invalid request body or validation error"),
        ),
        ("413", api_error_response("Payload too large")),
        ("415", api_error_response("Unsupported media type")),
        ("401", plain_response("Authentication required")),
        ("403", api_error_response("Forbidden")),
        ("404", api_error_response("Not found")),
        ("500", api_error_response("Internal server error")),
    ])
}

fn delete_responses() -> BTreeMap<&'static str, Value> {
    BTreeMap::from([
        ("200", plain_response("Deleted")),
        ("400", api_error_response("Invalid path parameters")),
        ("401", plain_response("Authentication required")),
        ("403", api_error_response("Forbidden")),
        ("404", api_error_response("Not found")),
        ("500", api_error_response("Internal server error")),
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

fn api_error_response(description: &'static str) -> Value {
    json_response(description, schema_ref("ApiErrorResponse"))
}

fn api_error_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "code": { "type": "string" },
            "message": { "type": "string" },
            "field": { "type": "string", "nullable": true }
        },
        "required": ["code", "message"]
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

fn list_query_parameters(
    resource: &ResourceSpec,
    parent_relation_field: Option<&str>,
) -> Vec<Value> {
    let mut limit_schema = json!({
        "type": "integer",
        "format": "int64",
        "minimum": 1
    });
    if let Some(default_limit) = resource.list.default_limit {
        limit_schema["default"] = json!(default_limit);
    }
    if let Some(max_limit) = resource.list.max_limit {
        limit_schema["maximum"] = json!(max_limit);
    }

    let mut parameters = vec![
        json!({
            "name": "limit",
            "in": "query",
            "required": false,
            "description": "Maximum number of rows to return",
            "schema": limit_schema
        }),
        json!({
            "name": "offset",
            "in": "query",
            "required": false,
            "description": "Rows to skip before returning results. Requires `limit`.",
            "schema": {
                "type": "integer",
                "format": "int64",
                "minimum": 0
            }
        }),
        json!({
            "name": "cursor",
            "in": "query",
            "required": false,
            "description": "Opaque cursor for keyset pagination. Cannot be combined with `offset`, `sort`, or `order`.",
            "schema": {
                "type": "string"
            }
        }),
        json!({
            "name": "sort",
            "in": "query",
            "required": false,
            "description": "Field to sort by",
            "schema": {
                "type": "string",
                "enum": resource.fields.iter().map(|field| field.name()).collect::<Vec<_>>()
            }
        }),
        json!({
            "name": "order",
            "in": "query",
            "required": false,
            "description": "Sort direction. Requires `sort`.",
            "schema": {
                "type": "string",
                "enum": ["asc", "desc"]
            }
        }),
    ];

    for field in &resource.fields {
        let field_name = field.name();
        let description = if parent_relation_field == Some(field_name.as_str()) {
            format!(
                "Exact-match filter for `{field_name}`. Nested route parent filtering is applied automatically."
            )
        } else {
            format!("Exact-match filter for `{field_name}`")
        };
        parameters.push(json!({
            "name": format!("filter_{field_name}"),
            "in": "query",
            "required": false,
            "description": description,
            "schema": query_parameter_schema(field),
        }));
    }

    parameters
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

fn list_response_schema(resource: &ResourceSpec) -> Value {
    json!({
        "type": "object",
        "properties": {
            "items": {
                "type": "array",
                "items": schema_ref(resource_name(resource)),
            },
            "total": {
                "type": "integer",
                "format": "int64",
                "minimum": 0
            },
            "count": {
                "type": "integer",
                "minimum": 0
            },
            "limit": {
                "type": "integer",
                "format": "int64",
                "nullable": true,
                "minimum": 1
            },
            "offset": {
                "type": "integer",
                "format": "int64",
                "minimum": 0
            },
            "next_offset": {
                "type": "integer",
                "format": "int64",
                "nullable": true,
                "minimum": 0
            },
            "next_cursor": {
                "type": "string",
                "nullable": true
            }
        },
        "required": ["items", "total", "count", "offset"]
    })
}

fn create_payload_schema(resource: &ResourceSpec) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();

    for field in create_payload_fields(resource) {
        let field_name = field.field.name();
        properties.insert(
            field_name.clone(),
            field_schema_with_optional(field.field, field.allow_admin_override),
        );
        if !field.allow_admin_override && !is_optional_type(&field.field.ty) {
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
    field_schema_with_optional(field, false)
}

fn query_parameter_schema(field: &FieldSpec) -> Value {
    let mut schema = field_schema_with_optional(field, false);
    if let Some(object) = schema.as_object_mut() {
        object.remove("nullable");
    }
    schema
}

fn field_schema_with_optional(field: &FieldSpec, force_optional: bool) -> Value {
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

    if force_optional || is_optional_type(&field.ty) {
        schema["nullable"] = json!(true);
    }

    apply_field_validation_schema(field, &mut schema);

    schema
}

fn apply_field_validation_schema(field: &FieldSpec, schema: &mut Value) {
    if let Some(min_length) = field.validation.min_length {
        schema["minLength"] = json!(min_length);
    }
    if let Some(max_length) = field.validation.max_length {
        schema["maxLength"] = json!(max_length);
    }
    if let Some(minimum) = &field.validation.minimum {
        schema["minimum"] = numeric_bound_json(minimum);
    }
    if let Some(maximum) = &field.validation.maximum {
        schema["maximum"] = numeric_bound_json(maximum);
    }
}

fn numeric_bound_json(bound: &super::model::NumericBound) -> Value {
    match bound {
        super::model::NumericBound::Integer(value) => json!(value),
        super::model::NumericBound::Float(value) => json!(value),
    }
}

struct CreatePayloadField<'a> {
    field: &'a FieldSpec,
    allow_admin_override: bool,
}

fn create_payload_fields(resource: &ResourceSpec) -> Vec<CreatePayloadField<'_>> {
    resource
        .fields
        .iter()
        .filter_map(|field| {
            if field.generated.skip_insert() {
                return None;
            }

            let controlled = resource
                .policies
                .create
                .iter()
                .any(|policy| policy.field == field.name());
            let allow_admin_override = controlled
                && resource.policies.admin_bypass
                && matches!(
                    resource
                        .policies
                        .create
                        .iter()
                        .find(|policy| policy.field == field.name())
                        .map(|policy| &policy.source),
                    Some(PolicyValueSource::Claim(_))
                );
            if controlled && !allow_admin_override {
                return None;
            }

            Some(CreatePayloadField {
                field,
                allow_admin_override,
            })
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

    fn example_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples")
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
            document["paths"]["/tenant_post"]["get"]["parameters"][0]["name"],
            "limit"
        );
        assert_eq!(
            document["paths"]["/tenant_post"]["get"]["parameters"][2]["name"],
            "cursor"
        );
        assert_eq!(
            document["paths"]["/tenant_post"]["get"]["parameters"][3]["name"],
            "sort"
        );
        assert_eq!(
            document["paths"]["/tenant_post"]["get"]["parameters"][5]["name"],
            "filter_id"
        );
        assert_eq!(
            document["paths"]["/tenant_post"]["get"]["responses"]["200"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/TenantPostListResponse"
        );
        assert_eq!(
            document["components"]["schemas"]["TenantPostListResponse"]["properties"]["next_offset"]
                ["nullable"],
            json!(true)
        );
        assert_eq!(
            document["components"]["schemas"]["TenantPostListResponse"]["properties"]["next_cursor"]
                ["nullable"],
            json!(true)
        );
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
    fn renders_openapi_nested_collection_query_parameters() {
        let service =
            load_service_from_path(&fixture_path("blog_api.eon")).expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("Blog API", "1.0.0", "/api"),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");

        assert_eq!(
            document["paths"]["/post/{parent_id}/comment"]["get"]["parameters"][0]["name"],
            "parent_id"
        );
        assert_eq!(
            document["paths"]["/post/{parent_id}/comment"]["get"]["parameters"][1]["name"],
            "limit"
        );
        assert_eq!(
            document["paths"]["/post/{parent_id}/comment"]["get"]["parameters"][3]["name"],
            "cursor"
        );
        assert_eq!(
            document["paths"]["/post/{parent_id}/comment"]["get"]["parameters"][6]["name"],
            "filter_id"
        );
        assert_eq!(
            document["paths"]["/post/{parent_id}/comment"]["get"]["responses"]["400"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/ApiErrorResponse"
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
    fn renders_openapi_validation_keywords_for_fields() {
        let root = temp_root("derive_openapi_validation");
        fs::create_dir_all(&root).expect("temp dir should exist");
        fs::write(
            root.join("main.rs"),
            r#"
            use very_simple_rest::prelude::*;

            #[derive(Debug, Clone, Serialize, Deserialize, FromRow, RestApi)]
            #[rest_api(table = "post", id = "id", db = "sqlite")]
            #[list(default_limit = 25, max_limit = 100)]
            struct Post {
                id: Option<i64>,
                #[validate(min_length = 3, max_length = 32)]
                title: String,
                #[validate(minimum = 1, maximum = 10)]
                score: i64,
            }
            "#,
        )
        .expect("main file should be written");

        let service = load_derive_service_from_path(&root).expect("derive service should load");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("Validated API", "1.0.0", "/api"),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");

        assert_eq!(
            document["components"]["schemas"]["Post"]["properties"]["title"]["minLength"],
            json!(3)
        );
        assert_eq!(
            document["components"]["schemas"]["Post"]["properties"]["title"]["maxLength"],
            json!(32)
        );
        assert_eq!(
            document["components"]["schemas"]["Post"]["properties"]["score"]["minimum"],
            json!(1)
        );
        assert_eq!(
            document["components"]["schemas"]["Post"]["properties"]["score"]["maximum"],
            json!(10)
        );
        assert_eq!(
            document["components"]["schemas"]["PostCreate"]["properties"]["title"]["minLength"],
            json!(3)
        );
        assert_eq!(
            document["paths"]["/post"]["get"]["parameters"][0]["schema"]["minimum"],
            json!(1)
        );
        assert_eq!(
            document["paths"]["/post"]["get"]["parameters"][2]["schema"]["type"],
            json!("string")
        );
        assert_eq!(
            document["paths"]["/post"]["get"]["parameters"][3]["schema"]["enum"],
            json!(["id", "title", "score"])
        );
        assert_eq!(
            document["paths"]["/post"]["get"]["parameters"][0]["schema"]["default"],
            json!(25)
        );
        assert_eq!(
            document["paths"]["/post"]["get"]["parameters"][0]["schema"]["maximum"],
            json!(100)
        );
        assert_eq!(
            document["paths"]["/post"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
                ["$ref"],
            "#/components/schemas/PostListResponse"
        );
        assert_eq!(
            document["components"]["schemas"]["PostListResponse"]["properties"]["items"]["type"],
            json!("array")
        );
        assert_eq!(
            document["components"]["schemas"]["PostListResponse"]["properties"]["next_cursor"]["nullable"],
            json!(true)
        );
        assert_eq!(
            document["paths"]["/post"]["get"]["parameters"][7]["schema"]["minimum"],
            json!(1)
        );
        assert_eq!(
            document["paths"]["/post"]["post"]["responses"]["400"]["content"]["application/json"]["schema"]
                ["$ref"],
            "#/components/schemas/ApiErrorResponse"
        );
        assert_eq!(
            document["paths"]["/post/{id}"]["get"]["responses"]["400"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/ApiErrorResponse"
        );
        assert_eq!(
            document["components"]["schemas"]["ApiErrorResponse"]["properties"]["field"]["nullable"],
            json!(true)
        );
    }

    #[test]
    fn renders_admin_bypass_create_fields_for_swagger_experimentation() {
        let service =
            load_service_from_path(&example_path("fine_grained_policies/ops_control.eon"))
                .expect("example should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("Ops Control", "1.0.0", "/api").with_builtin_auth(true),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");

        assert_eq!(
            document["components"]["schemas"]["WorkspaceCreate"]["properties"]["tenant_id"]["type"],
            "integer"
        );
        assert_eq!(
            document["components"]["schemas"]["WorkspaceCreate"]["properties"]["tenant_id"]["nullable"],
            json!(true)
        );
        assert_eq!(
            document["components"]["schemas"]["WorkspaceCreate"]["properties"]["owner_user_id"],
            Value::Null
        );
        assert!(
            document["components"]["schemas"]["WorkspaceCreate"]["required"]
                .as_array()
                .expect("required should be an array")
                .iter()
                .all(|entry| entry != "tenant_id")
        );
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
        assert!(document["paths"]["/auth/logout"]["post"].is_object());
        assert!(document["paths"]["/auth/me"]["get"].is_object());
        assert!(document["components"]["schemas"]["AuthTokenResponse"].is_object());
        assert!(document["components"]["schemas"]["ApiErrorResponse"].is_object());
        assert!(
            document["components"]["schemas"]["AuthTokenResponse"]["properties"]["csrf_token"]
                .is_object()
        );
        assert_eq!(document["paths"]["/auth/me"]["get"]["tags"][0], "Account");
        assert!(document["paths"]["/auth/login"]["post"]["security"].is_null());
        assert_eq!(
            document["paths"]["/auth/me"]["get"]["security"][0]["bearerAuth"],
            json!([])
        );
        assert_eq!(
            document["paths"]["/auth/login"]["post"]["responses"]["401"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/ApiErrorResponse"
        );
        assert_eq!(
            document["paths"]["/auth/login"]["post"]["responses"]["400"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/ApiErrorResponse"
        );
        assert_eq!(
            document["paths"]["/auth/register"]["post"]["responses"]["409"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/ApiErrorResponse"
        );
        assert!(
            document["tags"]
                .as_array()
                .expect("tags should be an array")
                .iter()
                .any(|tag| tag["name"] == "Account")
        );
    }
}
