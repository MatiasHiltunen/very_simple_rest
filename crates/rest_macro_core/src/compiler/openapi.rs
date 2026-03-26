use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::Span;
use serde_json::{Map, Value, json};

use super::model::{
    FieldSpec, GeneratedValue, PolicyValueSource, ResourceSpec, ServiceSpec, is_list_field,
    is_optional_type, is_typed_object_field, list_item_type, object_fields, read_requires_auth,
    structured_scalar_kind,
    supports_contains_filters, supports_exact_filters, supports_field_sort,
    supports_range_filters,
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
    let mut get = json!({
        "tags": [resource_name(resource)],
        "summary": format!("List {}", resource_name(resource)),
        "operationId": format!("list{}", resource_name(resource)),
        "parameters": list_query_parameters(resource, None),
        "responses": list_responses(resource),
    });
    if read_requires_auth(resource) {
        get["security"] = bearer_security();
    }

    json!({
        "get": get,
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
    let mut get = json!({
        "tags": [resource_name(resource)],
        "summary": format!("Get {}", resource_name(resource)),
        "operationId": format!("get{}", resource_name(resource)),
        "parameters": [id_parameter.clone()],
        "responses": get_one_responses(resource),
    });
    if read_requires_auth(resource) {
        get["security"] = bearer_security();
    }

    json!({
        "get": get,
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
    let mut get = json!({
        "tags": [resource_name(resource)],
        "summary": format!("List {} by {}", resource_name(resource), parent_table),
        "operationId": format!("list{}By{}", resource_name(resource), parent_table.to_case(CaseKind::Pascal)),
        "parameters": parameters,
        "responses": nested_list_responses(resource),
    });
    if read_requires_auth(resource) {
        get["security"] = bearer_security();
    }
    json!({ "get": get })
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
    schemas.insert(
        "VerifyEmailInput".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "token": { "type": "string" }
            },
            "required": ["token"]
        }),
    );
    schemas.insert(
        "VerificationResendInput".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "email": { "type": "string", "format": "email" }
            },
            "required": ["email"]
        }),
    );
    schemas.insert(
        "PasswordResetRequestInput".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "email": { "type": "string", "format": "email" }
            },
            "required": ["email"]
        }),
    );
    schemas.insert(
        "PasswordResetConfirmInput".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "token": { "type": "string" },
                "new_password": { "type": "string" }
            },
            "required": ["token", "new_password"]
        }),
    );
    schemas.insert(
        "ChangePasswordInput".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "current_password": { "type": "string" },
                "new_password": { "type": "string" }
            },
            "required": ["current_password", "new_password"]
        }),
    );
    schemas.insert(
        "ManagedUserPatchInput".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "role": { "type": "string" },
                "email_verified": { "type": "boolean" }
            }
        }),
    );
    schemas.insert(
        "ManagedUserCreateInput".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "email": { "type": "string", "format": "email" },
                "password": { "type": "string" },
                "role": { "type": "string" },
                "email_verified": { "type": "boolean" },
                "send_verification_email": { "type": "boolean" }
            },
            "required": ["email", "password"]
        }),
    );
    schemas.insert(
        "AuthAccountResponse".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "integer", "format": "int64" },
                "email": { "type": "string", "format": "email" },
                "role": { "type": "string" },
                "roles": { "type": "array", "items": { "type": "string" } },
                "email_verified": { "type": "boolean" },
                "email_verified_at": { "type": "string", "format": "date-time" },
                "created_at": { "type": "string", "format": "date-time" },
                "updated_at": { "type": "string", "format": "date-time" }
            },
            "required": ["id", "email", "role", "roles", "email_verified"],
            "additionalProperties": true
        }),
    );
    schemas.insert(
        "AuthAdminUserListResponse".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": schema_ref("AuthAccountResponse")
                },
                "limit": { "type": "integer", "format": "int32" },
                "offset": { "type": "integer", "format": "int32" }
            },
            "required": ["items", "limit", "offset"]
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
    paths.insert(
        "/auth/account".to_owned(),
        json!({
            "get": {
                "tags": ["Account"],
                "summary": "Get the authenticated account record",
                "operationId": "getAccountRecord",
                "security": bearer_security(),
                "responses": {
                    "200": json_response("OK", schema_ref("AuthAccountResponse")),
                    "401": api_error_response("Authentication required")
                }
            }
        }),
    );
    paths.insert(
        "/auth/account/password".to_owned(),
        json!({
            "post": {
                "tags": ["Account"],
                "summary": "Change the authenticated account password",
                "operationId": "changeAccountPassword",
                "security": bearer_security(),
                "requestBody": json_request_body("ChangePasswordInput"),
                "responses": {
                    "204": plain_response("Password updated"),
                    "400": api_error_response("Invalid request body"),
                    "401": api_error_response("Authentication required"),
                    "500": api_error_response("Internal server error")
                }
            }
        }),
    );
    paths.insert(
        "/auth/account/verification".to_owned(),
        json!({
            "post": {
                "tags": ["Account"],
                "summary": "Resend the authenticated account verification email",
                "operationId": "resendAccountVerificationEmail",
                "security": bearer_security(),
                "responses": {
                    "202": plain_response("Verification email sent"),
                    "204": plain_response("Already verified"),
                    "401": api_error_response("Authentication required"),
                    "503": api_error_response("Email delivery unavailable")
                }
            }
        }),
    );
    paths.insert(
        "/auth/verify-email".to_owned(),
        json!({
            "get": {
                "tags": ["Auth"],
                "summary": "Open the built-in email verification page",
                "operationId": "openVerifyEmailPage",
                "parameters": [{
                    "name": "token",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string" }
                }],
                "responses": {
                    "200": plain_response("Verification result page")
                }
            },
            "post": {
                "tags": ["Auth"],
                "summary": "Verify an email address with a token",
                "operationId": "verifyEmailAddress",
                "requestBody": json_request_body("VerifyEmailInput"),
                "responses": {
                    "204": plain_response("Email verified"),
                    "400": api_error_response("Invalid or expired token"),
                    "500": api_error_response("Internal server error")
                }
            }
        }),
    );
    paths.insert(
        "/auth/verification/resend".to_owned(),
        json!({
            "post": {
                "tags": ["Auth"],
                "summary": "Resend a verification email by email address",
                "operationId": "resendVerificationEmail",
                "requestBody": json_request_body("VerificationResendInput"),
                "responses": {
                    "202": plain_response("Verification email sent"),
                    "400": api_error_response("Invalid request body"),
                    "503": api_error_response("Email delivery unavailable")
                }
            }
        }),
    );
    paths.insert(
        "/auth/password-reset".to_owned(),
        json!({
            "get": {
                "tags": ["Auth"],
                "summary": "Open the built-in password reset page",
                "operationId": "openPasswordResetPage",
                "parameters": [{
                    "name": "token",
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string" }
                }],
                "responses": {
                    "200": plain_response("Password reset page")
                }
            }
        }),
    );
    paths.insert(
        "/auth/password-reset/request".to_owned(),
        json!({
            "post": {
                "tags": ["Auth"],
                "summary": "Request a password reset email",
                "operationId": "requestPasswordReset",
                "requestBody": json_request_body("PasswordResetRequestInput"),
                "responses": {
                    "202": plain_response("Password reset email sent"),
                    "400": api_error_response("Invalid request body"),
                    "503": api_error_response("Email delivery unavailable")
                }
            }
        }),
    );
    paths.insert(
        "/auth/password-reset/confirm".to_owned(),
        json!({
            "post": {
                "tags": ["Auth"],
                "summary": "Confirm a password reset with a token",
                "operationId": "confirmPasswordReset",
                "requestBody": json_request_body("PasswordResetConfirmInput"),
                "responses": {
                    "204": plain_response("Password updated"),
                    "400": api_error_response("Invalid or expired token"),
                    "500": api_error_response("Internal server error")
                }
            }
        }),
    );
    paths.insert(
        "/auth/admin/users".to_owned(),
        json!({
            "get": {
                "tags": ["Admin"],
                "summary": "List built-in auth users",
                "operationId": "listBuiltinAuthUsers",
                "security": bearer_security(),
                "parameters": [
                    {
                        "name": "limit",
                        "in": "query",
                        "required": false,
                        "schema": { "type": "integer", "format": "int32" }
                    },
                    {
                        "name": "offset",
                        "in": "query",
                        "required": false,
                        "schema": { "type": "integer", "format": "int32" }
                    },
                    {
                        "name": "email",
                        "in": "query",
                        "required": false,
                        "schema": { "type": "string" }
                    }
                ],
                "responses": {
                    "200": json_response("OK", schema_ref("AuthAdminUserListResponse")),
                    "401": api_error_response("Authentication required"),
                    "403": api_error_response("Admin role required")
                }
            },
            "post": {
                "tags": ["Admin"],
                "summary": "Create a built-in auth user",
                "operationId": "createBuiltinAuthUser",
                "security": bearer_security(),
                "requestBody": json_request_body("ManagedUserCreateInput"),
                "responses": {
                    "201": json_response("Created", schema_ref("AuthAccountResponse")),
                    "400": api_error_response("Invalid request body"),
                    "401": api_error_response("Authentication required"),
                    "403": api_error_response("Admin role required"),
                    "409": api_error_response("Email already exists"),
                    "503": api_error_response("Email delivery unavailable")
                }
            }
        }),
    );
    paths.insert(
        "/auth/admin/users/{id}".to_owned(),
        json!({
            "get": {
                "tags": ["Admin"],
                "summary": "Get a built-in auth user",
                "operationId": "getBuiltinAuthUser",
                "security": bearer_security(),
                "parameters": [id_parameter("id", "user")],
                "responses": {
                    "200": json_response("OK", schema_ref("AuthAccountResponse")),
                    "401": api_error_response("Authentication required"),
                    "403": api_error_response("Admin role required"),
                    "404": api_error_response("User not found")
                }
            },
            "patch": {
                "tags": ["Admin"],
                "summary": "Update a built-in auth user",
                "operationId": "updateBuiltinAuthUser",
                "security": bearer_security(),
                "parameters": [id_parameter("id", "user")],
                "requestBody": json_request_body("ManagedUserPatchInput"),
                "responses": {
                    "200": json_response("OK", schema_ref("AuthAccountResponse")),
                    "400": api_error_response("Invalid request body"),
                    "401": api_error_response("Authentication required"),
                    "403": api_error_response("Admin role required"),
                    "404": api_error_response("User not found")
                }
            },
            "delete": {
                "tags": ["Admin"],
                "summary": "Delete a built-in auth user",
                "operationId": "deleteBuiltinAuthUser",
                "security": bearer_security(),
                "parameters": [id_parameter("id", "user")],
                "responses": {
                    "204": plain_response("User deleted"),
                    "400": api_error_response("Invalid delete request"),
                    "401": api_error_response("Authentication required"),
                    "403": api_error_response("Admin role required"),
                    "404": api_error_response("User not found")
                }
            }
        }),
    );
    paths.insert(
        "/auth/admin/users/{id}/verification".to_owned(),
        json!({
            "post": {
                "tags": ["Admin"],
                "summary": "Resend verification email for a built-in auth user",
                "operationId": "resendBuiltinAuthUserVerification",
                "security": bearer_security(),
                "parameters": [id_parameter("id", "user")],
                "responses": {
                    "202": plain_response("Verification email sent"),
                    "204": plain_response("Already verified"),
                    "401": api_error_response("Authentication required"),
                    "403": api_error_response("Admin role required"),
                    "404": api_error_response("User not found"),
                    "503": api_error_response("Email delivery unavailable")
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
    let sortable_fields = resource
        .fields
        .iter()
        .filter(|field| supports_field_sort(field))
        .map(|field| field.name())
        .collect::<Vec<_>>();
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
                "enum": sortable_fields
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
        if supports_exact_filters(field) {
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

        if supports_contains_filters(field) {
            parameters.push(json!({
                "name": format!("filter_{field_name}_contains"),
                "in": "query",
                "required": false,
                "description": format!(
                    "Case-insensitive substring filter for `{field_name}`. `%`, `_`, and `\\` are treated literally."
                ),
                "schema": {
                    "type": "string"
                },
            }));
        }

        if supports_exact_filters(field) && supports_range_filters(&field.ty) {
            let kind_label = match structured_scalar_kind(&field.ty) {
                Some(super::model::StructuredScalarKind::DateTime) => "timestamp",
                Some(super::model::StructuredScalarKind::Date) => "date",
                Some(super::model::StructuredScalarKind::Time) => "time",
                _ => "value",
            };
            for (suffix, operator, inclusive) in [
                ("gt", "after", false),
                ("gte", "after", true),
                ("lt", "before", false),
                ("lte", "before", true),
            ] {
                let qualifier = if inclusive { " or equal to" } else { "" };
                parameters.push(json!({
                    "name": format!("filter_{field_name}_{suffix}"),
                    "in": "query",
                    "required": false,
                    "description": format!(
                        "Filter `{field_name}` values {operator}{qualifier} this {kind_label}"
                    ),
                    "schema": query_parameter_schema(field),
                }));
            }
        }
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

fn typed_object_schema(fields: &[FieldSpec]) -> Value {
    let mut schema = object_schema(&fields.iter().collect::<Vec<_>>());
    schema["additionalProperties"] = json!(false);
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
    let mut schema = if is_typed_object_field(field) {
        typed_object_schema(object_fields(field).expect("typed object field should define fields"))
    } else if is_list_field(field) {
        json!({
            "type": "array",
            "items": schema_for_type(
                list_item_type(field).expect("list field should define list item type")
            ),
        })
    } else {
        schema_for_type(&field.ty)
    };

    if !is_list_field(field)
        && (matches!(
            field.generated,
            GeneratedValue::CreatedAt | GeneratedValue::UpdatedAt
        ) || field.name().ends_with("_at"))
    {
        schema["format"] = json!("date-time");
    }

    if force_optional || is_optional_type(&field.ty) {
        schema["nullable"] = json!(true);
    }

    apply_field_validation_schema(field, &mut schema);

    schema
}

fn schema_for_type(ty: &syn::Type) -> Value {
    let mut schema = match structured_scalar_kind(ty) {
        Some(super::model::StructuredScalarKind::Json) => json!({}),
        Some(super::model::StructuredScalarKind::JsonObject) => json!({
            "type": "object",
            "additionalProperties": true,
        }),
        Some(super::model::StructuredScalarKind::JsonArray) => json!({
            "type": "array",
            "items": {},
        }),
        _ => {
            if super::model::is_bool_type(ty) {
                json!({
                    "type": "boolean",
                })
            } else {
                match super::model::infer_sql_type(ty, super::model::DbBackend::Sqlite).as_str() {
                    sql_type if super::model::is_integer_sql_type(sql_type) => json!({
                        "type": "integer",
                        "format": "int64",
                    }),
                    "REAL" => json!({
                        "type": "number",
                        "format": "double",
                    }),
                    _ => json!({
                        "type": "string",
                    }),
                }
            }
        }
    };

    if let Some(kind) = structured_scalar_kind(ty) {
        if let Some(format) = kind.openapi_format() {
            schema["format"] = json!(format);
        }
    }

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
        .controlled_filter_fields()
        .into_iter()
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
    fn renders_openapi_public_reads_without_bearer_security_and_with_contains_filters() {
        let service = load_service_from_path(&fixture_path("public_catalog_api.eon"))
            .expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("Public Catalog API", "1.0.0", "/api"),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");
        let parameters = document["paths"]["/organization"]["get"]["parameters"]
            .as_array()
            .expect("list parameters should be an array");

        let contains = parameters
            .iter()
            .find(|parameter| parameter["name"] == "filter_name_contains")
            .expect("contains filter should exist");

        assert!(
            document["paths"]["/organization"]["get"]["security"].is_null(),
            "public list routes should not advertise bearer auth"
        );
        assert!(
            document["paths"]["/organization/{id}"]["get"]["security"].is_null(),
            "public item routes should not advertise bearer auth"
        );
        assert!(
            document["paths"]["/organization/{parent_id}/interest"]["get"]["security"].is_null(),
            "public nested list routes should not advertise bearer auth"
        );
        assert_eq!(
            document["paths"]["/organization"]["post"]["security"][0]["bearerAuth"],
            json!([])
        );
        assert_eq!(contains["schema"]["type"], json!("string"));
        assert!(
            contains["description"]
                .as_str()
                .expect("contains description should be a string")
                .contains("treated literally")
        );
    }

    #[test]
    fn renders_openapi_datetime_filters_for_eon_service() {
        let service = load_service_from_path(&fixture_path("datetime_api.eon"))
            .expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("Datetime API", "1.0.0", "/api"),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");
        let parameters = document["paths"]["/event"]["get"]["parameters"]
            .as_array()
            .expect("list parameters should be an array");

        let starts_at_gte = parameters
            .iter()
            .find(|parameter| parameter["name"] == "filter_starts_at_gte")
            .expect("datetime gte filter should exist");
        let starts_at_lt = parameters
            .iter()
            .find(|parameter| parameter["name"] == "filter_starts_at_lt")
            .expect("datetime lt filter should exist");

        assert_eq!(starts_at_gte["schema"]["type"], json!("string"));
        assert_eq!(starts_at_gte["schema"]["format"], json!("date-time"));
        assert_eq!(starts_at_lt["schema"]["format"], json!("date-time"));
        assert_eq!(
            document["components"]["schemas"]["Event"]["properties"]["starts_at"]["format"],
            json!("date-time")
        );
    }

    #[test]
    fn renders_openapi_portable_scalar_formats_and_sort_constraints() {
        let service = load_service_from_path(&fixture_path("scalar_types_api.eon"))
            .expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("Scalar Types API", "1.0.0", "/api"),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");
        let parameters = document["paths"]["/schedule"]["get"]["parameters"]
            .as_array()
            .expect("list parameters should be an array");

        let run_on_gte = parameters
            .iter()
            .find(|parameter| parameter["name"] == "filter_run_on_gte")
            .expect("date gte filter should exist");
        let run_at_lte = parameters
            .iter()
            .find(|parameter| parameter["name"] == "filter_run_at_lte")
            .expect("time lte filter should exist");
        let sort = parameters
            .iter()
            .find(|parameter| parameter["name"] == "sort")
            .expect("sort parameter should exist");
        let sort_values = sort["schema"]["enum"]
            .as_array()
            .expect("sort enum should be present");

        assert_eq!(run_on_gte["schema"]["format"], json!("date"));
        assert_eq!(run_at_lte["schema"]["format"], json!("time"));
        assert_eq!(
            document["components"]["schemas"]["Schedule"]["properties"]["external_id"]["format"],
            json!("uuid")
        );
        assert_eq!(
            document["components"]["schemas"]["Schedule"]["properties"]["amount"]["format"],
            json!("decimal")
        );
        assert!(
            !sort_values.iter().any(|value| value == &json!("amount")),
            "decimal fields should not be listed as sortable"
        );
    }

    #[test]
    fn renders_openapi_json_field_shapes_without_list_filters() {
        let service = load_service_from_path(&fixture_path("json_fields_api.eon"))
            .expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("JSON Fields API", "1.0.0", "/api"),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");
        let parameters = document["paths"]["/block_document"]["get"]["parameters"]
            .as_array()
            .expect("list parameters should be an array");
        let sort = parameters
            .iter()
            .find(|parameter| parameter["name"] == "sort")
            .expect("sort parameter should exist");
        let sort_values = sort["schema"]["enum"]
            .as_array()
            .expect("sort enum should be present");

        assert!(
            parameters
                .iter()
                .all(|parameter| parameter["name"] != "filter_payload"),
            "generic JSON fields should not advertise exact-match filters"
        );
        assert!(
            parameters
                .iter()
                .all(|parameter| parameter["name"] != "filter_attributes"),
            "JSON object fields should not advertise exact-match filters"
        );
        assert!(
            parameters
                .iter()
                .all(|parameter| parameter["name"] != "filter_blocks"),
            "JSON array fields should not advertise exact-match filters"
        );
        assert!(
            !sort_values.iter().any(|value| value == &json!("payload")),
            "generic JSON fields should not be listed as sortable"
        );
        assert_eq!(
            document["components"]["schemas"]["BlockDocument"]["properties"]["attributes"]["type"],
            json!("object")
        );
        assert_eq!(
            document["components"]["schemas"]["BlockDocument"]["properties"]["blocks"]["type"],
            json!("array")
        );
        assert!(
            document["components"]["schemas"]["BlockDocument"]["properties"]["payload"]
                .as_object()
                .expect("payload schema should be an object")
                .get("type")
                .is_none(),
            "generic JSON fields should stay schema-open"
        );
    }

    #[test]
    fn renders_openapi_typed_list_field_schemas_without_list_filters() {
        let service = load_service_from_path(&fixture_path("list_fields_api.eon"))
            .expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("List Fields API", "1.0.0", "/api"),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");
        let parameters = document["paths"]["/entry"]["get"]["parameters"]
            .as_array()
            .expect("list parameters should be an array");

        assert!(
            parameters
                .iter()
                .all(|parameter| parameter["name"] != "filter_categories"),
            "list fields should not advertise exact-match filters"
        );
        assert_eq!(
            document["components"]["schemas"]["Entry"]["properties"]["categories"]["type"],
            json!("array")
        );
        assert_eq!(
            document["components"]["schemas"]["Entry"]["properties"]["categories"]["items"]["type"],
            json!("integer")
        );
        assert_eq!(
            document["components"]["schemas"]["Entry"]["properties"]["tags"]["items"]["type"],
            json!("string")
        );
        assert_eq!(
            document["components"]["schemas"]["Entry"]["properties"]["blocks"]["items"]["type"],
            json!("object")
        );
    }

    #[test]
    fn renders_openapi_typed_object_field_schemas_without_object_filters() {
        let service = load_service_from_path(&fixture_path("object_fields_api.eon"))
            .expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("Object Fields API", "1.0.0", "/api"),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");
        let parameters = document["paths"]["/entry"]["get"]["parameters"]
            .as_array()
            .expect("list parameters should be an array");

        assert!(
            parameters
                .iter()
                .all(|parameter| parameter["name"] != "filter_title"),
            "typed object fields should not advertise exact-match filters"
        );
        assert_eq!(
            document["components"]["schemas"]["Entry"]["properties"]["title"]["type"],
            json!("object")
        );
        assert_eq!(
            document["components"]["schemas"]["Entry"]["properties"]["title"]["additionalProperties"],
            json!(false)
        );
        assert_eq!(
            document["components"]["schemas"]["Entry"]["properties"]["title"]["properties"]["raw"]["type"],
            json!("string")
        );
        assert_eq!(
            document["components"]["schemas"]["Entry"]["properties"]["settings"]["properties"]["categories"]["items"]["type"],
            json!("integer")
        );
        assert_eq!(
            document["components"]["schemas"]["Entry"]["properties"]["settings"]["properties"]["seo"]["additionalProperties"],
            json!(false)
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
