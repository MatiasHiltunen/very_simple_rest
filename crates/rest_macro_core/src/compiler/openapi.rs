use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::Span;
use serde_json::{Map, Value, json};

use crate::{auth::AuthClaimType, security::DEFAULT_ANON_CLIENT_HEADER_NAME};

use super::model::{
    ComputedFieldSpec, FieldSpec, GeneratedValue, PolicyValueSource, ResourceActionMethod,
    ResourceActionTarget, ResourceSpec, ServiceSpec, is_list_field, is_optional_type,
    is_typed_object_field, list_item_type, object_fields, read_requires_auth,
    structured_scalar_kind, supports_contains_filters, supports_exact_filters, supports_field_sort,
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
    if !service.storage.uploads.is_empty() {
        schemas.insert(
            "StorageUploadResponse".to_owned(),
            storage_upload_response_schema(),
        );
        tags.push(json!({ "name": "Storage" }));
    }

    for resource in &service.resources {
        let name = resource_name(resource);
        schemas.insert(name.clone(), response_object_schema(resource));
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
            format!("/{}", resource.api_name()),
            collection_path_item(resource),
        );
        paths.insert(
            format!("/{}/{{id}}", resource.api_name()),
            item_path_item(resource),
        );
        for action in &resource.actions {
            if action.target != ResourceActionTarget::Item
                || action.method != ResourceActionMethod::Post
            {
                continue;
            }
            if !action.input_fields.is_empty() {
                schemas.insert(
                    action_input_schema_name(resource, action),
                    action_input_schema(resource, action),
                );
            }
            paths.insert(
                format!("/{}/{{id}}/{}", resource.api_name(), action.path),
                item_action_path_item(resource, action),
            );
        }

        for field in &resource.fields {
            let Some(relation) = field.relation.as_ref() else {
                continue;
            };
            if !relation.nested_route {
                continue;
            }
            let parent_api_name = service
                .resources
                .iter()
                .find(|candidate| candidate.table_name == relation.references_table)
                .map(|candidate| candidate.api_name().to_owned())
                .unwrap_or_else(|| relation.references_table.clone());
            paths.insert(
                format!("/{}/{{parent_id}}/{}", parent_api_name, resource.api_name()),
                nested_collection_path_item(resource, &parent_api_name, field.api_name()),
            );
        }

        for source_resource in &service.resources {
            for relation in &source_resource.many_to_many {
                if relation.target_table != resource.table_name {
                    continue;
                }
                paths.insert(
                    format!(
                        "/{}/{{parent_id}}/{}",
                        source_resource.api_name(),
                        relation.name
                    ),
                    many_to_many_collection_path_item(
                        resource,
                        source_resource.api_name(),
                        relation.name.as_str(),
                    ),
                );
            }
        }
    }

    for upload in &service.storage.uploads {
        paths.insert(
            format!("/{}", upload.path),
            storage_upload_path_item(upload),
        );
    }

    if options.include_builtin_auth {
        tags.push(json!({ "name": "Auth" }));
        tags.push(json!({ "name": "Account" }));
        append_builtin_auth_components(service, &mut schemas, &mut paths);
    }

    if service.authorization.management_api.enabled {
        tags.push(json!({ "name": "Authorization" }));
        append_authorization_management_components(
            &mut schemas,
            &mut paths,
            service.authorization.management_api.mount.as_str(),
        );
    }

    apply_default_client_security(&mut paths);

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
                "anonKey": {
                    "type": "apiKey",
                    "in": "header",
                    "name": DEFAULT_ANON_CLIENT_HEADER_NAME
                },
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

fn storage_upload_path_item(upload: &crate::storage::StorageUploadEndpoint) -> Value {
    let mut post = json!({
        "tags": ["Storage"],
        "summary": format!("Upload file to {}", upload.name),
        "operationId": format!("upload{}", pascal_case(upload.name.as_str())),
        "requestBody": {
            "required": true,
            "content": {
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "required": ["file"],
                        "properties": {
                            "file": {
                                "type": "string",
                                "format": "binary"
                            }
                        }
                    }
                }
            }
        },
        "responses": {
            "201": {
                "description": "Upload created",
                "content": {
                    "application/json": {
                        "schema": {
                            "$ref": "#/components/schemas/StorageUploadResponse"
                        }
                    }
                }
            },
            "400": api_error_response("Invalid multipart upload"),
            "401": api_error_response("Missing or invalid bearer token"),
            "403": api_error_response("Upload is not allowed for the current user"),
            "413": api_error_response("Uploaded file exceeds the configured limit"),
            "500": api_error_response("Unexpected server error"),
        }
    });
    if upload.require_auth || !upload.roles.is_empty() {
        post["security"] = bearer_security();
    }

    json!({
        "post": post,
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
    let mut post = json!({
        "tags": [resource_name(resource)],
        "summary": format!("Create {}", resource_name(resource)),
        "operationId": format!("create{}", resource_name(resource)),
        "security": bearer_security(),
        "requestBody": json_request_body(format!("{}Create", resource_name(resource))),
        "responses": create_responses(),
    });
    if let Some(parameter) = response_context_parameter(resource) {
        post["parameters"] = json!([parameter]);
    }

    json!({
        "get": get,
        "post": post,
    })
}

fn item_path_item(resource: &ResourceSpec) -> Value {
    let id_description = resource
        .find_field(resource.id_field.as_str())
        .map(|field| field.api_name())
        .unwrap_or(resource.id_field.as_str());
    let id_parameter = id_parameter("id", id_description);
    let mut get_parameters = vec![id_parameter.clone()];
    if let Some(parameter) = response_context_parameter(resource) {
        get_parameters.push(parameter);
    }
    let mut get = json!({
        "tags": [resource_name(resource)],
        "summary": format!("Get {}", resource_name(resource)),
        "operationId": format!("get{}", resource_name(resource)),
        "parameters": get_parameters,
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

fn item_action_path_item(
    resource: &ResourceSpec,
    action: &super::model::ResourceActionSpec,
) -> Value {
    let id_description = resource
        .find_field(resource.id_field.as_str())
        .map(|field| field.api_name())
        .unwrap_or(resource.id_field.as_str());
    let id_parameter = id_parameter("id", id_description);
    let mut post = json!({
        "tags": [resource_name(resource)],
        "summary": format!("Run {} on {}", action.name.to_case(CaseKind::Pascal), resource_name(resource)),
        "operationId": format!("{}{}", action.name.to_case(CaseKind::Pascal), resource_name(resource)),
        "parameters": [id_parameter],
        "security": bearer_security(),
        "responses": match &action.behavior {
            super::model::ResourceActionBehaviorSpec::UpdateFields { .. } => {
                json!(update_responses())
            }
            super::model::ResourceActionBehaviorSpec::DeleteResource => {
                json!(delete_responses())
            }
        },
    });
    if matches!(
        &action.behavior,
        super::model::ResourceActionBehaviorSpec::UpdateFields { .. }
    ) && !action.input_fields.is_empty()
    {
        post["requestBody"] = json_request_body(action_input_schema_name(resource, action));
    }
    json!({ "post": post })
}

fn nested_collection_path_item(
    resource: &ResourceSpec,
    parent_api_name: &str,
    relation_field: &str,
) -> Value {
    let mut parameters = vec![id_parameter("parent_id", relation_field)];
    parameters.extend(list_query_parameters(resource, Some(relation_field)));
    let mut get = json!({
        "tags": [resource_name(resource)],
        "summary": format!("List {} by {}", resource_name(resource), parent_api_name),
        "operationId": format!("list{}By{}", resource_name(resource), parent_api_name.to_case(CaseKind::Pascal)),
        "parameters": parameters,
        "responses": nested_list_responses(resource),
    });
    if read_requires_auth(resource) {
        get["security"] = bearer_security();
    }
    json!({ "get": get })
}

fn many_to_many_collection_path_item(
    resource: &ResourceSpec,
    parent_api_name: &str,
    relation_name: &str,
) -> Value {
    let mut parameters = vec![id_parameter("parent_id", relation_name)];
    parameters.extend(list_query_parameters(resource, None));
    let mut get = json!({
        "tags": [resource_name(resource)],
        "summary": format!("List {} by {}", resource_name(resource), parent_api_name),
        "operationId": format!(
            "list{}By{}{}",
            resource_name(resource),
            parent_api_name.to_case(CaseKind::Pascal),
            relation_name.to_case(CaseKind::Pascal)
        ),
        "parameters": parameters,
        "responses": nested_list_responses(resource),
    });
    if read_requires_auth(resource) {
        get["security"] = bearer_security();
    }
    json!({ "get": get })
}

fn append_builtin_auth_components(
    service: &ServiceSpec,
    schemas: &mut Map<String, Value>,
    paths: &mut Map<String, Value>,
) {
    let claim_properties = auth_claim_properties(service);
    let managed_claims_schema = if claim_properties.is_empty() {
        None
    } else {
        Some(json!({
            "type": "object",
            "properties": claim_properties,
            "additionalProperties": false
        }))
    };
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
        auth_me_response_schema(&claim_properties),
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
        managed_user_patch_input_schema(managed_claims_schema.clone()),
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
        auth_account_response_schema(&claim_properties),
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
    if service
        .security
        .auth
        .jwt
        .as_ref()
        .is_some_and(|jwt| !jwt.algorithm.is_symmetric() && !jwt.verification_keys.is_empty())
    {
        schemas.insert(
            "JwksResponse".to_owned(),
            json!({
                "type": "object",
                "properties": {
                    "keys": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": true
                        }
                    }
                },
                "required": ["keys"]
            }),
        );
    }

    if service
        .security
        .auth
        .jwt
        .as_ref()
        .is_some_and(|jwt| !jwt.algorithm.is_symmetric() && !jwt.verification_keys.is_empty())
    {
        paths.insert(
            "/.well-known/jwks.json".to_owned(),
            json!({
                "get": {
                    "tags": ["Auth"],
                    "summary": "Get the public JWKS for JWT verification",
                    "operationId": "getJsonWebKeySet",
                    "security": [],
                    "responses": {
                        "200": json_response("OK", schema_ref("JwksResponse")),
                        "500": api_error_response("Internal server error")
                    }
                }
            }),
        );
    }

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
    if let Some(portal) = service.security.auth.portal.as_ref() {
        paths.insert(
            portal.path.clone(),
            json!({
                "get": {
                    "tags": ["Account"],
                    "summary": "Open the built-in account portal page",
                    "operationId": "openBuiltinAccountPortal",
                    "responses": {
                        "200": plain_response("Account portal page")
                    }
                }
            }),
        );
    }
    if let Some(admin_dashboard) = service.security.auth.admin_dashboard.as_ref() {
        paths.insert(
            admin_dashboard.path.clone(),
            json!({
                "get": {
                    "tags": ["Admin"],
                    "summary": "Open the built-in admin dashboard page",
                    "operationId": "openBuiltinAdminDashboard",
                    "security": bearer_security(),
                    "responses": {
                        "200": plain_response("Admin dashboard page"),
                        "401": api_error_response("Authentication required"),
                        "403": api_error_response("Admin role required")
                    }
                }
            }),
        );
    }
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
                        "schema": {
                            "type": "integer",
                            "format": "int32",
                            "minimum": 1,
                            "maximum": 100
                        }
                    },
                    {
                        "name": "offset",
                        "in": "query",
                        "required": false,
                        "schema": {
                            "type": "integer",
                            "format": "int32",
                            "minimum": 0
                        }
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
                    "403": api_error_response("Admin role required"),
                    "500": api_error_response("Internal server error")
                }
            },
            "post": {
                "tags": ["Admin"],
                "summary": "Create a built-in auth user",
                "operationId": "createBuiltinAuthUser",
                "security": bearer_security(),
                "requestBody": json_request_body("ManagedUserCreateInput"),
                "responses": {
                    "201": json_response_with_headers("Created", schema_ref("AuthAccountResponse"), json!({
                        "Location": {
                            "description": "Canonical URL of the created built-in auth user",
                            "schema": { "type": "string" }
                        }
                    })),
                    "400": api_error_response("Invalid request body"),
                    "413": api_error_response("Payload too large"),
                    "415": api_error_response("Unsupported media type"),
                    "401": api_error_response("Authentication required"),
                    "403": api_error_response("Admin role required"),
                    "409": api_error_response("Email already exists"),
                    "500": api_error_response("Internal server error"),
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
                    "404": api_error_response("User not found"),
                    "500": api_error_response("Internal server error")
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
                    "413": api_error_response("Payload too large"),
                    "415": api_error_response("Unsupported media type"),
                    "401": api_error_response("Authentication required"),
                    "403": api_error_response("Admin role required"),
                    "404": api_error_response("User not found"),
                    "500": api_error_response("Internal server error")
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
                    "404": api_error_response("User not found"),
                    "500": api_error_response("Internal server error")
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
                    "500": api_error_response("Internal server error"),
                    "503": api_error_response("Email delivery unavailable")
                }
            }
        }),
    );
}

fn auth_claim_properties(service: &ServiceSpec) -> Map<String, Value> {
    service
        .security
        .auth
        .claims
        .iter()
        .map(|(name, mapping)| (name.clone(), auth_claim_value_schema(mapping.ty)))
        .collect()
}

fn auth_claim_value_schema(ty: AuthClaimType) -> Value {
    match ty {
        AuthClaimType::I64 => json!({
            "type": "integer",
            "format": "int64"
        }),
        AuthClaimType::String => json!({
            "type": "string"
        }),
        AuthClaimType::Bool => json!({
            "type": "boolean"
        }),
    }
}

fn auth_me_response_schema(claim_properties: &Map<String, Value>) -> Value {
    let mut properties = Map::new();
    properties.insert(
        "id".to_owned(),
        json!({
            "type": "integer",
            "format": "int64"
        }),
    );
    properties.insert(
        "roles".to_owned(),
        json!({
            "type": "array",
            "items": { "type": "string" }
        }),
    );
    for (name, schema) in claim_properties {
        properties.insert(name.clone(), schema.clone());
    }
    json!({
        "type": "object",
        "properties": properties,
        "required": ["id", "roles"],
        "additionalProperties": true
    })
}

fn managed_user_patch_input_schema(managed_claims_schema: Option<Value>) -> Value {
    let mut properties = Map::new();
    properties.insert("role".to_owned(), json!({ "type": "string" }));
    properties.insert("email_verified".to_owned(), json!({ "type": "boolean" }));
    if let Some(claims) = managed_claims_schema {
        properties.insert("claims".to_owned(), claims);
    }
    json!({
        "type": "object",
        "properties": properties
    })
}

fn auth_account_response_schema(claim_properties: &Map<String, Value>) -> Value {
    let mut properties = Map::new();
    properties.insert(
        "id".to_owned(),
        json!({
            "type": "integer",
            "format": "int64"
        }),
    );
    properties.insert(
        "email".to_owned(),
        json!({
            "type": "string",
            "format": "email"
        }),
    );
    properties.insert("role".to_owned(), json!({ "type": "string" }));
    properties.insert(
        "roles".to_owned(),
        json!({
            "type": "array",
            "items": { "type": "string" }
        }),
    );
    properties.insert("email_verified".to_owned(), json!({ "type": "boolean" }));
    properties.insert(
        "email_verified_at".to_owned(),
        json!({
            "type": "string",
            "format": "date-time"
        }),
    );
    properties.insert(
        "created_at".to_owned(),
        json!({
            "type": "string",
            "format": "date-time"
        }),
    );
    properties.insert(
        "updated_at".to_owned(),
        json!({
            "type": "string",
            "format": "date-time"
        }),
    );
    for (name, schema) in claim_properties {
        properties.insert(name.clone(), schema.clone());
    }
    json!({
        "type": "object",
        "properties": properties,
        "required": ["id", "email", "role", "roles", "email_verified"],
        "additionalProperties": true
    })
}

fn append_authorization_management_components(
    schemas: &mut Map<String, Value>,
    paths: &mut Map<String, Value>,
    mount: &str,
) {
    schemas.insert(
        "AuthorizationAction".to_owned(),
        json!({
            "type": "string",
            "enum": ["read", "create", "update", "delete"]
        }),
    );
    schemas.insert(
        "AuthorizationScopeBinding".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "scope": { "type": "string" },
                "value": { "type": "string" }
            },
            "required": ["scope", "value"]
        }),
    );
    schemas.insert(
        "AuthorizationScopedAssignmentPermissionTarget".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "kind": { "type": "string", "enum": ["permission"] },
                "name": { "type": "string" }
            },
            "required": ["kind", "name"]
        }),
    );
    schemas.insert(
        "AuthorizationScopedAssignmentTemplateTarget".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "kind": { "type": "string", "enum": ["template"] },
                "name": { "type": "string" }
            },
            "required": ["kind", "name"]
        }),
    );
    schemas.insert(
        "AuthorizationScopedAssignmentTarget".to_owned(),
        json!({
            "oneOf": [
                schema_ref("AuthorizationScopedAssignmentPermissionTarget"),
                schema_ref("AuthorizationScopedAssignmentTemplateTarget")
            ]
        }),
    );
    schemas.insert(
        "AuthorizationScopedAssignmentCreateInput".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "user_id": { "type": "integer", "format": "int64" },
                "target": schema_ref("AuthorizationScopedAssignmentTarget"),
                "scope": schema_ref("AuthorizationScopeBinding"),
                "expires_at": {
                    "type": "string",
                    "format": "date-time",
                    "nullable": true
                }
            },
            "required": ["user_id", "target", "scope"]
        }),
    );
    schemas.insert(
        "AuthorizationScopedAssignmentRecord".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "user_id": { "type": "integer", "format": "int64" },
                "target": schema_ref("AuthorizationScopedAssignmentTarget"),
                "scope": schema_ref("AuthorizationScopeBinding"),
                "created_at": { "type": "string", "format": "date-time" },
                "created_by_user_id": {
                    "type": "integer",
                    "format": "int64",
                    "nullable": true
                },
                "expires_at": {
                    "type": "string",
                    "format": "date-time",
                    "nullable": true
                }
            },
            "required": ["id", "user_id", "target", "scope", "created_at"]
        }),
    );
    schemas.insert(
        "AuthorizationScopedAssignmentEventKind".to_owned(),
        json!({
            "type": "string",
            "enum": ["created", "revoked", "renewed", "deleted"]
        }),
    );
    schemas.insert(
        "AuthorizationScopedAssignmentEventRecord".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "assignment_id": { "type": "string" },
                "user_id": { "type": "integer", "format": "int64" },
                "event": schema_ref("AuthorizationScopedAssignmentEventKind"),
                "occurred_at": { "type": "string", "format": "date-time" },
                "actor_user_id": {
                    "type": "integer",
                    "format": "int64",
                    "nullable": true
                },
                "target": schema_ref("AuthorizationScopedAssignmentTarget"),
                "scope": schema_ref("AuthorizationScopeBinding"),
                "expires_at": {
                    "type": "string",
                    "format": "date-time",
                    "nullable": true
                },
                "reason": {
                    "type": "string",
                    "nullable": true
                }
            },
            "required": [
                "id",
                "assignment_id",
                "user_id",
                "event",
                "occurred_at",
                "target",
                "scope"
            ]
        }),
    );
    schemas.insert(
        "AuthorizationScopedAssignmentRevokeInput".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "reason": {
                    "type": "string",
                    "nullable": true
                }
            }
        }),
    );
    schemas.insert(
        "AuthorizationScopedAssignmentRenewInput".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "expires_at": { "type": "string", "format": "date-time" },
                "reason": {
                    "type": "string",
                    "nullable": true
                }
            },
            "required": ["expires_at"]
        }),
    );
    schemas.insert(
        "AuthorizationScopedAssignmentTrace".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "target": schema_ref("AuthorizationScopedAssignmentTarget"),
                "scope": schema_ref("AuthorizationScopeBinding"),
                "scope_matched": { "type": "boolean" },
                "target_matched": { "type": "boolean" },
                "created_at": {
                    "type": "string",
                    "format": "date-time",
                    "nullable": true
                },
                "created_by_user_id": {
                    "type": "integer",
                    "format": "int64",
                    "nullable": true
                },
                "expires_at": {
                    "type": "string",
                    "format": "date-time",
                    "nullable": true
                },
                "expired": { "type": "boolean" },
                "resolved_permissions": {
                    "type": "array",
                    "items": { "type": "string" }
                },
                "resolved_template": {
                    "type": "string",
                    "nullable": true
                }
            },
            "required": [
                "id",
                "target",
                "scope",
                "scope_matched",
                "target_matched",
                "expired",
                "resolved_permissions"
            ]
        }),
    );
    schemas.insert(
        "AuthorizationRuntimeAccessInput".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "resource": { "type": "string" },
                "action": schema_ref("AuthorizationAction"),
                "scope": schema_ref("AuthorizationScopeBinding"),
                "user_id": {
                    "type": "integer",
                    "format": "int64",
                    "nullable": true
                }
            },
            "required": ["resource", "action", "scope"]
        }),
    );
    schemas.insert(
        "AuthorizationRuntimeAccessResult".to_owned(),
        json!({
            "type": "object",
            "properties": {
                "user_id": { "type": "integer", "format": "int64" },
                "resource_id": { "type": "string" },
                "resource": { "type": "string" },
                "action_id": { "type": "string" },
                "action": schema_ref("AuthorizationAction"),
                "scope": schema_ref("AuthorizationScopeBinding"),
                "allowed": { "type": "boolean" },
                "resolved_permissions": {
                    "type": "array",
                    "items": { "type": "string" }
                },
                "resolved_templates": {
                    "type": "array",
                    "items": { "type": "string" }
                },
                "runtime_assignments": {
                    "type": "array",
                    "items": schema_ref("AuthorizationScopedAssignmentTrace")
                },
                "notes": {
                    "type": "array",
                    "items": { "type": "string" }
                }
            },
            "required": [
                "user_id",
                "resource_id",
                "resource",
                "action_id",
                "action",
                "scope",
                "allowed",
                "resolved_permissions",
                "resolved_templates",
                "runtime_assignments",
                "notes"
            ]
        }),
    );

    let mount = normalized_openapi_mount(mount);
    paths.insert(
        openapi_join_mount_path(&mount, "evaluate"),
        json!({
            "post": {
                "tags": ["Authorization"],
                "summary": "Evaluate runtime authorization access",
                "operationId": "evaluateRuntimeAuthorizationAccess",
                "security": bearer_security(),
                "requestBody": json_request_body("AuthorizationRuntimeAccessInput"),
                "responses": {
                    "200": json_response("OK", schema_ref("AuthorizationRuntimeAccessResult")),
                    "400": api_error_response("Invalid runtime authorization access request"),
                    "401": api_error_response("Authentication required"),
                    "403": api_error_response("Admin role is required to evaluate another user"),
                    "500": api_error_response("Internal server error")
                }
            }
        }),
    );
    paths.insert(
        openapi_join_mount_path(&mount, "assignments"),
        json!({
            "get": {
                "tags": ["Authorization"],
                "summary": "List runtime authorization assignments for a user",
                "operationId": "listRuntimeAuthorizationAssignments",
                "security": bearer_security(),
                "parameters": [user_id_query_parameter()],
                "responses": {
                    "200": json_response("OK", json!({
                        "type": "array",
                        "items": schema_ref("AuthorizationScopedAssignmentRecord")
                    })),
                    "401": api_error_response("Authentication required"),
                    "403": api_error_response("Admin role required"),
                    "500": api_error_response("Internal server error")
                }
            },
            "post": {
                "tags": ["Authorization"],
                "summary": "Create a runtime authorization assignment",
                "operationId": "createRuntimeAuthorizationAssignment",
                "security": bearer_security(),
                "requestBody": json_request_body("AuthorizationScopedAssignmentCreateInput"),
                "responses": {
                    "201": json_response("Created", schema_ref("AuthorizationScopedAssignmentRecord")),
                    "400": api_error_response("Invalid runtime authorization assignment"),
                    "401": api_error_response("Authentication required"),
                    "403": api_error_response("Admin role required"),
                    "500": api_error_response("Internal server error")
                }
            }
        }),
    );
    paths.insert(
        openapi_join_mount_path(&mount, "assignment-events"),
        json!({
            "get": {
                "tags": ["Authorization"],
                "summary": "List runtime authorization assignment events for a user",
                "operationId": "listRuntimeAuthorizationAssignmentEvents",
                "security": bearer_security(),
                "parameters": [user_id_query_parameter()],
                "responses": {
                    "200": json_response("OK", json!({
                        "type": "array",
                        "items": schema_ref("AuthorizationScopedAssignmentEventRecord")
                    })),
                    "401": api_error_response("Authentication required"),
                    "403": api_error_response("Admin role required"),
                    "500": api_error_response("Internal server error")
                }
            }
        }),
    );
    paths.insert(
        openapi_join_mount_path(&mount, "assignments/{id}"),
        json!({
            "delete": {
                "tags": ["Authorization"],
                "summary": "Delete a runtime authorization assignment",
                "operationId": "deleteRuntimeAuthorizationAssignment",
                "security": bearer_security(),
                "parameters": [string_path_parameter("id", "runtime authorization assignment")],
                "responses": {
                    "204": plain_response("Assignment deleted"),
                    "401": api_error_response("Authentication required"),
                    "403": api_error_response("Admin role required"),
                    "404": api_error_response("Runtime authorization assignment not found"),
                    "500": api_error_response("Internal server error")
                }
            }
        }),
    );
    paths.insert(
        openapi_join_mount_path(&mount, "assignments/{id}/revoke"),
        json!({
            "post": {
                "tags": ["Authorization"],
                "summary": "Revoke a runtime authorization assignment",
                "operationId": "revokeRuntimeAuthorizationAssignment",
                "security": bearer_security(),
                "parameters": [string_path_parameter("id", "runtime authorization assignment")],
                "requestBody": json_request_body("AuthorizationScopedAssignmentRevokeInput"),
                "responses": {
                    "200": json_response("OK", schema_ref("AuthorizationScopedAssignmentRecord")),
                    "400": api_error_response("Invalid runtime authorization assignment"),
                    "401": api_error_response("Authentication required"),
                    "403": api_error_response("Admin role required"),
                    "404": api_error_response("Runtime authorization assignment not found"),
                    "500": api_error_response("Internal server error")
                }
            }
        }),
    );
    paths.insert(
        openapi_join_mount_path(&mount, "assignments/{id}/renew"),
        json!({
            "post": {
                "tags": ["Authorization"],
                "summary": "Renew a runtime authorization assignment",
                "operationId": "renewRuntimeAuthorizationAssignment",
                "security": bearer_security(),
                "parameters": [string_path_parameter("id", "runtime authorization assignment")],
                "requestBody": json_request_body("AuthorizationScopedAssignmentRenewInput"),
                "responses": {
                    "200": json_response("OK", schema_ref("AuthorizationScopedAssignmentRecord")),
                    "400": api_error_response("Invalid runtime authorization assignment"),
                    "401": api_error_response("Authentication required"),
                    "403": api_error_response("Admin role required"),
                    "404": api_error_response("Runtime authorization assignment not found"),
                    "500": api_error_response("Internal server error")
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
        (
            "201",
            plain_response_with_headers(
                "Created",
                json!({
                    "Location": {
                        "description": "Canonical URL of the created resource",
                        "schema": { "type": "string" }
                    }
                }),
            ),
        ),
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

fn json_response_with_headers(description: &'static str, schema: Value, headers: Value) -> Value {
    let mut response = json_response(description, schema);
    response["headers"] = headers;
    response
}

fn plain_response(description: &'static str) -> Value {
    json!({
        "description": description,
    })
}

fn plain_response_with_headers(description: &'static str, headers: Value) -> Value {
    let mut response = plain_response(description);
    response["headers"] = headers;
    response
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

fn storage_upload_response_schema() -> Value {
    json!({
        "type": "object",
        "required": ["backend", "object_key", "file_name", "size_bytes"],
        "properties": {
            "backend": { "type": "string" },
            "object_key": { "type": "string" },
            "public_url": { "type": "string", "nullable": true },
            "file_name": { "type": "string" },
            "content_type": { "type": "string", "nullable": true },
            "size_bytes": { "type": "integer", "format": "int64", "minimum": 0 }
        }
    })
}

fn pascal_case(value: &str) -> String {
    value
        .split(['-', '_', '/'])
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            let mut chars = segment.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<String>()
}

fn bearer_security() -> Value {
    json!([
        {
            "bearerAuth": []
        }
    ])
}

fn client_security() -> Value {
    json!([
        {
            "anonKey": []
        }
    ])
}

fn apply_default_client_security(paths: &mut Map<String, Value>) {
    for path_item in paths.values_mut() {
        let Some(path_item) = path_item.as_object_mut() else {
            continue;
        };

        for method in ["get", "post", "put", "patch", "delete", "options", "head"] {
            let Some(operation) = path_item.get_mut(method).and_then(Value::as_object_mut) else {
                continue;
            };

            match operation.get_mut("security") {
                Some(security) => {
                    let Some(entries) = security.as_array_mut() else {
                        *security = client_security();
                        continue;
                    };
                    if entries.is_empty() {
                        continue;
                    }

                    let transformed = entries
                        .iter()
                        .filter_map(Value::as_object)
                        .map(|entry| {
                            let mut entry = entry.clone();
                            entry.insert("anonKey".to_owned(), json!([]));
                            Value::Object(entry)
                        })
                        .collect::<Vec<_>>();

                    if transformed.is_empty() {
                        *security = client_security();
                    } else {
                        *security = Value::Array(transformed);
                    }
                }
                None => {
                    operation.insert("security".to_owned(), client_security());
                }
            }
        }
    }
}

fn schema_ref(name: impl Into<String>) -> Value {
    json!({
        "$ref": format!("#/components/schemas/{}", name.into()),
    })
}

fn normalized_openapi_mount(mount: &str) -> String {
    if mount == "/" {
        String::new()
    } else {
        mount.trim_end_matches('/').to_owned()
    }
}

fn openapi_join_mount_path(mount: &str, suffix: &str) -> String {
    let suffix = suffix.trim_start_matches('/');
    if mount.is_empty() {
        format!("/{suffix}")
    } else if suffix.is_empty() {
        mount.to_owned()
    } else {
        format!("{mount}/{suffix}")
    }
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

fn string_path_parameter(name: &str, description: &str) -> Value {
    json!({
        "name": name,
        "in": "path",
        "required": true,
        "description": format!("Path parameter for `{description}`"),
        "schema": {
            "type": "string"
        }
    })
}

fn user_id_query_parameter() -> Value {
    json!({
        "name": "user_id",
        "in": "query",
        "required": true,
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
        .api_fields()
        .filter(|field| supports_field_sort(field))
        .map(|field| field.api_name().to_owned())
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
    if let Some(parameter) = response_context_parameter(resource) {
        parameters.push(parameter);
    }

    for field in resource.api_fields() {
        let api_field_name = field.api_name().to_owned();
        if supports_exact_filters(field) {
            let description = if parent_relation_field == Some(api_field_name.as_str()) {
                format!(
                    "Exact-match filter for `{api_field_name}`. Nested route parent filtering is applied automatically."
                )
            } else {
                format!("Exact-match filter for `{api_field_name}`")
            };
            parameters.push(json!({
                "name": format!("filter_{api_field_name}"),
                "in": "query",
                "required": false,
                "description": description,
                "schema": query_parameter_schema(field),
            }));
        }

        if supports_contains_filters(field) {
            parameters.push(json!({
                "name": format!("filter_{api_field_name}_contains"),
                "in": "query",
                "required": false,
                "description": format!(
                    "Case-insensitive substring filter for `{api_field_name}`. `%`, `_`, and `\\` are treated literally."
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
                    "name": format!("filter_{api_field_name}_{suffix}"),
                    "in": "query",
                    "required": false,
                    "description": format!(
                        "Filter `{api_field_name}` values {operator}{qualifier} this {kind_label}"
                    ),
                    "schema": query_parameter_schema(field),
                }));
            }
        }
    }

    parameters
}

fn response_context_parameter(resource: &ResourceSpec) -> Option<Value> {
    let context_names = resource
        .response_context_names()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if context_names.is_empty() {
        return None;
    }

    let mut schema = json!({
        "type": "string",
        "enum": context_names
    });
    if let Some(default_context) = resource.default_response_context.as_deref() {
        schema["default"] = json!(default_context);
    }

    Some(json!({
        "name": "context",
        "in": "query",
        "required": false,
        "description": "Named response context for the returned resource shape",
        "schema": schema
    }))
}

fn object_schema(fields: &[&FieldSpec]) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();

    for field in fields {
        let field_name = field.api_name().to_owned();
        properties.insert(field_name.clone(), field_schema(field));
        if !is_optional_type(&field.ty) || field.validation.required {
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

fn response_object_schema(resource: &ResourceSpec) -> Value {
    let mut schema = object_schema(&resource.api_fields().collect::<Vec<_>>());
    let Some(properties) = schema["properties"].as_object_mut() else {
        return schema;
    };

    for field in &resource.computed_fields {
        properties.insert(field.api_name.clone(), computed_field_schema(field));
    }

    if let Some(required) = schema.get_mut("required").and_then(Value::as_array_mut) {
        for field in &resource.computed_fields {
            if !field.optional {
                required.push(json!(field.api_name));
            }
        }
    } else {
        let required = resource
            .computed_fields
            .iter()
            .filter(|field| !field.optional)
            .map(|field| json!(field.api_name))
            .collect::<Vec<_>>();
        if !required.is_empty() {
            schema["required"] = Value::Array(required);
        }
    }

    schema
}

fn computed_field_schema(field: &ComputedFieldSpec) -> Value {
    if field.optional {
        json!({
            "type": "string",
            "nullable": true,
        })
    } else {
        json!({
            "type": "string",
        })
    }
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
        let field_name = field.field.api_name().to_owned();
        properties.insert(
            field_name.clone(),
            field_schema_with_optional(field.field, field.allow_admin_override),
        );
        if !field.allow_admin_override
            && (!is_optional_type(&field.field.ty) || field.field.validation.required)
        {
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

fn action_input_schema_name(
    resource: &ResourceSpec,
    action: &super::model::ResourceActionSpec,
) -> String {
    format!(
        "{}{}ActionInput",
        resource_name(resource),
        action.name.to_case(CaseKind::Pascal)
    )
}

fn action_input_schema(
    resource: &ResourceSpec,
    action: &super::model::ResourceActionSpec,
) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();

    for input in &action.input_fields {
        let field = resource
            .find_field(input.target_field.as_str())
            .expect("validated action input target field should exist");
        properties.insert(input.name.clone(), field_schema(field));
        if !is_optional_type(&field.ty) || field.validation.required {
            required.push(input.name.clone());
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

    let inferred_datetime_suffix = field.name().ends_with("_at")
        && !matches!(
            structured_scalar_kind(&field.ty),
            Some(super::model::StructuredScalarKind::Date)
                | Some(super::model::StructuredScalarKind::Time)
        );

    if !is_list_field(field)
        && (matches!(
            field.generated,
            GeneratedValue::CreatedAt | GeneratedValue::UpdatedAt
        ) || inferred_datetime_suffix)
    {
        schema["format"] = json!("date-time");
    }

    if force_optional || is_optional_type(&field.ty) {
        schema["nullable"] = json!(true);
    }

    if let Some(enum_values) = field.enum_values() {
        schema["enum"] = json!(enum_values);
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
    if let Some(length) = field.validation.length.as_ref() {
        if is_list_field(field) {
            if matches!(length.mode, None | Some(super::model::LengthMode::Simple)) {
                if let Some(min) = length.min {
                    schema["minItems"] = json!(min);
                }
                if let Some(max) = length.max {
                    schema["maxItems"] = json!(max);
                }
                if let Some(equal) = length.equal {
                    schema["minItems"] = json!(equal);
                    schema["maxItems"] = json!(equal);
                }
            }
        } else if matches!(length.mode, Some(super::model::LengthMode::Chars)) {
            if let Some(min) = length.min {
                schema["minLength"] = json!(min);
            }
            if let Some(max) = length.max {
                schema["maxLength"] = json!(max);
            }
            if let Some(equal) = length.equal {
                schema["minLength"] = json!(equal);
                schema["maxLength"] = json!(equal);
            }
        }
    }

    if let Some(range) = field.validation.range.as_ref() {
        if let Some(minimum) = &range.min {
            schema["minimum"] = numeric_bound_json(minimum);
        }
        if let Some(maximum) = &range.max {
            schema["maximum"] = numeric_bound_json(maximum);
        }
        if let Some(equal) = &range.equal {
            let equal = numeric_bound_json(equal);
            schema["minimum"] = equal.clone();
            schema["maximum"] = equal;
        }
    }

    if let Some(pattern) = field.validation.pattern.as_deref() {
        schema["pattern"] = json!(pattern);
    }

    if field.validation.email {
        schema["format"] = json!("email");
    } else if field.validation.url {
        schema["format"] = json!("uri");
    } else if field.validation.ipv4 {
        schema["format"] = json!("ipv4");
    } else if field.validation.ipv6 {
        schema["format"] = json!("ipv6");
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

    fn snapshot_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/snapshots/openapi")
            .join(name)
    }

    fn assert_json_snapshot(snapshot: &PathBuf, actual: &Value) {
        let rendered =
            serde_json::to_string_pretty(actual).expect("snapshot json should serialize");
        if std::env::var_os("VSR_UPDATE_SNAPSHOTS").is_some() {
            if let Some(parent) = snapshot.parent() {
                fs::create_dir_all(parent).expect("snapshot parent should be creatable");
            }
            fs::write(snapshot, rendered).expect("snapshot should be writable");
            return;
        }

        let expected = fs::read_to_string(snapshot).unwrap_or_else(|error| {
            panic!(
                "snapshot {} is missing or unreadable: {error}. Re-run with VSR_UPDATE_SNAPSHOTS=1 to create it.",
                snapshot.display()
            )
        });
        assert_eq!(
            expected.trim_end_matches('\n'),
            rendered.trim_end_matches('\n'),
            "snapshot mismatch at {}",
            snapshot.display()
        );
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
    fn renders_openapi_many_to_many_collection_paths() {
        let service = load_service_from_path(&fixture_path("many_to_many_api.eon"))
            .expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("Many To Many API", "1.0.0", "/api"),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");

        assert!(document["paths"]["/posts/{parent_id}/tags"]["get"].is_object());
        assert_eq!(
            document["paths"]["/posts/{parent_id}/tags"]["get"]["parameters"][0]["name"],
            "parent_id"
        );
        assert_eq!(
            document["paths"]["/posts/{parent_id}/tags"]["get"]["parameters"][1]["name"],
            "limit"
        );
        assert_eq!(
            document["paths"]["/posts/{parent_id}/tags"]["get"]["responses"]["200"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/TagListResponse"
        );

        let snapshot = json!({
            "paths": {
                "/posts/{parent_id}/tags": document["paths"]["/posts/{parent_id}/tags"].clone()
            },
            "schemas": {
                "Tag": document["components"]["schemas"]["Tag"].clone(),
                "TagListResponse": document["components"]["schemas"]["TagListResponse"].clone()
            }
        });
        assert_json_snapshot(&snapshot_path("many_to_many_surface.json"), &snapshot);
    }

    #[test]
    fn renders_openapi_resource_action_paths() {
        let service = load_service_from_path(&fixture_path("resource_actions_api.eon"))
            .expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("Resource Actions API", "1.0.0", "/api"),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");

        assert!(document["paths"]["/posts/{id}/go-live"]["post"].is_object());
        assert_eq!(
            document["paths"]["/posts/{id}/go-live"]["post"]["parameters"][0]["name"],
            "id"
        );
        assert!(
            document["paths"]["/posts/{id}/go-live"]["post"]
                .get("requestBody")
                .is_none()
        );
        assert_eq!(
            document["paths"]["/posts/{id}/rename"]["post"]["requestBody"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/PostRenameActionInput"
        );
        assert_eq!(
            document["components"]["schemas"]["PostRenameActionInput"]["properties"]["newTitle"]["type"],
            "string"
        );
        assert_eq!(
            document["components"]["schemas"]["PostRenameActionInput"]["required"],
            json!(["newSlug", "newStatus", "newTitle"])
        );
        assert_eq!(
            document["paths"]["/posts/{id}/go-live"]["post"]["security"][0]["bearerAuth"],
            json!([])
        );
        assert!(
            document["paths"]["/posts/{id}/purge"]["post"]
                .get("requestBody")
                .is_none()
        );
        assert_eq!(
            document["paths"]["/posts/{id}/purge"]["post"]["responses"]["200"]["description"],
            "Deleted"
        );

        let snapshot = json!({
            "paths": {
                "/posts/{id}/go-live": document["paths"]["/posts/{id}/go-live"].clone(),
                "/posts/{id}/rename": document["paths"]["/posts/{id}/rename"].clone(),
                "/posts/{id}/purge": document["paths"]["/posts/{id}/purge"].clone()
            },
            "schemas": {
                "PostRenameActionInput": document["components"]["schemas"]["PostRenameActionInput"].clone(),
                "ApiErrorResponse": document["components"]["schemas"]["ApiErrorResponse"].clone()
            }
        });
        assert_json_snapshot(&snapshot_path("resource_actions_surface.json"), &snapshot);
    }

    #[test]
    fn renders_openapi_public_reads_with_anon_client_security_and_contains_filters() {
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

        assert_eq!(
            document["paths"]["/organization"]["get"]["security"][0]["anonKey"],
            json!([])
        );
        assert_eq!(
            document["paths"]["/organization/{id}"]["get"]["security"][0]["anonKey"],
            json!([])
        );
        assert_eq!(
            document["paths"]["/organization/{parent_id}/interest"]["get"]["security"][0]["anonKey"],
            json!([])
        );
        assert_eq!(
            document["paths"]["/organization"]["post"]["security"][0]["bearerAuth"],
            json!([])
        );
        assert_eq!(
            document["paths"]["/organization"]["post"]["security"][0]["anonKey"],
            json!([])
        );
        assert_eq!(contains["schema"]["type"], json!("string"));
        assert!(
            contains["description"]
                .as_str()
                .expect("contains description should be a string")
                .contains("treated literally")
        );

        let snapshot = json!({
            "paths": {
                "/organization": document["paths"]["/organization"].clone(),
                "/organization/{id}": document["paths"]["/organization/{id}"].clone(),
                "/organization/{parent_id}/interest": document["paths"]["/organization/{parent_id}/interest"].clone()
            },
            "schemas": {
                "Organization": document["components"]["schemas"]["Organization"].clone(),
                "OrganizationListResponse": document["components"]["schemas"]["OrganizationListResponse"].clone(),
                "InterestListResponse": document["components"]["schemas"]["InterestListResponse"].clone(),
                "ApiErrorResponse": document["components"]["schemas"]["ApiErrorResponse"].clone()
            }
        });
        assert_json_snapshot(&snapshot_path("public_catalog_surface.json"), &snapshot);
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

        let snapshot = json!({
            "paths": {
                "/entry": document["paths"]["/entry"].clone(),
                "/entry/{id}": document["paths"]["/entry/{id}"].clone()
            },
            "schemas": {
                "Entry": document["components"]["schemas"]["Entry"].clone(),
                "EntryCreate": document["components"]["schemas"]["EntryCreate"].clone(),
                "EntryListResponse": document["components"]["schemas"]["EntryListResponse"].clone()
            }
        });
        assert_json_snapshot(&snapshot_path("list_fields_surface.json"), &snapshot);
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
            document["components"]["schemas"]["Entry"]["properties"]["title"]["properties"]["raw"]
                ["type"],
            json!("string")
        );
        assert_eq!(
            document["components"]["schemas"]["Entry"]["properties"]["settings"]["properties"]["categories"]
                ["items"]["type"],
            json!("integer")
        );
        assert_eq!(
            document["components"]["schemas"]["Entry"]["properties"]["settings"]["properties"]["seo"]
                ["additionalProperties"],
            json!(false)
        );

        let snapshot = json!({
            "paths": {
                "/entry": document["paths"]["/entry"].clone(),
                "/entry/{id}": document["paths"]["/entry/{id}"].clone()
            },
            "schemas": {
                "Entry": document["components"]["schemas"]["Entry"].clone(),
                "EntryCreate": document["components"]["schemas"]["EntryCreate"].clone(),
                "EntryListResponse": document["components"]["schemas"]["EntryListResponse"].clone()
            }
        });
        assert_json_snapshot(&snapshot_path("object_fields_surface.json"), &snapshot);
    }

    #[test]
    fn renders_openapi_enum_field_metadata() {
        let service = load_service_from_path(&fixture_path("enum_fields_api.eon"))
            .expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("Enum Fields API", "1.0.0", "/api"),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");
        let parameters = document["paths"]["/posts"]["get"]["parameters"]
            .as_array()
            .expect("list parameters should be an array");
        let filter_status = parameters
            .iter()
            .find(|parameter| parameter["name"] == "filter_status")
            .expect("enum exact filter should exist");

        assert_eq!(
            document["components"]["schemas"]["Post"]["properties"]["status"]["enum"],
            json!(["draft", "published", "archived"])
        );
        assert_eq!(
            document["components"]["schemas"]["Post"]["properties"]["workflow"]["properties"]["current"]
                ["enum"],
            json!(["draft", "published", "archived"])
        );
        assert_eq!(
            filter_status["schema"]["enum"],
            json!(["draft", "published", "archived"])
        );
        assert!(
            parameters
                .iter()
                .all(|parameter| parameter["name"] != "filter_status_contains"),
            "enum fields should not advertise contains filters"
        );

        let snapshot = json!({
            "paths": {
                "/posts": document["paths"]["/posts"].clone(),
                "/posts/{id}": document["paths"]["/posts/{id}"].clone()
            },
            "schemas": {
                "Post": document["components"]["schemas"]["Post"].clone(),
                "PostCreate": document["components"]["schemas"]["PostCreate"].clone(),
                "PostListResponse": document["components"]["schemas"]["PostListResponse"].clone()
            }
        });
        assert_json_snapshot(&snapshot_path("enum_fields_surface.json"), &snapshot);
    }

    #[test]
    fn renders_openapi_api_aliases_for_paths_properties_and_query_parameters() {
        let service = load_service_from_path(&fixture_path("api_name_alias_api.eon"))
            .expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("API Name Alias API", "1.0.0", "/api"),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");
        let post_parameters = document["paths"]["/posts"]["get"]["parameters"]
            .as_array()
            .expect("post list parameters should be an array");

        assert!(document["paths"].get("/posts").is_some());
        assert!(document["paths"].get("/posts/{id}").is_some());
        assert!(
            document["paths"]
                .get("/posts/{parent_id}/comments")
                .is_some()
        );
        assert!(document["paths"].get("/blog_post").is_none());
        assert!(document["paths"].get("/comment_row").is_none());
        assert_eq!(
            document["components"]["schemas"]["Post"]["properties"]["title"]["type"],
            json!("string")
        );
        assert_eq!(
            document["components"]["schemas"]["Post"]["properties"]["author"]["type"],
            json!("integer")
        );
        assert_eq!(
            document["components"]["schemas"]["Post"]["properties"]["createdAt"]["format"],
            json!("date-time")
        );
        assert_eq!(
            document["components"]["schemas"]["Comment"]["properties"]["body"]["type"],
            json!("string")
        );
        assert!(
            post_parameters
                .iter()
                .any(|parameter| parameter["name"] == "filter_author")
        );
        assert!(
            post_parameters
                .iter()
                .any(|parameter| parameter["name"] == "filter_title_contains")
        );
        assert!(
            post_parameters
                .iter()
                .all(|parameter| parameter["name"] != "filter_author_id")
        );
        assert_eq!(
            document["paths"]["/posts"]["get"]["parameters"][3]["schema"]["enum"],
            json!(["id", "title", "author", "createdAt"])
        );

        let snapshot = json!({
            "paths": {
                "/posts": document["paths"]["/posts"].clone(),
                "/posts/{id}": document["paths"]["/posts/{id}"].clone(),
                "/posts/{parent_id}/comments": document["paths"]["/posts/{parent_id}/comments"].clone()
            },
            "schemas": {
                "Post": document["components"]["schemas"]["Post"].clone(),
                "PostCreate": document["components"]["schemas"]["PostCreate"].clone(),
                "PostListResponse": document["components"]["schemas"]["PostListResponse"].clone(),
                "CommentListResponse": document["components"]["schemas"]["CommentListResponse"].clone()
            }
        });
        assert_json_snapshot(&snapshot_path("api_alias_surface.json"), &snapshot);
    }

    #[test]
    fn renders_openapi_resource_api_field_projections() {
        let service = load_service_from_path(&fixture_path("api_projection_api.eon"))
            .expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("API Projection API", "1.0.0", "/api"),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");
        let parameters = document["paths"]["/posts"]["get"]["parameters"]
            .as_array()
            .expect("post list parameters should be an array");

        assert_eq!(
            document["components"]["schemas"]["Post"]["properties"]["title"]["type"],
            json!("string")
        );
        assert_eq!(
            document["components"]["schemas"]["Post"]["properties"]["author"]["type"],
            json!("integer")
        );
        assert!(
            document["components"]["schemas"]["Post"]["properties"]
                .get("draft_body")
                .is_none()
        );
        assert!(
            document["components"]["schemas"]["Post"]["properties"]
                .get("internal_note")
                .is_none()
        );
        assert!(
            parameters
                .iter()
                .any(|parameter| parameter["name"] == "filter_author")
        );
        assert!(
            parameters
                .iter()
                .all(|parameter| parameter["name"] != "filter_author_id")
        );
        assert_eq!(
            document["paths"]["/posts"]["get"]["parameters"][3]["schema"]["enum"],
            json!(["id", "title", "author"])
        );

        let snapshot = json!({
            "paths": {
                "/posts": document["paths"]["/posts"].clone(),
                "/posts/{id}": document["paths"]["/posts/{id}"].clone()
            },
            "schemas": {
                "Post": document["components"]["schemas"]["Post"].clone(),
                "PostCreate": document["components"]["schemas"]["PostCreate"].clone(),
                "PostListResponse": document["components"]["schemas"]["PostListResponse"].clone()
            }
        });
        assert_json_snapshot(&snapshot_path("api_projection_surface.json"), &snapshot);
    }

    #[test]
    fn renders_openapi_field_transform_resource_surface() {
        let service = load_service_from_path(&fixture_path("field_transforms_api.eon"))
            .expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("Field Transforms API", "1.0.0", "/api"),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");

        assert_eq!(
            document["components"]["schemas"]["Post"]["properties"]["status"]["enum"],
            json!(["draft", "published"])
        );
        assert_eq!(
            document["components"]["schemas"]["Post"]["properties"]["title"]["type"],
            json!("object")
        );
        assert_eq!(
            document["components"]["schemas"]["PostCreate"]["properties"]["slug"]["type"],
            json!("string")
        );

        let snapshot = json!({
            "paths": {
                "/posts": document["paths"]["/posts"].clone(),
                "/posts/{id}": document["paths"]["/posts/{id}"].clone()
            },
            "schemas": {
                "Post": document["components"]["schemas"]["Post"].clone(),
                "PostCreate": document["components"]["schemas"]["PostCreate"].clone(),
                "PostListResponse": document["components"]["schemas"]["PostListResponse"].clone()
            }
        });
        assert_json_snapshot(&snapshot_path("field_transforms_surface.json"), &snapshot);
    }

    #[test]
    fn renders_openapi_mixin_expanded_resource_surface() {
        let service = load_service_from_path(&fixture_path("mixin_fields_api.eon"))
            .expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("Mixin Fields API", "1.0.0", "/api"),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");

        assert_eq!(
            document["components"]["schemas"]["Post"]["properties"]["tenant_id"]["type"],
            json!("integer")
        );
        assert_eq!(
            document["components"]["schemas"]["Post"]["properties"]["slug"]["type"],
            json!("string")
        );
        assert_eq!(
            document["components"]["schemas"]["Post"]["properties"]["created_at"]["format"],
            json!("date-time")
        );
        assert_eq!(
            document["components"]["schemas"]["Post"]["properties"]["updated_at"]["format"],
            json!("date-time")
        );
        assert_eq!(
            document["components"]["schemas"]["PostListResponse"]["properties"]["items"]["items"]["$ref"],
            json!("#/components/schemas/Post")
        );

        let snapshot = json!({
            "paths": {
                "/post": document["paths"]["/post"].clone(),
                "/post/{id}": document["paths"]["/post/{id}"].clone()
            },
            "schemas": {
                "Post": document["components"]["schemas"]["Post"].clone(),
                "PostCreate": document["components"]["schemas"]["PostCreate"].clone(),
                "PostListResponse": document["components"]["schemas"]["PostListResponse"].clone()
            }
        });
        assert_json_snapshot(&snapshot_path("mixin_fields_surface.json"), &snapshot);
    }

    #[test]
    fn renders_openapi_computed_api_fields_only_in_response_schema() {
        let service = load_service_from_path(&fixture_path("api_computed_fields_api.eon"))
            .expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("Computed API Fields", "1.0.0", "/api"),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");

        assert_eq!(
            document["components"]["schemas"]["Post"]["properties"]["permalink"]["type"],
            json!("string")
        );
        assert_eq!(
            document["components"]["schemas"]["Post"]["properties"]["preview"]["nullable"],
            json!(true)
        );
        assert!(
            document["components"]["schemas"]["PostCreate"]["properties"]
                .get("permalink")
                .is_none()
        );
        assert!(
            document["paths"]["/posts"]["get"]["parameters"]
                .as_array()
                .expect("list parameters should exist")
                .iter()
                .all(|parameter| parameter["name"] != "filter_permalink")
        );

        let snapshot = json!({
            "paths": {
                "/posts": document["paths"]["/posts"].clone(),
                "/posts/{id}": document["paths"]["/posts/{id}"].clone()
            },
            "schemas": {
                "Post": document["components"]["schemas"]["Post"].clone(),
                "PostCreate": document["components"]["schemas"]["PostCreate"].clone()
            }
        });
        assert_json_snapshot(&snapshot_path("computed_fields_surface.json"), &snapshot);
    }

    #[test]
    fn renders_openapi_response_context_parameters() {
        let service = load_service_from_path(&fixture_path("api_contexts_api.eon"))
            .expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("API Contexts API", "1.0.0", "/api"),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");
        let list_parameters = document["paths"]["/posts"]["get"]["parameters"]
            .as_array()
            .expect("post list parameters should be an array");
        let get_parameters = document["paths"]["/posts/{id}"]["get"]["parameters"]
            .as_array()
            .expect("post item parameters should be an array");
        let post_parameters = document["paths"]["/posts"]["post"]["parameters"]
            .as_array()
            .expect("post create parameters should be an array");

        assert!(
            list_parameters
                .iter()
                .any(|parameter| parameter["name"] == "context")
        );
        assert_eq!(
            list_parameters
                .iter()
                .find(|parameter| parameter["name"] == "context")
                .expect("context parameter should exist")["schema"]["enum"],
            json!(["view", "edit"])
        );
        assert!(
            get_parameters
                .iter()
                .any(|parameter| parameter["name"] == "context")
        );
        assert_eq!(post_parameters[0]["name"], "context");
        assert_eq!(post_parameters[0]["schema"]["default"], json!("view"));

        let snapshot = json!({
            "paths": {
                "/posts": document["paths"]["/posts"].clone(),
                "/posts/{id}": document["paths"]["/posts/{id}"].clone()
            },
            "schemas": {
                "Post": document["components"]["schemas"]["Post"].clone(),
                "PostCreate": document["components"]["schemas"]["PostCreate"].clone(),
                "PostListResponse": document["components"]["schemas"]["PostListResponse"].clone()
            }
        });
        assert_json_snapshot(&snapshot_path("response_contexts_surface.json"), &snapshot);
    }

    #[test]
    fn renders_openapi_storage_upload_paths() {
        let service = load_service_from_path(&fixture_path("storage_upload_api.eon"))
            .expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("Storage Upload API", "1.0.0", "/api"),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");

        assert_eq!(
            document["paths"]["/uploads"]["post"]["requestBody"]["content"]["multipart/form-data"]
                ["schema"]["required"],
            json!(["file"])
        );
        assert_eq!(
            document["paths"]["/uploads"]["post"]["responses"]["201"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/StorageUploadResponse"
        );
        assert_eq!(
            document["paths"]["/uploads"]["post"]["security"][0]["bearerAuth"],
            json!([])
        );
        assert_eq!(
            document["components"]["schemas"]["StorageUploadResponse"]["properties"]["public_url"]
                ["nullable"],
            json!(true)
        );

        let snapshot = json!({
            "paths": {
                "/uploads": document["paths"]["/uploads"].clone()
            },
            "schemas": {
                "StorageUploadResponse": document["components"]["schemas"]["StorageUploadResponse"].clone()
            }
        });
        assert_json_snapshot(&snapshot_path("storage_upload_surface.json"), &snapshot);
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
        let score_filter = document["paths"]["/post"]["get"]["parameters"]
            .as_array()
            .expect("list parameters should be an array")
            .iter()
            .find(|parameter| parameter["name"] == "filter_score")
            .expect("score filter should exist");
        assert_eq!(score_filter["schema"]["minimum"], json!(1));
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
        assert_eq!(
            document["paths"]["/auth/login"]["post"]["security"][0]["anonKey"],
            json!([])
        );
        assert_eq!(
            document["paths"]["/auth/me"]["get"]["security"][0]["bearerAuth"],
            json!([])
        );
        assert_eq!(
            document["paths"]["/auth/me"]["get"]["security"][0]["anonKey"],
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

    #[test]
    fn renders_openapi_with_authorization_management_routes_when_enabled() {
        let service = load_service_from_path(&fixture_path("authz_management_api.eon"))
            .expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("Authorization Management API", "1.0.0", "/api"),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");

        assert!(
            document["paths"]["/authz/runtime/evaluate"]["post"].is_object(),
            "evaluate endpoint should be rendered"
        );
        assert!(
            document["paths"]["/authz/runtime/assignments"]["get"].is_object(),
            "assignments list endpoint should be rendered"
        );
        assert!(
            document["paths"]["/authz/runtime/assignments"]["post"].is_object(),
            "assignments create endpoint should be rendered"
        );
        assert!(
            document["paths"]["/authz/runtime/assignment-events"]["get"].is_object(),
            "assignment events endpoint should be rendered"
        );
        assert!(
            document["paths"]["/authz/runtime/assignments/{id}"]["delete"].is_object(),
            "assignment delete endpoint should be rendered"
        );
        assert!(
            document["paths"]["/authz/runtime/assignments/{id}/revoke"]["post"].is_object(),
            "assignment revoke endpoint should be rendered"
        );
        assert!(
            document["paths"]["/authz/runtime/assignments/{id}/renew"]["post"].is_object(),
            "assignment renew endpoint should be rendered"
        );
        assert_eq!(
            document["paths"]["/authz/runtime/evaluate"]["post"]["security"][0]["bearerAuth"],
            json!([])
        );
        assert_eq!(
            document["paths"]["/authz/runtime/assignments"]["get"]["parameters"][0]["name"],
            "user_id"
        );
        assert_eq!(
            document["paths"]["/authz/runtime/assignments/{id}"]["delete"]["parameters"][0]["schema"]
                ["type"],
            "string"
        );
        assert_eq!(
            document["paths"]["/authz/runtime/evaluate"]["post"]["requestBody"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/AuthorizationRuntimeAccessInput"
        );
        assert_eq!(
            document["paths"]["/authz/runtime/evaluate"]["post"]["responses"]["200"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/AuthorizationRuntimeAccessResult"
        );
        assert_eq!(
            document["components"]["schemas"]["AuthorizationAction"]["enum"],
            json!(["read", "create", "update", "delete"])
        );
        assert!(
            document["components"]["schemas"]["AuthorizationScopedAssignmentRecord"].is_object()
        );
        assert!(
            document["components"]["schemas"]["AuthorizationScopedAssignmentEventRecord"]
                .is_object()
        );
        assert!(
            document["tags"]
                .as_array()
                .expect("tags should be an array")
                .iter()
                .any(|tag| tag["name"] == "Authorization")
        );

        let snapshot = json!({
            "paths": {
                "/authz/runtime/evaluate": document["paths"]["/authz/runtime/evaluate"].clone(),
                "/authz/runtime/assignments": document["paths"]["/authz/runtime/assignments"].clone(),
                "/authz/runtime/assignment-events": document["paths"]["/authz/runtime/assignment-events"].clone(),
                "/authz/runtime/assignments/{id}": document["paths"]["/authz/runtime/assignments/{id}"].clone(),
                "/authz/runtime/assignments/{id}/revoke": document["paths"]["/authz/runtime/assignments/{id}/revoke"].clone(),
                "/authz/runtime/assignments/{id}/renew": document["paths"]["/authz/runtime/assignments/{id}/renew"].clone()
            },
            "schemas": {
                "AuthorizationAction": document["components"]["schemas"]["AuthorizationAction"].clone(),
                "AuthorizationRuntimeAccessInput": document["components"]["schemas"]["AuthorizationRuntimeAccessInput"].clone(),
                "AuthorizationRuntimeAccessResult": document["components"]["schemas"]["AuthorizationRuntimeAccessResult"].clone(),
                "AuthorizationScopedAssignmentRecord": document["components"]["schemas"]["AuthorizationScopedAssignmentRecord"].clone(),
                "AuthorizationScopedAssignmentEventRecord": document["components"]["schemas"]["AuthorizationScopedAssignmentEventRecord"].clone()
            }
        });
        assert_json_snapshot(&snapshot_path("authz_management_surface.json"), &snapshot);
    }

    #[test]
    fn renders_openapi_builtin_auth_claim_schemas_from_service_config() {
        let service = load_service_from_path(&fixture_path("auth_claims_api.eon"))
            .expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("Auth Claims API", "1.0.0", "/api").with_builtin_auth(true),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");

        assert_eq!(
            document["components"]["schemas"]["ManagedUserPatchInput"]["properties"]["claims"]["properties"]
                ["tenant_id"]["type"],
            "integer"
        );
        assert_eq!(
            document["components"]["schemas"]["ManagedUserPatchInput"]["properties"]["claims"]["properties"]
                ["tenant_id"]["format"],
            "int64"
        );
        assert_eq!(
            document["components"]["schemas"]["ManagedUserPatchInput"]["properties"]["claims"]["properties"]
                ["staff"]["type"],
            "boolean"
        );
        assert_eq!(
            document["components"]["schemas"]["ManagedUserPatchInput"]["properties"]["claims"]["properties"]
                ["plan"]["type"],
            "string"
        );
        assert_eq!(
            document["components"]["schemas"]["ManagedUserPatchInput"]["properties"]["claims"]["additionalProperties"],
            json!(false)
        );
        assert_eq!(
            document["components"]["schemas"]["AuthMeResponse"]["properties"]["workspace_id"]["type"],
            "integer"
        );
        assert_eq!(
            document["components"]["schemas"]["AuthAccountResponse"]["properties"]["staff"]["type"],
            "boolean"
        );
        assert_eq!(
            document["components"]["schemas"]["AuthAccountResponse"]["properties"]["plan"]["type"],
            "string"
        );
    }

    #[test]
    fn renders_openapi_builtin_auth_jwks_route_for_asymmetric_jwt() {
        let service = load_service_from_path(&fixture_path("asymmetric_jwt_api.eon"))
            .expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("Asymmetric JWT API", "1.0.0", "/api").with_builtin_auth(true),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");

        assert!(document["paths"]["/.well-known/jwks.json"]["get"].is_object());
        assert_eq!(
            document["paths"]["/.well-known/jwks.json"]["get"]["responses"]["200"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/JwksResponse"
        );
        assert_eq!(
            document["paths"]["/.well-known/jwks.json"]["get"]["security"],
            json!([])
        );
        assert!(document["components"]["schemas"]["JwksResponse"].is_object());

        let snapshot = json!({
            "paths": {
                "/.well-known/jwks.json": document["paths"]["/.well-known/jwks.json"].clone(),
                "/auth/login": document["paths"]["/auth/login"].clone(),
                "/auth/me": document["paths"]["/auth/me"].clone()
            },
            "schemas": {
                "JwksResponse": document["components"]["schemas"]["JwksResponse"].clone(),
                "AuthMeResponse": document["components"]["schemas"]["AuthMeResponse"].clone(),
                "AuthTokenResponse": document["components"]["schemas"]["AuthTokenResponse"].clone()
            }
        });
        assert_json_snapshot(&snapshot_path("asymmetric_jwt_surface.json"), &snapshot);
    }

    #[test]
    fn renders_openapi_builtin_auth_admin_routes_match_runtime_surface() {
        let service = load_service_from_path(&fixture_path("auth_claims_api.eon"))
            .expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("Auth Claims API", "1.0.0", "/api").with_builtin_auth(true),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");

        assert_eq!(
            document["paths"]["/auth/admin/users"]["get"]["parameters"][0]["schema"]["minimum"],
            json!(1)
        );
        assert_eq!(
            document["paths"]["/auth/admin/users"]["get"]["parameters"][0]["schema"]["maximum"],
            json!(100)
        );
        assert_eq!(
            document["paths"]["/auth/admin/users"]["post"]["responses"]["201"]["headers"]["Location"]
                ["schema"]["type"],
            "string"
        );
        assert!(document["paths"]["/auth/admin/users"]["post"]["responses"]["413"].is_object());
        assert!(document["paths"]["/auth/admin/users"]["post"]["responses"]["415"].is_object());
        assert!(
            document["paths"]["/auth/admin/users/{id}"]["patch"]["responses"]["500"].is_object()
        );
        assert!(
            document["paths"]["/auth/admin/users/{id}/verification"]["post"]["responses"]["500"]
                .is_object()
        );

        let snapshot = json!({
            "paths": {
                "/auth/admin/users": document["paths"]["/auth/admin/users"].clone(),
                "/auth/admin/users/{id}": document["paths"]["/auth/admin/users/{id}"].clone(),
                "/auth/admin/users/{id}/verification": document["paths"]["/auth/admin/users/{id}/verification"].clone()
            },
            "schemas": {
                "ManagedUserCreateInput": document["components"]["schemas"]["ManagedUserCreateInput"].clone(),
                "ManagedUserPatchInput": document["components"]["schemas"]["ManagedUserPatchInput"].clone(),
                "AuthAccountResponse": document["components"]["schemas"]["AuthAccountResponse"].clone(),
                "AuthAdminUserListResponse": document["components"]["schemas"]["AuthAdminUserListResponse"].clone()
            }
        });
        assert_json_snapshot(&snapshot_path("builtin_auth_admin_surface.json"), &snapshot);
    }

    #[test]
    fn renders_location_header_for_generic_create_responses() {
        let service =
            load_service_from_path(&fixture_path("mapped_api.eon")).expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("Mapped API", "1.0.0", "/api"),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");

        assert_eq!(
            document["paths"]["/post"]["post"]["responses"]["201"]["headers"]["Location"]["schema"]
                ["type"],
            "string"
        );
    }

    #[test]
    fn renders_openapi_builtin_auth_email_routes_match_runtime_surface() {
        let service = load_service_from_path(&fixture_path("auth_management_api.eon"))
            .expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("Auth Management API", "1.0.0", "/api")
                .with_builtin_auth(true),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");

        assert_eq!(
            document["paths"]["/auth/account/verification"]["post"]["responses"]["202"]["description"],
            "Verification email sent"
        );
        assert_eq!(
            document["paths"]["/auth/verify-email"]["post"]["responses"]["204"]["description"],
            "Email verified"
        );
        assert_eq!(
            document["paths"]["/auth/password-reset/request"]["post"]["responses"]["202"]["description"],
            "Password reset email sent"
        );

        let snapshot = json!({
            "paths": {
                "/auth/account/verification": document["paths"]["/auth/account/verification"].clone(),
                "/auth/verify-email": document["paths"]["/auth/verify-email"].clone(),
                "/auth/verification/resend": document["paths"]["/auth/verification/resend"].clone(),
                "/auth/password-reset": document["paths"]["/auth/password-reset"].clone(),
                "/auth/password-reset/request": document["paths"]["/auth/password-reset/request"].clone(),
                "/auth/password-reset/confirm": document["paths"]["/auth/password-reset/confirm"].clone()
            },
            "schemas": {
                "VerifyEmailInput": document["components"]["schemas"]["VerifyEmailInput"].clone(),
                "VerificationResendInput": document["components"]["schemas"]["VerificationResendInput"].clone(),
                "PasswordResetRequestInput": document["components"]["schemas"]["PasswordResetRequestInput"].clone(),
                "PasswordResetConfirmInput": document["components"]["schemas"]["PasswordResetConfirmInput"].clone()
            }
        });
        assert_json_snapshot(&snapshot_path("builtin_auth_email_surface.json"), &snapshot);
    }

    #[test]
    fn renders_openapi_builtin_auth_ui_routes_when_configured() {
        let service = load_service_from_path(&fixture_path("auth_management_api.eon"))
            .expect("fixture should parse");
        let json = render_service_openapi_json(
            &service,
            &OpenApiSpecOptions::new("Auth Management API", "1.0.0", "/api")
                .with_builtin_auth(true),
        )
        .expect("openapi should render");
        let document: Value = serde_json::from_str(&json).expect("json should parse");

        assert!(document["paths"]["/auth/portal"]["get"].is_object());
        assert!(document["paths"]["/auth/admin"]["get"].is_object());
        assert_eq!(
            document["paths"]["/auth/admin"]["get"]["security"][0]["bearerAuth"],
            json!([])
        );
        assert_eq!(
            document["paths"]["/auth/admin"]["get"]["responses"]["403"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/ApiErrorResponse"
        );
    }
}
