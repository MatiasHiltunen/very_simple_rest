//! Compiler-free preparation of native create, update, and action values.

use std::{collections::HashMap, future::Future};

use serde_json::{Map, Value};

use crate::{
    authz::policy::PolicyValueSource,
    field::{FieldKind, RuntimeField},
    native_policy_sql::PolicyPrincipal,
    native_resource::{
        RuntimeActionAssignmentSource, RuntimeActionUpdateAssignment, RuntimeBoundValue,
        RuntimeResource,
    },
    native_validation::{
        JsonFieldError, bound_value_to_json, parse_json_value, validate_bound_value,
    },
};

/// A validated value to write to an internal database field.
#[derive(Clone, Debug, PartialEq)]
pub struct WriteAssignment {
    /// Internal database field name.
    pub field_name: String,
    /// Parsed and normalized value.
    pub value: RuntimeBoundValue,
}

/// Values resolved once for both insertion and create requirement evaluation.
#[derive(Debug)]
pub struct PreparedCreate {
    /// Assignments in descriptor field order, excluding generated fields.
    pub assignments: Vec<WriteAssignment>,
}

impl PreparedCreate {
    /// Effective values keyed by internal field name for requirement planning.
    pub fn effective_values(&self) -> HashMap<String, RuntimeBoundValue> {
        self.assignments
            .iter()
            .map(|assignment| (assignment.field_name.clone(), assignment.value.clone()))
            .collect()
    }
}

/// A scoped create decision requested only when a claim cannot supply the value.
pub struct HybridCreateRequest<'a> {
    /// Authenticated principal ID.
    pub user_id: i64,
    /// Internal resource name.
    pub resource_name: &'a str,
    /// Configured authorization scope name.
    pub scope: &'a str,
    /// Parsed scope value expressed as a scalar string.
    pub scope_value: &'a str,
}

/// Supplies runtime grants without coupling write preparation to a database or HTTP.
pub trait HybridCreateAuthorizer: Send + Sync {
    /// Evaluate the create grant for the supplied principal, resource, and scope.
    fn allows_create(
        &self,
        request: HybridCreateRequest<'_>,
    ) -> impl Future<Output = Result<bool, String>> + Send;
}

/// Classified input failures mapped to the transport's existing error contract.
#[derive(Debug)]
pub enum WriteInputError {
    /// Malformed or incomplete scalar input.
    BadRequest {
        /// Stable public error code.
        code: &'static str,
        /// Public error detail.
        message: String,
    },
    /// Field validation failure, including nested object paths.
    Validation(JsonFieldError),
    /// Missing claim or denied scoped grant.
    Forbidden {
        /// Stable public error code.
        code: &'static str,
        /// Public error detail.
        message: String,
    },
    /// Invalid descriptor or authorization provider failure.
    Internal(String),
}

fn invalid_json() -> WriteInputError {
    WriteInputError::BadRequest {
        code: "invalid_json",
        message: "Request body is not valid JSON".to_owned(),
    }
}

fn missing_create_field(field: &RuntimeField) -> WriteInputError {
    WriteInputError::Validation(JsonFieldError {
        field: field.api_name.clone(),
        message: format!("Missing required create field `{}`", field.api_name),
    })
}

fn parse_body_value(
    field: &RuntimeField,
    value: Option<&Value>,
    allow_missing: bool,
) -> Result<RuntimeBoundValue, WriteInputError> {
    match value {
        None if allow_missing => Ok(RuntimeBoundValue::Null),
        Some(Value::Null) if field.optional || allow_missing => Ok(RuntimeBoundValue::Null),
        None | Some(Value::Null) => Err(invalid_json()),
        Some(value) => parse_json_value(field, value).map_err(|error| {
            if field.object_fields.is_some() {
                WriteInputError::Validation(error)
            } else {
                invalid_json()
            }
        }),
    }
}

fn validate(field: &RuntimeField, value: &RuntimeBoundValue) -> Result<(), WriteInputError> {
    validate_bound_value(field, value).map_err(WriteInputError::Validation)
}

fn field<'a>(
    resource: &'a RuntimeResource,
    name: &str,
) -> Result<&'a RuntimeField, WriteInputError> {
    resource
        .field_index
        .get(name)
        .and_then(|index| resource.fields.get(*index))
        .ok_or_else(|| {
            WriteInputError::Internal(format!(
                "field `{name}` not found in `{}`",
                resource.table_name,
            ))
        })
}

fn should_insert_field(resource: &RuntimeResource, field: &RuntimeField) -> bool {
    !field.generated.skip_insert()
        && (resource
            .create_fields
            .iter()
            .any(|rule| rule.name == field.name)
            || resource.create_assignment_sources.contains_key(&field.name))
}

async fn create_field_value(
    resource: &RuntimeResource,
    field: &RuntimeField,
    payload: &Map<String, Value>,
    principal: &PolicyPrincipal<'_>,
    is_admin: bool,
    authorizer: &impl HybridCreateAuthorizer,
) -> Result<RuntimeBoundValue, WriteInputError> {
    if let Some(source) = resource.create_assignment_sources.get(&field.name) {
        let claim_name = match source {
            PolicyValueSource::UserId => return Ok(RuntimeBoundValue::Integer(principal.user_id)),
            PolicyValueSource::Claim(name) => name,
            PolicyValueSource::InputField(_) => {
                return Err(WriteInputError::Internal(
                    "create assignments do not support input-field sources".to_owned(),
                ));
            }
        };
        let claim_value = principal
            .claims
            .get(claim_name)
            .and_then(|value| match field.kind {
                FieldKind::Integer => value.as_i64().map(RuntimeBoundValue::Integer),
                FieldKind::Boolean => value.as_bool().map(RuntimeBoundValue::Bool),
                _ => value
                    .as_str()
                    .map(|value| RuntimeBoundValue::Text(value.to_owned())),
            });
        let rule = resource
            .create_fields
            .iter()
            .find(|rule| rule.name == field.name);
        let allow_admin_override = rule.is_some_and(|rule| rule.allow_admin_override);
        let allow_hybrid_runtime = rule.is_some_and(|rule| rule.allow_hybrid_runtime);
        if is_admin && allow_admin_override {
            if let Some(value) = payload.get(&field.api_name) {
                return parse_body_value(field, Some(value), true);
            }
            return claim_value.ok_or_else(|| missing_create_field(field));
        }
        if let Some(value) = claim_value {
            return Ok(value);
        }
        if allow_hybrid_runtime {
            let raw_scope = payload
                .get(&field.api_name)
                .ok_or_else(|| missing_create_field(field))?;
            let scope_value = parse_body_value(field, Some(raw_scope), true)?;
            let scope = resource
                .hybrid
                .as_ref()
                .map_or("", |hybrid| hybrid.scope.as_str());
            let value = match bound_value_to_json(&scope_value) {
                Value::String(value) => value,
                Value::Bool(value) => value.to_string(),
                Value::Number(value) => value.to_string(),
                _ => String::new(),
            };
            if authorizer
                .allows_create(HybridCreateRequest {
                    user_id: principal.user_id,
                    resource_name: &resource.resource_name,
                    scope,
                    scope_value: &value,
                })
                .await
                .map_err(WriteInputError::Internal)?
            {
                return Ok(scope_value);
            }
            return Err(WriteInputError::Forbidden {
                code: "forbidden",
                message: format!(
                    "Insufficient privileges for create scope field `{}`",
                    field.api_name
                ),
            });
        }
        return Err(WriteInputError::Forbidden {
            code: "missing_claim",
            message: format!(
                "Missing required claim for create field `{}`",
                field.api_name
            ),
        });
    }
    let rule = resource
        .create_fields
        .iter()
        .find(|rule| rule.name == field.name)
        .ok_or_else(|| {
            WriteInputError::Internal(format!("missing create field rule `{}`", field.name))
        })?;
    parse_body_value(field, payload.get(&field.api_name), rule.payload_optional)
}

/// Resolve and validate create inputs, checking hybrid grants only when needed.
///
/// Role checks remain the caller's responsibility. Reuse the returned effective
/// values for create requirements rather than resolving claims or grants again.
pub async fn prepare_create(
    resource: &RuntimeResource,
    payload: &Map<String, Value>,
    principal: &PolicyPrincipal<'_>,
    is_admin: bool,
    authorizer: &impl HybridCreateAuthorizer,
) -> Result<PreparedCreate, WriteInputError> {
    let mut assignments = Vec::new();
    for field in &resource.fields {
        if !should_insert_field(resource, field) {
            continue;
        }
        let value =
            create_field_value(resource, field, payload, principal, is_admin, authorizer).await?;
        validate(field, &value)?;
        assignments.push(WriteAssignment {
            field_name: field.name.clone(),
            value,
        });
    }
    Ok(PreparedCreate { assignments })
}

/// Parse a native update's complete configured set of writable fields.
///
/// Missing optional fields become NULL, preserving native PUT semantics.
pub fn prepare_update(
    resource: &RuntimeResource,
    payload: &Map<String, Value>,
) -> Result<Vec<WriteAssignment>, WriteInputError> {
    if resource.update_field_names.is_empty() {
        return Err(WriteInputError::BadRequest {
            code: "no_updatable_fields",
            message: "No updatable fields configured".to_owned(),
        });
    }
    resource
        .update_field_names
        .iter()
        .map(|name| {
            let field = field(resource, name)?;
            let value = parse_body_value(field, payload.get(&field.api_name), field.optional)?;
            validate(field, &value)?;
            Ok(WriteAssignment {
                field_name: field.name.clone(),
                value,
            })
        })
        .collect()
}

/// Prepare custom action assignments using declared input names in diagnostics.
///
/// Literal values are already validated when the descriptor is compiled.
pub fn prepare_action_update(
    resource: &RuntimeResource,
    assignments: &[RuntimeActionUpdateAssignment],
    payload: &Map<String, Value>,
) -> Result<Vec<WriteAssignment>, WriteInputError> {
    assignments
        .iter()
        .map(|assignment| {
            let field = field(resource, &assignment.field_name)?;
            let value = match &assignment.source {
                RuntimeActionAssignmentSource::Literal(value) => value.clone(),
                RuntimeActionAssignmentSource::InputField(name) => {
                    let mut input_field = field.clone();
                    input_field.api_name = name.clone();
                    let value = parse_body_value(&input_field, payload.get(name), field.optional)?;
                    validate(&input_field, &value)?;
                    value
                }
            };
            Ok(WriteAssignment {
                field_name: assignment.field_name.clone(),
                value,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::Mutex,
    };

    use serde_json::json;

    use super::*;
    use crate::{
        authz::{RoleRequirements, policy::RowPolicies},
        field::{FieldTransform, FieldValidation, GeneratedValue, LengthValidation},
        model::DbBackend,
        native_resource::{RuntimeCreateFieldRule, RuntimeHybridResourceConfig},
    };

    struct Grant {
        result: Result<bool, String>,
        requests: Mutex<Vec<(i64, String, String, String)>>,
    }

    impl Grant {
        fn new(result: Result<bool, String>) -> Self {
            Self {
                result,
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl HybridCreateAuthorizer for Grant {
        async fn allows_create(&self, request: HybridCreateRequest<'_>) -> Result<bool, String> {
            self.requests.lock().unwrap().push((
                request.user_id,
                request.resource_name.into(),
                request.scope.into(),
                request.scope_value.into(),
            ));
            self.result.clone()
        }
    }

    fn field(name: &str, kind: FieldKind) -> RuntimeField {
        RuntimeField {
            name: name.into(),
            api_name: name.into(),
            expose_in_api: true,
            enum_values: None,
            transforms: Vec::new(),
            kind,
            list_item_kind: None,
            object_fields: None,
            optional: false,
            generated: GeneratedValue::None,
            validation: FieldValidation::default(),
            supports_exact_filters: false,
            supports_sort: false,
            supports_range_filters: false,
        }
    }

    fn resource(fields: Vec<RuntimeField>) -> RuntimeResource {
        let field_index = fields
            .iter()
            .enumerate()
            .map(|(index, field)| (field.name.clone(), index))
            .collect();
        let create_fields = fields
            .iter()
            .map(|field| RuntimeCreateFieldRule {
                name: field.name.clone(),
                allow_admin_override: false,
                allow_hybrid_runtime: false,
                payload_optional: field.optional,
            })
            .collect();
        RuntimeResource {
            resource_name: "Document".into(),
            table_name: "document".into(),
            api_name: "documents".into(),
            default_response_context: None,
            id_field: "id".into(),
            id_api_name: "id".into(),
            db: DbBackend::Sqlite,
            roles: RoleRequirements::default(),
            policies: RowPolicies::default(),
            default_limit: None,
            max_limit: None,
            filterable_in: BTreeSet::new(),
            count_endpoint: false,
            create_assignment_sources: HashMap::new(),
            fields,
            field_index,
            api_field_index: HashMap::new(),
            response_contexts: HashMap::new(),
            computed_fields: Vec::new(),
            create_fields,
            update_field_names: Vec::new(),
            actions: Vec::new(),
            audit: None,
            is_audit_sink: false,
            read_requires_auth: false,
            hybrid: None,
            nested_relations: Vec::new(),
            many_to_many_routes: Vec::new(),
        }
    }

    fn scoped_resource() -> RuntimeResource {
        let mut resource = resource(vec![field("tenant_id", FieldKind::Integer)]);
        resource.fields[0].api_name = "tenant".into();
        resource.create_assignment_sources.insert(
            "tenant_id".into(),
            PolicyValueSource::Claim("tenant".into()),
        );
        resource.create_fields[0].allow_hybrid_runtime = true;
        resource.hybrid = Some(RuntimeHybridResourceConfig {
            scope: "Tenant".into(),
            scope_field: "tenant_id".into(),
            item_read: false,
            collection_read: false,
            nested_read: false,
            create_payload: true,
            update: false,
            delete: false,
        });
        resource
    }

    fn payload(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    #[tokio::test]
    async fn create_prefers_typed_claim_and_ignores_payload_override() {
        let resource = scoped_resource();
        let grant = Grant::new(Err("must not call grants".into()));
        let claims = BTreeMap::from([("tenant".into(), json!(7))]);
        let prepared = prepare_create(
            &resource,
            &payload(json!({"tenant": 99})),
            &PolicyPrincipal {
                user_id: 11,
                claims: &claims,
            },
            false,
            &grant,
        )
        .await
        .unwrap();
        assert_eq!(
            prepared.effective_values()["tenant_id"],
            RuntimeBoundValue::Integer(7)
        );
        assert!(grant.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_hybrid_fallback_checks_identity_resource_and_parsed_scope_once() {
        let resource = scoped_resource();
        let grant = Grant::new(Ok(true));
        // A string claim cannot supply an integer field.
        let claims = BTreeMap::from([("tenant".into(), json!("7"))]);
        let prepared = prepare_create(
            &resource,
            &payload(json!({"tenant": 42})),
            &PolicyPrincipal {
                user_id: 11,
                claims: &claims,
            },
            false,
            &grant,
        )
        .await
        .unwrap();
        assert_eq!(
            prepared.assignments,
            vec![WriteAssignment {
                field_name: "tenant_id".into(),
                value: RuntimeBoundValue::Integer(42),
            }]
        );
        assert_eq!(
            prepared.effective_values()["tenant_id"],
            prepared.assignments[0].value
        );
        assert_eq!(
            *grant.requests.lock().unwrap(),
            vec![(11, "Document".into(), "Tenant".into(), "42".into())]
        );
    }

    #[tokio::test]
    async fn create_denies_without_a_grant_and_preserves_provider_failures() {
        let resource = scoped_resource();
        let claims = BTreeMap::new();
        let principal = PolicyPrincipal {
            user_id: 11,
            claims: &claims,
        };
        let input = payload(json!({"tenant": 42}));
        let denied = prepare_create(&resource, &input, &principal, false, &Grant::new(Ok(false)))
            .await
            .unwrap_err();
        assert!(matches!(
            denied,
            WriteInputError::Forbidden {
                code: "forbidden",
                ..
            }
        ));
        let failed = prepare_create(
            &resource,
            &input,
            &principal,
            false,
            &Grant::new(Err("database unavailable".into())),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(failed, WriteInputError::Internal(message) if message == "database unavailable")
        );
        let missing = prepare_create(
            &resource,
            &Map::new(),
            &principal,
            false,
            &Grant::new(Ok(true)),
        )
        .await
        .unwrap_err();
        assert!(matches!(missing, WriteInputError::Validation(error) if error.field == "tenant"));
    }

    #[tokio::test]
    async fn admin_override_requires_the_configured_permission() {
        let mut resource = scoped_resource();
        resource.create_fields[0].allow_hybrid_runtime = false;
        let claims = BTreeMap::new();
        let principal = PolicyPrincipal {
            user_id: 11,
            claims: &claims,
        };
        let input = payload(json!({"tenant": 42}));
        let grant = Grant::new(Err("must not call grants".into()));
        let error = prepare_create(&resource, &input, &principal, true, &grant)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            WriteInputError::Forbidden {
                code: "missing_claim",
                ..
            }
        ));
        resource.create_fields[0].allow_admin_override = true;
        let prepared = prepare_create(&resource, &input, &principal, true, &grant)
            .await
            .unwrap();
        assert_eq!(
            prepared.effective_values()["tenant_id"],
            RuntimeBoundValue::Integer(42)
        );
        let missing = prepare_create(&resource, &Map::new(), &principal, true, &grant)
            .await
            .unwrap_err();
        assert!(matches!(missing, WriteInputError::Validation(_)));
        assert!(grant.requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_skips_generated_fields_and_validates_effective_principal_values() {
        let mut id = field("id", FieldKind::Integer);
        id.generated = GeneratedValue::AutoIncrement;
        let mut name = field("name", FieldKind::Text);
        name.validation.length = Some(LengthValidation {
            min: Some(3),
            ..LengthValidation::default()
        });
        let mut resource = resource(vec![id, name]);
        resource
            .create_assignment_sources
            .insert("name".into(), PolicyValueSource::Claim("name".into()));
        let grant = Grant::new(Ok(false));
        let claims = BTreeMap::from([("name".into(), json!("ab"))]);
        let error = prepare_create(
            &resource,
            &Map::new(),
            &PolicyPrincipal {
                user_id: 11,
                claims: &claims,
            },
            false,
            &grant,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, WriteInputError::Validation(error) if error.field == "name"));
        let claims = BTreeMap::from([("name".into(), json!("valid"))]);
        let prepared = prepare_create(
            &resource,
            &Map::new(),
            &PolicyPrincipal {
                user_id: 11,
                claims: &claims,
            },
            false,
            &grant,
        )
        .await
        .unwrap();
        assert_eq!(prepared.assignments.len(), 1);
        assert_eq!(prepared.assignments[0].field_name, "name");
    }

    #[test]
    fn update_preserves_aliases_transforms_and_optional_nulls() {
        let mut title = field("title", FieldKind::Text);
        title.api_name = "heading".into();
        title.transforms = vec![FieldTransform::Trim, FieldTransform::Lowercase];
        let mut description = field("description", FieldKind::Text);
        description.optional = true;
        let mut resource = resource(vec![title, description]);
        resource.update_field_names = vec!["title".into(), "description".into()];
        let assignments =
            prepare_update(&resource, &payload(json!({"heading": "  HELLO  "}))).unwrap();
        assert_eq!(
            assignments,
            vec![
                WriteAssignment {
                    field_name: "title".into(),
                    value: RuntimeBoundValue::Text("hello".into())
                },
                WriteAssignment {
                    field_name: "description".into(),
                    value: RuntimeBoundValue::Null
                },
            ]
        );
        assert!(matches!(
            prepare_update(&resource, &Map::new()),
            Err(WriteInputError::BadRequest {
                code: "invalid_json",
                ..
            })
        ));
    }

    #[test]
    fn action_input_validation_uses_the_declared_input_path() {
        let mut title = field("title", FieldKind::Text);
        title.validation.length = Some(LengthValidation {
            min: Some(3),
            ..LengthValidation::default()
        });
        let resource = resource(vec![title]);
        let assignments = vec![RuntimeActionUpdateAssignment {
            field_name: "title".into(),
            source: RuntimeActionAssignmentSource::InputField("new_title".into()),
        }];
        let invalid = prepare_action_update(
            &resource,
            &assignments,
            &payload(json!({"new_title": "no"})),
        )
        .unwrap_err();
        assert!(
            matches!(invalid, WriteInputError::Validation(error) if error.field == "new_title")
        );
        let valid = prepare_action_update(
            &resource,
            &assignments,
            &payload(json!({"new_title": "Hello"})),
        )
        .unwrap();
        assert_eq!(valid[0].field_name, "title");
        assert_eq!(valid[0].value, RuntimeBoundValue::Text("Hello".into()));
    }
}
