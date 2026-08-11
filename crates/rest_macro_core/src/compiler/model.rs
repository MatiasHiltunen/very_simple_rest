//! # Compiler model
//!
//! Shared AST + helpers for the `.eon` parser, codegen, OpenAPI emitter, and
//! migrations. The crate's public surface re-exports from this module, so
//! every name kept here remains visible at the same path callers used before
//! the split (`crate::compiler::model::*`).
//!
//! ## Layout
//!
//! | Module | Purpose |
//! |---|---|
//! | [`scalars`] | Generated-type aliases, `StructuredScalarKind`, `DbBackend`, `GeneratedValue`, role/access enums |
//! | [`policies`] | Row policy types (`PolicyFilterExpression`, `RowPolicies`, …) and traversal helpers |
//! | [`validation`] | `FieldValidation`, `LengthValidation`, `RangeValidation`, `ListConfig`, build/clients configs |
//! | [`specs`] | `FieldSpec`, `ResourceSpec`, `ServiceSpec`, action/audit specs, identifier sanitizers |
//! | [`helpers`] | Type inference (`infer_sql_type`, `is_optional_type`, …) and access helpers (`read_requires_auth`) |
//! | [`audit`] | Audit-sink validation (`validate_resource_audit`, `is_audit_sink_resource`) |
//! | [`validators`] | Service-/resource-/field-level validators (`validate_security_config`, `validate_row_policies`, …) |
//!
//! Layering rule: lower files in the table never depend on higher files.
//! `helpers` may depend on `scalars` and `specs`, but `specs` does not depend
//! on `helpers`. `validators` is the top of the layer and may depend on
//! everything below it.

mod audit;
mod helpers;
mod policies;
mod scalars;
mod specs;
mod validation;
mod validators;

#[cfg(test)]
mod tests;

// ── Public re-exports ────────────────────────────────────────────────────────
//
// These are the names callers used before the model.rs split. Order matches
// the historical declaration order in `model.rs` so `git blame` can still
// locate where each item was defined.

pub use scalars::{
    DbBackend, GENERATED_DATE_ALIAS, GENERATED_DATETIME_ALIAS, GENERATED_DECIMAL_ALIAS,
    GENERATED_JSON_ALIAS, GENERATED_JSON_ARRAY_ALIAS, GENERATED_JSON_OBJECT_ALIAS,
    GENERATED_TIME_ALIAS, GENERATED_UUID_ALIAS, GeneratedTemporalKind, GeneratedValue,
    ResourceAccess, ResourceReadAccess, RoleRequirements, StructuredScalarKind,
};

pub use policies::{
    PolicyAssignment, PolicyComparisonValue, PolicyExistsCondition, PolicyExistsFilter,
    PolicyFilter, PolicyFilterExpression, PolicyFilterOperator, PolicyLiteralValue,
    PolicyValueSource, RowPolicies, RowPolicyKind,
};

pub use validation::{
    BuildArtifactPathConfig, BuildArtifactsConfig, BuildCacheArtifactConfig,
    BuildCacheCleanupStrategy, BuildConfig, BuildLtoMode, ClientValueConfig, ClientsConfig,
    FieldTransform, FieldValidation, LengthMode, LengthValidation, ListConfig, NumericBound,
    RangeValidation, ReleaseBuildConfig, TsClientAutomationConfig, TsClientConfig, WriteModelStyle,
};

pub use specs::{
    ComputedFieldPart, ComputedFieldSpec, EnumSpec, FieldSpec, IndexSpec, ManyToManySpec,
    ReferentialAction, RelationSpec, ResourceActionAssignmentSpec, ResourceActionBehaviorSpec,
    ResourceActionInputFieldSpec, ResourceActionMethod, ResourceActionSpec, ResourceActionTarget,
    ResourceActionValueSpec, ResourceAuditActionSelection, ResourceAuditConfig, ResourceSpec,
    ResponseContextSpec, ServiceSpec, StaticCacheProfile, StaticMode, StaticMountSpec,
    default_resource_module_ident, infer_generated_value, sanitize_module_ident,
    sanitize_struct_ident, validate_sql_identifier,
};

pub use helpers::{
    apply_service_read_access_defaults, base_type, default_service_database_url,
    generated_temporal_kind_for_field, infer_sql_type, is_bool_type, is_date_type,
    is_datetime_type, is_decimal_type, is_enum_field, is_integer_sql_type, is_json_array_type,
    is_json_object_type, is_json_type, is_list_field, is_optional_type, is_structured_scalar_type,
    is_time_type, is_typed_object_field, is_uuid_type, list_item_type, object_fields,
    policy_field_claim_type, read_requires_auth, structured_scalar_kind, supports_contains_filters,
    supports_declared_index, supports_exact_filters, supports_field_sort,
    supports_field_transforms, supports_range_filters, supports_sort, temporal_scalar_kind,
};

pub use audit::{is_audit_sink_resource, validate_resource_audit};

pub use validators::{
    validate_authorization_contract, validate_build_config, validate_clients_config,
    validate_field_transforms, validate_field_validations, validate_list_config,
    validate_logging_config, validate_policy_claim_sources, validate_relations,
    validate_resource_access, validate_row_policies, validate_runtime_config,
    validate_security_config, validate_tls_config,
};
