//! Service-, resource-, and field-level validators.
//!
//! These functions enforce the declarative invariants of the `.eon` contract
//! after parsing. They walk `ServiceSpec` / `ResourceSpec` / `FieldSpec` and
//! return `syn::Error`s with source spans, so the macro and CLI surface emit
//! readable diagnostics.

use std::{collections::HashSet, net::IpAddr, str::FromStr};

use actix_web::http::{Method, Uri, header::HeaderName};
use proc_macro2::Span;
use syn::Type;
use url::Url;

use crate::auth::{AuthClaimType, AuthEmailProvider, AuthJwtAlgorithm, SessionCookieSameSite};
use crate::authorization::AuthorizationContract;
use crate::logging::LoggingConfig;
use crate::runtime::RuntimeConfig;
use crate::secret::SecretRef;
use crate::security::SecurityConfig;
use crate::tls::TlsConfig;

use super::helpers::{
    base_type, infer_sql_type, is_bool_type, is_integer_sql_type, is_optional_type,
    policy_field_claim_type, read_requires_auth, supports_exact_filters, supports_field_transform,
    type_leaf_name,
};
use super::policies::{
    PolicyAssignment, PolicyComparisonValue, PolicyExistsCondition, PolicyExistsFilter,
    PolicyFilter, PolicyFilterExpression, PolicyFilterOperator, PolicyLiteralValue,
    PolicyValueSource, RowPolicies, read_filter_uses_principal_values,
};
use super::scalars::{DbBackend, GeneratedValue, ResourceReadAccess};
use super::specs::{
    FieldSpec, ReferentialAction, ResourceSpec, is_valid_sql_identifier, validate_sql_identifier,
};
use super::validation::{
    BuildConfig, ClientsConfig, FieldValidation, LengthMode, ListConfig, NumericBound,
};

pub fn validate_resource_access(resource: &ResourceSpec, span: Span) -> syn::Result<()> {
    if resource.access.read != ResourceReadAccess::Public {
        return Ok(());
    }

    if resource.roles.read.is_some() {
        return Err(syn::Error::new(
            span,
            format!(
                "resource `{}` cannot combine `access.read = public` with `roles.read`",
                resource.struct_ident,
            ),
        ));
    }

    if read_filter_uses_principal_values(resource.policies.read.as_ref()) {
        return Err(syn::Error::new(
            span,
            format!(
                "resource `{}` cannot use `access.read = public` with read row policies that depend on `user.*` or `claim.*` values",
                resource.struct_ident,
            ),
        ));
    }

    Ok(())
}

pub fn validate_row_policies(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    policies: &RowPolicies,
    span: Span,
) -> syn::Result<()> {
    validate_policy_filters(
        resource,
        resources,
        "read",
        policies.read.as_ref(),
        false,
        span,
    )?;
    validate_policy_filters(
        resource,
        resources,
        "create.require",
        policies.create_require.as_ref(),
        true,
        span,
    )?;
    validate_policy_assignments(&resource.fields, "create", &policies.create, span)?;
    validate_policy_filters(
        resource,
        resources,
        "update",
        policies.update.as_ref(),
        false,
        span,
    )?;
    validate_policy_filters(
        resource,
        resources,
        "delete",
        policies.delete.as_ref(),
        false,
        span,
    )
}

pub fn validate_policy_claim_sources(
    resources: &[ResourceSpec],
    security: &SecurityConfig,
    span: Span,
) -> syn::Result<()> {
    if security.auth.claims.is_empty() {
        return Ok(());
    }

    for resource in resources {
        validate_policy_claim_sources_in_expression(
            resource,
            resources,
            "read",
            resource.policies.read.as_ref(),
            security,
            span,
        )?;
        validate_policy_claim_sources_in_expression(
            resource,
            resources,
            "create.require",
            resource.policies.create_require.as_ref(),
            security,
            span,
        )?;
        validate_policy_claim_sources_in_expression(
            resource,
            resources,
            "update",
            resource.policies.update.as_ref(),
            security,
            span,
        )?;
        validate_policy_claim_sources_in_expression(
            resource,
            resources,
            "delete",
            resource.policies.delete.as_ref(),
            security,
            span,
        )?;
        for (scope, assignment) in resource.policies.iter_assignments() {
            validate_policy_claim_source(
                resource,
                scope,
                &assignment.field,
                &assignment.source,
                security,
                span,
            )?;
        }
    }

    Ok(())
}

fn validate_policy_claim_sources_in_expression(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    scope: &str,
    expression: Option<&PolicyFilterExpression>,
    security: &SecurityConfig,
    span: Span,
) -> syn::Result<()> {
    let Some(expression) = expression else {
        return Ok(());
    };
    match expression {
        PolicyFilterExpression::Match(filter) => {
            validate_policy_filter_claim_source(resource, scope, filter, security, span)
        }
        PolicyFilterExpression::All(expressions) | PolicyFilterExpression::Any(expressions) => {
            for expression in expressions {
                validate_policy_claim_sources_in_expression(
                    resource,
                    resources,
                    scope,
                    Some(expression),
                    security,
                    span,
                )?;
            }
            Ok(())
        }
        PolicyFilterExpression::Not(expression) => validate_policy_claim_sources_in_expression(
            resource,
            resources,
            scope,
            Some(expression),
            security,
            span,
        ),
        PolicyFilterExpression::Exists(filter) => {
            let target_resource = resources.iter().find(|candidate| {
                candidate.struct_ident == filter.resource.as_str()
                    || candidate.table_name == filter.resource
            });
            let Some(target_resource) = target_resource else {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "row policy for `{scope}` references unknown exists resource `{}`",
                        filter.resource
                    ),
                ));
            };
            validate_exists_policy_claim_sources(
                target_resource,
                scope,
                &filter.condition,
                security,
                span,
            )
        }
    }
}

pub fn validate_relations(fields: &[FieldSpec], span: Span) -> syn::Result<()> {
    for field in fields {
        let Some(relation) = &field.relation else {
            continue;
        };

        if relation.on_delete == Some(ReferentialAction::SetNull) && !is_optional_type(&field.ty) {
            return Err(syn::Error::new(
                span,
                format!(
                    "relation field `{}` uses `on_delete = SetNull` but is not nullable",
                    field.name()
                ),
            ));
        }
    }

    Ok(())
}

pub fn validate_field_validations(fields: &[FieldSpec], span: Span) -> syn::Result<()> {
    for field in fields {
        if let Some(nested_fields) = field.object_fields.as_deref() {
            validate_field_validations(nested_fields, span)?;
        }

        let validation = &field.validation;
        if validation.is_empty() {
            continue;
        }

        validate_field_validation(field, validation, span, field.name().as_str())?;
    }

    Ok(())
}

fn validate_field_validation(
    field: &FieldSpec,
    validation: &FieldValidation,
    span: Span,
    label: &str,
) -> syn::Result<()> {
    let optional = is_optional_type(&field.ty);
    let is_list = field.list_item_ty.is_some();
    let is_object = field.object_fields.is_some();
    let is_bool = !is_list && is_bool_type(&field.ty);
    let is_string =
        !is_list && !is_object && matches!(type_leaf_name(&field.ty).as_deref(), Some("String"));
    let is_integer = !is_list && !is_bool && is_integer_sql_type(field.sql_type.as_str());
    let is_float = !is_list && !is_bool && field.sql_type == "REAL";

    if field.enum_name.is_some() {
        return Err(syn::Error::new(
            span,
            format!(
                "enum field `{}` does not support validation constraints",
                field.name()
            ),
        ));
    }

    if validation.required && !optional {
        return Err(syn::Error::new(
            span,
            format!("field `{label}` only supports `required` on optional fields"),
        ));
    }

    if validation.has_string_rules() && !is_string {
        return Err(syn::Error::new(
            span,
            format!("field `{label}` only supports string garde rules on string fields"),
        ));
    }

    if validation.dive && !is_object {
        return Err(syn::Error::new(
            span,
            format!("field `{label}` only supports `dive` on object fields"),
        ));
    }

    if let Some(length) = &validation.length {
        if !is_string && !is_list {
            return Err(syn::Error::new(
                span,
                format!("field `{label}` only supports `length` on string or list fields"),
            ));
        }

        if length.equal.is_some() && (length.min.is_some() || length.max.is_some()) {
            return Err(syn::Error::new(
                span,
                format!(
                    "field `{label}` cannot combine `length.equal` with `length.min` or `length.max`"
                ),
            ));
        }

        if length.equal.is_none() && length.min.is_none() && length.max.is_none() {
            return Err(syn::Error::new(
                span,
                format!(
                    "field `{label}` must set at least one of `length.min`, `length.max`, or `length.equal`"
                ),
            ));
        }

        if let (Some(min), Some(max)) = (length.min, length.max)
            && min > max
        {
            return Err(syn::Error::new(
                span,
                format!("field `{label}` has `length.min` greater than `length.max`"),
            ));
        }

        if is_list
            && matches!(
                length.mode,
                Some(
                    LengthMode::Bytes
                        | LengthMode::Chars
                        | LengthMode::Graphemes
                        | LengthMode::Utf16
                )
            )
        {
            return Err(syn::Error::new(
                span,
                format!("field `{label}` only supports `length.mode = Simple` on list fields"),
            ));
        }
    }

    if let Some(range) = &validation.range {
        if !is_integer && !is_float {
            return Err(syn::Error::new(
                span,
                format!(
                    "field `{label}` only supports `range` on integer or floating-point fields"
                ),
            ));
        }

        if range.equal.is_some() && (range.min.is_some() || range.max.is_some()) {
            return Err(syn::Error::new(
                span,
                format!(
                    "field `{label}` cannot combine `range.equal` with `range.min` or `range.max`"
                ),
            ));
        }

        if range.equal.is_none() && range.min.is_none() && range.max.is_none() {
            return Err(syn::Error::new(
                span,
                format!(
                    "field `{label}` must set at least one of `range.min`, `range.max`, or `range.equal`"
                ),
            ));
        }

        if is_integer
            && !matches!(
                (&range.min, &range.max, &range.equal),
                (
                    None | Some(NumericBound::Integer(_)),
                    None | Some(NumericBound::Integer(_)),
                    None | Some(NumericBound::Integer(_))
                )
            )
        {
            return Err(syn::Error::new(
                span,
                format!("integer field `{label}` requires integer `range` bounds"),
            ));
        }

        if let (Some(minimum), Some(maximum)) = (&range.min, &range.max)
            && minimum.as_f64() > maximum.as_f64()
        {
            return Err(syn::Error::new(
                span,
                format!("field `{label}` has `range.min` greater than `range.max`"),
            ));
        }
    }

    if let Some(inner) = validation.inner.as_deref() {
        if optional {
            let inner_ty = base_type(&field.ty);
            let inner_label = format!("{label} inner");
            validate_nested_inner_validation(
                inner,
                &inner_ty,
                field.list_item_ty.as_ref(),
                field.object_fields.as_deref(),
                field.sql_type.as_str(),
                span,
                inner_label.as_str(),
            )?;
        } else if let Some(item_ty) = field.list_item_ty.as_ref() {
            let inner_sql_type = infer_sql_type(item_ty, DbBackend::Sqlite);
            let inner_label = format!("{label} inner");
            validate_nested_inner_validation(
                inner,
                item_ty,
                None,
                None,
                inner_sql_type.as_str(),
                span,
                inner_label.as_str(),
            )?;
        } else {
            return Err(syn::Error::new(
                span,
                format!("field `{label}` only supports `inner` on optional or list fields"),
            ));
        }
    }

    Ok(())
}

fn validate_nested_inner_validation(
    validation: &FieldValidation,
    ty: &Type,
    list_item_ty: Option<&Type>,
    object_fields: Option<&[FieldSpec]>,
    sql_type: &str,
    span: Span,
    label: &str,
) -> syn::Result<()> {
    let synthetic_field = FieldSpec {
        ident: syn::parse_str("inner_value").expect("synthetic field name should parse"),
        api_name: "inner_value".to_owned(),
        expose_in_api: true,
        unique: false,
        enum_name: None,
        enum_values: None,
        transforms: Vec::new(),
        ty: ty.clone(),
        list_item_ty: list_item_ty.cloned(),
        object_fields: object_fields.map(|fields| fields.to_vec()),
        sql_type: sql_type.to_owned(),
        is_id: false,
        generated: GeneratedValue::None,
        validation: validation.clone(),
        relation: None,
    };
    validate_field_validation(&synthetic_field, validation, span, label)
}

pub fn validate_field_transforms(fields: &[FieldSpec], span: Span) -> syn::Result<()> {
    for field in fields {
        if let Some(nested_fields) = field.object_fields.as_deref() {
            validate_field_transforms(nested_fields, span)?;
        }

        if field.transforms.is_empty() {
            continue;
        }

        if field.generated != GeneratedValue::None {
            return Err(syn::Error::new(
                span,
                format!(
                    "generated field `{}` does not support write-time transforms",
                    field.name()
                ),
            ));
        }

        let mut seen = std::collections::HashSet::new();
        for transform in &field.transforms {
            if !supports_field_transform(field, *transform) {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "field `{}` does not support write-time transform `{:?}`",
                        field.name(),
                        transform
                    ),
                ));
            }
            if !seen.insert(*transform) {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "field `{}` declares write-time transform `{:?}` more than once",
                        field.name(),
                        transform
                    ),
                ));
            }
        }
    }

    Ok(())
}

pub fn validate_list_config(
    resource: &ResourceSpec,
    list: &ListConfig,
    span: Span,
) -> syn::Result<()> {
    if matches!(list.default_limit, Some(0)) {
        return Err(syn::Error::new(
            span,
            "`default_limit` must be greater than 0",
        ));
    }

    if matches!(list.max_limit, Some(0)) {
        return Err(syn::Error::new(span, "`max_limit` must be greater than 0"));
    }

    if let (Some(default_limit), Some(max_limit)) = (list.default_limit, list.max_limit)
        && default_limit > max_limit
    {
        return Err(syn::Error::new(
            span,
            "`default_limit` cannot be greater than `max_limit`",
        ));
    }

    let mut seen_filterable_in = HashSet::new();
    for field_name in &list.filterable_in {
        if field_name.trim().is_empty() {
            return Err(syn::Error::new(
                span,
                "`filterable_in` cannot contain empty field names",
            ));
        }
        if !seen_filterable_in.insert(field_name.as_str()) {
            return Err(syn::Error::new(
                span,
                format!("duplicate `filterable_in` field `{field_name}`"),
            ));
        }

        let Some(field) = resource.find_field(field_name) else {
            return Err(syn::Error::new(
                span,
                format!(
                    "`filterable_in` references missing field `{field_name}` on resource `{}`",
                    resource.struct_ident
                ),
            ));
        };
        if !field.expose_in_api() {
            return Err(syn::Error::new(
                span,
                format!(
                    "`filterable_in` field `{field_name}` on resource `{}` must be exposed in the API",
                    resource.struct_ident
                ),
            ));
        }
        if !supports_exact_filters(field) {
            return Err(syn::Error::new(
                span,
                format!(
                    "`filterable_in` field `{field_name}` on resource `{}` must support exact filters",
                    resource.struct_ident
                ),
            ));
        }
    }

    Ok(())
}

pub fn validate_authorization_contract(
    contract: &AuthorizationContract,
    resources: &[ResourceSpec],
    span: Span,
) -> syn::Result<()> {
    validate_authorization_management_api(&contract.management_api, span)?;

    let mut scope_names = HashSet::new();
    for scope in &contract.scopes {
        validate_authorization_identifier(&scope.name, span, "authorization scope name")?;
        if !scope_names.insert(scope.name.as_str()) {
            return Err(syn::Error::new(
                span,
                format!("duplicate authorization scope `{}`", scope.name),
            ));
        }
        if matches!(scope.description.as_deref(), Some(description) if description.trim().is_empty())
        {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.scopes.{}` description cannot be empty",
                    scope.name
                ),
            ));
        }
    }

    for scope in &contract.scopes {
        if let Some(parent) = &scope.parent
            && !scope_names.contains(parent.as_str())
        {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.scopes.{}` references unknown parent scope `{parent}`",
                    scope.name
                ),
            ));
        }
    }
    for scope in &contract.scopes {
        let mut seen = HashSet::new();
        let mut current = scope.parent.as_deref();
        while let Some(parent) = current {
            if !seen.insert(parent) {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "`authorization.scopes.{}` contains a parent cycle involving `{parent}`",
                        scope.name
                    ),
                ));
            }
            current = contract
                .scopes
                .iter()
                .find(|candidate| candidate.name == parent)
                .and_then(|candidate| candidate.parent.as_deref());
        }
    }

    let resource_names = resources
        .iter()
        .map(|resource| resource.struct_ident.to_string())
        .collect::<HashSet<_>>();

    let mut permission_names = HashSet::new();
    for permission in &contract.permissions {
        validate_authorization_identifier(&permission.name, span, "authorization permission name")?;
        if !permission_names.insert(permission.name.as_str()) {
            return Err(syn::Error::new(
                span,
                format!("duplicate authorization permission `{}`", permission.name),
            ));
        }
        if matches!(permission.description.as_deref(), Some(description) if description.trim().is_empty())
        {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.permissions.{}` description cannot be empty",
                    permission.name
                ),
            ));
        }
        if permission.actions.is_empty() {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.permissions.{}` must declare at least one action",
                    permission.name
                ),
            ));
        }
        if permission.resources.is_empty() {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.permissions.{}` must declare at least one resource",
                    permission.name
                ),
            ));
        }
        for resource_name in &permission.resources {
            if !resource_names.contains(resource_name) {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "`authorization.permissions.{}` references unknown resource `{resource_name}`",
                        permission.name
                    ),
                ));
            }
        }
        for scope_name in &permission.scopes {
            if !scope_names.contains(scope_name.as_str()) {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "`authorization.permissions.{}` references unknown scope `{scope_name}`",
                        permission.name
                    ),
                ));
            }
        }
    }

    let permission_names = permission_names;
    let mut template_names = HashSet::new();
    for template in &contract.templates {
        validate_authorization_identifier(&template.name, span, "authorization template name")?;
        if !template_names.insert(template.name.as_str()) {
            return Err(syn::Error::new(
                span,
                format!("duplicate authorization template `{}`", template.name),
            ));
        }
        if matches!(template.description.as_deref(), Some(description) if description.trim().is_empty())
        {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.templates.{}` description cannot be empty",
                    template.name
                ),
            ));
        }
        if template.permissions.is_empty() {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.templates.{}` must declare at least one permission",
                    template.name
                ),
            ));
        }
        for permission_name in &template.permissions {
            if !permission_names.contains(permission_name.as_str()) {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "`authorization.templates.{}` references unknown permission `{permission_name}`",
                        template.name
                    ),
                ));
            }
        }
        for scope_name in &template.scopes {
            if !scope_names.contains(scope_name.as_str()) {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "`authorization.templates.{}` references unknown scope `{scope_name}`",
                        template.name
                    ),
                ));
            }
        }
    }

    validate_authorization_hybrid_enforcement(contract, resources, &scope_names, span)?;

    Ok(())
}

fn validate_authorization_hybrid_enforcement(
    contract: &AuthorizationContract,
    resources: &[ResourceSpec],
    scope_names: &HashSet<&str>,
    span: Span,
) -> syn::Result<()> {
    let mut seen_resources = HashSet::new();
    for config in &contract.hybrid_enforcement.resources {
        if !seen_resources.insert(config.resource.as_str()) {
            return Err(syn::Error::new(
                span,
                format!(
                    "duplicate authorization hybrid enforcement resource `{}`",
                    config.resource
                ),
            ));
        }

        let resource = resources
            .iter()
            .find(|resource| resource.struct_ident == config.resource.as_str())
            .ok_or_else(|| {
                syn::Error::new(
                    span,
                    format!(
                        "`authorization.hybrid_enforcement.resources.{}` references unknown resource `{}`",
                        config.resource, config.resource
                    ),
                )
            })?;

        if !scope_names.contains(config.scope.as_str()) {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.hybrid_enforcement.resources.{}` references unknown scope `{}`",
                    config.resource, config.scope
                ),
            ));
        }

        let field = resource.find_field(&config.scope_field).ok_or_else(|| {
            syn::Error::new(
                span,
                format!(
                    "`authorization.hybrid_enforcement.resources.{}.scope_field` references missing field `{}`",
                    config.resource, config.scope_field
                ),
            )
        })?;

        if policy_field_claim_type(&field.ty).is_none() {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.hybrid_enforcement.resources.{}.scope_field` must use type `i64`, `String`, `bool`, or an `Option<...>` of one of those types",
                    config.resource
                ),
            ));
        }

        if config.scope_sources.collection_filter
            && !config.supports_action(crate::authorization::AuthorizationAction::Read)
        {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.hybrid_enforcement.resources.{}` `scope_sources.collection_filter` requires `Read`",
                    config.resource
                ),
            ));
        }
        if config.scope_sources.nested_parent
            && !config.supports_action(crate::authorization::AuthorizationAction::Read)
        {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.hybrid_enforcement.resources.{}` `scope_sources.nested_parent` requires `Read`",
                    config.resource
                ),
            ));
        }
        if config.scope_sources.create_payload
            && !config.supports_action(crate::authorization::AuthorizationAction::Create)
        {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.hybrid_enforcement.resources.{}` `scope_sources.create_payload` requires `Create`",
                    config.resource
                ),
            ));
        }
        if config.scope_sources.item
            && !config.supports_action(crate::authorization::AuthorizationAction::Read)
            && !config.supports_action(crate::authorization::AuthorizationAction::Update)
            && !config.supports_action(crate::authorization::AuthorizationAction::Delete)
        {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.hybrid_enforcement.resources.{}` `scope_sources.item` requires `Read`, `Update`, or `Delete`",
                    config.resource
                ),
            ));
        }

        if config.actions.is_empty() {
            return Err(syn::Error::new(
                span,
                format!(
                    "`authorization.hybrid_enforcement.resources.{}` must declare at least one action",
                    config.resource
                ),
            ));
        }

        let mut seen_actions = HashSet::new();
        for action in &config.actions {
            if !seen_actions.insert(*action) {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "`authorization.hybrid_enforcement.resources.{}` contains duplicate action `{:?}`",
                        config.resource, action
                    ),
                ));
            }

            match action {
                crate::authorization::AuthorizationAction::Read => {
                    if !read_requires_auth(resource) {
                        return Err(syn::Error::new(
                            span,
                            format!(
                                "`authorization.hybrid_enforcement.resources.{}` cannot enable `Read` for a public resource; add read auth first",
                                config.resource
                            ),
                        ));
                    }
                    if !resource.policies.has_read_filters() {
                        return Err(syn::Error::new(
                            span,
                            format!(
                                "`authorization.hybrid_enforcement.resources.{}` `Read` requires a static read row policy to supplement",
                                config.resource
                            ),
                        ));
                    }
                    if !config.scope_sources.item
                        && !config.scope_sources.collection_filter
                        && !config.scope_sources.nested_parent
                    {
                        return Err(syn::Error::new(
                            span,
                            format!(
                                "`authorization.hybrid_enforcement.resources.{}` `Read` requires at least one of `scope_sources.item`, `scope_sources.collection_filter`, or `scope_sources.nested_parent`",
                                config.resource
                            ),
                        ));
                    }
                }
                crate::authorization::AuthorizationAction::Update => {
                    if !resource.policies.has_update_filters() {
                        return Err(syn::Error::new(
                            span,
                            format!(
                                "`authorization.hybrid_enforcement.resources.{}` `Update` requires a static update row policy to supplement",
                                config.resource
                            ),
                        ));
                    }
                    if !config.scope_sources.item {
                        return Err(syn::Error::new(
                            span,
                            format!(
                                "`authorization.hybrid_enforcement.resources.{}` `Update` requires `scope_sources.item = true`",
                                config.resource
                            ),
                        ));
                    }
                }
                crate::authorization::AuthorizationAction::Delete => {
                    if !resource.policies.has_delete_filters() {
                        return Err(syn::Error::new(
                            span,
                            format!(
                                "`authorization.hybrid_enforcement.resources.{}` `Delete` requires a static delete row policy to supplement",
                                config.resource
                            ),
                        ));
                    }
                    if !config.scope_sources.item {
                        return Err(syn::Error::new(
                            span,
                            format!(
                                "`authorization.hybrid_enforcement.resources.{}` `Delete` requires `scope_sources.item = true`",
                                config.resource
                            ),
                        ));
                    }
                }
                crate::authorization::AuthorizationAction::Create => {
                    if !config.scope_sources.create_payload {
                        return Err(syn::Error::new(
                            span,
                            format!(
                                "`authorization.hybrid_enforcement.resources.{}` `Create` requires `scope_sources.create_payload = true`",
                                config.resource
                            ),
                        ));
                    }
                    let Some(assignment) = resource
                        .policies
                        .create
                        .iter()
                        .find(|assignment| assignment.field == config.scope_field)
                    else {
                        return Err(syn::Error::new(
                            span,
                            format!(
                                "`authorization.hybrid_enforcement.resources.{}` `Create` requires `{}` to be assigned by a static create policy",
                                config.resource, config.scope_field
                            ),
                        ));
                    };
                    if !matches!(assignment.source, PolicyValueSource::Claim(_)) {
                        return Err(syn::Error::new(
                            span,
                            format!(
                                "`authorization.hybrid_enforcement.resources.{}` `Create` requires `{}` to be claim-controlled in `policies.create`",
                                config.resource, config.scope_field
                            ),
                        ));
                    }
                }
            }

            let has_permission = contract.permissions.iter().any(|permission| {
                permission.supports_scope(&config.scope)
                    && permission.matches_resource_action(&config.resource, *action)
            });
            if !has_permission {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "`authorization.hybrid_enforcement.resources.{}` action `{:?}` has no matching declared permission for resource `{}` and scope `{}`",
                        config.resource, action, config.resource, config.scope
                    ),
                ));
            }
        }
    }

    Ok(())
}

fn validate_authorization_management_api(
    config: &crate::authorization::AuthorizationManagementApiConfig,
    span: Span,
) -> syn::Result<()> {
    if config.mount.trim().is_empty() {
        return Err(syn::Error::new(
            span,
            "`authorization.management_api.mount` cannot be empty",
        ));
    }

    if !config.mount.starts_with('/') {
        return Err(syn::Error::new(
            span,
            "`authorization.management_api.mount` must start with `/`",
        ));
    }

    if config.mount.contains("//") {
        return Err(syn::Error::new(
            span,
            "`authorization.management_api.mount` cannot contain `//`",
        ));
    }

    Ok(())
}

fn validate_authorization_identifier(value: &str, span: Span, label: &str) -> syn::Result<()> {
    if is_valid_sql_identifier(value) {
        Ok(())
    } else {
        Err(syn::Error::new(
            span,
            format!(
                "{label} `{value}` is not valid; use only letters, digits, and underscores, and start with a letter or underscore"
            ),
        ))
    }
}

pub fn validate_security_config(security: &SecurityConfig, span: Span) -> syn::Result<()> {
    if matches!(security.requests.json_max_bytes, Some(0)) {
        return Err(syn::Error::new(
            span,
            "`security.requests.json_max_bytes` must be greater than 0",
        ));
    }

    if matches!(security.requests.max_filter_in_values, Some(0)) {
        return Err(syn::Error::new(
            span,
            "`security.requests.max_filter_in_values` must be greater than 0",
        ));
    }

    if let Some(hsts) = &security.headers.hsts
        && hsts.max_age_seconds == 0
    {
        return Err(syn::Error::new(
            span,
            "`security.headers.hsts.max_age_seconds` must be greater than 0",
        ));
    }

    if security.auth.access_token_ttl_seconds <= 0 {
        return Err(syn::Error::new(
            span,
            "`security.auth.access_token_ttl_seconds` must be greater than 0",
        ));
    }

    if security.auth.verification_token_ttl_seconds <= 0 {
        return Err(syn::Error::new(
            span,
            "`security.auth.verification_token_ttl_seconds` must be greater than 0",
        ));
    }

    if security.auth.password_reset_token_ttl_seconds <= 0 {
        return Err(syn::Error::new(
            span,
            "`security.auth.password_reset_token_ttl_seconds` must be greater than 0",
        ));
    }

    for (claim_name, mapping) in &security.auth.claims {
        if !is_valid_sql_identifier(claim_name) {
            return Err(syn::Error::new(
                span,
                format!(
                    "`security.auth.claims.{claim_name}` is not a valid claim identifier; use only letters, digits, and underscores, and start with a letter or underscore"
                ),
            ));
        }

        if is_reserved_auth_claim_name(claim_name) {
            return Err(syn::Error::new(
                span,
                format!("`security.auth.claims.{claim_name}` uses a reserved JWT/auth field name"),
            ));
        }

        validate_sql_identifier(
            &mapping.column,
            span,
            &format!("`security.auth.claims.{claim_name}.column`"),
        )?;
    }

    if security.auth.require_email_verification && security.auth.email.is_none() {
        return Err(syn::Error::new(
            span,
            "`security.auth.require_email_verification = true` requires `security.auth.email`",
        ));
    }

    if matches!(security.cors.max_age_seconds, Some(0)) {
        return Err(syn::Error::new(
            span,
            "`security.cors.max_age_seconds` must be greater than 0",
        ));
    }

    if matches!(security.cors.origins_env.as_deref(), Some("")) {
        return Err(syn::Error::new(
            span,
            "`security.cors.origins_env` cannot be empty",
        ));
    }

    let wildcard_origin = security.cors.origins.iter().any(|origin| origin == "*");
    if wildcard_origin && security.cors.allow_credentials {
        return Err(syn::Error::new(
            span,
            "`security.cors.allow_credentials` cannot be combined with wildcard `*` origins",
        ));
    }

    for origin in &security.cors.origins {
        if origin == "*" {
            continue;
        }
        Uri::try_from(origin.as_str()).map_err(|_| {
            syn::Error::new(
                span,
                format!("`security.cors.origins` contains invalid origin `{origin}`"),
            )
        })?;
    }

    for method in &security.cors.allow_methods {
        if method == "*" {
            continue;
        }
        Method::from_bytes(method.as_bytes()).map_err(|_| {
            syn::Error::new(
                span,
                format!("`security.cors.allow_methods` contains invalid method `{method}`"),
            )
        })?;
    }

    for header in security
        .cors
        .allow_headers
        .iter()
        .chain(security.cors.expose_headers.iter())
    {
        if header == "*" {
            continue;
        }
        HeaderName::try_from(header.as_str()).map_err(|_| {
            syn::Error::new(
                span,
                format!("`security.cors` contains invalid header name `{header}`"),
            )
        })?;
    }

    if matches!(security.trusted_proxies.proxies_env.as_deref(), Some("")) {
        return Err(syn::Error::new(
            span,
            "`security.trusted_proxies.proxies_env` cannot be empty",
        ));
    }

    for proxy in &security.trusted_proxies.proxies {
        IpAddr::from_str(proxy).map_err(|_| {
            syn::Error::new(
                span,
                format!("`security.trusted_proxies.proxies` contains invalid IP `{proxy}`"),
            )
        })?;
    }

    validate_rate_limit_rule("login", security.rate_limits.login, span)?;
    validate_rate_limit_rule("register", security.rate_limits.register, span)?;

    if let Some(cookie) = &security.auth.session_cookie {
        if cookie.name.trim().is_empty() {
            return Err(syn::Error::new(
                span,
                "`security.auth.session_cookie.name` cannot be empty",
            ));
        }

        if cookie.csrf_cookie_name.trim().is_empty() {
            return Err(syn::Error::new(
                span,
                "`security.auth.session_cookie.csrf_cookie_name` cannot be empty",
            ));
        }

        if cookie.csrf_cookie_name == cookie.name {
            return Err(syn::Error::new(
                span,
                "`security.auth.session_cookie.csrf_cookie_name` must differ from `name`",
            ));
        }

        if cookie.csrf_header_name.trim().is_empty() {
            return Err(syn::Error::new(
                span,
                "`security.auth.session_cookie.csrf_header_name` cannot be empty",
            ));
        }

        HeaderName::try_from(cookie.csrf_header_name.as_str()).map_err(|_| {
            syn::Error::new(
                span,
                format!(
                    "`security.auth.session_cookie.csrf_header_name` contains invalid header name `{}`",
                    cookie.csrf_header_name
                ),
            )
        })?;

        if !cookie.path.starts_with('/') {
            return Err(syn::Error::new(
                span,
                "`security.auth.session_cookie.path` must start with `/`",
            ));
        }

        if matches!(cookie.same_site, SessionCookieSameSite::None) && !cookie.secure {
            return Err(syn::Error::new(
                span,
                "`security.auth.session_cookie.same_site = None` requires `secure = true`",
            ));
        }

        for (label, name) in [
            ("name", cookie.name.as_str()),
            ("csrf_cookie_name", cookie.csrf_cookie_name.as_str()),
        ] {
            if name.starts_with("__Host-") && (!cookie.secure || cookie.path != "/") {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "`security.auth.session_cookie.{label}` uses the `__Host-` prefix but requires `secure = true` and `path = \"/\"`",
                    ),
                ));
            }
        }
        // Retain field-specific diagnostics above while sharing response constraints.
        crate::auth::session::cookie_policy(cookie)
            .validate()
            .map_err(|_| {
                syn::Error::new(
                    span,
                    "`security.auth.session_cookie` contains an unsafe or ambiguous cookie name, path, CSRF header or prefix",
                )
            })?;
    }

    if security.auth.jwt.is_some() && security.auth.jwt_secret.is_some() {
        return Err(syn::Error::new(
            span,
            "`security.auth.jwt` cannot be combined with `security.auth.jwt_secret`",
        ));
    }

    if let Some(jwt) = &security.auth.jwt {
        if matches!(jwt.active_kid.as_deref(), Some("")) {
            return Err(syn::Error::new(
                span,
                "`security.auth.jwt.active_kid` cannot be empty",
            ));
        }

        validate_secret_ref(&jwt.signing_key, "security.auth.jwt.signing_key", span)?;

        if !jwt.verification_keys.is_empty() && jwt.active_kid.is_none() {
            return Err(syn::Error::new(
                span,
                "`security.auth.jwt.active_kid` is required when verification keys are configured",
            ));
        }

        if !jwt.algorithm.is_symmetric() && jwt.verification_keys.is_empty() {
            return Err(syn::Error::new(
                span,
                format!(
                    "`security.auth.jwt.verification_keys` is required for asymmetric `{}` JWT configuration",
                    match jwt.algorithm {
                        AuthJwtAlgorithm::Es256 => "ES256",
                        AuthJwtAlgorithm::Es384 => "ES384",
                        AuthJwtAlgorithm::EdDsa => "EdDSA",
                        AuthJwtAlgorithm::Hs256 => "HS256",
                        AuthJwtAlgorithm::Hs384 => "HS384",
                        AuthJwtAlgorithm::Hs512 => "HS512",
                    }
                ),
            ));
        }

        let mut seen_kids = HashSet::new();
        for key in &jwt.verification_keys {
            if key.kid.trim().is_empty() {
                return Err(syn::Error::new(
                    span,
                    "`security.auth.jwt.verification_keys[].kid` cannot be empty",
                ));
            }
            if !seen_kids.insert(key.kid.as_str()) {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "duplicate `security.auth.jwt.verification_keys[].kid` value `{}`",
                        key.kid
                    ),
                ));
            }
            validate_secret_ref(
                &key.key,
                &format!("security.auth.jwt.verification_keys[{}].key", key.kid),
                span,
            )?;
        }

        if let Some(active_kid) = jwt.active_kid.as_deref()
            && !jwt.verification_keys.is_empty()
            && !jwt
                .verification_keys
                .iter()
                .any(|verification_key| verification_key.kid == active_kid)
        {
            return Err(syn::Error::new(
                span,
                format!(
                    "`security.auth.jwt.active_kid` references unknown verification key `{active_kid}`",
                ),
            ));
        }
    }

    if let Some(jwt_secret) = &security.auth.jwt_secret {
        validate_secret_ref(jwt_secret, "security.auth.jwt_secret", span)?;
    }

    if let Some(email) = &security.auth.email {
        if email.from_email.trim().is_empty() {
            return Err(syn::Error::new(
                span,
                "`security.auth.email.from_email` cannot be empty",
            ));
        }
        if !email.from_email.contains('@') {
            return Err(syn::Error::new(
                span,
                "`security.auth.email.from_email` must look like an email address",
            ));
        }
        if matches!(email.reply_to.as_deref(), Some("")) {
            return Err(syn::Error::new(
                span,
                "`security.auth.email.reply_to` cannot be empty",
            ));
        }
        if let Some(public_base_url) = &email.public_base_url {
            Url::parse(public_base_url).map_err(|_| {
                syn::Error::new(
                    span,
                    "`security.auth.email.public_base_url` must be a valid absolute URL",
                )
            })?;
        }

        match &email.provider {
            AuthEmailProvider::Resend {
                api_key,
                api_base_url,
            } => {
                validate_secret_ref(api_key, "security.auth.email.provider.api_key", span)?;
                if let Some(api_base_url) = api_base_url {
                    Url::parse(api_base_url).map_err(|_| {
                        syn::Error::new(
                            span,
                            "`security.auth.email.provider.api_base_url` must be a valid absolute URL",
                        )
                    })?;
                }
            }
            AuthEmailProvider::Smtp { connection_url } => {
                validate_secret_ref(
                    connection_url,
                    "security.auth.email.provider.connection_url",
                    span,
                )?;
            }
        }
    }

    let reserved_auth_paths = [
        "/auth/register",
        "/auth/login",
        "/auth/logout",
        "/auth/me",
        "/auth/account",
        "/auth/account/password",
        "/auth/account/verification",
        "/auth/verify-email",
        "/auth/verification/resend",
        "/auth/password-reset",
        "/auth/password-reset/request",
        "/auth/password-reset/confirm",
        "/auth/admin/users",
    ];
    let mut custom_paths = std::collections::HashSet::<String>::new();
    for (label, page) in [
        ("portal", security.auth.portal.as_ref()),
        ("admin_dashboard", security.auth.admin_dashboard.as_ref()),
    ] {
        let Some(page) = page else {
            continue;
        };
        if page.path.trim().is_empty() {
            return Err(syn::Error::new(
                span,
                format!("`security.auth.{label}.path` cannot be empty"),
            ));
        }
        if !page.path.starts_with('/') {
            return Err(syn::Error::new(
                span,
                format!("`security.auth.{label}.path` must start with `/`"),
            ));
        }
        if page.title.trim().is_empty() {
            return Err(syn::Error::new(
                span,
                format!("`security.auth.{label}.title` cannot be empty"),
            ));
        }
        if reserved_auth_paths.contains(&page.path.as_str()) {
            return Err(syn::Error::new(
                span,
                format!(
                    "`security.auth.{label}.path` conflicts with a built-in auth route: `{}`",
                    page.path
                ),
            ));
        }
        if !custom_paths.insert(page.path.clone()) {
            return Err(syn::Error::new(span, "custom auth UI paths must be unique"));
        }
    }

    Ok(())
}

fn validate_secret_ref(secret: &SecretRef, label: &str, span: Span) -> syn::Result<()> {
    match secret {
        SecretRef::Env { var_name } | SecretRef::EnvOrFile { var_name } => {
            if var_name.trim().is_empty() {
                return Err(syn::Error::new(
                    span,
                    format!("`{label}` cannot use an empty environment variable name"),
                ));
            }
        }
        SecretRef::SystemdCredential { id } => {
            if id.trim().is_empty() {
                return Err(syn::Error::new(
                    span,
                    format!("`{label}` cannot use an empty systemd credential id"),
                ));
            }
        }
        SecretRef::External { provider, locator } => {
            if provider.trim().is_empty() {
                return Err(syn::Error::new(
                    span,
                    format!("`{label}.provider` cannot be empty"),
                ));
            }
            if locator.trim().is_empty() {
                return Err(syn::Error::new(
                    span,
                    format!("`{label}.locator` cannot be empty"),
                ));
            }
        }
        SecretRef::File { path } => {
            let rendered = path.to_string_lossy();
            if rendered.trim().is_empty() {
                return Err(syn::Error::new(
                    span,
                    format!("`{label}` cannot use an empty file path"),
                ));
            }
        }
    }

    Ok(())
}

fn validate_policy_claim_source(
    resource: &ResourceSpec,
    scope: &str,
    field_name: &str,
    source: &PolicyValueSource,
    security: &SecurityConfig,
    span: Span,
) -> syn::Result<()> {
    let PolicyValueSource::Claim(claim_name) = source else {
        return Ok(());
    };

    let field = resource
        .fields
        .iter()
        .find(|field| field.name() == field_name)
        .ok_or_else(|| {
            syn::Error::new(
                span,
                format!(
                    "resource `{}` {scope} row policy references missing field `{field_name}`",
                    resource.struct_ident,
                ),
            )
        })?;
    let expected_ty = policy_field_claim_type(&field.ty).ok_or_else(|| {
        syn::Error::new(
            span,
            format!(
                "resource `{}` {scope} row policy field `{field_name}` must use type `i64`, `String`, `bool`, or an `Option<...>` of one of those types",
                resource.struct_ident,
            ),
        )
    })?;

    if let Some(mapping) = security.auth.claims.get(claim_name) {
        if mapping.ty != expected_ty {
            return Err(syn::Error::new(
                span,
                format!(
                    "resource `{}` {scope} row policy for field `{field_name}` uses `claim.{claim_name}`, but `security.auth.claims.{claim_name}` is `{}` while the field expects `{}`",
                    resource.struct_ident,
                    auth_claim_type_label(mapping.ty),
                    auth_claim_type_label(expected_ty),
                ),
            ));
        }
        return Ok(());
    }

    if legacy_auth_claim_name_supported(claim_name) && expected_ty == AuthClaimType::I64 {
        return Ok(());
    }

    Err(syn::Error::new(
        span,
        format!(
            "resource `{}` {scope} row policy for field `{field_name}` references undeclared `claim.{claim_name}`; declare `security.auth.claims.{claim_name}`{}",
            resource.struct_ident,
            if expected_ty == AuthClaimType::I64 {
                " or keep using a legacy numeric `*_id` claim"
            } else {
                ""
            },
        ),
    ))
}

fn validate_policy_filter_claim_source(
    resource: &ResourceSpec,
    scope: &str,
    filter: &PolicyFilter,
    security: &SecurityConfig,
    span: Span,
) -> syn::Result<()> {
    match &filter.operator {
        PolicyFilterOperator::Equals(PolicyComparisonValue::Source(source)) => match source {
            PolicyValueSource::InputField(_) => Ok(()),
            _ => {
                validate_policy_claim_source(resource, scope, &filter.field, source, security, span)
            }
        },
        PolicyFilterOperator::Equals(PolicyComparisonValue::Literal(_)) => Ok(()),
        PolicyFilterOperator::IsNull | PolicyFilterOperator::IsNotNull => Ok(()),
    }
}

fn legacy_auth_claim_name_supported(claim_name: &str) -> bool {
    claim_name.ends_with("_id") && claim_name != "id"
}

fn is_reserved_auth_claim_name(claim_name: &str) -> bool {
    matches!(
        claim_name,
        "sub" | "roles" | "iss" | "aud" | "exp" | "id" | "_vsr_auth_state"
    )
}

fn auth_claim_type_label(ty: AuthClaimType) -> &'static str {
    match ty {
        AuthClaimType::I64 => "I64",
        AuthClaimType::String => "String",
        AuthClaimType::Bool => "Bool",
    }
}

pub fn validate_runtime_config(_runtime: &RuntimeConfig, _span: Span) -> syn::Result<()> {
    Ok(())
}

pub fn validate_build_config(build: &BuildConfig, span: Span) -> syn::Result<()> {
    if build.release.codegen_units == Some(0) {
        return Err(syn::Error::new(
            span,
            "`build.release.codegen_units` must be greater than zero",
        ));
    }

    for (label, value) in [
        (
            "build.artifacts.binary.path",
            build.artifacts.binary.path.as_deref(),
        ),
        (
            "build.artifacts.binary.env",
            build.artifacts.binary.env.as_deref(),
        ),
        (
            "build.artifacts.bundle.path",
            build.artifacts.bundle.path.as_deref(),
        ),
        (
            "build.artifacts.bundle.env",
            build.artifacts.bundle.env.as_deref(),
        ),
        (
            "build.artifacts.cache.root",
            build.artifacts.cache.root.as_deref(),
        ),
        (
            "build.artifacts.cache.env",
            build.artifacts.cache.env.as_deref(),
        ),
    ] {
        if value.is_some_and(|value| value.trim().is_empty()) {
            return Err(syn::Error::new(span, format!("`{label}` cannot be empty")));
        }
    }

    Ok(())
}

pub fn validate_clients_config(clients: &ClientsConfig, span: Span) -> syn::Result<()> {
    for (label, value) in [
        (
            "clients.ts.output_dir.path",
            clients.ts.output_dir.path.as_deref(),
        ),
        (
            "clients.ts.output_dir.env",
            clients.ts.output_dir.env.as_deref(),
        ),
        (
            "clients.ts.package_name.value",
            clients.ts.package_name.value.as_deref(),
        ),
        (
            "clients.ts.package_name.env",
            clients.ts.package_name.env.as_deref(),
        ),
        ("clients.ts.server_url", clients.ts.server_url.as_deref()),
        (
            "clients.ts.automation.self_test_report.path",
            clients.ts.automation.self_test_report.path.as_deref(),
        ),
        (
            "clients.ts.automation.self_test_report.env",
            clients.ts.automation.self_test_report.env.as_deref(),
        ),
    ] {
        if value.is_some_and(|value| value.trim().is_empty()) {
            return Err(syn::Error::new(span, format!("`{label}` cannot be empty")));
        }
    }

    for excluded in &clients.ts.exclude_tables {
        if excluded.trim().is_empty() {
            return Err(syn::Error::new(
                span,
                "`clients.ts.exclude_tables` cannot contain empty table names",
            ));
        }
    }

    Ok(())
}

pub fn validate_logging_config(logging: &LoggingConfig, span: Span) -> syn::Result<()> {
    if logging.filter_env.trim().is_empty() {
        return Err(syn::Error::new(
            span,
            "`logging.filter_env` cannot be empty",
        ));
    }

    if logging.default_filter.trim().is_empty() {
        return Err(syn::Error::new(
            span,
            "`logging.default_filter` cannot be empty",
        ));
    }

    Ok(())
}

pub fn validate_tls_config(tls: &TlsConfig, span: Span) -> syn::Result<()> {
    if !tls.is_enabled() {
        return Ok(());
    }

    if tls
        .cert_path
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(syn::Error::new(span, "`tls.cert_path` cannot be empty"));
    }

    if tls
        .key_path
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(syn::Error::new(span, "`tls.key_path` cannot be empty"));
    }

    if tls
        .cert_path_env
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(syn::Error::new(span, "`tls.cert_path_env` cannot be empty"));
    }

    if tls
        .key_path_env
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(syn::Error::new(span, "`tls.key_path_env` cannot be empty"));
    }

    if tls.cert_path.is_none() && tls.cert_path_env.is_none() {
        return Err(syn::Error::new(
            span,
            "`tls.cert_path` or `tls.cert_path_env` must be configured when TLS is enabled",
        ));
    }

    if tls.key_path.is_none() && tls.key_path_env.is_none() {
        return Err(syn::Error::new(
            span,
            "`tls.key_path` or `tls.key_path_env` must be configured when TLS is enabled",
        ));
    }

    Ok(())
}

fn validate_rate_limit_rule(
    scope: &str,
    rule: Option<crate::security::RateLimitRule>,
    span: Span,
) -> syn::Result<()> {
    let Some(rule) = rule else {
        return Ok(());
    };

    if rule.requests == 0 {
        return Err(syn::Error::new(
            span,
            format!("`security.rate_limits.{scope}.requests` must be greater than 0"),
        ));
    }

    if rule.window_seconds == 0 {
        return Err(syn::Error::new(
            span,
            format!("`security.rate_limits.{scope}.window_seconds` must be greater than 0"),
        ));
    }

    Ok(())
}

fn validate_policy_filters(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    scope: &str,
    expression: Option<&PolicyFilterExpression>,
    allow_input_fields: bool,
    span: Span,
) -> syn::Result<()> {
    let Some(expression) = expression else {
        return Ok(());
    };
    validate_policy_filter_expression(
        resource,
        resources,
        scope,
        expression,
        allow_input_fields,
        span,
    )
}

fn validate_policy_filter_expression(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    scope: &str,
    expression: &PolicyFilterExpression,
    allow_input_fields: bool,
    span: Span,
) -> syn::Result<()> {
    match expression {
        PolicyFilterExpression::Match(policy) => {
            let field = validate_policy_field(&resource.fields, scope, &policy.field, span)?;
            validate_policy_filter_operator(
                resource,
                scope,
                &policy.field,
                field,
                &policy.operator,
                allow_input_fields,
                span,
            )
        }
        PolicyFilterExpression::All(expressions) | PolicyFilterExpression::Any(expressions) => {
            for expression in expressions {
                validate_policy_filter_expression(
                    resource,
                    resources,
                    scope,
                    expression,
                    allow_input_fields,
                    span,
                )?;
            }
            Ok(())
        }
        PolicyFilterExpression::Not(expression) => validate_policy_filter_expression(
            resource,
            resources,
            scope,
            expression,
            allow_input_fields,
            span,
        ),
        PolicyFilterExpression::Exists(filter) => validate_exists_policy_filter(
            resource,
            resources,
            scope,
            filter,
            allow_input_fields,
            span,
        ),
    }
}

fn validate_exists_policy_filter(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    scope: &str,
    filter: &PolicyExistsFilter,
    allow_input_fields: bool,
    span: Span,
) -> syn::Result<()> {
    let target_resource = resources.iter().find(|candidate| {
        candidate.struct_ident == filter.resource.as_str()
            || candidate.table_name == filter.resource
    });
    let Some(target_resource) = target_resource else {
        return Err(syn::Error::new(
            span,
            format!(
                "row policy for `{scope}` references unknown exists resource `{}`",
                filter.resource
            ),
        ));
    };

    validate_exists_policy_condition(
        resource,
        target_resource,
        scope,
        &filter.condition,
        allow_input_fields,
        span,
    )
}

fn validate_exists_policy_condition(
    resource: &ResourceSpec,
    target_resource: &ResourceSpec,
    scope: &str,
    condition: &PolicyExistsCondition,
    allow_input_fields: bool,
    span: Span,
) -> syn::Result<()> {
    match condition {
        PolicyExistsCondition::Match(policy) => {
            let field = validate_policy_field(&target_resource.fields, scope, &policy.field, span)?;
            validate_policy_filter_operator(
                resource,
                scope,
                &policy.field,
                field,
                &policy.operator,
                allow_input_fields,
                span,
            )
        }
        PolicyExistsCondition::CurrentRowField { field, row_field } => {
            let target_field = validate_policy_field(&target_resource.fields, scope, field, span)?;
            let row_field_spec = validate_policy_field(&resource.fields, scope, row_field, span)?;
            let target_ty = policy_field_claim_type(&target_field.ty).ok_or_else(|| {
                syn::Error::new(
                    span,
                    format!(
                        "exists row policy field `{field}` must use type `i64`, `String`, `bool`, or an `Option<...>` of one of those types"
                    ),
                )
            })?;
            let row_ty = policy_field_claim_type(&row_field_spec.ty).ok_or_else(|| {
                syn::Error::new(
                    span,
                    format!(
                        "exists row policy outer field `{row_field}` must use type `i64`, `String`, `bool`, or an `Option<...>` of one of those types"
                    ),
                )
            })?;
            if target_ty != row_ty {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "exists row policy `{field} = row.{row_field}` compares incompatible field types `{}` and `{}`",
                        auth_claim_type_label(target_ty),
                        auth_claim_type_label(row_ty),
                    ),
                ));
            }
            Ok(())
        }
        PolicyExistsCondition::All(expressions) | PolicyExistsCondition::Any(expressions) => {
            for expression in expressions {
                validate_exists_policy_condition(
                    resource,
                    target_resource,
                    scope,
                    expression,
                    allow_input_fields,
                    span,
                )?;
            }
            Ok(())
        }
        PolicyExistsCondition::Not(expression) => validate_exists_policy_condition(
            resource,
            target_resource,
            scope,
            expression,
            allow_input_fields,
            span,
        ),
    }
}

fn validate_exists_policy_claim_sources(
    target_resource: &ResourceSpec,
    scope: &str,
    condition: &PolicyExistsCondition,
    security: &SecurityConfig,
    span: Span,
) -> syn::Result<()> {
    match condition {
        PolicyExistsCondition::Match(condition) => {
            validate_policy_filter_claim_source(target_resource, scope, condition, security, span)
        }
        PolicyExistsCondition::CurrentRowField { .. } => Ok(()),
        PolicyExistsCondition::All(expressions) | PolicyExistsCondition::Any(expressions) => {
            for expression in expressions {
                validate_exists_policy_claim_sources(
                    target_resource,
                    scope,
                    expression,
                    security,
                    span,
                )?;
            }
            Ok(())
        }
        PolicyExistsCondition::Not(expression) => {
            validate_exists_policy_claim_sources(target_resource, scope, expression, security, span)
        }
    }
}

fn validate_policy_filter_operator(
    source_resource: &ResourceSpec,
    scope: &str,
    field_name: &str,
    field: &FieldSpec,
    operator: &PolicyFilterOperator,
    allow_input_fields: bool,
    span: Span,
) -> syn::Result<()> {
    match operator {
        PolicyFilterOperator::Equals(PolicyComparisonValue::Source(source)) => {
            if let PolicyValueSource::InputField(input_field_name) = source {
                if !allow_input_fields {
                    return Err(syn::Error::new(
                        span,
                        format!(
                            "{scope} row policy field `{field_name}` cannot use `input.{input_field_name}`"
                        ),
                    ));
                }

                let expected_ty = policy_field_claim_type(&field.ty).ok_or_else(|| {
                    syn::Error::new(
                        span,
                        format!(
                            "row policy field `{field_name}` must use type `i64`, `String`, `bool`, or an `Option<...>` of one of those types"
                        ),
                    )
                })?;
                let input_field =
                    validate_policy_field(&source_resource.fields, scope, input_field_name, span)?;
                let input_ty = policy_field_claim_type(&input_field.ty).ok_or_else(|| {
                    syn::Error::new(
                        span,
                        format!(
                            "input row policy field `{input_field_name}` must use type `i64`, `String`, `bool`, or an `Option<...>` of one of those types"
                        ),
                    )
                })?;
                if expected_ty != input_ty {
                    return Err(syn::Error::new(
                        span,
                        format!(
                            "{scope} row policy `{field_name} = input.{input_field_name}` compares incompatible field types `{}` and `{}`",
                            auth_claim_type_label(expected_ty),
                            auth_claim_type_label(input_ty),
                        ),
                    ));
                }
            }
            Ok(())
        }
        PolicyFilterOperator::Equals(PolicyComparisonValue::Literal(literal)) => {
            let expected_ty = policy_field_claim_type(&field.ty).ok_or_else(|| {
                syn::Error::new(
                    span,
                    format!(
                        "row policy field `{field_name}` must use type `i64`, `String`, `bool`, or an `Option<...>` of one of those types"
                    ),
                )
            })?;
            let literal_ty = literal.claim_type();
            if expected_ty != literal_ty {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "{scope} row policy field `{field_name}` compares incompatible field types `{}` and `{}`",
                        auth_claim_type_label(expected_ty),
                        auth_claim_type_label(literal_ty),
                    ),
                ));
            }

            if let (Some(enum_values), PolicyLiteralValue::String(value)) =
                (field.enum_values(), literal)
                && !enum_values.iter().any(|candidate| candidate == value)
            {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "{scope} row policy field `{field_name}` must use one of declared enum values [{}]",
                        enum_values.join(", ")
                    ),
                ));
            }

            Ok(())
        }
        PolicyFilterOperator::IsNull | PolicyFilterOperator::IsNotNull => {
            if is_optional_type(&field.ty) {
                Ok(())
            } else {
                Err(syn::Error::new(
                    span,
                    format!(
                        "{scope} row policy null checks require nullable/optional field `{field_name}`"
                    ),
                ))
            }
        }
    }
}

fn validate_policy_assignments(
    fields: &[FieldSpec],
    scope: &str,
    policies: &[PolicyAssignment],
    span: Span,
) -> syn::Result<()> {
    let mut seen_fields = HashSet::new();
    for policy in policies {
        validate_policy_field(fields, scope, &policy.field, span)?;
        if !seen_fields.insert(policy.field.clone()) {
            return Err(syn::Error::new(
                span,
                format!(
                    "duplicate row policy field `{}` for `{scope}`",
                    policy.field
                ),
            ));
        }
    }

    Ok(())
}

fn validate_policy_field<'a>(
    fields: &'a [FieldSpec],
    scope: &str,
    field_name: &str,
    span: Span,
) -> syn::Result<&'a FieldSpec> {
    let field = fields
        .iter()
        .find(|field| field.name() == field_name)
        .ok_or_else(|| {
            syn::Error::new(
                span,
                format!("row policy for `{scope}` references missing field `{field_name}`"),
            )
        })?;

    if policy_field_claim_type(&field.ty).is_none() {
        return Err(syn::Error::new(
            span,
            format!(
                "row policy field `{field_name}` must use type `i64`, `String`, `bool`, or an `Option<...>` of one of those types"
            ),
        ));
    }

    Ok(field)
}
