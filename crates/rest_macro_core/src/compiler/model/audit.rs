//! Audit-sink validation.
//!
//! These validators inspect a resource's `audit` configuration and ensure the
//! referenced sink resource has the right shape. The helpers and the validator
//! live together because they share the same private predicates.

use proc_macro2::Span;

use super::helpers::{
    is_bool_type, is_integer_sql_type, is_json_array_type, is_json_object_type, is_json_type,
    is_optional_type,
};
use super::scalars::GeneratedValue;
use super::specs::{FieldSpec, ResourceAuditActionSelection, ResourceSpec};

pub(super) fn resolve_audit_sink_resource<'a>(
    resources: &'a [ResourceSpec],
    selector: &str,
) -> syn::Result<&'a ResourceSpec> {
    resources
        .iter()
        .find(|candidate| candidate.struct_ident == selector || candidate.table_name == selector)
        .ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                format!("audit sink resource `{selector}` was not found"),
            )
        })
}

pub(super) fn field_is_text_like(field: &FieldSpec) -> bool {
    if field.list_item_ty.is_some() || field.object_fields.is_some() {
        return false;
    }

    if is_bool_type(&field.ty)
        || is_integer_sql_type(field.sql_type.as_str())
        || matches!(field.sql_type.as_str(), "REAL")
        || is_json_type(&field.ty)
        || is_json_object_type(&field.ty)
        || is_json_array_type(&field.ty)
    {
        return false;
    }

    true
}

pub(super) fn field_is_integer(field: &FieldSpec) -> bool {
    field.list_item_ty.is_none() && is_integer_sql_type(field.sql_type.as_str())
}

pub(super) fn sink_field<'a>(
    sink: &'a ResourceSpec,
    field_name: &str,
    sink_label: &str,
) -> syn::Result<&'a FieldSpec> {
    sink.find_field(field_name).ok_or_else(|| {
        syn::Error::new(
            Span::call_site(),
            format!("audit sink resource `{sink_label}` must declare field `{field_name}`"),
        )
    })
}

pub(super) fn validate_audit_sink_shape(
    audited: &ResourceSpec,
    sink: &ResourceSpec,
) -> syn::Result<()> {
    let sink_label = sink.struct_ident.to_string();
    let id_field = sink.find_field(sink.id_field.as_str()).ok_or_else(|| {
        syn::Error::new(
            Span::call_site(),
            format!(
                "audit sink resource `{sink_label}` is missing its configured id field `{}`",
                sink.id_field
            ),
        )
    })?;
    if !id_field.generated.skip_insert() || !field_is_integer(id_field) {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "audit sink resource `{sink_label}` must use an auto-generated integer id field"
            ),
        ));
    }

    let created_at = sink_field(sink, "created_at", sink_label.as_str())?;
    if created_at.generated != GeneratedValue::CreatedAt {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "audit sink resource `{sink_label}` field `created_at` must be generated as `CreatedAt`"
            ),
        ));
    }

    for field_name in [
        "event_kind",
        "resource_name",
        "actor_roles_json",
        "payload_json",
    ] {
        let field = sink_field(sink, field_name, sink_label.as_str())?;
        if !field_is_text_like(field) || is_optional_type(&field.ty) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "audit sink resource `{sink_label}` field `{field_name}` must be a required string-like field"
                ),
            ));
        }
    }

    let record_id = sink_field(sink, "record_id", sink_label.as_str())?;
    if !field_is_integer(record_id) || is_optional_type(&record_id.ty) {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "audit sink resource `{sink_label}` field `record_id` must be a required integer field"
            ),
        ));
    }

    let actor_user_id = sink_field(sink, "actor_user_id", sink_label.as_str())?;
    if !field_is_integer(actor_user_id) || !is_optional_type(&actor_user_id.ty) {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "audit sink resource `{sink_label}` field `actor_user_id` must be a nullable integer field"
            ),
        ));
    }

    let allowed_non_generated = [
        "event_kind",
        "resource_name",
        "record_id",
        "actor_user_id",
        "actor_roles_json",
        "payload_json",
    ];
    for field in &sink.fields {
        if field.is_id || field.generated.skip_insert() {
            continue;
        }
        if !allowed_non_generated.contains(&field.name().as_str()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "audit sink resource `{sink_label}` cannot require extra writable field `{}`",
                    field.name()
                ),
            ));
        }
    }

    if sink.audit.is_some() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("audit sink resource `{sink_label}` cannot itself emit audit events"),
        ));
    }

    for action in &sink.actions {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "audit sink resource `{sink_label}` cannot declare action `{}`",
                action.name
            ),
        ));
    }

    if audited.table_name == sink.table_name {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "resource `{}` cannot use itself as an audit sink",
                audited.struct_ident
            ),
        ));
    }

    Ok(())
}

pub fn validate_resource_audit(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
) -> syn::Result<()> {
    let Some(audit) = resource.audit.as_ref() else {
        return Ok(());
    };

    if !audit.is_enabled() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "resource `{}` audit config must enable at least one event",
                resource.struct_ident
            ),
        ));
    }

    if let Some(ResourceAuditActionSelection::Named(action_names)) = audit.actions.as_ref() {
        if action_names.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "resource `{}` audit action list cannot be empty",
                    resource.struct_ident
                ),
            ));
        }
        for action_name in action_names {
            if !resource
                .actions
                .iter()
                .any(|action| action.name == *action_name)
            {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "resource `{}` audit config references unknown action `{action_name}`",
                        resource.struct_ident
                    ),
                ));
            }
        }
    }

    let sink = resolve_audit_sink_resource(resources, audit.resource.as_str())?;
    validate_audit_sink_shape(resource, sink)
}

pub fn is_audit_sink_resource(resource: &ResourceSpec, resources: &[ResourceSpec]) -> bool {
    let resource_name = resource.struct_ident.to_string();
    resources
        .iter()
        .filter_map(|candidate| candidate.audit.as_ref())
        .any(|audit| audit.resource == resource_name || audit.resource == resource.table_name)
}
