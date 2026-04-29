//! Resource building: converts parsed EON documents into `ResourceSpec`,
//! `EnumSpec`, `IndexSpec`, and related model types used by the code
//! generator.
//!
//! Entry points called from `super::load_service_document`:
//! `build_enums`, `build_mixins`, `expand_resource_mixins`,
//! `build_resources_with_enums`.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, NaiveDate, NaiveTime, SecondsFormat, Utc};
use heck::ToSnakeCase;
use proc_macro2::Span;
use rust_decimal::Decimal;
use serde_json::Value as JsonValue;
use uuid::Uuid;

use super::super::model::{
    DbBackend, EnumSpec, FieldSpec, FieldTransform, GeneratedValue, IndexSpec, LengthMode,
    NumericBound, ResourceActionAssignmentSpec, ResourceActionBehaviorSpec,
    ResourceActionInputFieldSpec, ResourceActionMethod, ResourceActionSpec, ResourceActionTarget,
    ResourceActionValueSpec, ResourceSpec, ResponseContextSpec, RowPolicies,
    WriteModelStyle,
    default_resource_module_ident, infer_generated_value, infer_sql_type,
    is_json_array_type, is_json_object_type, is_json_type, is_list_field,
    is_optional_type, is_typed_object_field, sanitize_struct_ident,
    structured_scalar_kind, supports_declared_index, validate_field_transforms,
    validate_field_validations, validate_list_config, validate_relations, validate_resource_access,
    validate_row_policies, validate_sql_identifier,
};
use super::documents::{
    ApiFieldProjectionDocument, EnumDocument, FieldDocument, FieldTypeDocument,
    IndexDocument, ManyToManyDocument, MixinDocument, ScalarType,
    ResourceActionAssignmentValueDocument, ResourceActionBehaviorDocument,
    ResourceActionDocument, ResourceDocument, ResponseContextDocument,
};
use super::{
    // Functions from sibling submodules, re-exported into parent namespace
    // via `use self::field_parsing::*` etc. in eon_parser.rs.
    parse_field_type, parse_field_transforms_document, parse_field_validation_document,
    parse_list_config, parse_relation_document,
    parse_resource_access_document, parse_row_policies, reject_legacy_field_validation,
    validate_api_name,
};
pub(super) fn build_enums(documents: Vec<EnumDocument>) -> syn::Result<Vec<EnumSpec>> {
    let mut seen_names = HashSet::new();
    let mut enums = Vec::with_capacity(documents.len());

    for document in documents {
        if !seen_names.insert(document.name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("duplicate enum `{}`", document.name),
            ));
        }
        syn::parse_str::<syn::Ident>(&document.name).map_err(|_| {
            syn::Error::new(
                Span::call_site(),
                format!(
                    "enum name `{}` is not a valid Rust identifier",
                    document.name
                ),
            )
        })?;
        if document.values.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("enum `{}` must declare at least one value", document.name),
            ));
        }
        let mut seen_values = HashSet::new();
        for value in &document.values {
            if !seen_values.insert(value.clone()) {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "enum `{}` contains duplicate value `{value}`",
                        document.name
                    ),
                ));
            }
        }
        enums.push(EnumSpec {
            name: document.name,
            values: document.values,
        });
    }

    Ok(enums)
}

pub(super) fn build_mixins(documents: Vec<MixinDocument>) -> syn::Result<HashMap<String, MixinDocument>> {
    let mut seen_names = HashSet::new();
    let mut mixins = HashMap::with_capacity(documents.len());

    for document in documents {
        if !seen_names.insert(document.name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("duplicate mixin `{}`", document.name),
            ));
        }
        syn::parse_str::<syn::Ident>(document.name.as_str()).map_err(|_| {
            syn::Error::new(
                Span::call_site(),
                format!(
                    "mixin name `{}` is not a valid Rust identifier",
                    document.name
                ),
            )
        })?;
        validate_mixin_document(&document)?;
        mixins.insert(document.name.clone(), document);
    }

    Ok(mixins)
}

pub(super) fn validate_mixin_document(mixin: &MixinDocument) -> syn::Result<()> {
    let mut seen_fields = HashSet::new();
    let mut seen_api_names = HashSet::new();

    for field in &mixin.fields {
        if !seen_fields.insert(field.name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("duplicate field `{}` in mixin `{}`", field.name, mixin.name),
            ));
        }

        let field_api_name = field.api_name.as_deref().unwrap_or(field.name.as_str());
        if !seen_api_names.insert(field_api_name.to_owned()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "duplicate field api_name `{field_api_name}` in mixin `{}`",
                    mixin.name
                ),
            ));
        }

        if field.id {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "mixin `{}` cannot declare id field `{}`",
                    mixin.name, field.name
                ),
            ));
        }
    }

    let field_names = mixin
        .fields
        .iter()
        .map(|field| field.name.as_str())
        .collect::<HashSet<_>>();
    for index in &mixin.indexes {
        if index.fields.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "mixin `{}` index definitions must declare at least one field",
                    mixin.name
                ),
            ));
        }
        for field_name in &index.fields {
            if !field_names.contains(field_name.as_str()) {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "mixin `{}` index references unknown mixin field `{field_name}`",
                        mixin.name
                    ),
                ));
            }
        }
    }

    Ok(())
}

pub(super) fn expand_resource_mixins(
    resources: Vec<ResourceDocument>,
    mixins: &HashMap<String, MixinDocument>,
) -> syn::Result<Vec<ResourceDocument>> {
    let mut expanded = Vec::with_capacity(resources.len());

    for mut resource in resources {
        let mut seen_mixins = HashSet::new();
        let mut mixin_fields = Vec::new();
        let mut mixin_indexes = Vec::new();

        for mixin_name in &resource.use_mixins {
            if !seen_mixins.insert(mixin_name.clone()) {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "resource `{}` uses mixin `{mixin_name}` more than once",
                        resource.name
                    ),
                ));
            }
            let mixin = mixins.get(mixin_name).ok_or_else(|| {
                syn::Error::new(
                    Span::call_site(),
                    format!(
                        "resource `{}` references unknown mixin `{mixin_name}`",
                        resource.name
                    ),
                )
            })?;
            mixin_fields.extend(mixin.fields.clone());
            mixin_indexes.extend(mixin.indexes.clone());
        }

        mixin_fields.extend(resource.fields);
        mixin_indexes.extend(resource.indexes);
        resource.fields = mixin_fields;
        resource.indexes = mixin_indexes;
        expanded.push(resource);
    }

    Ok(expanded)
}

pub(super) fn build_resources_with_enums(
    db: DbBackend,
    resources: Vec<ResourceDocument>,
    enums: &[EnumSpec],
) -> syn::Result<Vec<ResourceSpec>> {
    let mut seen_names = HashSet::new();
    let mut seen_api_names = HashSet::new();
    let mut pending_many_to_many = Vec::with_capacity(resources.len());
    let mut result = Vec::with_capacity(resources.len());

    for resource in resources {
        let struct_ident = sanitize_struct_ident(&resource.name, Span::call_site());
        let struct_name = struct_ident.to_string();
        if !seen_names.insert(struct_name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("duplicate resource `{struct_name}`"),
            ));
        }

        let table_name = resource
            .table
            .unwrap_or_else(|| struct_name.to_snake_case());
        validate_sql_identifier(&table_name, Span::call_site(), "table name")?;
        let api_name = resource.api_name.unwrap_or_else(|| table_name.clone());
        validate_api_name(
            api_name.as_str(),
            format!("resource `{struct_name}` api_name").as_str(),
        )?;
        if !seen_api_names.insert(api_name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("duplicate resource api_name `{api_name}`"),
            ));
        }
        let configured_id = resource.id_field.unwrap_or_else(|| "id".to_owned());
        let resource_api = resource.api.unwrap_or_default();
        let resource_many_to_many = resource.many_to_many;
        let resource_actions = resource.actions;
        let has_api_projection_block = !resource_api.fields.is_empty();
        if has_api_projection_block && resource.fields.iter().any(|field| field.api_name.is_some())
        {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "resource `{struct_name}` cannot combine resource `api.fields` with per-field `api_name`"
                ),
            ));
        }

        let mut seen_fields = HashSet::new();
        let mut seen_field_api_names = HashSet::new();
        let mut fields = Vec::with_capacity(resource.fields.len());

        for field in resource.fields {
            if !seen_fields.insert(field.name.clone()) {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "duplicate field `{}` on resource `{struct_name}`",
                        field.name
                    ),
                ));
            }
            let (field_api_name, expose_in_api) = if has_api_projection_block {
                (field.name.clone(), false)
            } else {
                let field_api_name = field.api_name.unwrap_or_else(|| field.name.clone());
                validate_api_name(
                    field_api_name.as_str(),
                    format!(
                        "field `{}` on resource `{struct_name}` api_name",
                        field.name
                    )
                    .as_str(),
                )?;
                if !seen_field_api_names.insert(field_api_name.clone()) {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!(
                            "duplicate field api_name `{}` on resource `{struct_name}`",
                            field_api_name
                        ),
                    ));
                }
                (field_api_name, true)
            };
            reject_legacy_field_validation(
                field.legacy_validate.as_ref(),
                format!("field `{}` on resource `{struct_name}`", field.name).as_str(),
            )?;

            let is_id = field.id || field.name == configured_id;
            let generated = match field.generated {
                GeneratedValue::None => infer_generated_value(&field.name, is_id),
                other => other,
            };

            let parsed_ty = parse_field_type(
                &field.ty,
                field.items.as_ref(),
                field.nullable || generated != GeneratedValue::None,
                enums,
            )?;
            let sql_type = infer_sql_type(&parsed_ty.ty, db);
            let object_fields = match &field.ty {
                FieldTypeDocument::Scalar(ScalarType::Object) => {
                    if field.fields.is_empty() {
                        return Err(syn::Error::new(
                            Span::call_site(),
                            format!(
                                "field `{}` on resource `{struct_name}` must set nested `fields` when `type = Object`",
                                field.name
                            ),
                        ));
                    }
                    if is_id {
                        return Err(syn::Error::new(
                            Span::call_site(),
                            format!(
                                "field `{}` on resource `{struct_name}` cannot be an object ID field",
                                field.name
                            ),
                        ));
                    }
                    if field.relation.is_some() {
                        return Err(syn::Error::new(
                            Span::call_site(),
                            format!(
                                "field `{}` on resource `{struct_name}` cannot combine `type = Object` with `relation`",
                                field.name
                            ),
                        ));
                    }
                    if field.validate.is_some() {
                        return Err(syn::Error::new(
                            Span::call_site(),
                            format!(
                                "field `{}` on resource `{struct_name}` only supports nested garde validation through child fields and `dive`/`required`",
                                field.name
                            ),
                        ));
                    }
                    Some(build_object_fields(
                        db,
                        field.fields,
                        format!("resource `{struct_name}` field `{}`", field.name).as_str(),
                        enums,
                    )?)
                }
                _ => {
                    if !field.fields.is_empty() {
                        return Err(syn::Error::new(
                            Span::call_site(),
                            format!(
                                "field `{}` on resource `{struct_name}` can only set nested `fields` when `type = Object`",
                                field.name
                            ),
                        ));
                    }
                    None
                }
            };

            if parsed_ty.list_item_ty.is_some() {
                if is_id {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!(
                            "field `{}` on resource `{struct_name}` cannot be a list ID field",
                            field.name
                        ),
                    ));
                }
                if field.relation.is_some() {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!(
                            "field `{}` on resource `{struct_name}` cannot combine `type = List` with `relation`",
                            field.name
                        ),
                    ));
                }
            }

            let relation = match field.relation {
                Some(relation) => Some(parse_relation_document(relation)?),
                None => None,
            };
            let validation = parse_field_validation_document(field.validate)?;
            let transforms = parse_field_transforms_document(field.transforms)?;

            fields.push(FieldSpec {
                ident: syn::parse_str(&field.name).map_err(|_| {
                    syn::Error::new(
                        Span::call_site(),
                        format!("field name `{}` is not a valid Rust identifier", field.name),
                    )
                })?,
                api_name: field_api_name,
                expose_in_api,
                unique: field.unique,
                enum_name: parsed_ty.enum_name,
                enum_values: parsed_ty.enum_values,
                transforms,
                ty: parsed_ty.ty,
                list_item_ty: parsed_ty.list_item_ty,
                object_fields,
                sql_type,
                is_id,
                generated,
                validation,
                relation,
            });
        }

        if !fields.iter().any(|field| field.name() == configured_id) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("configured id field `{configured_id}` does not exist on `{struct_name}`"),
            ));
        }

        let computed_fields = if has_api_projection_block {
            apply_resource_api_projections(
                &mut fields,
                resource_api.fields.clone(),
                struct_name.as_str(),
                configured_id.as_str(),
            )?
        } else {
            Vec::new()
        };

        let policies = parse_row_policies(resource.policies).map_err(|error| {
            syn::Error::new(
                error.span(),
                format!("failed to parse row policies for `{struct_name}`: {error}"),
            )
        })?;
        let access = parse_resource_access_document(resource.access)?;
        let (default_response_context, response_contexts) = build_response_contexts(
            fields.as_slice(),
            computed_fields.as_slice(),
            resource_api.default_context,
            resource_api.contexts,
            struct_name.as_str(),
        )?;
        let indexes = build_index_specs(resource.indexes);
        let actions = build_resource_action_specs(
            struct_name.as_str(),
            fields.as_slice(),
            &policies,
            resource_actions,
        )?;
        pending_many_to_many.push((struct_name.clone(), resource_many_to_many));

        result.push(ResourceSpec {
            struct_ident: struct_ident.clone(),
            impl_module_ident: default_resource_module_ident(&struct_ident),
            table_name,
            api_name,
            default_response_context,
            response_contexts,
            id_field: configured_id,
            db,
            access,
            roles: resource.roles.with_legacy_defaults(),
            policies,
            list: parse_list_config(resource.list),
            indexes,
            many_to_many: Vec::new(),
            actions,
            computed_fields,
            fields,
            write_style: WriteModelStyle::GeneratedStructWithDtos,
        });
    }

    let resolved_many_to_many = result
        .iter()
        .zip(pending_many_to_many.iter())
        .map(|(resource, (resource_name, documents))| {
            resolve_many_to_many_specs(resource, resource_name.as_str(), documents, &result)
        })
        .collect::<syn::Result<Vec<_>>>()?;

    for (resource, many_to_many) in result.iter_mut().zip(resolved_many_to_many) {
        resource.many_to_many = many_to_many;
    }

    for resource in &result {
        validate_resource_access(resource, Span::call_site())?;
        validate_row_policies(resource, &result, &resource.policies, Span::call_site())?;
        validate_relations(&resource.fields, Span::call_site())?;
        validate_field_validations(&resource.fields, Span::call_site())?;
        validate_field_transforms(&resource.fields, Span::call_site())?;
        validate_list_config(&resource.list, Span::call_site())?;
        validate_resource_indexes(resource, Span::call_site())?;
    }

    Ok(result)
}

pub(super) fn resolve_many_to_many_specs(
    source_resource: &ResourceSpec,
    source_resource_name: &str,
    documents: &[ManyToManyDocument],
    resources: &[ResourceSpec],
) -> syn::Result<Vec<super::super::model::ManyToManySpec>> {
    let mut seen_names = HashSet::new();
    let mut relations = Vec::with_capacity(documents.len());

    for document in documents {
        validate_api_name(
            document.name.as_str(),
            format!(
                "many_to_many `{}` on resource `{source_resource_name}`",
                document.name
            )
            .as_str(),
        )?;
        if !seen_names.insert(document.name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "duplicate many_to_many `{}` on resource `{source_resource_name}`",
                    document.name
                ),
            ));
        }
        validate_sql_identifier(
            document.source_field.as_str(),
            Span::call_site(),
            "many_to_many source_field",
        )?;
        validate_sql_identifier(
            document.target_field.as_str(),
            Span::call_site(),
            "many_to_many target_field",
        )?;

        let target_resource = resolve_resource_selector(
            resources,
            document.target.as_str(),
            format!(
                "many_to_many `{}` on resource `{source_resource_name}` target",
                document.name
            )
            .as_str(),
        )?;
        let through_resource = resolve_resource_selector(
            resources,
            document.through.as_str(),
            format!(
                "many_to_many `{}` on resource `{source_resource_name}` through",
                document.name
            )
            .as_str(),
        )?;

        let source_field = through_resource
            .find_field(document.source_field.as_str())
            .ok_or_else(|| {
                syn::Error::new(
                    Span::call_site(),
                    format!(
                        "many_to_many `{}` on resource `{source_resource_name}` references unknown through field `{}` on `{}`",
                        document.name, document.source_field, through_resource.table_name
                    ),
                )
            })?;
        let source_relation = source_field.relation.as_ref().ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                format!(
                    "many_to_many `{}` on resource `{source_resource_name}` requires through field `{}` on `{}` to declare a relation",
                    document.name, document.source_field, through_resource.table_name
                ),
            )
        })?;
        if source_relation.references_table != source_resource.table_name
            || source_relation.references_field != source_resource.id_field
        {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "many_to_many `{}` on resource `{source_resource_name}` requires through field `{}` on `{}` to reference `{}.{}`",
                    document.name,
                    document.source_field,
                    through_resource.table_name,
                    source_resource.table_name,
                    source_resource.id_field
                ),
            ));
        }

        let target_field = through_resource
            .find_field(document.target_field.as_str())
            .ok_or_else(|| {
                syn::Error::new(
                    Span::call_site(),
                    format!(
                        "many_to_many `{}` on resource `{source_resource_name}` references unknown through field `{}` on `{}`",
                        document.name, document.target_field, through_resource.table_name
                    ),
                )
            })?;
        let target_relation = target_field.relation.as_ref().ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                format!(
                    "many_to_many `{}` on resource `{source_resource_name}` requires through field `{}` on `{}` to declare a relation",
                    document.name, document.target_field, through_resource.table_name
                ),
            )
        })?;
        if target_relation.references_table != target_resource.table_name
            || target_relation.references_field != target_resource.id_field
        {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "many_to_many `{}` on resource `{source_resource_name}` requires through field `{}` on `{}` to reference `{}.{}`",
                    document.name,
                    document.target_field,
                    through_resource.table_name,
                    target_resource.table_name,
                    target_resource.id_field
                ),
            ));
        }

        relations.push(super::super::model::ManyToManySpec {
            name: document.name.clone(),
            target_table: target_resource.table_name.clone(),
            through_table: through_resource.table_name.clone(),
            source_field: document.source_field.clone(),
            target_field: document.target_field.clone(),
        });
    }

    Ok(relations)
}

pub(super) fn resolve_resource_selector<'a>(
    resources: &'a [ResourceSpec],
    selector: &str,
    context: &str,
) -> syn::Result<&'a ResourceSpec> {
    resources
        .iter()
        .find(|resource| {
            resource.struct_ident == sanitize_struct_ident(selector, Span::call_site())
                || resource.table_name == selector
        })
        .ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                format!("{context} references unknown resource `{selector}`"),
            )
        })
}

pub(super) fn build_resource_action_specs(
    resource_name: &str,
    fields: &[FieldSpec],
    policies: &RowPolicies,
    documents: Vec<ResourceActionDocument>,
) -> syn::Result<Vec<ResourceActionSpec>> {
    let controlled_fields = policies
        .controlled_filter_fields()
        .into_iter()
        .chain(
            policies
                .iter_assignments()
                .map(|(_, policy)| policy.field.clone()),
        )
        .collect::<HashSet<_>>();
    let mut seen_names = HashSet::new();
    let mut seen_paths = HashSet::new();
    let mut actions = Vec::with_capacity(documents.len());

    for document in documents {
        validate_api_name(
            document.name.as_str(),
            format!("resource `{resource_name}` action `{}`", document.name).as_str(),
        )?;
        if !seen_names.insert(document.name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "duplicate action `{}` on resource `{resource_name}`",
                    document.name
                ),
            ));
        }
        let path = document.path.unwrap_or_else(|| document.name.clone());
        validate_api_name(
            path.as_str(),
            format!("resource `{resource_name}` action `{}` path", document.name).as_str(),
        )?;
        if !seen_paths.insert(path.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("duplicate action path `{path}` on resource `{resource_name}`",),
            ));
        }

        let target = parse_resource_action_target(
            document.target.as_deref(),
            resource_name,
            document.name.as_str(),
        )?;
        let method = parse_resource_action_method(
            document.method.as_deref(),
            resource_name,
            document.name.as_str(),
        )?;
        let behavior = parse_resource_action_behavior(
            resource_name,
            document.name.as_str(),
            fields,
            &controlled_fields,
            document.behavior,
        )?;
        let input_fields = match &behavior {
            ResourceActionBehaviorSpec::UpdateFields { assignments } => assignments
                .iter()
                .filter_map(|assignment| match &assignment.value {
                    ResourceActionValueSpec::InputField(name) => {
                        Some(ResourceActionInputFieldSpec {
                            name: name.clone(),
                            target_field: assignment.field.clone(),
                        })
                    }
                    ResourceActionValueSpec::Literal(_) => None,
                })
                .collect(),
            ResourceActionBehaviorSpec::DeleteResource => Vec::new(),
        };

        actions.push(ResourceActionSpec {
            name: document.name,
            path,
            target,
            method,
            input_fields,
            behavior,
        });
    }

    Ok(actions)
}

pub(super) fn parse_resource_action_target(
    value: Option<&str>,
    resource_name: &str,
    action_name: &str,
) -> syn::Result<ResourceActionTarget> {
    match value.unwrap_or("Item") {
        "Item" => Ok(ResourceActionTarget::Item),
        other => Err(syn::Error::new(
            Span::call_site(),
            format!(
                "resource `{resource_name}` action `{action_name}` has unsupported target `{other}`; only `Item` is supported"
            ),
        )),
    }
}

pub(super) fn parse_resource_action_method(
    value: Option<&str>,
    resource_name: &str,
    action_name: &str,
) -> syn::Result<ResourceActionMethod> {
    match value.unwrap_or("POST") {
        "POST" => Ok(ResourceActionMethod::Post),
        other => Err(syn::Error::new(
            Span::call_site(),
            format!(
                "resource `{resource_name}` action `{action_name}` has unsupported method `{other}`; only `POST` is supported"
            ),
        )),
    }
}

pub(super) fn parse_resource_action_behavior(
    resource_name: &str,
    action_name: &str,
    fields: &[FieldSpec],
    controlled_fields: &HashSet<String>,
    document: ResourceActionBehaviorDocument,
) -> syn::Result<ResourceActionBehaviorSpec> {
    match document.kind.as_str() {
        "UpdateFields" => {
            if document.set.is_empty() {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "resource `{resource_name}` action `{action_name}` must declare at least one `behavior.set` field"
                    ),
                ));
            }
            let mut seen_input_fields = HashSet::new();
            let assignments = document
                .set
                .into_iter()
                .map(|(field_name, value)| {
                    let Some(field) = fields.iter().find(|field| field.name() == field_name) else {
                        return Err(syn::Error::new(
                            Span::call_site(),
                            format!(
                                "resource `{resource_name}` action `{action_name}` references unknown field `{field_name}`"
                            ),
                        ));
                    };
                    validate_resource_action_assignment_field(
                        resource_name,
                        action_name,
                        field,
                        controlled_fields,
                    )?;
                    Ok(ResourceActionAssignmentSpec {
                        field: field_name,
                        value: match value {
                            ResourceActionAssignmentValueDocument::Literal(value) => {
                                ResourceActionValueSpec::Literal(
                                    normalize_resource_action_field_value(
                                        resource_name,
                                        action_name,
                                        field,
                                        &value,
                                    )?,
                                )
                            }
                            ResourceActionAssignmentValueDocument::Input(input) => {
                                validate_api_name(
                                    input.input.as_str(),
                                    format!(
                                        "resource `{resource_name}` action `{action_name}` input"
                                    )
                                    .as_str(),
                                )?;
                                if !seen_input_fields.insert(input.input.clone()) {
                                    return Err(syn::Error::new(
                                        Span::call_site(),
                                        format!(
                                            "resource `{resource_name}` action `{action_name}` reuses input field `{}` across multiple assignments; duplicate action inputs are not supported yet",
                                            input.input
                                        ),
                                    ));
                                }
                                ResourceActionValueSpec::InputField(input.input)
                            }
                        },
                    })
                })
                .collect::<syn::Result<Vec<_>>>()?;
            Ok(ResourceActionBehaviorSpec::UpdateFields { assignments })
        }
        "DeleteResource" => {
            if !document.set.is_empty() {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "resource `{resource_name}` action `{action_name}` with `DeleteResource` behavior cannot declare `behavior.set` fields"
                    ),
                ));
            }
            Ok(ResourceActionBehaviorSpec::DeleteResource)
        }
        other => Err(syn::Error::new(
            Span::call_site(),
            format!(
                "resource `{resource_name}` action `{action_name}` has unsupported behavior kind `{other}`; only `UpdateFields` and `DeleteResource` are supported"
            ),
        )),
    }
}

pub(super) fn validate_resource_action_assignment_field(
    resource_name: &str,
    action_name: &str,
    field: &FieldSpec,
    controlled_fields: &HashSet<String>,
) -> syn::Result<()> {
    if field.is_id {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "resource `{resource_name}` action `{action_name}` cannot assign id field `{}`",
                field.name()
            ),
        ));
    }
    if field.generated.skip_update_bind() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "resource `{resource_name}` action `{action_name}` cannot assign generated field `{}`",
                field.name()
            ),
        ));
    }
    if controlled_fields.contains(&field.name()) {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "resource `{resource_name}` action `{action_name}` cannot assign policy-controlled field `{}`",
                field.name()
            ),
        ));
    }
    if is_typed_object_field(field)
        || is_list_field(field)
        || is_json_type(&field.ty)
        || is_json_object_type(&field.ty)
        || is_json_array_type(&field.ty)
    {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "resource `{resource_name}` action `{action_name}` only supports scalar assignment fields in the first slice; `{}` is not supported",
                field.name()
            ),
        ));
    }
    Ok(())
}

pub(super) fn normalize_resource_action_field_value(
    resource_name: &str,
    action_name: &str,
    field: &FieldSpec,
    value: &JsonValue,
) -> syn::Result<JsonValue> {
    let label = format!(
        "resource `{resource_name}` action `{action_name}` field `{}`",
        field.name()
    );

    if value.is_null() {
        return if is_optional_type(&field.ty) {
            Ok(JsonValue::Null)
        } else {
            Err(syn::Error::new(
                Span::call_site(),
                format!("{label} cannot be null"),
            ))
        };
    }

    let normalized =
        if let Some(kind) = structured_scalar_kind(&field.ty) {
            let text = value.as_str().ok_or_else(|| {
                syn::Error::new(Span::call_site(), format!("{label} must be a string"))
            })?;
            JsonValue::String(normalize_structured_scalar_action_text(kind, text).map_err(
                |error| syn::Error::new(Span::call_site(), format!("{label} is invalid: {error}")),
            )?)
        } else if super::super::model::is_bool_type(&field.ty) {
            JsonValue::Bool(value.as_bool().ok_or_else(|| {
                syn::Error::new(Span::call_site(), format!("{label} must be a boolean"))
            })?)
        } else {
            match infer_sql_type(&field.ty, DbBackend::Sqlite).as_str() {
                sql_type if super::super::model::is_integer_sql_type(sql_type) => {
                    JsonValue::from(value.as_i64().ok_or_else(|| {
                        syn::Error::new(Span::call_site(), format!("{label} must be an integer"))
                    })?)
                }
                "REAL" => JsonValue::Number(
                    serde_json::Number::from_f64(value.as_f64().ok_or_else(|| {
                        syn::Error::new(Span::call_site(), format!("{label} must be a number"))
                    })?)
                    .ok_or_else(|| {
                        syn::Error::new(
                            Span::call_site(),
                            format!("{label} must be a finite number"),
                        )
                    })?,
                ),
                _ => {
                    let text = value.as_str().ok_or_else(|| {
                        syn::Error::new(Span::call_site(), format!("{label} must be a string"))
                    })?;
                    JsonValue::String(apply_action_field_transforms(field.transforms(), text))
                }
            }
        };

    validate_resource_action_scalar_value(field, &normalized, &label)?;
    Ok(normalized)
}

pub(super) fn normalize_structured_scalar_action_text(
    kind: super::super::model::StructuredScalarKind,
    value: &str,
) -> Result<String, String> {
    Ok(match kind {
        super::super::model::StructuredScalarKind::DateTime => DateTime::parse_from_rfc3339(value)
            .map_err(|error| format!("invalid date-time `{value}`: {error}"))?
            .with_timezone(&Utc)
            .to_rfc3339_opts(SecondsFormat::Micros, false),
        super::super::model::StructuredScalarKind::Date => NaiveDate::parse_from_str(value, "%Y-%m-%d")
            .map_err(|error| format!("invalid date `{value}`: {error}"))?
            .format("%Y-%m-%d")
            .to_string(),
        super::super::model::StructuredScalarKind::Time => value
            .parse::<NaiveTime>()
            .map_err(|error| format!("invalid time `{value}`: {error}"))?
            .format("%H:%M:%S.%6f")
            .to_string(),
        super::super::model::StructuredScalarKind::Uuid => Uuid::parse_str(value)
            .map_err(|error| format!("invalid uuid `{value}`: {error}"))?
            .as_hyphenated()
            .to_string(),
        super::super::model::StructuredScalarKind::Decimal => value
            .parse::<Decimal>()
            .map_err(|error| format!("invalid decimal `{value}`: {error}"))?
            .normalize()
            .to_string(),
        super::super::model::StructuredScalarKind::Json
        | super::super::model::StructuredScalarKind::JsonObject
        | super::super::model::StructuredScalarKind::JsonArray => {
            return Err("JSON scalar fields are not supported in action assignments".to_owned());
        }
    })
}

pub(super) fn apply_action_field_transforms(transforms: &[FieldTransform], value: &str) -> String {
    transforms
        .iter()
        .fold(value.to_owned(), |current, transform| match transform {
            FieldTransform::Trim => current.trim().to_owned(),
            FieldTransform::Lowercase => current.to_lowercase(),
            FieldTransform::CollapseWhitespace => {
                current.split_whitespace().collect::<Vec<_>>().join(" ")
            }
            FieldTransform::Slugify => {
                let mut slug = String::new();
                let mut pending_dash = false;
                for ch in current.chars() {
                    if ch.is_alphanumeric() {
                        if pending_dash && !slug.is_empty() {
                            slug.push('-');
                        }
                        pending_dash = false;
                        for lower in ch.to_lowercase() {
                            slug.push(lower);
                        }
                    } else if !slug.is_empty() {
                        pending_dash = true;
                    }
                }
                slug
            }
        })
}

pub(super) fn validate_resource_action_scalar_value(
    field: &FieldSpec,
    value: &JsonValue,
    label: &str,
) -> syn::Result<()> {
    if let Some(enum_values) = field.enum_values() {
        let text = value.as_str().ok_or_else(|| {
            syn::Error::new(Span::call_site(), format!("{label} must be a string"))
        })?;
        if !enum_values.iter().any(|candidate| candidate == text) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("{label} must be one of: {}", enum_values.join(", ")),
            ));
        }
    }

    if let Some(length) = field.validation.length.as_ref() {
        let text = value.as_str().ok_or_else(|| {
            syn::Error::new(Span::call_site(), format!("{label} must be a string"))
        })?;
        let measured = match length.mode {
            Some(LengthMode::Chars) => text.chars().count(),
            _ => text.len(),
        };
        if let Some(min_length) = length.min
            && measured < min_length
        {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("{label} must have at least {min_length} characters"),
            ));
        }
        if let Some(max_length) = length.max
            && measured > max_length
        {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("{label} must have at most {max_length} characters"),
            ));
        }
        if let Some(equal) = length.equal
            && measured != equal
        {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("{label} must have exactly {equal} characters"),
            ));
        }
    }

    if let Some(range) = field.validation.range.as_ref() {
        match infer_sql_type(&field.ty, DbBackend::Sqlite).as_str() {
            sql_type if super::super::model::is_integer_sql_type(sql_type) => {
                if let Some(NumericBound::Integer(minimum)) = &range.min
                    && value.as_i64().is_some_and(|actual| actual < *minimum)
                {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!("{label} must be at least {minimum}"),
                    ));
                }
                if let Some(NumericBound::Integer(maximum)) = &range.max
                    && value.as_i64().is_some_and(|actual| actual > *maximum)
                {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!("{label} must be at most {maximum}"),
                    ));
                }
                if let Some(NumericBound::Integer(equal)) = &range.equal
                    && value.as_i64().is_some_and(|actual| actual != *equal)
                {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!("{label} must equal {equal}"),
                    ));
                }
            }
            "REAL" => {
                if let Some(minimum) = &range.min
                    && value
                        .as_f64()
                        .is_some_and(|actual| actual < minimum.as_f64())
                {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!("{label} must be at least {}", minimum.as_f64()),
                    ));
                }
                if let Some(maximum) = &range.max
                    && value
                        .as_f64()
                        .is_some_and(|actual| actual > maximum.as_f64())
                {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!("{label} must be at most {}", maximum.as_f64()),
                    ));
                }
                if let Some(equal) = &range.equal
                    && value
                        .as_f64()
                        .is_some_and(|actual| actual != equal.as_f64())
                {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!("{label} must equal {}", equal.as_f64()),
                    ));
                }
            }
            _ => {}
        }
    }

    Ok(())
}

pub(super) fn build_computed_field_spec(
    api_name: &str,
    template: &str,
    available_fields: &[&FieldSpec],
    resource_name: &str,
) -> syn::Result<super::super::model::ComputedFieldSpec> {
    use super::super::model::{ComputedFieldPart, ComputedFieldSpec};

    let mut parts = Vec::new();
    let mut optional = false;
    let mut cursor = 0;

    while let Some(start_offset) = template[cursor..].find('{') {
        let start = cursor + start_offset;
        if start > cursor {
            parts.push(ComputedFieldPart::Literal(
                template[cursor..start].to_owned(),
            ));
        }
        let placeholder_start = start + 1;
        let Some(end_offset) = template[placeholder_start..].find('}') else {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "resource `{resource_name}` computed api field `{api_name}` has an unterminated template placeholder"
                ),
            ));
        };
        let end = placeholder_start + end_offset;
        let field_name = template[placeholder_start..end].trim();
        if field_name.is_empty() {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "resource `{resource_name}` computed api field `{api_name}` has an empty template placeholder"
                ),
            ));
        }
        let Some(field) = available_fields
            .iter()
            .find(|field| field.api_name() == field_name)
        else {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "resource `{resource_name}` computed api field `{api_name}` references unknown API field `{field_name}`"
                ),
            ));
        };
        if !supports_computed_template_field(field) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "resource `{resource_name}` computed api field `{api_name}` cannot interpolate non-scalar API field `{field_name}`"
                ),
            ));
        }
        optional |= super::super::model::is_optional_type(&field.ty);
        parts.push(ComputedFieldPart::Field(field_name.to_owned()));
        cursor = end + 1;
    }

    if cursor < template.len() {
        parts.push(ComputedFieldPart::Literal(template[cursor..].to_owned()));
    }

    if parts.is_empty() {
        parts.push(ComputedFieldPart::Literal(String::new()));
    }

    Ok(ComputedFieldSpec {
        api_name: api_name.to_owned(),
        optional,
        parts,
    })
}

pub(super) fn supports_computed_template_field(field: &FieldSpec) -> bool {
    field.list_item_ty.is_none()
        && field.object_fields.is_none()
        && !super::super::model::is_json_type(&field.ty)
        && !super::super::model::is_json_object_type(&field.ty)
        && !super::super::model::is_json_array_type(&field.ty)
}

pub(super) fn apply_resource_api_projections(
    fields: &mut [FieldSpec],
    projections: Vec<ApiFieldProjectionDocument>,
    resource_name: &str,
    configured_id: &str,
) -> syn::Result<Vec<super::super::model::ComputedFieldSpec>> {
    let mut seen_api_names = HashSet::new();
    let mut seen_storage_fields = HashSet::new();

    for projection in &projections {
        match (&projection.from, &projection.template) {
            (Some(_), None) | (None, Some(_)) => {}
            (Some(_), Some(_)) => {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "resource `{resource_name}` api field `{}` cannot set both `from` and `template`",
                        projection.name
                    ),
                ));
            }
            (None, None) => {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "resource `{resource_name}` api field `{}` must set either `from` or `template`",
                        projection.name
                    ),
                ));
            }
        }
    }

    for projection in projections
        .iter()
        .filter(|projection| projection.from.is_some())
    {
        validate_api_name(
            projection.name.as_str(),
            format!(
                "resource `{resource_name}` api.fields `{}`",
                projection.name
            )
            .as_str(),
        )?;
        if !seen_api_names.insert(projection.name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "duplicate api field projection `{}` on resource `{resource_name}`",
                    projection.name
                ),
            ));
        }
        let storage_field_name = projection
            .from
            .as_ref()
            .expect("projection storage field should exist");
        if !seen_storage_fields.insert(storage_field_name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "resource `{resource_name}` maps storage field `{}` more than once in `api.fields`",
                    storage_field_name
                ),
            ));
        }
        let Some(field) = fields
            .iter_mut()
            .find(|field| field.name() == *storage_field_name)
        else {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "resource `{resource_name}` api field `{}` references unknown storage field `{}`",
                    projection.name, storage_field_name
                ),
            ));
        };
        field.api_name = projection.name.clone();
        field.expose_in_api = true;
    }

    let mut computed_fields = Vec::new();
    let available_fields = fields
        .iter()
        .filter(|field| field.expose_in_api())
        .collect::<Vec<_>>();
    for projection in projections
        .into_iter()
        .filter(|projection| projection.template.is_some())
    {
        validate_api_name(
            projection.name.as_str(),
            format!(
                "resource `{resource_name}` api.fields `{}`",
                projection.name
            )
            .as_str(),
        )?;
        if !seen_api_names.insert(projection.name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "duplicate api field projection `{}` on resource `{resource_name}`",
                    projection.name
                ),
            ));
        }
        let template = projection
            .template
            .as_deref()
            .expect("computed template should exist");
        computed_fields.push(build_computed_field_spec(
            projection.name.as_str(),
            template,
            available_fields.as_slice(),
            resource_name,
        )?);
    }

    if !fields
        .iter()
        .any(|field| field.name() == configured_id && field.expose_in_api())
    {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "resource `{resource_name}` must expose configured id field `{configured_id}` in `api.fields`"
            ),
        ));
    }

    Ok(computed_fields)
}

pub(super) fn build_response_contexts(
    fields: &[FieldSpec],
    computed_fields: &[super::super::model::ComputedFieldSpec],
    default_context: Option<String>,
    contexts: Vec<ResponseContextDocument>,
    resource_name: &str,
) -> syn::Result<(Option<String>, Vec<ResponseContextSpec>)> {
    let mut seen_contexts = HashSet::new();
    let mut parsed_contexts = Vec::with_capacity(contexts.len());

    for context in contexts {
        validate_api_name(
            context.name.as_str(),
            format!("resource `{resource_name}` api.contexts `{}`", context.name).as_str(),
        )?;
        if !seen_contexts.insert(context.name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "duplicate response context `{}` on resource `{resource_name}`",
                    context.name
                ),
            ));
        }

        let mut seen_fields = HashSet::new();
        let mut parsed_fields = Vec::with_capacity(context.fields.len());
        for field_name in context.fields {
            if !seen_fields.insert(field_name.clone()) {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "response context `{}` on resource `{resource_name}` includes field `{field_name}` more than once",
                        context.name
                    ),
                ));
            }
            if !fields
                .iter()
                .any(|field| field.expose_in_api() && field.api_name() == field_name)
                && !computed_fields
                    .iter()
                    .any(|field| field.api_name == field_name)
            {
                return Err(syn::Error::new(
                    Span::call_site(),
                    format!(
                        "response context `{}` on resource `{resource_name}` references unknown API field `{field_name}`",
                        context.name
                    ),
                ));
            }
            parsed_fields.push(field_name);
        }

        parsed_contexts.push(ResponseContextSpec {
            name: context.name,
            fields: parsed_fields,
        });
    }

    if let Some(default_context_name) = default_context {
        validate_api_name(
            default_context_name.as_str(),
            format!("resource `{resource_name}` api.default_context").as_str(),
        )?;
        if !parsed_contexts
            .iter()
            .any(|context| context.name == default_context_name)
        {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "resource `{resource_name}` api.default_context `{default_context_name}` does not match any configured `api.contexts`"
                ),
            ));
        }
        Ok((Some(default_context_name), parsed_contexts))
    } else {
        Ok((None, parsed_contexts))
    }
}

pub(super) fn build_index_specs(indexes: Vec<IndexDocument>) -> Vec<IndexSpec> {
    indexes
        .into_iter()
        .map(|index| IndexSpec {
            fields: index.fields,
            unique: index.unique,
        })
        .collect()
}

pub(super) fn validate_resource_indexes(resource: &ResourceSpec, span: Span) -> syn::Result<()> {
    for field in &resource.fields {
        if !field.unique {
            continue;
        }

        if field.is_id {
            return Err(syn::Error::new(
                span,
                format!(
                    "field `{}` on resource `{}` cannot combine `id` with `unique`",
                    field.name(),
                    resource.struct_ident
                ),
            ));
        }

        if !supports_declared_index(field) {
            return Err(syn::Error::new(
                span,
                format!(
                    "field `{}` on resource `{}` does not support `unique`",
                    field.name(),
                    resource.struct_ident
                ),
            ));
        }
    }

    let mut seen_indexes = HashSet::new();
    for index in &resource.indexes {
        if index.fields.is_empty() {
            return Err(syn::Error::new(
                span,
                format!(
                    "resource `{}` index definitions must declare at least one field",
                    resource.struct_ident
                ),
            ));
        }

        let mut seen_fields = HashSet::new();
        for field_name in &index.fields {
            if !seen_fields.insert(field_name.clone()) {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "resource `{}` index `{}` lists field `{field_name}` more than once",
                        resource.struct_ident,
                        index.name_for_table(resource.table_name.as_str())
                    ),
                ));
            }

            let field = resource.find_field(field_name.as_str()).ok_or_else(|| {
                syn::Error::new(
                    span,
                    format!(
                        "resource `{}` index references unknown field `{field_name}`",
                        resource.struct_ident
                    ),
                )
            })?;
            if !supports_declared_index(field) {
                return Err(syn::Error::new(
                    span,
                    format!(
                        "resource `{}` index references unsupported field `{field_name}`",
                        resource.struct_ident
                    ),
                ));
            }
        }

        let key = format!("{}:{}", index.unique as u8, index.fields.join("\u{1f}"));
        if !seen_indexes.insert(key) {
            return Err(syn::Error::new(
                span,
                format!(
                    "resource `{}` declares duplicate index `{}`",
                    resource.struct_ident,
                    index.name_for_table(resource.table_name.as_str())
                ),
            ));
        }
    }

    Ok(())
}

pub(super) fn build_object_fields(
    db: DbBackend,
    fields: Vec<FieldDocument>,
    context: &str,
    enums: &[EnumSpec],
) -> syn::Result<Vec<FieldSpec>> {
    let mut seen_fields = HashSet::new();
    let mut seen_api_names = HashSet::new();
    let mut result = Vec::with_capacity(fields.len());

    for field in fields {
        if !seen_fields.insert(field.name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!("duplicate nested field `{}` in {context}", field.name),
            ));
        }
        let field_api_name = field.api_name.unwrap_or_else(|| field.name.clone());
        validate_api_name(
            field_api_name.as_str(),
            format!("nested field `{}` in {context} api_name", field.name).as_str(),
        )?;
        if !seen_api_names.insert(field_api_name.clone()) {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "duplicate nested field api_name `{}` in {context}",
                    field_api_name
                ),
            ));
        }
        reject_legacy_field_validation(
            field.legacy_validate.as_ref(),
            format!("nested field `{}` in {context}", field.name).as_str(),
        )?;

        if field.id {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "nested field `{}` in {context} cannot set `id = true`",
                    field.name
                ),
            ));
        }
        if field.generated != GeneratedValue::None {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "nested field `{}` in {context} cannot set `generated`",
                    field.name
                ),
            ));
        }
        if field.relation.is_some() {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "nested field `{}` in {context} cannot set `relation`",
                    field.name
                ),
            ));
        }

        let parsed_ty = parse_field_type(&field.ty, field.items.as_ref(), field.nullable, enums)?;
        let sql_type = infer_sql_type(&parsed_ty.ty, db);
        let nested_context = format!("{context}.{}", field.name);
        if field.unique {
            return Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "nested field `{}` in {context} cannot declare `unique`",
                    field.name
                ),
            ));
        }
        let object_fields = match &field.ty {
            FieldTypeDocument::Scalar(ScalarType::Object) => {
                if field.fields.is_empty() {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!(
                            "nested field `{}` in {context} must set nested `fields` when `type = Object`",
                            field.name
                        ),
                    ));
                }
                if field.validate.is_some() {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!(
                            "nested field `{}` in {context} only supports nested garde validation through child fields and `dive`/`required`",
                            field.name
                        ),
                    ));
                }
                Some(build_object_fields(
                    db,
                    field.fields,
                    nested_context.as_str(),
                    enums,
                )?)
            }
            _ => {
                if !field.fields.is_empty() {
                    return Err(syn::Error::new(
                        Span::call_site(),
                        format!(
                            "nested field `{}` in {context} can only set nested `fields` when `type = Object`",
                            field.name
                        ),
                    ));
                }
                None
            }
        };

        result.push(FieldSpec {
            ident: syn::parse_str(&field.name).map_err(|_| {
                syn::Error::new(
                    Span::call_site(),
                    format!(
                        "nested field name `{}` in {context} is not a valid Rust identifier",
                        field.name
                    ),
                )
            })?,
            api_name: field_api_name,
            expose_in_api: true,
            unique: field.unique,
            enum_name: parsed_ty.enum_name,
            enum_values: parsed_ty.enum_values,
            transforms: parse_field_transforms_document(field.transforms)?,
            ty: parsed_ty.ty,
            list_item_ty: parsed_ty.list_item_ty,
            object_fields,
            sql_type,
            is_id: false,
            generated: GeneratedValue::None,
            validation: parse_field_validation_document(field.validate)?,
            relation: None,
        });
    }

    Ok(result)
}

