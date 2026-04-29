//! Resource struct token generators and supporting helpers.
//!
//! Extracted from [`super`] to keep the parent module focused on the
//! entry-point dispatch functions.
//!
//! ## Cohesion
//! Every function here is concerned with emitting Rust struct definitions
//! for resource types (payload structs, list-query structs, garde attributes,
//! typed-object validator/normalizer boilerplate, and row-deserialization).

use heck::{ToSnakeCase, ToUpperCamelCase};
use proc_macro2::{Literal, TokenStream};
use quote::{format_ident, quote};
use syn::{Path, Type};

use super::super::model::{ResourceSpec, WriteModelStyle};
use super::{
    // Parent-module functions and types (codegen.rs) called from the
    // functions in this module.  Child modules can access private parent
    // items via super::.
    ListBindKind,
    create_payload_field_is_optional, create_payload_field_ty, create_payload_fields,
    enum_values_as_message,
    list_bind_ident, list_bind_kinds,
    list_cursor_payload_ident, list_cursor_value_ident,
    list_filter_field_ty, list_plan_ident,
    list_query_ident, list_response_ident,
    list_sort_field_ident, list_sort_order_ident,
    resource_action_input_struct_tokens,
    update_payload_fields,
};
use crate::authorization::AuthorizationContract;
pub(super) fn resource_struct_tokens(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    authorization: Option<&AuthorizationContract>,
    runtime_crate: &Path,
) -> TokenStream {
    let struct_ident = &resource.struct_ident;
    let create_ident = format_ident!("{struct_ident}Create");
    let update_ident = format_ident!("{struct_ident}Update");
    let garde_helper_defs = garde_validation_helper_defs(resource, runtime_crate);
    let action_input_structs = resource
        .actions
        .iter()
        .filter_map(|action| resource_action_input_struct_tokens(resource, action, runtime_crate))
        .collect::<Vec<_>>();
    let list_query_tokens = list_query_tokens(resource, resources, runtime_crate);
    let generated_from_row = generated_from_row_tokens(resource, runtime_crate);
    let object_validator_defs = typed_object_validator_defs(resource, runtime_crate);
    let fields = resource.api_fields().map(|field| {
        let ident = &field.ident;
        let ty = &field.ty;
        let rename_attr = serde_rename_attr(field.api_name(), &field.name());
        quote! {
            #rename_attr
            pub #ident: #ty,
        }
    });

    let create_fields = create_payload_fields(resource, authorization)
        .into_iter()
        .map(|field| {
            let ident = &field.field.ident;
            let ty = create_payload_field_ty(&field);
            let rename_attr = serde_rename_attr(field.field.api_name(), &field.field.name());
            let garde_attr = garde_field_attr_tokens(
                field.field,
                create_payload_field_is_optional(&field),
                super::super::model::is_optional_type(&field.field.ty),
            );
            quote! {
                #rename_attr
                #garde_attr
                pub #ident: #ty,
            }
        });
    let update_fields = update_payload_fields(resource).into_iter().map(|field| {
        let ident = &field.ident;
        let ty = &field.ty;
        let rename_attr = serde_rename_attr(field.api_name(), &field.name());
        let garde_attr =
            garde_field_attr_tokens(field, super::super::model::is_optional_type(&field.ty), true);
        quote! {
            #rename_attr
            #garde_attr
            pub #ident: #ty,
        }
    });

    match resource.write_style {
        WriteModelStyle::ExistingStructWithDtos => quote! {
            #(#garde_helper_defs)*
            #(#object_validator_defs)*

            #[derive(
                Debug,
                Clone,
                #runtime_crate::serde::Serialize,
                #runtime_crate::serde::Deserialize,
                #runtime_crate::garde::Validate
            )]
            #[garde(allow_unvalidated)]
            pub struct #create_ident {
                #(#create_fields)*
            }

            #[derive(
                Debug,
                Clone,
                #runtime_crate::serde::Serialize,
                #runtime_crate::serde::Deserialize,
                #runtime_crate::garde::Validate
            )]
            #[garde(allow_unvalidated)]
            pub struct #update_ident {
                #(#update_fields)*
            }

            #(#action_input_structs)*

            #list_query_tokens
        },
        WriteModelStyle::GeneratedStructWithDtos => quote! {
            #(#garde_helper_defs)*
            #(#object_validator_defs)*

            #[derive(
                Debug,
                Clone,
                #runtime_crate::serde::Serialize,
                #runtime_crate::serde::Deserialize
            )]
            pub struct #struct_ident {
                #(#fields)*
            }

            #generated_from_row

            #[derive(
                Debug,
                Clone,
                #runtime_crate::serde::Serialize,
                #runtime_crate::serde::Deserialize,
                #runtime_crate::garde::Validate
            )]
            #[garde(allow_unvalidated)]
            pub struct #create_ident {
                #(#create_fields)*
            }

            #[derive(
                Debug,
                Clone,
                #runtime_crate::serde::Serialize,
                #runtime_crate::serde::Deserialize,
                #runtime_crate::garde::Validate
            )]
            #[garde(allow_unvalidated)]
            pub struct #update_ident {
                #(#update_fields)*
            }

            #(#action_input_structs)*

            #list_query_tokens
        },
    }
}

pub(super) fn serde_rename_attr(api_name: &str, storage_name: &str) -> TokenStream {
    if api_name == storage_name {
        quote! {}
    } else {
        let api_name = Literal::string(api_name);
        quote!(#[serde(rename = #api_name)])
    }
}

pub(super) fn garde_validation_error_helper(resource: &ResourceSpec) -> syn::Ident {
    format_ident!(
        "garde_validation_error_{}",
        resource.struct_ident.to_string().to_snake_case()
    )
}

pub(super) fn prefixed_garde_validation_error_helper(resource: &ResourceSpec) -> syn::Ident {
    format_ident!(
        "prefixed_garde_validation_error_{}",
        resource.struct_ident.to_string().to_snake_case()
    )
}

pub(super) fn garde_validation_helper_defs(resource: &ResourceSpec, runtime_crate: &Path) -> Vec<TokenStream> {
    let error_helper = garde_validation_error_helper(resource);
    let prefixed_error_helper = prefixed_garde_validation_error_helper(resource);

    vec![
        quote! {
            #[allow(dead_code)]
            fn #error_helper(
                report: #runtime_crate::garde::Report,
            ) -> (Option<String>, String) {
                match report.iter().next() {
                    Some((path, error)) => {
                        let field = path.to_string();
                        let message = error.to_string();
                        if field.is_empty() {
                            (None, message)
                        } else {
                            (
                                Some(field.clone()),
                                format!("Field `{}` {}", field, message),
                            )
                        }
                    }
                    None => (None, "Validation failed".to_owned()),
                }
            }
        },
        quote! {
            #[allow(dead_code)]
            fn #prefixed_error_helper(
                base_path: &str,
                report: #runtime_crate::garde::Report,
            ) -> (String, String) {
                match report.iter().next() {
                    Some((path, error)) => {
                        let suffix = path.to_string();
                        let field_path = if suffix.is_empty() {
                            base_path.to_owned()
                        } else if base_path.is_empty() {
                            suffix
                        } else {
                            format!("{}.{}", base_path, suffix)
                        };
                        (
                            field_path.clone(),
                            format!("Field `{}` {}", field_path, error),
                        )
                    }
                    None => (
                        base_path.to_owned(),
                        format!("Field `{}` is invalid", base_path),
                    ),
                }
            }
        },
    ]
}

pub(super) fn garde_field_attr_tokens(
    field: &super::super::model::FieldSpec,
    actual_optional: bool,
    emit_required: bool,
) -> TokenStream {
    let mut rules = Vec::new();
    if emit_required && field.validation.required {
        rules.push(quote!(required));
    }

    let nested_rules = garde_rule_tokens_from_validation(&field.validation, false);
    if actual_optional {
        if !nested_rules.is_empty() {
            rules.push(quote!(inner(#(#nested_rules),*)));
        }
    } else {
        rules.extend(nested_rules);
    }

    if rules.is_empty() {
        quote! {}
    } else {
        quote!(#[garde(#(#rules),*)])
    }
}

pub(super) fn garde_rule_tokens_from_validation(
    validation: &super::super::model::FieldValidation,
    include_required: bool,
) -> Vec<TokenStream> {
    let mut rules = Vec::new();

    if include_required && validation.required {
        rules.push(quote!(required));
    }
    if validation.ascii {
        rules.push(quote!(ascii));
    }
    if validation.alphanumeric {
        rules.push(quote!(alphanumeric));
    }
    if validation.email {
        rules.push(quote!(email));
    }
    if validation.url {
        rules.push(quote!(url));
    }
    if validation.ip {
        rules.push(quote!(ip));
    }
    if validation.ipv4 {
        rules.push(quote!(ipv4));
    }
    if validation.ipv6 {
        rules.push(quote!(ipv6));
    }
    if validation.phone_number {
        rules.push(quote!(phone_number));
    }
    if validation.credit_card {
        rules.push(quote!(credit_card));
    }
    if let Some(value) = validation.contains.as_deref() {
        let value = Literal::string(value);
        rules.push(quote!(contains(#value)));
    }
    if let Some(value) = validation.prefix.as_deref() {
        let value = Literal::string(value);
        rules.push(quote!(prefix(#value)));
    }
    if let Some(value) = validation.suffix.as_deref() {
        let value = Literal::string(value);
        rules.push(quote!(suffix(#value)));
    }
    if let Some(value) = validation.pattern.as_deref() {
        let value = Literal::string(value);
        rules.push(quote!(pattern(#value)));
    }
    if let Some(length) = validation.length.as_ref() {
        rules.push(garde_length_rule_tokens(length));
    }
    if let Some(range) = validation.range.as_ref() {
        rules.push(garde_range_rule_tokens(range));
    }
    if let Some(inner) = validation.inner.as_deref() {
        let nested_rules = garde_rule_tokens_from_validation(inner, true);
        if !nested_rules.is_empty() {
            rules.push(quote!(inner(#(#nested_rules),*)));
        }
    }

    rules
}

pub(super) fn garde_length_rule_tokens(length: &super::super::model::LengthValidation) -> TokenStream {
    let mode = length.mode.map(garde_length_mode_tokens);
    let min = length.min.map(Literal::usize_unsuffixed);
    let max = length.max.map(Literal::usize_unsuffixed);
    let equal = length.equal.map(Literal::usize_unsuffixed);

    let mut args = Vec::new();
    if let Some(mode) = mode {
        args.push(quote!(#mode));
    }
    if let Some(min) = min {
        args.push(quote!(min = #min));
    }
    if let Some(max) = max {
        args.push(quote!(max = #max));
    }
    if let Some(equal) = equal {
        args.push(quote!(equal = #equal));
    }

    quote!(length(#(#args),*))
}

pub(super) fn garde_range_rule_tokens(range: &super::super::model::RangeValidation) -> TokenStream {
    let mut args = Vec::new();

    if let Some(min) = range.min.as_ref() {
        let min = numeric_bound_literal(min);
        args.push(quote!(min = #min));
    }
    if let Some(max) = range.max.as_ref() {
        let max = numeric_bound_literal(max);
        args.push(quote!(max = #max));
    }
    if let Some(equal) = range.equal.as_ref() {
        let equal = numeric_bound_literal(equal);
        args.push(quote!(equal = #equal));
    }

    quote!(range(#(#args),*))
}

pub(super) fn garde_length_mode_tokens(mode: super::super::model::LengthMode) -> syn::Ident {
    match mode {
        super::super::model::LengthMode::Simple => format_ident!("simple"),
        super::super::model::LengthMode::Bytes => format_ident!("bytes"),
        super::super::model::LengthMode::Chars => format_ident!("chars"),
        super::super::model::LengthMode::Graphemes => format_ident!("graphemes"),
        super::super::model::LengthMode::Utf16 => format_ident!("utf16"),
    }
}

pub(super) fn numeric_bound_literal(bound: &super::super::model::NumericBound) -> Literal {
    match bound {
        super::super::model::NumericBound::Integer(value) => Literal::i64_unsuffixed(*value),
        super::super::model::NumericBound::Float(value) => Literal::f64_unsuffixed(*value),
    }
}

pub(super) fn typed_object_validator_defs(resource: &ResourceSpec, runtime_crate: &Path) -> Vec<TokenStream> {
    resource
        .api_fields()
        .flat_map(|field| {
            let path = vec![field.name()];
            collect_typed_object_validator_defs(resource, field, &path, runtime_crate)
        })
        .collect()
}

pub(super) fn typed_object_normalizer_defs(resource: &ResourceSpec, runtime_crate: &Path) -> Vec<TokenStream> {
    resource
        .api_fields()
        .flat_map(|field| {
            let path = vec![field.name()];
            collect_typed_object_normalizer_defs(resource, field, &path, runtime_crate)
        })
        .collect()
}

pub(super) fn field_needs_normalization(field: &super::super::model::FieldSpec) -> bool {
    !field.transforms().is_empty()
        || field
            .object_fields
            .as_deref()
            .map(|nested_fields| nested_fields.iter().any(field_needs_normalization))
            .unwrap_or(false)
}

pub(super) fn collect_typed_object_normalizer_defs(
    resource: &ResourceSpec,
    field: &super::super::model::FieldSpec,
    path: &[String],
    runtime_crate: &Path,
) -> Vec<TokenStream> {
    let Some(nested_fields) = field.object_fields.as_deref() else {
        return Vec::new();
    };

    let mut definitions = Vec::new();
    for nested_field in nested_fields {
        let mut nested_path = path.to_vec();
        nested_path.push(nested_field.name());
        definitions.extend(collect_typed_object_normalizer_defs(
            resource,
            nested_field,
            &nested_path,
            runtime_crate,
        ));
    }

    let helper_ident = typed_object_normalizer_ident(resource, path);
    let statements = nested_fields
        .iter()
        .filter_map(|nested_field| {
            let field_name = Literal::string(nested_field.api_name());
            if nested_field.object_fields.is_some() {
                if !field_needs_normalization(nested_field) {
                    return None;
                }
                let mut nested_path = path.to_vec();
                nested_path.push(nested_field.name());
                let nested_helper_ident = typed_object_normalizer_ident(resource, &nested_path);
                Some(quote! {
                    if let Some(value) = object.get_mut(#field_name) {
                        Self::#nested_helper_ident(value);
                    }
                })
            } else if !nested_field.transforms().is_empty() {
                let transform_ops = string_transform_ops(nested_field.transforms());
                Some(quote! {
                    if let Some(value) = object.get_mut(#field_name) {
                        if let #runtime_crate::serde_json::Value::String(value) = value {
                            #(#transform_ops)*
                        }
                    }
                })
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    if statements.is_empty() {
        return definitions;
    }

    definitions.push(quote! {
        fn #helper_ident(value: &mut #runtime_crate::serde_json::Value) {
            let Some(object) = value.as_object_mut() else {
                return;
            };
            #(#statements)*
        }
    });

    definitions
}

pub(super) fn collect_typed_object_validator_defs(
    resource: &ResourceSpec,
    field: &super::super::model::FieldSpec,
    path: &[String],
    runtime_crate: &Path,
) -> Vec<TokenStream> {
    let Some(nested_fields) = field.object_fields.as_deref() else {
        return Vec::new();
    };

    let mut definitions = Vec::new();
    for nested_field in nested_fields {
        let mut nested_path = path.to_vec();
        nested_path.push(nested_field.name());
        definitions.extend(collect_typed_object_validator_defs(
            resource,
            nested_field,
            &nested_path,
            runtime_crate,
        ));
    }

    let struct_ident = typed_object_validator_ident(resource, path);
    let field_defs = nested_fields.iter().map(|nested_field| {
        let ident = &nested_field.ident;
        let mut nested_path = path.to_vec();
        nested_path.push(nested_field.name());
        let ty = typed_object_validator_field_type_tokens(
            resource,
            nested_field,
            &nested_path,
            runtime_crate,
        );
        let rename_attr = serde_rename_attr(nested_field.api_name(), &nested_field.name());
        let garde_attr = garde_field_attr_tokens(
            nested_field,
            super::super::model::is_optional_type(&nested_field.ty),
            true,
        );
        if super::super::model::is_optional_type(&nested_field.ty) {
            quote! {
                #rename_attr
                #garde_attr
                #[serde(default)]
                pub #ident: #ty,
            }
        } else {
            quote! {
                #rename_attr
                #garde_attr
                pub #ident: #ty,
            }
        }
    });
    let validations = nested_fields
        .iter()
        .map(typed_object_validator_field_check_tokens);
    let prefixed_error_helper = prefixed_garde_validation_error_helper(resource);

    definitions.push(quote! {
        #[allow(dead_code)]
        #[derive(
            Debug,
            Clone,
            #runtime_crate::serde::Deserialize,
            #runtime_crate::garde::Validate
        )]
        #[garde(allow_unvalidated)]
        #[serde(deny_unknown_fields)]
        struct #struct_ident {
            #(#field_defs)*
        }

        impl #struct_ident {
            fn validate(&self, base_path: &str) -> Result<(), (String, String)> {
                if let Err(report) = #runtime_crate::garde::Validate::validate(self) {
                    return Err(#prefixed_error_helper(base_path, report));
                }
                #(#validations)*
                Ok(())
            }
        }
    });

    definitions
}

pub(super) fn typed_object_validator_ident(resource: &ResourceSpec, path: &[String]) -> syn::Ident {
    let suffix = path
        .iter()
        .map(|segment| segment.to_upper_camel_case())
        .collect::<String>();
    format_ident!("{}{}ObjectSchema", resource.struct_ident, suffix)
}

pub(super) fn typed_object_normalizer_ident(resource: &ResourceSpec, path: &[String]) -> syn::Ident {
    let suffix = path
        .iter()
        .map(|segment| segment.to_upper_camel_case())
        .collect::<String>();
    format_ident!(
        "normalize_{}_{}_object",
        resource.struct_ident.to_string().to_snake_case(),
        suffix.to_snake_case()
    )
}

pub(super) fn string_transform_ops(transforms: &[super::super::model::FieldTransform]) -> Vec<TokenStream> {
    transforms
        .iter()
        .map(|transform| match transform {
            super::super::model::FieldTransform::Trim => quote! {
                *value = value.trim().to_owned();
            },
            super::super::model::FieldTransform::Lowercase => quote! {
                *value = value.to_lowercase();
            },
            super::super::model::FieldTransform::CollapseWhitespace => quote! {
                *value = value.split_whitespace().collect::<Vec<_>>().join(" ");
            },
            super::super::model::FieldTransform::Slugify => quote! {
                {
                    let mut slug = String::new();
                    let mut pending_dash = false;
                    for ch in value.chars() {
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
                    *value = slug;
                }
            },
        })
        .collect()
}

pub(super) fn typed_object_validator_scalar_type_tokens(ty: &Type, runtime_crate: &Path) -> TokenStream {
    let base_ty = super::super::model::base_type(ty);
    if let Some(kind) = super::super::model::structured_scalar_kind(&base_ty) {
        return match kind {
            super::super::model::StructuredScalarKind::Json => {
                quote!(#runtime_crate::serde_json::Value)
            }
            super::super::model::StructuredScalarKind::JsonObject => {
                quote!(#runtime_crate::serde_json::Map<String, #runtime_crate::serde_json::Value>)
            }
            super::super::model::StructuredScalarKind::JsonArray => {
                quote!(Vec<#runtime_crate::serde_json::Value>)
            }
            _ => structured_scalar_type_tokens(kind, runtime_crate),
        };
    }

    if super::super::model::is_bool_type(&base_ty) {
        quote!(bool)
    } else {
        quote!(#base_ty)
    }
}

pub(super) fn typed_object_validator_list_item_type_tokens(ty: &Type, runtime_crate: &Path) -> TokenStream {
    if let Some(kind) = super::super::model::structured_scalar_kind(ty) {
        return match kind {
            super::super::model::StructuredScalarKind::Json => {
                quote!(#runtime_crate::serde_json::Value)
            }
            super::super::model::StructuredScalarKind::JsonObject => {
                quote!(#runtime_crate::serde_json::Map<String, #runtime_crate::serde_json::Value>)
            }
            super::super::model::StructuredScalarKind::JsonArray => {
                quote!(Vec<#runtime_crate::serde_json::Value>)
            }
            _ => structured_scalar_type_tokens(kind, runtime_crate),
        };
    }

    if super::super::model::is_bool_type(ty) {
        quote!(bool)
    } else {
        quote!(#ty)
    }
}

pub(super) fn typed_object_validator_field_type_tokens(
    resource: &ResourceSpec,
    field: &super::super::model::FieldSpec,
    path: &[String],
    runtime_crate: &Path,
) -> TokenStream {
    let inner_ty = if field.object_fields.is_some() {
        let ident = typed_object_validator_ident(resource, path);
        quote!(#ident)
    } else if let Some(item_ty) = field.list_item_ty.as_ref() {
        let item_ty = typed_object_validator_list_item_type_tokens(item_ty, runtime_crate);
        quote!(Vec<#item_ty>)
    } else {
        typed_object_validator_scalar_type_tokens(&field.ty, runtime_crate)
    };

    if super::super::model::is_optional_type(&field.ty) {
        quote!(Option<#inner_ty>)
    } else {
        inner_ty
    }
}

pub(super) fn typed_object_validator_field_check_tokens(field: &super::super::model::FieldSpec) -> TokenStream {
    let ident = &field.ident;
    let field_name = field.api_name().to_owned();
    let field_name_lit = Literal::string(&field_name);

    if field.object_fields.is_some() {
        return if super::super::model::is_optional_type(&field.ty) {
            quote! {
                if let Some(value) = &self.#ident {
                    let nested_path = format!("{}.{}", base_path, #field_name_lit);
                    value.validate(nested_path.as_str())?;
                }
            }
        } else {
            quote! {
                let nested_path = format!("{}.{}", base_path, #field_name_lit);
                self.#ident.validate(nested_path.as_str())?;
            }
        };
    }

    if field.enum_values().is_none() {
        return quote! {};
    }

    let checks = typed_object_validator_scalar_checks(field);
    if checks.is_empty() {
        return quote! {};
    }

    if super::super::model::is_optional_type(&field.ty) {
        quote! {
            if let Some(value) = &self.#ident {
                let field_path = format!("{}.{}", base_path, #field_name_lit);
                #(#checks)*
            }
        }
    } else {
        quote! {
            let value = &self.#ident;
            let field_path = format!("{}.{}", base_path, #field_name_lit);
            #(#checks)*
        }
    }
}

pub(super) fn typed_object_validator_scalar_checks(field: &super::super::model::FieldSpec) -> Vec<TokenStream> {
    let mut checks = Vec::new();

    if let Some(enum_values) = field.enum_values() {
        let enum_values = enum_values
            .iter()
            .map(|value| Literal::string(value.as_str()))
            .collect::<Vec<_>>();
        let enum_values_message = Literal::string(&enum_values_as_message(field));
        checks.push(quote! {
            if ![#(#enum_values),*].contains(&value.as_str()) {
                return Err((
                    field_path.clone(),
                    format!("Field `{}` must be one of: {}", field_path, #enum_values_message),
                ));
            }
        });
    }

    checks
}

pub(super) fn structured_scalar_type_tokens(
    kind: super::super::model::StructuredScalarKind,
    runtime_crate: &Path,
) -> TokenStream {
    match kind {
        super::super::model::StructuredScalarKind::DateTime => {
            quote!(#runtime_crate::chrono::DateTime<#runtime_crate::chrono::Utc>)
        }
        super::super::model::StructuredScalarKind::Date => quote!(#runtime_crate::chrono::NaiveDate),
        super::super::model::StructuredScalarKind::Time => quote!(#runtime_crate::chrono::NaiveTime),
        super::super::model::StructuredScalarKind::Uuid => quote!(#runtime_crate::uuid::Uuid),
        super::super::model::StructuredScalarKind::Decimal => {
            quote!(#runtime_crate::rust_decimal::Decimal)
        }
        super::super::model::StructuredScalarKind::Json
        | super::super::model::StructuredScalarKind::JsonObject
        | super::super::model::StructuredScalarKind::JsonArray => {
            quote!(#runtime_crate::serde_json::Value)
        }
    }
}

pub(super) fn structured_scalar_to_text_tokens(
    ty: &syn::Type,
    value: TokenStream,
    runtime_crate: &Path,
) -> Option<TokenStream> {
    match super::super::model::structured_scalar_kind(ty)? {
        super::super::model::StructuredScalarKind::DateTime => Some(quote! {
            #value.to_rfc3339_opts(#runtime_crate::chrono::SecondsFormat::Micros, false)
        }),
        super::super::model::StructuredScalarKind::Date => {
            Some(quote!(#value.format("%Y-%m-%d").to_string()))
        }
        super::super::model::StructuredScalarKind::Time => {
            Some(quote!(#value.format("%H:%M:%S.%6f").to_string()))
        }
        super::super::model::StructuredScalarKind::Uuid => {
            Some(quote!(#value.as_hyphenated().to_string()))
        }
        super::super::model::StructuredScalarKind::Decimal => Some(quote!(#value.normalize().to_string())),
        super::super::model::StructuredScalarKind::Json
        | super::super::model::StructuredScalarKind::JsonObject
        | super::super::model::StructuredScalarKind::JsonArray => Some(quote!(
            #runtime_crate::serde_json::to_string(#value).expect("JSON fields should serialize")
        )),
    }
}

pub(super) fn json_bind_tokens(field: &super::super::model::FieldSpec, runtime_crate: &Path) -> Option<TokenStream> {
    if field.list_item_ty.is_some() {
        let ident = &field.ident;
        if super::super::model::is_optional_type(&field.ty) {
            return Some(quote! {
                item.#ident.as_ref().map(|value| {
                    #runtime_crate::serde_json::to_string(value)
                        .expect("list fields should serialize")
                })
            });
        }
        return Some(quote! {
            #runtime_crate::serde_json::to_string(&item.#ident)
                .expect("list fields should serialize")
        });
    }

    match super::super::model::structured_scalar_kind(&field.ty) {
        Some(
            super::super::model::StructuredScalarKind::Json
            | super::super::model::StructuredScalarKind::JsonObject
            | super::super::model::StructuredScalarKind::JsonArray,
        ) => {
            let ident = &field.ident;
            if super::super::model::is_optional_type(&field.ty) {
                Some(quote! {
                    item.#ident.as_ref().map(|value| {
                        #runtime_crate::serde_json::to_string(value)
                            .expect("JSON fields should serialize")
                    })
                })
            } else {
                Some(quote! {
                    #runtime_crate::serde_json::to_string(&item.#ident)
                        .expect("JSON fields should serialize")
                })
            }
        }
        _ => None,
    }
}

pub(super) fn list_field_from_text_tokens(
    base_ty: &Type,
    value_ident: TokenStream,
    field_name_lit: &Literal,
    runtime_crate: &Path,
) -> TokenStream {
    quote! {
        #runtime_crate::serde_json::from_str::<#base_ty>(&#value_ident).map_err(
            |error| #runtime_crate::sqlx::Error::ColumnDecode {
                index: #field_name_lit.to_owned(),
                source: Box::new(error),
            }
        )?
    }
}

pub(super) fn structured_scalar_from_text_tokens(
    kind: super::super::model::StructuredScalarKind,
    base_ty: &Type,
    value_ident: TokenStream,
    field_name_lit: &Literal,
    runtime_crate: &Path,
) -> TokenStream {
    match kind {
        super::super::model::StructuredScalarKind::DateTime
        | super::super::model::StructuredScalarKind::Date
        | super::super::model::StructuredScalarKind::Time
        | super::super::model::StructuredScalarKind::Uuid
        | super::super::model::StructuredScalarKind::Decimal => quote! {
            #value_ident.parse::<#base_ty>().map_err(|error| #runtime_crate::sqlx::Error::ColumnDecode {
                index: #field_name_lit.to_owned(),
                source: Box::new(error),
            })?
        },
        super::super::model::StructuredScalarKind::Json => quote! {
            #runtime_crate::serde_json::from_str::<#base_ty>(&#value_ident).map_err(
                |error| #runtime_crate::sqlx::Error::ColumnDecode {
                    index: #field_name_lit.to_owned(),
                    source: Box::new(error),
                }
            )?
        },
        super::super::model::StructuredScalarKind::JsonObject => quote! {{
            let parsed = #runtime_crate::serde_json::from_str::<#base_ty>(&#value_ident).map_err(
                |error| #runtime_crate::sqlx::Error::ColumnDecode {
                    index: #field_name_lit.to_owned(),
                    source: Box::new(error),
                }
            )?;
            if !matches!(parsed, #runtime_crate::serde_json::Value::Object(_)) {
                return Err(#runtime_crate::sqlx::Error::ColumnDecode {
                    index: #field_name_lit.to_owned(),
                    source: Box::new(::std::io::Error::new(
                        ::std::io::ErrorKind::InvalidData,
                        "expected JSON object",
                    )),
                });
            }
            parsed
        }},
        super::super::model::StructuredScalarKind::JsonArray => quote! {{
            let parsed = #runtime_crate::serde_json::from_str::<#base_ty>(&#value_ident).map_err(
                |error| #runtime_crate::sqlx::Error::ColumnDecode {
                    index: #field_name_lit.to_owned(),
                    source: Box::new(error),
                }
            )?;
            if !matches!(parsed, #runtime_crate::serde_json::Value::Array(_)) {
                return Err(#runtime_crate::sqlx::Error::ColumnDecode {
                    index: #field_name_lit.to_owned(),
                    source: Box::new(::std::io::Error::new(
                        ::std::io::ErrorKind::InvalidData,
                        "expected JSON array",
                    )),
                });
            }
            parsed
        }},
    }
}

pub(super) fn field_supports_sort(field: &super::super::model::FieldSpec) -> bool {
    super::super::model::supports_field_sort(field)
}

pub(super) fn generated_from_row_tokens(resource: &ResourceSpec, runtime_crate: &Path) -> TokenStream {
    let struct_ident = &resource.struct_ident;
    let field_extracts = resource.api_fields().map(|field| {
        let ident = &field.ident;
        let ty = &field.ty;
        let storage_field_name_lit = Literal::string(&field.name());
        let api_field_name_lit = Literal::string(field.api_name());

        if field.list_item_ty.is_some() {
            let base_ty = super::super::model::base_type(&field.ty);
            if super::super::model::is_optional_type(&field.ty) {
                let parsed_value = list_field_from_text_tokens(
                    &base_ty,
                    quote!(value),
                    &storage_field_name_lit,
                    runtime_crate,
                );
                quote! {
                    let #ident: #ty = match #runtime_crate::sqlx::Row::try_get::<Option<String>, _>(row, #storage_field_name_lit)? {
                        Some(value) => Some(#parsed_value),
                        None => None,
                    };
                }
            } else {
                let parsed_value = list_field_from_text_tokens(
                    &base_ty,
                    quote!(value),
                    &storage_field_name_lit,
                    runtime_crate,
                );
                quote! {
                    let #ident: #ty = {
                        let value = #runtime_crate::sqlx::Row::try_get::<String, _>(row, #storage_field_name_lit)?;
                        #parsed_value
                    };
                }
            }
        } else if super::super::model::is_structured_scalar_type(&field.ty) {
            let base_ty = super::super::model::base_type(&field.ty);
            let kind = super::super::model::structured_scalar_kind(&field.ty)
                .expect("structured scalar kind should exist");
            let parsed_value = if kind == super::super::model::StructuredScalarKind::JsonObject
                && field.object_fields.is_some()
            {
                let validator_ident =
                    typed_object_validator_ident(resource, &[field.name()]);
                quote! {{
                    let parsed = #runtime_crate::serde_json::from_str::<#base_ty>(&value).map_err(
                        |error| #runtime_crate::sqlx::Error::ColumnDecode {
                            index: #storage_field_name_lit.to_owned(),
                            source: Box::new(error),
                        }
                    )?;
                    let validated: #validator_ident = #runtime_crate::serde_json::from_value(parsed.clone()).map_err(
                        |error| #runtime_crate::sqlx::Error::ColumnDecode {
                            index: #storage_field_name_lit.to_owned(),
                            source: Box::new(::std::io::Error::new(
                                ::std::io::ErrorKind::InvalidData,
                                format!("Field `{}` is invalid: {}", #api_field_name_lit, error),
                            )),
                        }
                    )?;
                    if let Err((_field_path, message)) = validated.validate(#api_field_name_lit) {
                        return Err(#runtime_crate::sqlx::Error::ColumnDecode {
                            index: #storage_field_name_lit.to_owned(),
                            source: Box::new(::std::io::Error::new(
                                ::std::io::ErrorKind::InvalidData,
                                message,
                            )),
                        });
                    }
                    parsed
                }}
            } else {
                structured_scalar_from_text_tokens(
                    kind,
                    &base_ty,
                    quote!(value),
                    &storage_field_name_lit,
                    runtime_crate,
                )
            };
            if super::super::model::is_optional_type(&field.ty) {
                quote! {
                    let #ident: #ty = match #runtime_crate::sqlx::Row::try_get::<Option<String>, _>(row, #storage_field_name_lit)? {
                        Some(value) => Some(#parsed_value),
                        None => None,
                    };
                }
            } else {
                quote! {
                    let #ident: #ty = {
                        let value = #runtime_crate::sqlx::Row::try_get::<String, _>(row, #storage_field_name_lit)?;
                        #parsed_value
                    };
                }
            }
        } else if super::super::model::is_bool_type(&field.ty) {
            if super::super::model::is_optional_type(&field.ty) {
                quote! {
                    let #ident: #ty = match #runtime_crate::sqlx::Row::try_get::<Option<bool>, _>(row, #storage_field_name_lit) {
                        Ok(value) => value,
                        Err(#runtime_crate::sqlx::Error::ColumnDecode { .. }) => {
                            match #runtime_crate::sqlx::Row::try_get::<Option<i64>, _>(row, #storage_field_name_lit) {
                                Ok(value) => value.map(|value| value != 0),
                                Err(#runtime_crate::sqlx::Error::ColumnDecode { .. }) => {
                                    #runtime_crate::sqlx::Row::try_get::<Option<i32>, _>(row, #storage_field_name_lit)?
                                        .map(|value| value != 0)
                                }
                                Err(error) => return Err(error),
                            }
                        }
                        Err(error) => return Err(error),
                    };
                }
            } else {
                quote! {
                    let #ident: #ty = match #runtime_crate::sqlx::Row::try_get::<bool, _>(row, #storage_field_name_lit) {
                        Ok(value) => value,
                        Err(#runtime_crate::sqlx::Error::ColumnDecode { .. }) => {
                            match #runtime_crate::sqlx::Row::try_get::<i64, _>(row, #storage_field_name_lit) {
                                Ok(value) => value != 0,
                                Err(#runtime_crate::sqlx::Error::ColumnDecode { .. }) => {
                                    #runtime_crate::sqlx::Row::try_get::<i32, _>(row, #storage_field_name_lit)? != 0
                                }
                                Err(error) => return Err(error),
                            }
                        }
                        Err(error) => return Err(error),
                    };
                }
            }
        } else {
            quote! {
                let #ident: #ty = #runtime_crate::sqlx::Row::try_get(row, #storage_field_name_lit)?;
            }
        }
    });
    let field_names = resource.api_fields().map(|field| &field.ident);

    quote! {
        impl<'r> #runtime_crate::sqlx::FromRow<'r, #runtime_crate::sqlx::any::AnyRow> for #struct_ident {
            fn from_row(row: &'r #runtime_crate::sqlx::any::AnyRow) -> Result<Self, #runtime_crate::sqlx::Error> {
                #(#field_extracts)*

                Ok(Self {
                    #(#field_names),*
                })
            }
        }
    }
}

pub(super) fn list_query_tokens(
    resource: &ResourceSpec,
    resources: &[ResourceSpec],
    runtime_crate: &Path,
) -> TokenStream {
    let list_query_ident = list_query_ident(resource);
    let sort_field_ident = list_sort_field_ident(resource);
    let sort_order_ident = list_sort_order_ident(resource);
    let bind_ident = list_bind_ident(resource);
    let response_ident = list_response_ident(resource);
    let plan_ident = list_plan_ident(resource);
    let cursor_value_ident = list_cursor_value_ident(resource);
    let cursor_payload_ident = list_cursor_payload_ident(resource);
    let struct_ident = &resource.struct_ident;
    let bind_variants = list_bind_kinds(resource, resources)
        .into_iter()
        .map(|kind| match kind {
            ListBindKind::Integer => quote!(Integer(i64),),
            ListBindKind::Real => quote!(Real(f64),),
            ListBindKind::Boolean => quote!(Boolean(bool),),
            ListBindKind::Text => quote!(Text(String),),
        })
        .collect::<Vec<_>>();
    let sortable_fields = resource
        .api_fields()
        .filter(|field| field_supports_sort(field))
        .collect::<Vec<_>>();
    let filter_fields = resource.api_fields().flat_map(|field| {
        let mut tokens = Vec::new();

        if super::super::model::supports_exact_filters(field) {
            let filter_ident = format_ident!("filter_{}", field.ident);
            let base_ty = list_filter_field_ty(field, runtime_crate);
            let rename = Literal::string(&format!("filter_{}", field.api_name()));
            tokens.push(quote! {
                #[serde(rename = #rename)]
                pub #filter_ident: Option<#base_ty>,
            });
        }

        if super::super::model::supports_contains_filters(field) {
            let contains_ident = format_ident!("filter_{}_contains", field.ident);
            let rename = Literal::string(&format!("filter_{}_contains", field.api_name()));
            tokens.push(quote! {
                #[serde(rename = #rename)]
                pub #contains_ident: Option<String>,
            });
        }

        if super::super::model::supports_exact_filters(field)
            && super::super::model::supports_range_filters(&field.ty)
        {
            for suffix in ["gt", "gte", "lt", "lte"] {
                let ident = format_ident!("filter_{}_{}", field.ident, suffix);
                let range_ty = list_filter_field_ty(field, runtime_crate);
                let rename = Literal::string(&format!("filter_{}_{}", field.api_name(), suffix));
                tokens.push(quote! {
                    #[serde(rename = #rename)]
                    pub #ident: Option<#range_ty>,
                });
            }
        }

        tokens
    });
    let sort_variants = sortable_fields.iter().map(|field| {
        let variant_ident = super::super::model::sanitize_struct_ident(&field.name(), field.ident.span());
        let field_name = Literal::string(field.api_name());
        quote! {
            #[serde(rename = #field_name)]
            #variant_ident,
        }
    });
    let sort_variant_sql = sortable_fields.iter().map(|field| {
        let variant_ident = super::super::model::sanitize_struct_ident(&field.name(), field.ident.span());
        let field_name = Literal::string(&field.name());
        quote! {
            Self::#variant_ident => #field_name,
        }
    });
    let sort_variant_name = sortable_fields.iter().map(|field| {
        let variant_ident = super::super::model::sanitize_struct_ident(&field.name(), field.ident.span());
        let field_name = Literal::string(field.api_name());
        quote! {
            Self::#variant_ident => #field_name,
        }
    });
    let sort_variant_parse = sortable_fields.iter().map(|field| {
        let variant_ident = super::super::model::sanitize_struct_ident(&field.name(), field.ident.span());
        let field_name = Literal::string(field.api_name());
        quote! {
            #field_name => Some(Self::#variant_ident),
        }
    });

    quote! {
        #[derive(Debug, Clone, #runtime_crate::serde::Deserialize, Default)]
        #[serde(default, deny_unknown_fields)]
        pub struct #list_query_ident {
            pub limit: Option<u32>,
            pub offset: Option<u32>,
            pub sort: Option<#sort_field_ident>,
            pub order: Option<#sort_order_ident>,
            pub cursor: Option<String>,
            pub context: Option<String>,
            #(#filter_fields)*
        }

        #[derive(Debug, Clone, #runtime_crate::serde::Deserialize)]
        #[serde(rename_all = "lowercase")]
        pub enum #sort_order_ident {
            Asc,
            Desc,
        }

        impl #sort_order_ident {
            fn as_sql(&self) -> &'static str {
                match self {
                    Self::Asc => "ASC",
                    Self::Desc => "DESC",
                }
            }

            fn as_str(&self) -> &'static str {
                match self {
                    Self::Asc => "asc",
                    Self::Desc => "desc",
                }
            }

            fn parse(value: &str) -> Option<Self> {
                match value {
                    "asc" => Some(Self::Asc),
                    "desc" => Some(Self::Desc),
                    _ => None,
                }
            }
        }

        #[derive(Debug, Clone, #runtime_crate::serde::Deserialize)]
        pub enum #sort_field_ident {
            #(#sort_variants)*
        }

        impl #sort_field_ident {
            fn as_sql(&self) -> &'static str {
                match self {
                    #(#sort_variant_sql)*
                }
            }

            fn as_name(&self) -> &'static str {
                match self {
                    #(#sort_variant_name)*
                }
            }

            fn from_name(value: &str) -> Option<Self> {
                match value {
                    #(#sort_variant_parse)*
                    _ => None,
                }
            }
        }

        #[derive(Debug, Clone)]
        enum #bind_ident {
            #(#bind_variants)*
        }

        #[derive(Debug, Clone, #runtime_crate::serde::Serialize, #runtime_crate::serde::Deserialize)]
        enum #cursor_value_ident {
            Integer(i64),
            Real(f64),
            Boolean(bool),
            Text(String),
        }

        #[derive(Debug, Clone, #runtime_crate::serde::Serialize, #runtime_crate::serde::Deserialize)]
        struct #cursor_payload_ident {
            sort: String,
            order: String,
            last_id: i64,
            value: #cursor_value_ident,
        }

        #[derive(Debug)]
        struct #plan_ident {
            select_sql: String,
            count_sql: String,
            filter_binds: Vec<#bind_ident>,
            select_binds: Vec<#bind_ident>,
            limit: Option<u32>,
            offset: u32,
            sort: #sort_field_ident,
            order: #sort_order_ident,
            cursor_mode: bool,
        }

        #[derive(Debug, Clone, #runtime_crate::serde::Serialize, #runtime_crate::serde::Deserialize)]
        pub struct #response_ident {
            pub items: Vec<#struct_ident>,
            pub total: i64,
            pub count: usize,
            pub limit: Option<u32>,
            pub offset: u32,
            pub next_offset: Option<u32>,
            pub next_cursor: Option<String>,
        }
    }
}
