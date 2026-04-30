//! Typed-object and structured-scalar token generators.
//!
//! Helpers for:
//! - Typed-object validator / normalizer def generators
//!   (`typed_object_validator_defs`, `collect_typed_object_validator_defs`, …)
//! - Typed-object ident builders
//!   (`typed_object_validator_ident`, `typed_object_normalizer_ident`)
//! - Field transform / normalization helpers (`string_transform_ops`)
//! - Structured-scalar type / text-encoding helpers
//!   (`structured_scalar_type_tokens`, `structured_scalar_to_text_tokens`, …)
//! - JSON / list bind helpers (`json_bind_tokens`, `list_field_from_text_tokens`)
//! - Sort-support predicate (`field_supports_sort`)
//!
//! Extracted from `resource_struct_tokens.rs` to keep that module focused on
//! struct-shape generation and row-deserialization.  These helpers are
//! consumed by `resource_struct_tokens.rs`, `resource_impl.rs`,
//! `payload_tokens.rs`, and `list_tokens.rs` via the parent-module glob
//! re-export.

use heck::{ToSnakeCase, ToUpperCamelCase};
use proc_macro2::{Literal, TokenStream};
use quote::{format_ident, quote};
use syn::{Path, Type};

use super::super::model::{
    FieldSpec, FieldTransform, ResourceSpec, StructuredScalarKind,
    base_type, is_bool_type, is_optional_type, structured_scalar_kind,
    supports_field_sort,
};

// Items from sibling modules accessible via the parent glob re-export.
use super::{
    enum_values_as_message,
    garde_field_attr_tokens,
    prefixed_garde_validation_error_helper,
    serde_rename_attr,
};

// ─── Typed-object validator / normalizer defs ─────────────────────────────────

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

pub(super) fn field_needs_normalization(field: &FieldSpec) -> bool {
    !field.transforms().is_empty()
        || field
            .object_fields
            .as_deref()
            .map(|nested_fields| nested_fields.iter().any(field_needs_normalization))
            .unwrap_or(false)
}

pub(super) fn collect_typed_object_normalizer_defs(
    resource: &ResourceSpec,
    field: &FieldSpec,
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
    field: &FieldSpec,
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
            is_optional_type(&nested_field.ty),
            true,
        );
        if is_optional_type(&nested_field.ty) {
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

// ─── Typed-object ident builders ─────────────────────────────────────────────

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

// ─── Field transform / normalization helpers ──────────────────────────────────

pub(super) fn string_transform_ops(transforms: &[FieldTransform]) -> Vec<TokenStream> {
    transforms
        .iter()
        .map(|transform| match transform {
            FieldTransform::Trim => quote! {
                *value = value.trim().to_owned();
            },
            FieldTransform::Lowercase => quote! {
                *value = value.to_lowercase();
            },
            FieldTransform::CollapseWhitespace => quote! {
                *value = value.split_whitespace().collect::<Vec<_>>().join(" ");
            },
            FieldTransform::Slugify => quote! {
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

// ─── Typed-object validator scalar/field helpers ──────────────────────────────

pub(super) fn typed_object_validator_scalar_type_tokens(ty: &Type, runtime_crate: &Path) -> TokenStream {
    let base_ty = base_type(ty);
    if let Some(kind) = structured_scalar_kind(&base_ty) {
        return match kind {
            StructuredScalarKind::Json => {
                quote!(#runtime_crate::serde_json::Value)
            }
            StructuredScalarKind::JsonObject => {
                quote!(#runtime_crate::serde_json::Map<String, #runtime_crate::serde_json::Value>)
            }
            StructuredScalarKind::JsonArray => {
                quote!(Vec<#runtime_crate::serde_json::Value>)
            }
            _ => structured_scalar_type_tokens(kind, runtime_crate),
        };
    }

    if is_bool_type(&base_ty) {
        quote!(bool)
    } else {
        quote!(#base_ty)
    }
}

pub(super) fn typed_object_validator_list_item_type_tokens(ty: &Type, runtime_crate: &Path) -> TokenStream {
    if let Some(kind) = structured_scalar_kind(ty) {
        return match kind {
            StructuredScalarKind::Json => {
                quote!(#runtime_crate::serde_json::Value)
            }
            StructuredScalarKind::JsonObject => {
                quote!(#runtime_crate::serde_json::Map<String, #runtime_crate::serde_json::Value>)
            }
            StructuredScalarKind::JsonArray => {
                quote!(Vec<#runtime_crate::serde_json::Value>)
            }
            _ => structured_scalar_type_tokens(kind, runtime_crate),
        };
    }

    if is_bool_type(ty) {
        quote!(bool)
    } else {
        quote!(#ty)
    }
}

pub(super) fn typed_object_validator_field_type_tokens(
    resource: &ResourceSpec,
    field: &FieldSpec,
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

    if is_optional_type(&field.ty) {
        quote!(Option<#inner_ty>)
    } else {
        inner_ty
    }
}

pub(super) fn typed_object_validator_field_check_tokens(field: &FieldSpec) -> TokenStream {
    let ident = &field.ident;
    let field_name = field.api_name().to_owned();
    let field_name_lit = Literal::string(&field_name);

    if field.object_fields.is_some() {
        return if is_optional_type(&field.ty) {
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

    if is_optional_type(&field.ty) {
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

pub(super) fn typed_object_validator_scalar_checks(field: &FieldSpec) -> Vec<TokenStream> {
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

// ─── Structured-scalar type / encoding helpers ────────────────────────────────

pub(super) fn structured_scalar_type_tokens(
    kind: StructuredScalarKind,
    runtime_crate: &Path,
) -> TokenStream {
    match kind {
        StructuredScalarKind::DateTime => {
            quote!(#runtime_crate::chrono::DateTime<#runtime_crate::chrono::Utc>)
        }
        StructuredScalarKind::Date => quote!(#runtime_crate::chrono::NaiveDate),
        StructuredScalarKind::Time => quote!(#runtime_crate::chrono::NaiveTime),
        StructuredScalarKind::Uuid => quote!(#runtime_crate::uuid::Uuid),
        StructuredScalarKind::Decimal => {
            quote!(#runtime_crate::rust_decimal::Decimal)
        }
        StructuredScalarKind::Json
        | StructuredScalarKind::JsonObject
        | StructuredScalarKind::JsonArray => {
            quote!(#runtime_crate::serde_json::Value)
        }
    }
}

pub(super) fn structured_scalar_to_text_tokens(
    ty: &syn::Type,
    value: TokenStream,
    runtime_crate: &Path,
) -> Option<TokenStream> {
    match structured_scalar_kind(ty)? {
        StructuredScalarKind::DateTime => Some(quote! {
            #value.to_rfc3339_opts(#runtime_crate::chrono::SecondsFormat::Micros, false)
        }),
        StructuredScalarKind::Date => {
            Some(quote!(#value.format("%Y-%m-%d").to_string()))
        }
        StructuredScalarKind::Time => {
            Some(quote!(#value.format("%H:%M:%S.%6f").to_string()))
        }
        StructuredScalarKind::Uuid => {
            Some(quote!(#value.as_hyphenated().to_string()))
        }
        StructuredScalarKind::Decimal => Some(quote!(#value.normalize().to_string())),
        StructuredScalarKind::Json
        | StructuredScalarKind::JsonObject
        | StructuredScalarKind::JsonArray => Some(quote!(
            #runtime_crate::serde_json::to_string(#value).expect("JSON fields should serialize")
        )),
    }
}

pub(super) fn json_bind_tokens(field: &FieldSpec, runtime_crate: &Path) -> Option<TokenStream> {
    if field.list_item_ty.is_some() {
        let ident = &field.ident;
        if is_optional_type(&field.ty) {
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

    match structured_scalar_kind(&field.ty) {
        Some(
            StructuredScalarKind::Json
            | StructuredScalarKind::JsonObject
            | StructuredScalarKind::JsonArray,
        ) => {
            let ident = &field.ident;
            if is_optional_type(&field.ty) {
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
    kind: StructuredScalarKind,
    base_ty: &Type,
    value_ident: TokenStream,
    field_name_lit: &Literal,
    runtime_crate: &Path,
) -> TokenStream {
    match kind {
        StructuredScalarKind::DateTime
        | StructuredScalarKind::Date
        | StructuredScalarKind::Time
        | StructuredScalarKind::Uuid
        | StructuredScalarKind::Decimal => quote! {
            #value_ident.parse::<#base_ty>().map_err(|error| #runtime_crate::sqlx::Error::ColumnDecode {
                index: #field_name_lit.to_owned(),
                source: Box::new(error),
            })?
        },
        StructuredScalarKind::Json => quote! {
            #runtime_crate::serde_json::from_str::<#base_ty>(&#value_ident).map_err(
                |error| #runtime_crate::sqlx::Error::ColumnDecode {
                    index: #field_name_lit.to_owned(),
                    source: Box::new(error),
                }
            )?
        },
        StructuredScalarKind::JsonObject => quote! {{
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
        StructuredScalarKind::JsonArray => quote! {{
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

// ─── Sort support ─────────────────────────────────────────────────────────────

pub(super) fn field_supports_sort(field: &FieldSpec) -> bool {
    supports_field_sort(field)
}
