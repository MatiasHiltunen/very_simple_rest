//! Payload, bind, normalization, and validation token generators.
//!
//! Contains helpers for:
//! - Payload type idents (`CreatePayloadField`, `create_payload_fields`, …)
//! - Field bind helpers (`bind_field_value_tokens`, `integer_to_i64_tokens`)
//! - Normalization token generators (`normalization_tokens`, …)
//! - Validation token generators (`create_validation_tokens`, …)
//!
//! Extracted from `codegen.rs` to keep the parent module focused on
//! entry-point dispatch.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Path, Type};

use super::super::model::{
    FieldSpec, PolicyValueSource, ResourceSpec, WriteModelStyle,
    base_type, is_optional_type, structured_scalar_kind,
};
use crate::authorization::AuthorizationContract;

use super::{
    // from codegen.rs parent
    hybrid_resource_enforcement,
    // from policy_plan_tokens (via parent namespace)
    create_assignment_source,
    policy_controlled_fields,
    validation_tokens,
    // from resource_struct_tokens (via parent namespace)
    field_needs_normalization,
    string_transform_ops,
    typed_object_normalizer_ident,
};

pub(super) fn create_payload_type(resource: &ResourceSpec) -> TokenStream {
    match resource.write_style {
        WriteModelStyle::ExistingStructWithDtos | WriteModelStyle::GeneratedStructWithDtos => {
            let ident = format_ident!("{}Create", resource.struct_ident);
            quote!(#ident)
        }
    }
}

pub(super) fn update_payload_type(resource: &ResourceSpec) -> TokenStream {
    match resource.write_style {
        WriteModelStyle::ExistingStructWithDtos | WriteModelStyle::GeneratedStructWithDtos => {
            let ident = format_ident!("{}Update", resource.struct_ident);
            quote!(#ident)
        }
    }
}

pub(super) struct CreatePayloadField<'a> {
    pub(super) field: &'a FieldSpec,
    pub(super) allow_admin_override: bool,
    pub(super) allow_hybrid_runtime: bool,
}

pub(super) fn create_payload_fields<'a>(
    resource: &'a ResourceSpec,
    authorization: Option<&'a AuthorizationContract>,
) -> Vec<CreatePayloadField<'a>> {
    let hybrid_create_scope_field = hybrid_resource_enforcement(resource, authorization)
        .filter(|config| config.create_payload)
        .map(|config| config.scope_field.name());
    resource
        .fields
        .iter()
        .filter_map(|field| {
            if field.generated.skip_insert() {
                return None;
            }

            let controlled = create_assignment_source(resource, &field.name()).is_some();
            let allow_admin_override = controlled
                && resource.policies.admin_bypass
                && matches!(
                    create_assignment_source(resource, &field.name()),
                    Some(PolicyValueSource::Claim(_))
                );
            let allow_hybrid_runtime =
                controlled && hybrid_create_scope_field.as_deref() == Some(field.name().as_str());
            if controlled && !allow_admin_override && !allow_hybrid_runtime {
                return None;
            }

            Some(CreatePayloadField {
                field,
                allow_admin_override,
                allow_hybrid_runtime,
            })
        })
        .collect()
}

pub(super) fn create_payload_field_ty(field: &CreatePayloadField<'_>) -> syn::Type {
    if (field.allow_admin_override || field.allow_hybrid_runtime)
        && !is_optional_type(&field.field.ty)
    {
        let ty = &field.field.ty;
        syn::parse_quote!(Option<#ty>)
    } else {
        field.field.ty.clone()
    }
}

pub(super) fn create_payload_field_is_optional(field: &CreatePayloadField<'_>) -> bool {
    field.allow_admin_override
        || field.allow_hybrid_runtime
        || is_optional_type(&field.field.ty)
}

fn type_leaf_name(ty: &Type) -> Option<String> {
    match base_type(ty) {
        Type::Path(type_path) => type_path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        _ => None,
    }
}

fn type_is_copy_like(ty: &Type) -> bool {
    if structured_scalar_kind(ty).is_some() {
        return true;
    }

    matches!(
        type_leaf_name(ty).as_deref(),
        Some(
            "bool"
                | "i8"
                | "i16"
                | "i32"
                | "i64"
                | "isize"
                | "u8"
                | "u16"
                | "u32"
                | "u64"
                | "usize"
                | "f32"
                | "f64"
        )
    )
}

pub(super) fn bind_field_value_tokens(field: &FieldSpec, expr: TokenStream) -> TokenStream {
    if type_is_copy_like(&field.ty) {
        quote!(#expr)
    } else {
        quote!((#expr).clone())
    }
}

pub(super) fn integer_to_i64_tokens(ty: &Type, expr: TokenStream) -> TokenStream {
    match type_leaf_name(ty).as_deref() {
        Some("i64") => quote!(#expr),
        _ => quote!((#expr) as i64),
    }
}

pub(super) fn update_payload_fields(resource: &ResourceSpec) -> Vec<&FieldSpec> {
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

pub(super) fn garde_validate_item_tokens(error_helper: &syn::Ident, runtime_crate: &Path) -> TokenStream {
    quote! {
        if let Err(report) = #runtime_crate::garde::Validate::validate(&item) {
            let (field, message) = super::#error_helper(report);
            return match field {
                Some(field) => #runtime_crate::core::errors::validation_error(field, message),
                None => #runtime_crate::core::errors::bad_request("validation_error", message),
            };
        }
    }
}

pub(super) fn create_validation_tokens(
    resource: &ResourceSpec,
    authorization: Option<&AuthorizationContract>,
    runtime_crate: &Path,
) -> Vec<TokenStream> {
    create_payload_fields(resource, authorization)
        .into_iter()
        .filter_map(|field| {
            validation_tokens(
                resource,
                field.field,
                &field.field.ident,
                create_payload_field_is_optional(&field),
                runtime_crate,
            )
        })
        .collect()
}

pub(super) fn create_normalization_tokens(
    resource: &ResourceSpec,
    authorization: Option<&AuthorizationContract>,
) -> Vec<TokenStream> {
    create_payload_fields(resource, authorization)
        .into_iter()
        .filter_map(|field| {
            normalization_tokens(
                resource,
                field.field,
                &field.field.ident,
                create_payload_field_is_optional(&field),
            )
        })
        .collect()
}

pub(super) fn update_normalization_tokens(resource: &ResourceSpec) -> Vec<TokenStream> {
    update_payload_fields(resource)
        .into_iter()
        .filter_map(|field| {
            normalization_tokens(
                resource,
                field,
                &field.ident,
                is_optional_type(&field.ty),
            )
        })
        .collect()
}

pub(super) fn normalization_tokens(
    resource: &ResourceSpec,
    field: &FieldSpec,
    ident: &syn::Ident,
    optional: bool,
) -> Option<TokenStream> {
    if let Some(_nested_fields) = field.object_fields.as_deref() {
        if !field_needs_normalization(field) {
            return None;
        }
        let helper_ident = typed_object_normalizer_ident(resource, &[field.name()]);
        return Some(if optional {
            quote! {
                if let Some(value) = &mut item.#ident {
                    Self::#helper_ident(value);
                }
            }
        } else {
            quote! {
                Self::#helper_ident(&mut item.#ident);
            }
        });
    }

    if field.transforms().is_empty() {
        return None;
    }

    let transform_ops = string_transform_ops(field.transforms());
    Some(if optional {
        quote! {
            if let Some(value) = &mut item.#ident {
                #(#transform_ops)*
            }
        }
    } else {
        quote! {
            {
                let value = &mut item.#ident;
                #(#transform_ops)*
            }
        }
    })
}

pub(super) fn update_validation_tokens(resource: &ResourceSpec, runtime_crate: &Path) -> Vec<TokenStream> {
    update_payload_fields(resource)
        .into_iter()
        .filter_map(|field| {
            validation_tokens(
                resource,
                field,
                &field.ident,
                is_optional_type(&field.ty),
                runtime_crate,
            )
        })
        .collect()
}
