//! Garde attribute and validation-error helper token generators.
//!
//! Helpers for:
//! - Emitting `#[garde(...)]` attribute tokens on payload struct fields
//!   (`garde_field_attr_tokens`, `garde_rule_tokens_from_validation`, …)
//! - Emitting the validation-error helper function bodies that are injected
//!   into every resource impl block
//!   (`garde_validation_error_helper`, `garde_validation_helper_defs`, …)
//!
//! Extracted from `resource_struct_tokens.rs` to keep that module focused on
//! struct-shape generation.  These helpers are consumed by
//! `resource_struct_tokens.rs`, `resource_action_tokens.rs`, and
//! `payload_tokens.rs` via the parent-module glob re-export.

use heck::ToSnakeCase;
use proc_macro2::{Literal, TokenStream};
use quote::{format_ident, quote};
use syn::Path;

use super::super::model::{
    FieldSpec, FieldValidation, LengthMode, LengthValidation, NumericBound,
    RangeValidation, ResourceSpec,
};

// ─── Error-helper idents ──────────────────────────────────────────────────────

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

// ─── Helper-function bodies emitted into each resource impl ───────────────────

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

// ─── Attribute token emitters ─────────────────────────────────────────────────

pub(super) fn garde_field_attr_tokens(
    field: &FieldSpec,
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
    validation: &FieldValidation,
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

// ─── Length / range rule builders ────────────────────────────────────────────

pub(super) fn garde_length_rule_tokens(length: &LengthValidation) -> TokenStream {
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

pub(super) fn garde_range_rule_tokens(range: &RangeValidation) -> TokenStream {
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

pub(super) fn garde_length_mode_tokens(mode: LengthMode) -> syn::Ident {
    match mode {
        LengthMode::Simple => format_ident!("simple"),
        LengthMode::Bytes => format_ident!("bytes"),
        LengthMode::Chars => format_ident!("chars"),
        LengthMode::Graphemes => format_ident!("graphemes"),
        LengthMode::Utf16 => format_ident!("utf16"),
    }
}

pub(super) fn numeric_bound_literal(bound: &NumericBound) -> Literal {
    match bound {
        NumericBound::Integer(value) => Literal::i64_unsuffixed(*value),
        NumericBound::Float(value) => Literal::f64_unsuffixed(*value),
    }
}
