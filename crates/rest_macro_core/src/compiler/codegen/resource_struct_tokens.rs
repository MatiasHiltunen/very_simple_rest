//! Resource struct token generators and supporting helpers.
//!
//! Extracted from [`super`] to keep the parent module focused on the
//! entry-point dispatch functions.
//!
//! ## Cohesion
//! Every function here is concerned with emitting Rust struct definitions
//! for resource types (payload structs, list-query structs, typed-object
//! validator/normalizer boilerplate, and row-deserialization).
//!
//! Garde attribute helpers live in the sibling `garde_tokens` module and
//! arrive here through the parent-module glob re-export.

use proc_macro2::{Literal, TokenStream};
use quote::{format_ident, quote};
use syn::Path;

use super::super::model::{ResourceSpec, WriteModelStyle};
use super::{
    // Parent-module functions and types (codegen.rs) called from the
    // functions in this module.  Child modules can access private parent
    // items via super::.
    ListBindKind,
    create_payload_field_is_optional, create_payload_field_ty, create_payload_fields,
    // garde helpers (from garde_tokens via parent glob re-export)
    garde_field_attr_tokens,
    garde_validation_helper_defs,
    list_bind_ident, list_bind_kinds,
    list_cursor_payload_ident, list_cursor_value_ident,
    list_filter_field_ty, list_plan_ident,
    list_query_ident, list_response_ident,
    list_sort_field_ident, list_sort_order_ident,
    resource_action_input_struct_tokens,
    // typed_object helpers (from typed_object_tokens via parent glob re-export)
    field_supports_sort,
    list_field_from_text_tokens,
    structured_scalar_from_text_tokens,
    typed_object_validator_defs, typed_object_validator_ident,
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
