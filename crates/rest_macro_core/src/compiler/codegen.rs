use std::collections::BTreeSet;

use proc_macro2::{Literal, TokenStream};
use quote::{format_ident, quote};
use syn::Path;

use super::model::{
    GeneratedValue, PolicyFilter, PolicyValueSource, ResourceSpec, ServiceSpec, StaticCacheProfile,
    StaticMode, WriteModelStyle,
};

pub fn expand_resource_impl(
    resource: &ResourceSpec,
    runtime_crate: &Path,
) -> syn::Result<TokenStream> {
    let impl_module_ident = &resource.impl_module_ident;
    let impl_body = resource_impl_tokens(resource, runtime_crate);

    Ok(quote! {
        mod #impl_module_ident {
            use super::*;
            #impl_body
        }
    })
}

pub fn expand_derive_resource(
    resource: &ResourceSpec,
    runtime_crate: &Path,
) -> syn::Result<TokenStream> {
    let struct_tokens = resource_struct_tokens(resource, runtime_crate);
    let impl_tokens = expand_resource_impl(resource, runtime_crate)?;

    Ok(quote! {
        #struct_tokens
        #impl_tokens
    })
}

pub fn expand_service_module(
    service: &ServiceSpec,
    runtime_crate: &Path,
    include_path: &str,
) -> syn::Result<TokenStream> {
    let module_ident = &service.module_ident;
    let include_path_lit = Literal::string(include_path);
    let resources = service
        .resources
        .iter()
        .map(|resource| {
            let struct_tokens = resource_struct_tokens(resource, runtime_crate);
            let impl_tokens = expand_resource_impl(resource, runtime_crate)?;
            Ok(quote! {
                #struct_tokens
                #impl_tokens
            })
        })
        .collect::<syn::Result<Vec<_>>>()?;
    let configure_calls = service.resources.iter().map(|resource| {
        let struct_ident = &resource.struct_ident;
        quote! {
            #struct_ident::configure(cfg, db.clone());
        }
    });
    let static_mounts = service.static_mounts.iter().map(|mount| {
        let mount_path = Literal::string(&mount.mount_path);
        let resolved_dir = Literal::string(&mount.resolved_dir);
        let index_file = match mount.index_file.as_deref() {
            Some(value) => {
                let value = Literal::string(value);
                quote!(Some(#value))
            }
            None => quote!(None),
        };
        let fallback_file = match mount.fallback_file.as_deref() {
            Some(value) => {
                let value = Literal::string(value);
                quote!(Some(#value))
            }
            None => quote!(None),
        };
        let mode = match mount.mode {
            StaticMode::Directory => {
                quote!(#runtime_crate::core::static_files::StaticMode::Directory)
            }
            StaticMode::Spa => quote!(#runtime_crate::core::static_files::StaticMode::Spa),
        };
        let cache = match mount.cache {
            StaticCacheProfile::NoStore => {
                quote!(#runtime_crate::core::static_files::StaticCacheProfile::NoStore)
            }
            StaticCacheProfile::Revalidate => {
                quote!(#runtime_crate::core::static_files::StaticCacheProfile::Revalidate)
            }
            StaticCacheProfile::Immutable => {
                quote!(#runtime_crate::core::static_files::StaticCacheProfile::Immutable)
            }
        };

        quote! {
            #runtime_crate::core::static_files::StaticMount {
                mount_path: #mount_path,
                resolved_dir: #resolved_dir,
                mode: #mode,
                index_file: #index_file,
                fallback_file: #fallback_file,
                cache: #cache,
            }
        }
    });
    let configure_static_body = if service.static_mounts.is_empty() {
        quote! {}
    } else {
        quote! {
            let mounts = [
                #(#static_mounts),*
            ];
            #runtime_crate::core::static_files::configure_static_mounts(cfg, &mounts);
        }
    };

    Ok(quote! {
        pub mod #module_ident {
            const _: &str = include_str!(#include_path_lit);

            use #runtime_crate::actix_web::{web, HttpResponse, Responder};
            use #runtime_crate::sqlx::AnyPool;

            #(#resources)*

            pub fn configure(cfg: &mut web::ServiceConfig, db: AnyPool) {
                #(#configure_calls)*
            }

            pub fn configure_static(cfg: &mut web::ServiceConfig) {
                #configure_static_body
            }
        }
    })
}

fn resource_struct_tokens(resource: &ResourceSpec, runtime_crate: &Path) -> TokenStream {
    let struct_ident = &resource.struct_ident;
    let create_ident = format_ident!("{struct_ident}Create");
    let update_ident = format_ident!("{struct_ident}Update");
    let list_query_tokens = list_query_tokens(resource, runtime_crate);
    let fields = resource.fields.iter().map(|field| {
        let ident = &field.ident;
        let ty = &field.ty;
        quote! {
            pub #ident: #ty,
        }
    });

    let create_fields = create_payload_fields(resource).into_iter().map(|field| {
        let ident = &field.field.ident;
        let ty = create_payload_field_ty(&field);
        quote! {
            pub #ident: #ty,
        }
    });
    let update_fields = update_payload_fields(resource).into_iter().map(|field| {
        let ident = &field.ident;
        let ty = &field.ty;
        quote! {
            pub #ident: #ty,
        }
    });

    match resource.write_style {
        WriteModelStyle::ExistingStructWithDtos => quote! {
            #[derive(
                Debug,
                Clone,
                #runtime_crate::serde::Serialize,
                #runtime_crate::serde::Deserialize
            )]
            pub struct #create_ident {
                #(#create_fields)*
            }

            #[derive(
                Debug,
                Clone,
                #runtime_crate::serde::Serialize,
                #runtime_crate::serde::Deserialize
            )]
            pub struct #update_ident {
                #(#update_fields)*
            }

            #list_query_tokens
        },
        WriteModelStyle::GeneratedStructWithDtos => quote! {
            #[derive(
                Debug,
                Clone,
                #runtime_crate::serde::Serialize,
                #runtime_crate::serde::Deserialize,
                #runtime_crate::sqlx::FromRow
            )]
            pub struct #struct_ident {
                #(#fields)*
            }

            #[derive(
                Debug,
                Clone,
                #runtime_crate::serde::Serialize,
                #runtime_crate::serde::Deserialize
            )]
            pub struct #create_ident {
                #(#create_fields)*
            }

            #[derive(
                Debug,
                Clone,
                #runtime_crate::serde::Serialize,
                #runtime_crate::serde::Deserialize
            )]
            pub struct #update_ident {
                #(#update_fields)*
            }

            #list_query_tokens
        },
    }
}

fn list_query_tokens(resource: &ResourceSpec, runtime_crate: &Path) -> TokenStream {
    let list_query_ident = list_query_ident(resource);
    let sort_field_ident = list_sort_field_ident(resource);
    let sort_order_ident = list_sort_order_ident(resource);
    let bind_ident = list_bind_ident(resource);
    let response_ident = list_response_ident(resource);
    let plan_ident = list_plan_ident(resource);
    let struct_ident = &resource.struct_ident;
    let filter_fields = resource.fields.iter().map(|field| {
        let filter_ident = format_ident!("filter_{}", field.ident);
        let ty = list_filter_field_ty(field);
        quote! {
            pub #filter_ident: Option<#ty>,
        }
    });
    let sort_variants = resource.fields.iter().map(|field| {
        let variant_ident = super::model::sanitize_struct_ident(&field.name(), field.ident.span());
        let field_name = Literal::string(&field.name());
        quote! {
            #[serde(rename = #field_name)]
            #variant_ident,
        }
    });
    let sort_variant_sql = resource.fields.iter().map(|field| {
        let variant_ident = super::model::sanitize_struct_ident(&field.name(), field.ident.span());
        let field_name = Literal::string(&field.name());
        quote! {
            Self::#variant_ident => #field_name,
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
        }

        #[derive(Debug, Clone)]
        enum #bind_ident {
            Integer(i64),
            Real(f64),
            Boolean(bool),
            Text(String),
        }

        #[derive(Debug)]
        struct #plan_ident {
            select_sql: String,
            count_sql: String,
            filter_binds: Vec<#bind_ident>,
            select_binds: Vec<#bind_ident>,
            limit: Option<u32>,
            offset: u32,
        }

        #[derive(Debug, Clone, #runtime_crate::serde::Serialize, #runtime_crate::serde::Deserialize)]
        pub struct #response_ident {
            pub items: Vec<#struct_ident>,
            pub total: i64,
            pub count: usize,
            pub limit: Option<u32>,
            pub offset: u32,
            pub next_offset: Option<u32>,
        }
    }
}

fn resource_impl_tokens(resource: &ResourceSpec, runtime_crate: &Path) -> TokenStream {
    let struct_ident = &resource.struct_ident;
    let table_name = &resource.table_name;
    let id_field = &resource.id_field;
    let create_payload_ty = create_payload_type(resource);
    let update_payload_ty = update_payload_type(resource);
    let list_query_ty = list_query_type(resource);
    let list_bind_ty = list_bind_type(resource);
    let list_plan_ty = list_plan_type(resource);
    let list_response_ty = list_response_type(resource);
    let create_check = role_guard(runtime_crate, resource.roles.create.as_deref());
    let read_check = role_guard(runtime_crate, resource.roles.read.as_deref());
    let update_check = role_guard(runtime_crate, resource.roles.update.as_deref());
    let delete_check = role_guard(runtime_crate, resource.roles.delete.as_deref());
    let create_validation = create_validation_tokens(resource, runtime_crate);
    let update_validation = update_validation_tokens(resource, runtime_crate);
    let is_admin = quote! { user.roles.iter().any(|candidate| candidate == "admin") };
    let admin_bypass = resource.policies.admin_bypass;

    let insert_fields = insert_fields(resource);
    let insert_fields_csv = insert_fields
        .iter()
        .map(|field| field.name())
        .collect::<Vec<_>>()
        .join(", ");
    let insert_placeholders = insert_fields
        .iter()
        .enumerate()
        .map(|(index, _)| resource.db.placeholder(index + 1))
        .collect::<Vec<_>>()
        .join(", ");
    let bind_fields_insert = insert_fields.iter().map(|field| {
        let ident = &field.ident;
        let field_name = field.name();
        if let Some(source) = create_assignment_source(resource, &field_name) {
            let value = policy_source_value(source, runtime_crate);
            quote! {
                q = q.bind(#value);
            }
        } else {
            quote! {
                q = q.bind(&item.#ident);
            }
        }
    });
    let bind_fields_insert_admin = insert_fields.iter().map(|field| {
        let ident = &field.ident;
        let field_name = field.name();
        if let Some(source) = create_assignment_source(resource, &field_name) {
            match source {
                PolicyValueSource::Claim(_) => {
                    let value = optional_policy_source_value(source);
                    let field_name_lit = Literal::string(&field_name);
                    quote! {
                        match &item.#ident {
                            Some(value) => {
                                q = q.bind(value);
                            }
                            None => match #value {
                                Some(value) => {
                                    q = q.bind(value);
                                }
                                None => {
                                    return #runtime_crate::core::errors::validation_error(
                                        #field_name_lit,
                                        format!("Missing required create field `{}`", #field_name_lit),
                                    );
                                }
                            },
                        }
                    }
                }
                PolicyValueSource::UserId => {
                    let value = policy_source_value(source, runtime_crate);
                    quote! {
                        q = q.bind(#value);
                    }
                }
            }
        } else {
            quote! {
                q = q.bind(&item.#ident);
            }
        }
    });

    let update_plan = build_update_plan(resource);
    let update_sql = update_plan
        .clauses
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    let bind_fields_update = update_plan
        .bind_fields
        .iter()
        .map(|ident| {
            quote! {
                q = q.bind(&item.#ident);
            }
        })
        .collect::<Vec<_>>();
    let read_filter_binds = bind_policy_filters(&resource.policies.read, runtime_crate);
    let update_filter_binds = bind_policy_filters(&resource.policies.update, runtime_crate);
    let delete_filter_binds = bind_policy_filters(&resource.policies.delete, runtime_crate);
    let list_placeholder_body = match resource.db {
        super::model::DbBackend::Postgres => quote!(format!("${index}")),
        super::model::DbBackend::Sqlite | super::model::DbBackend::Mysql => {
            quote!("?".to_owned())
        }
    };
    let read_policy_list_conditions = read_list_policy_condition_tokens(resource, runtime_crate);
    let query_filter_conditions = list_query_condition_tokens(resource);
    let list_bind_matches = list_bind_match_tokens(resource, "q");
    let count_bind_matches = list_bind_match_tokens(resource, "count_query");

    let get_one_body = if resource.policies.read.is_empty() {
        let id_placeholder = resource.db.placeholder(1);
        quote! {
            let sql = format!("SELECT * FROM {} WHERE {} = {}", #table_name, #id_field, #id_placeholder);
            match #runtime_crate::sqlx::query_as::<_, Self>(&sql)
                .bind(path.into_inner())
                .fetch_optional(db.get_ref())
                .await
            {
                Ok(Some(item)) => HttpResponse::Ok().json(item),
                Ok(None) => #runtime_crate::core::errors::not_found("Not found"),
                Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
            }
        }
    } else {
        let id_placeholder = resource.db.placeholder(1);
        let filtered_sql = filtered_select_by_id_sql(resource, &resource.policies.read);
        quote! {
            let sql = format!("SELECT * FROM {} WHERE {} = {}", #table_name, #id_field, #id_placeholder);
            let filtered_sql = #filtered_sql;

            let query = if #admin_bypass && #is_admin {
                #runtime_crate::sqlx::query_as::<_, Self>(&sql).bind(path.into_inner())
            } else {
                let mut q = #runtime_crate::sqlx::query_as::<_, Self>(filtered_sql)
                    .bind(path.into_inner());
                #(#read_filter_binds)*
                q
            };

            match query.fetch_optional(db.get_ref()).await {
                Ok(Some(item)) => HttpResponse::Ok().json(item),
                Ok(None) => #runtime_crate::core::errors::not_found("Not found"),
                Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
            }
        }
    };

    let create_body = if insert_fields.is_empty() {
        quote! {
            let sql = format!("INSERT INTO {} DEFAULT VALUES", #table_name);
            match #runtime_crate::sqlx::query(&sql).execute(db.get_ref()).await {
                Ok(_) => HttpResponse::Created().finish(),
                Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
            }
        }
    } else {
        if resource.policies.admin_bypass && resource.policies.create.iter().next().is_some() {
            quote! {
                let sql = format!("INSERT INTO {} ({}) VALUES ({})", #table_name, #insert_fields_csv, #insert_placeholders);
                let mut q = #runtime_crate::sqlx::query(&sql);
                if #is_admin {
                    #(#bind_fields_insert_admin)*
                } else {
                    #(#bind_fields_insert)*
                }
                match q.execute(db.get_ref()).await {
                    Ok(_) => HttpResponse::Created().finish(),
                    Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                }
            }
        } else {
            quote! {
                let sql = format!("INSERT INTO {} ({}) VALUES ({})", #table_name, #insert_fields_csv, #insert_placeholders);
                let mut q = #runtime_crate::sqlx::query(&sql);
                #(#bind_fields_insert)*
                match q.execute(db.get_ref()).await {
                    Ok(_) => HttpResponse::Created().finish(),
                    Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                }
            }
        }
    };

    let update_body = if update_plan.clauses.is_empty() {
        quote! {
            #runtime_crate::core::errors::bad_request(
                "no_updatable_fields",
                "No updatable fields configured",
            )
        }
    } else {
        if resource.policies.update.is_empty() {
            let sql = format!(
                "UPDATE {} SET {} WHERE {} = {}",
                resource.table_name,
                update_sql,
                resource.id_field,
                resource.db.placeholder(update_plan.where_index)
            );

            quote! {
                let sql = #sql;
                let mut q = #runtime_crate::sqlx::query(sql);
                #(#bind_fields_update)*
                q = q.bind(path.into_inner());
                match q.execute(db.get_ref()).await {
                    Ok(result) if result.rows_affected() == 0 => #runtime_crate::core::errors::not_found("Not found"),
                    Ok(_) => HttpResponse::Ok().finish(),
                    Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                }
            }
        } else {
            let filtered_sql = filtered_update_sql(
                resource,
                &update_sql,
                &resource.policies.update,
                update_plan.where_index + 1,
            );
            let admin_sql = format!(
                "UPDATE {} SET {} WHERE {} = {}",
                resource.table_name,
                update_sql,
                resource.id_field,
                resource.db.placeholder(update_plan.where_index)
            );

            quote! {
                if #admin_bypass && #is_admin {
                    let sql = #admin_sql;
                    let mut q = #runtime_crate::sqlx::query(sql);
                    #(#bind_fields_update)*
                    q = q.bind(path.into_inner());
                    match q.execute(db.get_ref()).await {
                        Ok(result) if result.rows_affected() == 0 => #runtime_crate::core::errors::not_found("Not found"),
                        Ok(_) => HttpResponse::Ok().finish(),
                        Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                    }
                } else {
                    let sql = #filtered_sql;
                    let mut q = #runtime_crate::sqlx::query(sql);
                    #(#bind_fields_update)*
                    q = q.bind(path.into_inner());
                    #(#update_filter_binds)*
                    match q.execute(db.get_ref()).await {
                        Ok(result) if result.rows_affected() == 0 => #runtime_crate::core::errors::not_found("Not found"),
                        Ok(_) => HttpResponse::Ok().finish(),
                        Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                    }
                }
            }
        }
    };

    let delete_body = if resource.policies.delete.is_empty() {
        let id_placeholder = resource.db.placeholder(1);
        quote! {
            let sql = format!("DELETE FROM {} WHERE {} = {}", #table_name, #id_field, #id_placeholder);
            match #runtime_crate::sqlx::query(&sql)
                .bind(path.into_inner())
                .execute(db.get_ref())
                .await
            {
                Ok(result) if result.rows_affected() == 0 => #runtime_crate::core::errors::not_found("Not found"),
                Ok(_) => HttpResponse::Ok().finish(),
                Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
            }
        }
    } else {
        let filtered_sql = filtered_delete_sql(resource, &resource.policies.delete, 2);
        let admin_sql = format!(
            "DELETE FROM {} WHERE {} = {}",
            resource.table_name,
            resource.id_field,
            resource.db.placeholder(1)
        );
        quote! {
            if #admin_bypass && #is_admin {
                let sql = #admin_sql;
                match #runtime_crate::sqlx::query(sql)
                    .bind(path.into_inner())
                    .execute(db.get_ref())
                    .await
                {
                    Ok(result) if result.rows_affected() == 0 => #runtime_crate::core::errors::not_found("Not found"),
                    Ok(_) => HttpResponse::Ok().finish(),
                    Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                }
            } else {
                let sql = #filtered_sql;
                let mut q = #runtime_crate::sqlx::query(sql);
                q = q.bind(path.into_inner());
                #(#delete_filter_binds)*
                match q.execute(db.get_ref()).await {
                    Ok(result) if result.rows_affected() == 0 => #runtime_crate::core::errors::not_found("Not found"),
                    Ok(_) => HttpResponse::Ok().finish(),
                    Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                }
            }
        }
    };

    let relation_routes = resource.fields.iter().filter_map(|field| {
        field
            .relation
            .as_ref()
            .filter(|relation| relation.nested_route)
            .map(|relation| (field.ident.clone(), relation.references_table.clone()))
    });
    let nested_route_registrations = relation_routes.clone().map(|(field_ident, parent_table)| {
        let handler_ident = format_ident!("get_by_{}", field_ident);
        quote! {
            cfg.service(
                web::resource(format!("/{}/{{parent_id}}/{}", #parent_table, #table_name))
                    .route(web::get().to(Self::#handler_ident))
            );
        }
    });
    let nested_handlers = relation_routes.map(|(field_ident, _)| {
        let handler_ident = format_ident!("get_by_{}", field_ident);
        quote! {
            async fn #handler_ident(
                path: web::Path<i64>,
                query: web::Query<#list_query_ty>,
                user: #runtime_crate::core::auth::UserContext,
                db: web::Data<AnyPool>,
            ) -> impl Responder {
                #read_check

                let parent_id = path.into_inner();
                let query = query.into_inner();
                let plan = match Self::build_list_plan(
                    &query,
                    &user,
                    Some((stringify!(#field_ident), parent_id)),
                ) {
                    Ok(parts) => parts,
                    Err(response) => return response,
                };
                let mut count_query =
                    #runtime_crate::sqlx::query_scalar::<_, i64>(&plan.count_sql);
                for bind in plan.filter_binds {
                    count_query = match bind {
                        #(#count_bind_matches)*
                    };
                }
                let total = match count_query.fetch_one(db.get_ref()).await {
                    Ok(total) => total,
                    Err(error) => return #runtime_crate::core::errors::internal_error(error.to_string()),
                };
                let mut q = #runtime_crate::sqlx::query_as::<_, Self>(&plan.select_sql);
                for bind in plan.select_binds {
                    q = match bind {
                        #(#list_bind_matches)*
                    };
                }
                match q.fetch_all(db.get_ref()).await {
                    Ok(items) => {
                        let count = items.len();
                        let next_offset = match plan.limit {
                            Some(limit) if (plan.offset as i64) + (count as i64) < total => {
                                Some(plan.offset + count as u32)
                            }
                            _ => None,
                        };
                        HttpResponse::Ok().json(#list_response_ty {
                            items,
                            total,
                            count,
                            limit: plan.limit,
                            offset: plan.offset,
                            next_offset,
                        })
                    }
                    Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                }
            }
        }
    });

    quote! {
        use #runtime_crate::actix_web::{web, HttpResponse, Responder};
        use #runtime_crate::sqlx::AnyPool;

        impl #struct_ident {
            pub fn configure(cfg: &mut web::ServiceConfig, db: AnyPool) {
                let db = web::Data::new(db);
                #runtime_crate::core::errors::configure_extractor_errors(cfg);
                cfg.app_data(db.clone());

                cfg.service(
                    web::resource(format!("/{}", #table_name))
                        .route(web::get().to(Self::get_all))
                        .route(web::post().to(Self::create))
                )
                .service(
                    web::resource(format!("/{}/{{id}}", #table_name))
                        .route(web::get().to(Self::get_one))
                        .route(web::put().to(Self::update))
                        .route(web::delete().to(Self::delete))
                );

                #(#nested_route_registrations)*
            }

            fn list_placeholder(index: usize) -> String {
                #list_placeholder_body
            }

            fn build_list_plan(
                query: &#list_query_ty,
                user: &#runtime_crate::core::auth::UserContext,
                parent_filter: Option<(&'static str, i64)>,
            ) -> Result<#list_plan_ty, HttpResponse> {
                let mut select_sql = format!("SELECT * FROM {}", #table_name);
                let mut count_sql = format!("SELECT COUNT(*) FROM {}", #table_name);
                let mut conditions: Vec<String> = Vec::new();
                let mut filter_binds: Vec<#list_bind_ty> = Vec::new();
                let is_admin = #is_admin;
                let offset = query.offset.unwrap_or(0);

                if let Some((field_name, value)) = parent_filter {
                    conditions.push(format!(
                        "{} = {}",
                        field_name,
                        Self::list_placeholder(filter_binds.len() + 1)
                    ));
                    filter_binds.push(#list_bind_ty::Integer(value));
                }

                if !(#admin_bypass && is_admin) {
                    #(#read_policy_list_conditions)*
                }

                #(#query_filter_conditions)*

                if !conditions.is_empty() {
                    let where_sql = conditions.join(" AND ");
                    select_sql.push_str(" WHERE ");
                    select_sql.push_str(&where_sql);
                    count_sql.push_str(" WHERE ");
                    count_sql.push_str(&where_sql);
                }

                match (&query.sort, &query.order) {
                    (Some(sort), Some(order)) => {
                        select_sql.push_str(" ORDER BY ");
                        select_sql.push_str(sort.as_sql());
                        select_sql.push(' ');
                        select_sql.push_str(order.as_sql());
                    }
                    (Some(sort), None) => {
                        select_sql.push_str(" ORDER BY ");
                        select_sql.push_str(sort.as_sql());
                        select_sql.push_str(" ASC");
                    }
                    (None, Some(_)) => {
                        return Err(#runtime_crate::core::errors::bad_request(
                            "invalid_sort",
                            "`order` requires `sort`",
                        ));
                    }
                    (None, None) => {}
                }

                if let Some(limit) = query.limit {
                    if limit == 0 {
                        return Err(#runtime_crate::core::errors::bad_request(
                            "invalid_pagination",
                            "`limit` must be greater than 0",
                        ));
                    }
                    select_sql.push_str(" LIMIT ");
                    select_sql.push_str(&Self::list_placeholder(filter_binds.len() + 1));
                }

                if let Some(offset) = query.offset {
                    if query.limit.is_none() {
                        return Err(#runtime_crate::core::errors::bad_request(
                            "invalid_pagination",
                            "`offset` requires `limit`",
                        ));
                    }
                    select_sql.push_str(" OFFSET ");
                    let placeholder_index = filter_binds.len() + 2;
                    select_sql.push_str(&Self::list_placeholder(placeholder_index));
                }

                let mut select_binds = filter_binds.clone();
                if let Some(limit) = query.limit {
                    select_binds.push(#list_bind_ty::Integer(limit as i64));
                }
                if query.offset.is_some() {
                    select_binds.push(#list_bind_ty::Integer(offset as i64));
                }

                Ok(#list_plan_ty {
                    select_sql,
                    count_sql,
                    filter_binds,
                    select_binds,
                    limit: query.limit,
                    offset,
                })
            }

            async fn get_all(
                query: web::Query<#list_query_ty>,
                user: #runtime_crate::core::auth::UserContext,
                db: web::Data<AnyPool>,
            ) -> impl Responder {
                #read_check
                let query = query.into_inner();
                let plan = match Self::build_list_plan(&query, &user, None) {
                    Ok(parts) => parts,
                    Err(response) => return response,
                };
                let mut count_query =
                    #runtime_crate::sqlx::query_scalar::<_, i64>(&plan.count_sql);
                for bind in plan.filter_binds {
                    count_query = match bind {
                        #(#count_bind_matches)*
                    };
                }
                let total = match count_query.fetch_one(db.get_ref()).await {
                    Ok(total) => total,
                    Err(error) => return #runtime_crate::core::errors::internal_error(error.to_string()),
                };
                let mut q = #runtime_crate::sqlx::query_as::<_, Self>(&plan.select_sql);
                for bind in plan.select_binds {
                    q = match bind {
                        #(#list_bind_matches)*
                    };
                }
                match q.fetch_all(db.get_ref()).await {
                    Ok(items) => {
                        let count = items.len();
                        let next_offset = match plan.limit {
                            Some(limit) if (plan.offset as i64) + (count as i64) < total => {
                                Some(plan.offset + count as u32)
                            }
                            _ => None,
                        };
                        HttpResponse::Ok().json(#list_response_ty {
                            items,
                            total,
                            count,
                            limit: plan.limit,
                            offset: plan.offset,
                            next_offset,
                        })
                    }
                    Err(error) => #runtime_crate::core::errors::internal_error(error.to_string()),
                }
            }

            async fn get_one(
                path: web::Path<i64>,
                user: #runtime_crate::core::auth::UserContext,
                db: web::Data<AnyPool>,
            ) -> impl Responder {
                #read_check
                #get_one_body
            }

            async fn create(
                item: web::Json<#create_payload_ty>,
                user: #runtime_crate::core::auth::UserContext,
                db: web::Data<AnyPool>,
            ) -> impl Responder {
                #create_check
                #(#create_validation)*
                #create_body
            }

            async fn update(
                path: web::Path<i64>,
                item: web::Json<#update_payload_ty>,
                user: #runtime_crate::core::auth::UserContext,
                db: web::Data<AnyPool>,
            ) -> impl Responder {
                #update_check
                #(#update_validation)*
                #update_body
            }

            async fn delete(
                path: web::Path<i64>,
                user: #runtime_crate::core::auth::UserContext,
                db: web::Data<AnyPool>,
            ) -> impl Responder {
                #delete_check
                #delete_body
            }

            #(#nested_handlers)*
        }
    }
}

fn create_payload_type(resource: &ResourceSpec) -> TokenStream {
    match resource.write_style {
        WriteModelStyle::ExistingStructWithDtos | WriteModelStyle::GeneratedStructWithDtos => {
            let ident = format_ident!("{}Create", resource.struct_ident);
            quote!(#ident)
        }
    }
}

fn update_payload_type(resource: &ResourceSpec) -> TokenStream {
    match resource.write_style {
        WriteModelStyle::ExistingStructWithDtos | WriteModelStyle::GeneratedStructWithDtos => {
            let ident = format_ident!("{}Update", resource.struct_ident);
            quote!(#ident)
        }
    }
}

struct CreatePayloadField<'a> {
    field: &'a super::model::FieldSpec,
    allow_admin_override: bool,
}

fn create_payload_fields(resource: &ResourceSpec) -> Vec<CreatePayloadField<'_>> {
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
            if controlled && !allow_admin_override {
                return None;
            }

            Some(CreatePayloadField {
                field,
                allow_admin_override,
            })
        })
        .collect()
}

fn create_payload_field_ty(field: &CreatePayloadField<'_>) -> syn::Type {
    if field.allow_admin_override && !super::model::is_optional_type(&field.field.ty) {
        let ty = &field.field.ty;
        syn::parse_quote!(Option<#ty>)
    } else {
        field.field.ty.clone()
    }
}

fn create_payload_field_is_optional(field: &CreatePayloadField<'_>) -> bool {
    field.allow_admin_override || super::model::is_optional_type(&field.field.ty)
}

fn update_payload_fields(resource: &ResourceSpec) -> Vec<&super::model::FieldSpec> {
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

fn list_query_ident(resource: &ResourceSpec) -> syn::Ident {
    format_ident!("{}ListQuery", resource.struct_ident)
}

fn list_query_type(resource: &ResourceSpec) -> TokenStream {
    let ident = list_query_ident(resource);
    quote!(#ident)
}

fn list_sort_field_ident(resource: &ResourceSpec) -> syn::Ident {
    format_ident!("{}ListSortField", resource.struct_ident)
}

fn list_sort_order_ident(resource: &ResourceSpec) -> syn::Ident {
    format_ident!("{}ListSortOrder", resource.struct_ident)
}

fn list_bind_ident(resource: &ResourceSpec) -> syn::Ident {
    format_ident!("{}ListBindValue", resource.struct_ident)
}

fn list_bind_type(resource: &ResourceSpec) -> TokenStream {
    let ident = list_bind_ident(resource);
    quote!(#ident)
}

fn list_plan_ident(resource: &ResourceSpec) -> syn::Ident {
    format_ident!("{}ListQueryPlan", resource.struct_ident)
}

fn list_plan_type(resource: &ResourceSpec) -> TokenStream {
    let ident = list_plan_ident(resource);
    quote!(#ident)
}

fn list_response_ident(resource: &ResourceSpec) -> syn::Ident {
    format_ident!("{}ListResponse", resource.struct_ident)
}

fn list_response_type(resource: &ResourceSpec) -> TokenStream {
    let ident = list_response_ident(resource);
    quote!(#ident)
}

fn list_filter_field_ty(field: &super::model::FieldSpec) -> syn::Type {
    match field.sql_type.as_str() {
        "INTEGER" => syn::parse_quote!(i64),
        "REAL" => syn::parse_quote!(f64),
        "BOOLEAN" => syn::parse_quote!(bool),
        _ => syn::parse_quote!(String),
    }
}

fn read_list_policy_condition_tokens(
    resource: &ResourceSpec,
    runtime_crate: &Path,
) -> Vec<TokenStream> {
    let bind_ident = list_bind_ident(resource);
    resource
        .policies
        .read
        .iter()
        .map(|filter| {
            let field_name = Literal::string(&filter.field);
            let value = policy_source_result_value(&filter.source, runtime_crate);
            quote! {
                conditions.push(format!(
                    "{} = {}",
                    #field_name,
                    Self::list_placeholder(filter_binds.len() + 1)
                ));
                filter_binds.push(#bind_ident::Integer(#value));
            }
        })
        .collect()
}

fn list_query_condition_tokens(resource: &ResourceSpec) -> Vec<TokenStream> {
    let bind_ident = list_bind_ident(resource);
    resource
        .fields
        .iter()
        .map(|field| {
            let field_name = Literal::string(&field.name());
            let filter_ident = format_ident!("filter_{}", field.ident);
            match field.sql_type.as_str() {
                "INTEGER" => quote! {
                    if let Some(value) = query.#filter_ident {
                        conditions.push(format!(
                            "{} = {}",
                            #field_name,
                            Self::list_placeholder(filter_binds.len() + 1)
                        ));
                        filter_binds.push(#bind_ident::Integer(value));
                    }
                },
                "REAL" => quote! {
                    if let Some(value) = query.#filter_ident {
                        conditions.push(format!(
                            "{} = {}",
                            #field_name,
                            Self::list_placeholder(filter_binds.len() + 1)
                        ));
                        filter_binds.push(#bind_ident::Real(value));
                    }
                },
                "BOOLEAN" => quote! {
                    if let Some(value) = query.#filter_ident {
                        conditions.push(format!(
                            "{} = {}",
                            #field_name,
                            Self::list_placeholder(filter_binds.len() + 1)
                        ));
                        filter_binds.push(#bind_ident::Boolean(value));
                    }
                },
                _ => quote! {
                    if let Some(value) = &query.#filter_ident {
                        conditions.push(format!(
                            "{} = {}",
                            #field_name,
                            Self::list_placeholder(filter_binds.len() + 1)
                        ));
                        filter_binds.push(#bind_ident::Text(value.clone()));
                    }
                },
            }
        })
        .collect()
}

fn list_bind_match_tokens(resource: &ResourceSpec, query_ident: &str) -> Vec<TokenStream> {
    let bind_ident = list_bind_ident(resource);
    let query_ident = syn::Ident::new(query_ident, proc_macro2::Span::call_site());
    vec![
        quote! {
            #bind_ident::Integer(value) => #query_ident.bind(value),
        },
        quote! {
            #bind_ident::Real(value) => #query_ident.bind(value),
        },
        quote! {
            #bind_ident::Boolean(value) => #query_ident.bind(value),
        },
        quote! {
            #bind_ident::Text(value) => #query_ident.bind(value),
        },
    ]
}

fn create_validation_tokens(resource: &ResourceSpec, runtime_crate: &Path) -> Vec<TokenStream> {
    create_payload_fields(resource)
        .into_iter()
        .filter_map(|field| {
            validation_tokens(
                field.field,
                &field.field.ident,
                create_payload_field_is_optional(&field),
                runtime_crate,
            )
        })
        .collect()
}

fn update_validation_tokens(resource: &ResourceSpec, runtime_crate: &Path) -> Vec<TokenStream> {
    update_payload_fields(resource)
        .into_iter()
        .filter_map(|field| {
            validation_tokens(
                field,
                &field.ident,
                super::model::is_optional_type(&field.ty),
                runtime_crate,
            )
        })
        .collect()
}

fn validation_tokens(
    field: &super::model::FieldSpec,
    ident: &syn::Ident,
    optional: bool,
    runtime_crate: &Path,
) -> Option<TokenStream> {
    if field.validation.is_empty() {
        return None;
    }

    let field_name = Literal::string(&field.name());
    let checks = validation_checks(field, &field_name, runtime_crate);
    if checks.is_empty() {
        return None;
    }

    Some(if optional {
        quote! {
            if let Some(value) = &item.#ident {
                #(#checks)*
            }
        }
    } else {
        quote! {
            let value = &item.#ident;
            #(#checks)*
        }
    })
}

fn validation_checks(
    field: &super::model::FieldSpec,
    field_name: &Literal,
    runtime_crate: &Path,
) -> Vec<TokenStream> {
    let mut checks = Vec::new();

    if let Some(min_length) = field.validation.min_length {
        checks.push(quote! {
            if value.chars().count() < #min_length {
                return #runtime_crate::core::errors::validation_error(
                    #field_name,
                    format!("Field `{}` must have at least {} characters", #field_name, #min_length),
                );
            }
        });
    }

    if let Some(max_length) = field.validation.max_length {
        checks.push(quote! {
            if value.chars().count() > #max_length {
                return #runtime_crate::core::errors::validation_error(
                    #field_name,
                    format!("Field `{}` must have at most {} characters", #field_name, #max_length),
                );
            }
        });
    }

    match field.sql_type.as_str() {
        "INTEGER" => {
            if let Some(super::model::NumericBound::Integer(minimum)) = &field.validation.minimum {
                let minimum = Literal::i64_unsuffixed(*minimum);
                checks.push(quote! {
                    if *value < #minimum {
                        return #runtime_crate::core::errors::validation_error(
                            #field_name,
                            format!("Field `{}` must be at least {}", #field_name, #minimum),
                        );
                    }
                });
            }
            if let Some(super::model::NumericBound::Integer(maximum)) = &field.validation.maximum {
                let maximum = Literal::i64_unsuffixed(*maximum);
                checks.push(quote! {
                    if *value > #maximum {
                        return #runtime_crate::core::errors::validation_error(
                            #field_name,
                            format!("Field `{}` must be at most {}", #field_name, #maximum),
                        );
                    }
                });
            }
        }
        "REAL" => {
            if let Some(minimum) = &field.validation.minimum {
                let minimum = Literal::f64_unsuffixed(minimum.as_f64());
                checks.push(quote! {
                    if (*value as f64) < #minimum {
                        return #runtime_crate::core::errors::validation_error(
                            #field_name,
                            format!("Field `{}` must be at least {}", #field_name, #minimum),
                        );
                    }
                });
            }
            if let Some(maximum) = &field.validation.maximum {
                let maximum = Literal::f64_unsuffixed(maximum.as_f64());
                checks.push(quote! {
                    if (*value as f64) > #maximum {
                        return #runtime_crate::core::errors::validation_error(
                            #field_name,
                            format!("Field `{}` must be at most {}", #field_name, #maximum),
                        );
                    }
                });
            }
        }
        _ => {}
    }

    checks
}

fn insert_fields(resource: &ResourceSpec) -> Vec<&super::model::FieldSpec> {
    resource
        .fields
        .iter()
        .filter(|field| !field.generated.skip_insert())
        .collect()
}

fn policy_controlled_fields(resource: &ResourceSpec) -> BTreeSet<String> {
    resource
        .policies
        .iter_filters()
        .map(|(_, policy)| policy.field.clone())
        .chain(
            resource
                .policies
                .iter_assignments()
                .map(|(_, policy)| policy.field.clone()),
        )
        .collect()
}

fn create_assignment_source<'a>(
    resource: &'a ResourceSpec,
    field_name: &str,
) -> Option<&'a PolicyValueSource> {
    resource
        .policies
        .create
        .iter()
        .find(|policy| policy.field == field_name)
        .map(|policy| &policy.source)
}

fn bind_policy_filters(filters: &[PolicyFilter], runtime_crate: &Path) -> Vec<TokenStream> {
    filters
        .iter()
        .map(|filter| {
            let value = policy_source_value(&filter.source, runtime_crate);
            quote! {
                q = q.bind(#value);
            }
        })
        .collect()
}

fn policy_source_value(source: &PolicyValueSource, runtime_crate: &Path) -> TokenStream {
    match source {
        PolicyValueSource::UserId => quote!(user.id),
        PolicyValueSource::Claim(name) => {
            let claim_name = Literal::string(name);
            quote! {
                {
                    match user.claim_i64(#claim_name) {
                        Some(value) => value,
                        None => return #runtime_crate::core::errors::forbidden(
                            "missing_claim",
                            format!("Missing required claim `{}`", #claim_name),
                        ),
                    }
                }
            }
        }
    }
}

fn policy_source_result_value(source: &PolicyValueSource, runtime_crate: &Path) -> TokenStream {
    match source {
        PolicyValueSource::UserId => quote!(user.id),
        PolicyValueSource::Claim(name) => {
            let claim_name = Literal::string(name);
            quote! {
                {
                    match user.claim_i64(#claim_name) {
                        Some(value) => value,
                        None => return Err(#runtime_crate::core::errors::forbidden(
                            "missing_claim",
                            format!("Missing required claim `{}`", #claim_name),
                        )),
                    }
                }
            }
        }
    }
}

fn optional_policy_source_value(source: &PolicyValueSource) -> TokenStream {
    match source {
        PolicyValueSource::UserId => quote!(Some(user.id)),
        PolicyValueSource::Claim(name) => {
            let claim_name = Literal::string(name);
            quote!(user.claim_i64(#claim_name))
        }
    }
}

fn filtered_select_by_id_sql(resource: &ResourceSpec, filters: &[PolicyFilter]) -> String {
    let mut conditions = vec![format!(
        "{} = {}",
        resource.id_field,
        resource.db.placeholder(1)
    )];
    conditions.extend(filter_conditions_sql(resource, filters, 2));
    format!(
        "SELECT * FROM {} WHERE {}",
        resource.table_name,
        conditions.join(" AND ")
    )
}

fn filtered_update_sql(
    resource: &ResourceSpec,
    update_sql: &str,
    filters: &[PolicyFilter],
    start_index: usize,
) -> String {
    let mut conditions = vec![format!(
        "{} = {}",
        resource.id_field,
        resource.db.placeholder(start_index - 1)
    )];
    conditions.extend(filter_conditions_sql(resource, filters, start_index));
    format!(
        "UPDATE {} SET {} WHERE {}",
        resource.table_name,
        update_sql,
        conditions.join(" AND ")
    )
}

fn filtered_delete_sql(
    resource: &ResourceSpec,
    filters: &[PolicyFilter],
    start_index: usize,
) -> String {
    let mut conditions = vec![format!(
        "{} = {}",
        resource.id_field,
        resource.db.placeholder(1)
    )];
    conditions.extend(filter_conditions_sql(resource, filters, start_index));
    format!(
        "DELETE FROM {} WHERE {}",
        resource.table_name,
        conditions.join(" AND ")
    )
}

fn filter_conditions_sql(
    resource: &ResourceSpec,
    filters: &[PolicyFilter],
    start_index: usize,
) -> Vec<String> {
    filters
        .iter()
        .enumerate()
        .map(|(index, filter)| {
            format!(
                "{} = {}",
                filter.field,
                resource.db.placeholder(start_index + index)
            )
        })
        .collect()
}

fn role_guard(runtime_crate: &Path, role: Option<&str>) -> TokenStream {
    match role {
        Some(role) => quote! {
            if !user.roles.iter().any(|candidate| candidate == "admin" || candidate == #role) {
                return #runtime_crate::core::errors::forbidden(
                    "forbidden",
                    "Insufficient privileges",
                );
            }
        },
        None => quote! {},
    }
}

struct UpdatePlan {
    clauses: Vec<String>,
    bind_fields: Vec<syn::Ident>,
    where_index: usize,
}

fn build_update_plan(resource: &ResourceSpec) -> UpdatePlan {
    let mut clauses = Vec::new();
    let mut bind_fields = Vec::new();
    let mut bind_index = 1;
    let controlled_fields = policy_controlled_fields(resource);

    for field in &resource.fields {
        if field.is_id || controlled_fields.contains(&field.name()) {
            continue;
        }

        let field_name = field.name();
        match field.generated {
            GeneratedValue::UpdatedAt => {
                clauses.push(format!("{field_name} = CURRENT_TIMESTAMP"));
            }
            GeneratedValue::AutoIncrement | GeneratedValue::CreatedAt => {}
            GeneratedValue::None => {
                clauses.push(format!(
                    "{field_name} = {}",
                    resource.db.placeholder(bind_index)
                ));
                bind_fields.push(field.ident.clone());
                bind_index += 1;
            }
        }
    }

    UpdatePlan {
        clauses,
        bind_fields,
        where_index: bind_index,
    }
}
