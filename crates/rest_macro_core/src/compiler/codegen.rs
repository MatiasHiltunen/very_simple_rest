use std::collections::BTreeSet;

use proc_macro2::{Literal, TokenStream};
use quote::{format_ident, quote};
use syn::Path;

use super::model::{
    GeneratedValue, PolicyFilter, PolicyValueSource, ResourceSpec, ServiceSpec, WriteModelStyle,
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

    Ok(quote! {
        pub mod #module_ident {
            const _: &str = include_str!(#include_path_lit);

            use #runtime_crate::actix_web::{web, HttpResponse, Responder};
            use #runtime_crate::sqlx::AnyPool;

            #(#resources)*

            pub fn configure(cfg: &mut web::ServiceConfig, db: AnyPool) {
                #(#configure_calls)*
            }
        }
    })
}

fn resource_struct_tokens(resource: &ResourceSpec, runtime_crate: &Path) -> TokenStream {
    let struct_ident = &resource.struct_ident;
    let create_ident = format_ident!("{struct_ident}Create");
    let update_ident = format_ident!("{struct_ident}Update");
    let fields = resource.fields.iter().map(|field| {
        let ident = &field.ident;
        let ty = &field.ty;
        quote! {
            pub #ident: #ty,
        }
    });

    let create_fields = create_payload_fields(resource).into_iter().map(|field| {
        let ident = &field.ident;
        let ty = &field.ty;
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
        },
    }
}

fn resource_impl_tokens(resource: &ResourceSpec, runtime_crate: &Path) -> TokenStream {
    let struct_ident = &resource.struct_ident;
    let table_name = &resource.table_name;
    let id_field = &resource.id_field;
    let create_payload_ty = create_payload_type(resource);
    let update_payload_ty = update_payload_type(resource);
    let create_check = role_guard(runtime_crate, resource.roles.create.as_deref());
    let read_check = role_guard(runtime_crate, resource.roles.read.as_deref());
    let update_check = role_guard(runtime_crate, resource.roles.update.as_deref());
    let delete_check = role_guard(runtime_crate, resource.roles.delete.as_deref());
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
            let value = policy_source_value(source);
            quote! {
                q = q.bind(#value);
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
    let read_filter_binds = bind_policy_filters(&resource.policies.read);
    let update_filter_binds = bind_policy_filters(&resource.policies.update);
    let delete_filter_binds = bind_policy_filters(&resource.policies.delete);

    let get_all_body = if resource.policies.read.is_empty() {
        quote! {
            let sql = format!("SELECT * FROM {}", #table_name);
            match #runtime_crate::sqlx::query_as::<_, Self>(&sql)
                .fetch_all(db.get_ref())
                .await
            {
                Ok(data) => HttpResponse::Ok().json(data),
                Err(error) => HttpResponse::InternalServerError().body(error.to_string()),
            }
        }
    } else {
        let filtered_sql = filtered_select_sql(resource, &resource.policies.read, 1);
        quote! {
            let sql = format!("SELECT * FROM {}", #table_name);
            let filtered_sql = #filtered_sql;

            if #admin_bypass && #is_admin {
                match #runtime_crate::sqlx::query_as::<_, Self>(&sql)
                    .fetch_all(db.get_ref())
                    .await
                {
                    Ok(data) => HttpResponse::Ok().json(data),
                    Err(error) => HttpResponse::InternalServerError().body(error.to_string()),
                }
            } else {
                let mut q = #runtime_crate::sqlx::query_as::<_, Self>(filtered_sql);
                #(#read_filter_binds)*
                match q.fetch_all(db.get_ref()).await {
                    Ok(data) => HttpResponse::Ok().json(data),
                    Err(error) => HttpResponse::InternalServerError().body(error.to_string()),
                }
            }
        }
    };

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
                Ok(None) => HttpResponse::NotFound().finish(),
                Err(error) => HttpResponse::InternalServerError().body(error.to_string()),
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
                Ok(None) => HttpResponse::NotFound().finish(),
                Err(error) => HttpResponse::InternalServerError().body(error.to_string()),
            }
        }
    };

    let create_body = if insert_fields.is_empty() {
        quote! {
            let sql = format!("INSERT INTO {} DEFAULT VALUES", #table_name);
            match #runtime_crate::sqlx::query(&sql).execute(db.get_ref()).await {
                Ok(_) => HttpResponse::Created().finish(),
                Err(error) => HttpResponse::InternalServerError().body(error.to_string()),
            }
        }
    } else {
        quote! {
            let sql = format!("INSERT INTO {} ({}) VALUES ({})", #table_name, #insert_fields_csv, #insert_placeholders);
            let mut q = #runtime_crate::sqlx::query(&sql);
            #(#bind_fields_insert)*
            match q.execute(db.get_ref()).await {
                Ok(_) => HttpResponse::Created().finish(),
                Err(error) => HttpResponse::InternalServerError().body(error.to_string()),
            }
        }
    };

    let update_body = if update_plan.clauses.is_empty() {
        quote! {
            HttpResponse::BadRequest().body("No updatable fields configured")
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
                    Ok(result) if result.rows_affected() == 0 => HttpResponse::NotFound().finish(),
                    Ok(_) => HttpResponse::Ok().finish(),
                    Err(error) => HttpResponse::InternalServerError().body(error.to_string()),
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
                        Ok(result) if result.rows_affected() == 0 => HttpResponse::NotFound().finish(),
                        Ok(_) => HttpResponse::Ok().finish(),
                        Err(error) => HttpResponse::InternalServerError().body(error.to_string()),
                    }
                } else {
                    let sql = #filtered_sql;
                    let mut q = #runtime_crate::sqlx::query(sql);
                    #(#bind_fields_update)*
                    q = q.bind(path.into_inner());
                    #(#update_filter_binds)*
                    match q.execute(db.get_ref()).await {
                        Ok(result) if result.rows_affected() == 0 => HttpResponse::NotFound().finish(),
                        Ok(_) => HttpResponse::Ok().finish(),
                        Err(error) => HttpResponse::InternalServerError().body(error.to_string()),
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
                Ok(result) if result.rows_affected() == 0 => HttpResponse::NotFound().finish(),
                Ok(_) => HttpResponse::Ok().finish(),
                Err(error) => HttpResponse::InternalServerError().body(error.to_string()),
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
                    Ok(result) if result.rows_affected() == 0 => HttpResponse::NotFound().finish(),
                    Ok(_) => HttpResponse::Ok().finish(),
                    Err(error) => HttpResponse::InternalServerError().body(error.to_string()),
                }
            } else {
                let sql = #filtered_sql;
                let mut q = #runtime_crate::sqlx::query(sql);
                q = q.bind(path.into_inner());
                #(#delete_filter_binds)*
                match q.execute(db.get_ref()).await {
                    Ok(result) if result.rows_affected() == 0 => HttpResponse::NotFound().finish(),
                    Ok(_) => HttpResponse::Ok().finish(),
                    Err(error) => HttpResponse::InternalServerError().body(error.to_string()),
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
        let relation_name = field_ident.to_string();
        if !resource.policies.read.is_empty() {
            let relation_placeholder = resource.db.placeholder(1);
            let filtered_sql =
                filtered_nested_select_sql(resource, &relation_name, &resource.policies.read, 2);
            quote! {
                async fn #handler_ident(
                    path: web::Path<i64>,
                    user: #runtime_crate::core::auth::UserContext,
                    db: web::Data<AnyPool>,
                ) -> impl Responder {
                    #read_check

                    let sql = format!("SELECT * FROM {} WHERE {} = {}", #table_name, stringify!(#field_ident), #relation_placeholder);
                    let filtered_sql = #filtered_sql;

                    if #admin_bypass && #is_admin {
                        match #runtime_crate::sqlx::query_as::<_, Self>(&sql)
                            .bind(path.into_inner())
                            .fetch_all(db.get_ref())
                            .await
                        {
                            Ok(items) => HttpResponse::Ok().json(items),
                            Err(error) => HttpResponse::InternalServerError().body(error.to_string()),
                        }
                    } else {
                        let mut q = #runtime_crate::sqlx::query_as::<_, Self>(filtered_sql)
                            .bind(path.into_inner());
                        #(#read_filter_binds)*
                        match q.fetch_all(db.get_ref()).await {
                            Ok(items) => HttpResponse::Ok().json(items),
                            Err(error) => HttpResponse::InternalServerError().body(error.to_string()),
                        }
                    }
                }
            }
        } else {
            let id_placeholder = resource.db.placeholder(1);
            quote! {
                async fn #handler_ident(
                    path: web::Path<i64>,
                    user: #runtime_crate::core::auth::UserContext,
                    db: web::Data<AnyPool>,
                ) -> impl Responder {
                    #read_check

                    let sql = format!("SELECT * FROM {} WHERE {} = {}", #table_name, stringify!(#field_ident), #id_placeholder);
                    match #runtime_crate::sqlx::query_as::<_, Self>(&sql)
                        .bind(path.into_inner())
                        .fetch_all(db.get_ref())
                        .await
                    {
                        Ok(items) => HttpResponse::Ok().json(items),
                        Err(error) => HttpResponse::InternalServerError().body(error.to_string()),
                    }
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

            async fn get_all(
                user: #runtime_crate::core::auth::UserContext,
                db: web::Data<AnyPool>,
            ) -> impl Responder {
                #read_check
                #get_all_body
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
                #create_body
            }

            async fn update(
                path: web::Path<i64>,
                item: web::Json<#update_payload_ty>,
                user: #runtime_crate::core::auth::UserContext,
                db: web::Data<AnyPool>,
            ) -> impl Responder {
                #update_check
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

fn create_payload_fields(resource: &ResourceSpec) -> Vec<&super::model::FieldSpec> {
    resource
        .fields
        .iter()
        .filter(|field| {
            !field.generated.skip_insert()
                && create_assignment_source(resource, &field.name()).is_none()
        })
        .collect()
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

fn bind_policy_filters(filters: &[PolicyFilter]) -> Vec<TokenStream> {
    filters
        .iter()
        .map(|filter| {
            let value = policy_source_value(&filter.source);
            quote! {
                q = q.bind(#value);
            }
        })
        .collect()
}

fn policy_source_value(source: &PolicyValueSource) -> TokenStream {
    match source {
        PolicyValueSource::UserId => quote!(user.id),
        PolicyValueSource::Claim(name) => {
            let claim_name = Literal::string(name);
            quote! {
                {
                    match user.claim_i64(#claim_name) {
                        Some(value) => value,
                        None => return HttpResponse::Forbidden().body(format!("Missing required claim `{}`", #claim_name)),
                    }
                }
            }
        }
    }
}

fn filtered_select_sql(
    resource: &ResourceSpec,
    filters: &[PolicyFilter],
    start_index: usize,
) -> String {
    let where_sql = filter_where_sql(resource, filters, start_index);
    format!("SELECT * FROM {} WHERE {}", resource.table_name, where_sql)
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

fn filtered_nested_select_sql(
    resource: &ResourceSpec,
    relation_name: &str,
    filters: &[PolicyFilter],
    start_index: usize,
) -> String {
    let mut conditions = vec![format!(
        "{} = {}",
        relation_name,
        resource.db.placeholder(1)
    )];
    conditions.extend(filter_conditions_sql(resource, filters, start_index));
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

fn filter_where_sql(
    resource: &ResourceSpec,
    filters: &[PolicyFilter],
    start_index: usize,
) -> String {
    filter_conditions_sql(resource, filters, start_index).join(" AND ")
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
                return #runtime_crate::actix_web::HttpResponse::Forbidden().body("Insufficient privileges");
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
