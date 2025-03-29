use proc_macro::TokenStream;
use quote::{format_ident, quote};
use std::collections::HashSet;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(RestApi, attributes(rest_api, require_role, relation))]
pub fn rest_api_macro(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;
    let lower_name = struct_name.to_string().to_lowercase();
    let module_ident = format_ident!("__rest_api_impl_for_{}", lower_name);

    let mut field_defs = vec![];
    let mut field_names = vec![];
    let mut field_idents = vec![];
    let mut bind_fields_insert = vec![];
    let mut bind_fields_update = vec![];
    let mut update_clauses = vec![];
    let mut skip_insert_fields = HashSet::new();

    let db_type = "sqlite";
    let table_name = lower_name.clone();
    let id_field = "id";

    // Track relations for nested routes
    let mut relation_field = String::new();
    let mut relation_parent_table = String::new();

    // Default role requirements
    let mut read_role = None;
    let mut update_role = None;
    let mut delete_role = None;

    // Parse require_role attributes
    for attr in &input.attrs {
        if attr.path().is_ident("require_role") {
            let _ = attr.parse_nested_meta(|meta| {
                let path = meta.path.get_ident().unwrap().to_string();
                let value = meta.value()?.parse::<syn::LitStr>()?.value();

                if path == "read" {
                    read_role = Some(value);
                } else if path == "update" {
                    update_role = Some(value);
                } else if path == "delete" {
                    delete_role = Some(value);
                }

                Ok(())
            });
        }
    }

    // Generate role check for read operations
    let read_check = if let Some(role) = &read_role {
        quote! {
            if !user.roles.contains(&String::from(#role)) {
                return HttpResponse::Forbidden().body("Insufficient privileges");
            }
        }
    } else {
        quote! {}
    };

    // Generate role check for update operations
    let update_check = if let Some(role) = &update_role {
        quote! {
            if !user.roles.contains(&String::from(#role)) {
                return HttpResponse::Forbidden().body("Insufficient privileges");
            }
        }
    } else {
        quote! {}
    };

    // Generate role check for delete operations
    let delete_check = if let Some(role) = &delete_role {
        quote! {
            if !user.roles.contains(&String::from(#role)) {
                return HttpResponse::Forbidden().body("Insufficient privileges");
            }
        }
    } else {
        quote! {}
    };

    if let syn::Data::Struct(data_struct) = &input.data {
        if let syn::Fields::Named(fields_named) = &data_struct.fields {
            for field in &fields_named.named {
                let name = field.ident.as_ref().unwrap().to_string();
                let ident = field.ident.as_ref().unwrap();

                // Check for relation attribute
                for attr in &field.attrs {
                    if attr.path().is_ident("relation") {
                        let mut foreign_key = None;
                        let mut references = None;
                        let mut nested_route = false;

                        let _ = attr.parse_nested_meta(|meta| {
                            let path = meta.path.get_ident().unwrap().to_string();

                            if path == "foreign_key" {
                                foreign_key = Some(meta.value()?.parse::<syn::LitStr>()?.value());
                            } else if path == "references" {
                                references = Some(meta.value()?.parse::<syn::LitStr>()?.value());
                            } else if path == "nested_route" {
                                let value = meta.value()?.parse::<syn::LitStr>()?.value();
                                nested_route = value == "true";
                            }

                            Ok(())
                        });

                        if let (Some(_), Some(refs)) = (foreign_key, references) {
                            let parts: Vec<&str> = refs.split('.').collect();
                            if parts.len() == 2 {
                                let parent_table = parts[0];
                                relation_field = name.clone();
                                relation_parent_table = parent_table.to_string();
                            }
                        }
                    }
                }

                if name == "created_at" || name == "updated_at" {
                    field_defs.push(format!("{} TEXT DEFAULT CURRENT_TIMESTAMP", name));
                    skip_insert_fields.insert(name.clone());
                    if name == "updated_at" {
                        update_clauses.push("updated_at = CURRENT_TIMESTAMP".to_string());
                    }
                    continue;
                }

                let ty_str = quote!(#field.ty).to_string();
                let sql_type = if ty_str.contains("i32") || ty_str.contains("i64") {
                    "INTEGER"
                } else if ty_str.contains("f32") || ty_str.contains("f64") {
                    "REAL"
                } else {
                    "TEXT"
                };

                let is_id = name == id_field;
                if is_id {
                    field_defs.push(format!("{} INTEGER PRIMARY KEY AUTOINCREMENT", name));
                    skip_insert_fields.insert(name.clone());
                } else {
                    field_defs.push(format!("{} {}", name, sql_type));
                }

                field_names.push(name.clone());
                field_idents.push(ident.clone());

                if !skip_insert_fields.contains(&name) {
                    bind_fields_insert.push(quote! { q = q.bind(&item.#ident); });
                }
                if !is_id && name != "created_at" && name != "updated_at" {
                    bind_fields_update.push(quote! { q = q.bind(&item.#ident); });
                    let clause = if db_type == "postgres" {
                        format!("{} = ${}", name, update_clauses.len() + 1)
                    } else {
                        format!("{} = ?", name)
                    };
                    update_clauses.push(clause);
                }
            }
        }
    }
    // let insert_fields: Vec<String> = field_names.iter().cloned().filter(|f| !skip_insert_fields.contains(f)).collect();

    let insert_fields: Vec<String> = field_names
        .iter()
        .filter(|&f| !skip_insert_fields.contains(f))
        .cloned()
        .collect();
    let insert_placeholders = insert_fields
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(", ");
    let update_sql = update_clauses.join(", ");
    let insert_fields_csv = insert_fields.join(", ");
    let field_defs_sql = field_defs.join(", ");

    let expanded = quote! {
        mod #module_ident {
            use super::*;
            use actix_web::{web, HttpResponse, Responder};
            use sqlx::AnyPool;

            // Access UserContext through the core module which is re-exported in rest_api
            use very_simple_rest::core::auth::UserContext;

            impl #struct_name {
                pub fn configure(cfg: &mut web::ServiceConfig, db: AnyPool) {
                    let db = web::Data::new(db);
                    cfg.app_data(db.clone());

                    actix_web::rt::spawn(Self::create_table_if_not_exists(db.clone()));

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

                    // Configure nested routes if relation field exists
                    let has_relation = !#relation_field.is_empty();
                    if has_relation {
                        cfg.service(
                            web::resource(format!("/{}/{{parent_id}}/{}", #relation_parent_table, #table_name))
                                .route(web::get().to(Self::get_by_parent_id))
                        );
                    }
                }

                async fn create_table_if_not_exists(db: web::Data<AnyPool>) {
                    let sql = format!("CREATE TABLE IF NOT EXISTS {} ({})", #table_name, #field_defs_sql);
                    let _ = sqlx::query(&sql).execute(db.get_ref()).await;
                }

                async fn get_all(user: UserContext, db: web::Data<AnyPool>) -> impl Responder {
                    #read_check

                    let sql = format!("SELECT * FROM {}", #table_name);
                    match sqlx::query_as::<_, Self>(&sql).fetch_all(db.get_ref()).await {
                        Ok(data) => HttpResponse::Ok().json(data),
                        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
                    }
                }

                async fn get_one(path: web::Path<i64>, user: UserContext, db: web::Data<AnyPool>) -> impl Responder {
                    #read_check

                    let sql = format!("SELECT * FROM {} WHERE {} = ?", #table_name, #id_field);
                    match sqlx::query_as::<_, Self>(&sql)
                        .bind(path.into_inner())
                        .fetch_optional(db.get_ref())
                        .await
                    {
                        Ok(Some(item)) => HttpResponse::Ok().json(item),
                        Ok(None) => HttpResponse::NotFound().finish(),
                        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
                    }
                }

                async fn create(item: web::Json<Self>, user: UserContext, db: web::Data<AnyPool>) -> impl Responder {
                    #update_check

                    let sql = format!("INSERT INTO {} ({}) VALUES ({})", #table_name, #insert_fields_csv, #insert_placeholders);
                    let mut q = sqlx::query(&sql);
                    #(#bind_fields_insert)*
                    match q.execute(db.get_ref()).await {
                        Ok(_) => HttpResponse::Created().finish(),
                        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
                    }
                }

                async fn update(path: web::Path<i64>, item: web::Json<Self>, user: UserContext, db: web::Data<AnyPool>) -> impl Responder {
                    #update_check

                    let sql = format!("UPDATE {} SET {} WHERE {} = ?", #table_name, #update_sql, #id_field);
                    let mut q = sqlx::query(&sql);
                    #(#bind_fields_update)*
                    q = q.bind(path.into_inner());
                    match q.execute(db.get_ref()).await {
                        Ok(_) => HttpResponse::Ok().finish(),
                        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
                    }
                }

                async fn delete(path: web::Path<i64>, user: UserContext, db: web::Data<AnyPool>) -> impl Responder {
                    #delete_check

                    let sql = format!("DELETE FROM {} WHERE {} = ?", #table_name, #id_field);
                    match sqlx::query(&sql)
                        .bind(path.into_inner())
                        .execute(db.get_ref())
                        .await
                    {
                        Ok(_) => HttpResponse::Ok().finish(),
                        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
                    }
                }

                // Handler for nested routes - returns all child items for a parent
                async fn get_by_parent_id(path: web::Path<i64>, user: UserContext, db: web::Data<AnyPool>) -> impl Responder {
                    #read_check

                    let parent_id = path.into_inner();
                    let sql = format!("SELECT * FROM {} WHERE {} = ?", #table_name, #relation_field);
                    match sqlx::query_as::<_, Self>(&sql)
                        .bind(parent_id)
                        .fetch_all(db.get_ref())
                        .await
                    {
                        Ok(items) => HttpResponse::Ok().json(items),
                        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
                    }
                }
            }
        }
    };

    TokenStream::from(expanded)
}
