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
            // Admin role always has access
            if !user.roles.contains(&String::from("admin")) && !user.roles.contains(&String::from(#role)) {
                return HttpResponse::Forbidden().body("Insufficient privileges");
            }
        }
    } else {
        quote! {}
    };

    // Generate role check for update operations
    let update_check = if let Some(role) = &update_role {
        quote! {
            // Admin role always has access
            if !user.roles.contains(&String::from("admin")) && !user.roles.contains(&String::from(#role)) {
                return HttpResponse::Forbidden().body("Insufficient privileges");
            }
        }
    } else {
        quote! {}
    };

    // Generate role check for delete operations
    let delete_check = if let Some(role) = &delete_role {
        quote! {
            // Admin role always has access
            if !user.roles.contains(&String::from("admin")) && !user.roles.contains(&String::from(#role)) {
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

    // Generate partial_struct_name and partial_fields for PATCH
    let (partial_struct_name, partial_fields) = if let syn::Data::Struct(data_struct) = &input.data {
        if let syn::Fields::Named(fields_named) = &data_struct.fields {
            let fields: Vec<_> = fields_named.named
                .iter()
                .filter(|f| f.ident.as_ref().unwrap() != "id")  // Skip primary key field
                .map(|f| {
                    let ident = &f.ident;
                    let ty = &f.ty;
                    quote! { #ident: Option<#ty> }
                })
                .collect();
            let name = format_ident!("Partial{}", struct_name);
            (name, fields)
        } else {
            (format_ident!("Partial{}", struct_name), vec![])
        }
    } else {
        (format_ident!("Partial{}", struct_name), vec![])
    };

    // Example:
    //
    // pub struct PartialPost {
    //     title: Option<String>,
    //     content: Option<String>,
    //     created_at: Option<String>,
    //     updated_at: Option<String>,
    // }
    let expanded_partial = quote! {
        #[derive(serde::Deserialize)]
        pub struct #partial_struct_name {
            #(#partial_fields),*
        }
    };

    // Generate the patch implementation
    let patch_impl = {
        let mut set_tokens = Vec::new();
        let mut bind_tokens = Vec::new();

        for ident in &field_idents {
            let name = ident.to_string();
            if name == "id" || name == "created_at" || name == "updated_at" {
                continue;
            }

            let name_lit = syn::LitStr::new(&name, ident.span());

            // Example generated code:
            //
            // If the JSON body is:
            // {
            //     "title": "New title",
            //     "content": "New content"
            // }
            //
            // The generated code will be:
            // UPDATE post SET title = ?, content = ? WHERE id = ?
            set_tokens.push(quote! {
                if partial.#ident.is_some() {
                    if !first {
                        sql.push_str(", ");
                    }
                    sql.push_str(#name_lit);
                    sql.push_str(" = ?");
                    first = false;
                }
            });

            // For each field that is Some in the PATCH request, bind its value to the SQL query
            bind_tokens.push(quote! {
                if let Some(v) = &partial.#ident {
                    query = query.bind(v);
                }
            });
        }

        let updated_at_code = if field_names.contains(&"updated_at".to_string()) {
            quote! {
                if !first {
                    sql.push_str(", updated_at = CURRENT_TIMESTAMP");
                } else {
                    sql.push_str("updated_at = CURRENT_TIMESTAMP");
                    first = false;
                }
            }
        } else {
            quote! {}
        };

        quote! {
            impl #partial_struct_name {
                pub async fn patch(
                    path: web::Path<i64>,
                    json: web::Json<Self>,
                    user: UserContext,
                    db: web::Data<AnyPool>,
                ) -> impl Responder {
                    #update_check

                    let id = path.into_inner();
                    let partial = json.into_inner();    // Instance of PartialStruct

                    let mut sql = String::from("UPDATE ");
                    sql.push_str(#table_name);
                    sql.push_str(" SET ");  // Start of SET clause
                    let mut first = true;   // Boolean to track if it's the first field in SET clause

                    // Build SET clause dynamically based on which fields are Some
                    #(#set_tokens)*
                    #updated_at_code

                    // If no fields were updated, return OK
                    if first {
                        return HttpResponse::Ok().finish();
                    }

                    sql.push_str(" WHERE id = ?");
                    let mut query = sqlx::query(&sql);

                    // Bind values for fields that are Some
                    #(#bind_tokens)*
                    query = query.bind(id);

                    match query.execute(db.get_ref()).await {
                        Ok(res) => {
                            if res.rows_affected() > 0 {
                                HttpResponse::Ok().finish()
                            } else {
                                HttpResponse::NotFound().finish()
                            }
                        }
                        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
                    }
                }
            }
        }
    };

    // Conditional get_by_parent_id method
    let get_by_parent_id_impl = if !relation_field.is_empty() {
        let field_lit = syn::LitStr::new(&relation_field, struct_name.span());
        
        quote! {
            async fn get_by_parent_id(
                path: web::Path<i64>,
                user: UserContext,
                db: web::Data<AnyPool>,
            ) -> impl Responder {
                #read_check
                let parent_id = path.into_inner();
                let sql = format!("SELECT * FROM {} WHERE {} = ?", #table_name, #field_lit);
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
    } else {
        quote! {}
    };

    // Conditional nested route registration
    let nested_route_registration = if !relation_parent_table.is_empty() {
        let parent_table_lit = syn::LitStr::new(&relation_parent_table, struct_name.span());
        quote! {
            cfg.service(
                web::resource(format!("/{}/{{parent_id}}/{}", #parent_table_lit, #table_name))
                    .route(web::get().to(Self::get_by_parent_id))
            );
        }
    } else {
        quote! {}
    };

    // FINAL EXPANDED OUTPUT
    let expanded = quote! {
        #expanded_partial

        mod #module_ident {
            use super::*;
            use actix_web::{web, HttpResponse, Responder};
            use sqlx::AnyPool;
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
                            .route(web::patch().to(#partial_struct_name::patch))
                            .route(web::delete().to(Self::delete))
                    );

                    #nested_route_registration
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
                    let id = path.into_inner();
                    let sql = format!("SELECT * FROM {} WHERE {} = ?", #table_name, #id_field);
                    match sqlx::query_as::<_, Self>(&sql)
                        .bind(id)
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
                    let id = path.into_inner();
                    let sql = format!("UPDATE {} SET {} WHERE {} = ?", #table_name, #update_sql, #id_field);
                    let mut q = sqlx::query(&sql);
                    #(#bind_fields_update)*
                    q = q.bind(id);
                    match q.execute(db.get_ref()).await {
                        Ok(_) => HttpResponse::Ok().finish(),
                        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
                    }
                }

                async fn delete(path: web::Path<i64>, user: UserContext, db: web::Data<AnyPool>) -> impl Responder {
                    #delete_check
                    let id = path.into_inner();
                    let sql = format!("DELETE FROM {} WHERE {} = ?", #table_name, #id_field);
                    match sqlx::query(&sql)
                        .bind(id)
                        .execute(db.get_ref())
                        .await
                    {
                        Ok(_) => HttpResponse::Ok().finish(),
                        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
                    }
                }

                #get_by_parent_id_impl
            }

            #patch_impl
        }
    };

    TokenStream::from(expanded)
}
