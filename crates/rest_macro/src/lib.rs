use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(RestApi, attributes(rest_api, require_role, relation))]
pub fn rest_api_macro(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    // ---------------------------------------------------------------------
    // 1) Basic info about the struct
    // ---------------------------------------------------------------------
    let struct_name = &input.ident;
    let lower_name = struct_name.to_string().to_lowercase();
    let module_ident = format_ident!("__rest_api_impl_for_{}", lower_name);

    // We assume SQLite-like syntax for placeholders (?) 
    // If you need Postgres ($1, $2, ...), adapt accordingly.
    let db_type = "sqlite";
    let table_name = lower_name.clone();
    let id_field = "id";

    // ---------------------------------------------------------------------
    // 2) Parse role requirements
    // ---------------------------------------------------------------------
    #[derive(Default)]
    struct RoleRequirements {
        read: Option<String>,
        update: Option<String>,
        delete: Option<String>,
    }

    fn parse_role_requirements(attrs: &[syn::Attribute]) -> RoleRequirements {
        let mut roles = RoleRequirements::default();

        for attr in attrs {
            if attr.path().is_ident("require_role") {
                let _ = attr.parse_nested_meta(|meta| {
                    let path = meta.path.get_ident().unwrap().to_string();
                    let value = meta.value()?.parse::<syn::LitStr>()?.value();

                    match path.as_str() {
                        "read" => roles.read = Some(value),
                        "update" => roles.update = Some(value),
                        "delete" => roles.delete = Some(value),
                        _ => {}
                    }
                    Ok(())
                });
            }
        }

        roles
    }

    let roles = parse_role_requirements(&input.attrs);

    fn build_role_check(role: &Option<String>) -> proc_macro2::TokenStream {
        if let Some(role) = role {
            quote! {
                // 'admin' overrides everything
                if !user.roles.contains(&String::from("admin")) && !user.roles.contains(&String::from(#role)) {
                    return HttpResponse::Forbidden().body("Insufficient privileges");
                }
            }
        } else {
            quote! {}
        }
    }

    let read_check   = build_role_check(&roles.read);
    let update_check = build_role_check(&roles.update);
    let delete_check = build_role_check(&roles.delete);

    // ---------------------------------------------------------------------
    // 3) Parse struct fields
    // ---------------------------------------------------------------------
    struct FieldMetadata {
        name: String,
        ident: syn::Ident,
        sql_type: String,
        skip_insert: bool,
        is_primary_key: bool,
        is_created_at: bool,
        is_updated_at: bool,
    }

    #[derive(Default)]
    struct RelationMetadata {
        field_name: String,
        parent_table: String,
    }

    let mut field_metadatas = Vec::new();
    let mut relation_meta = RelationMetadata::default();

    if let syn::Data::Struct(data_struct) = &input.data {
        if let syn::Fields::Named(fields_named) = &data_struct.fields {
            for field in &fields_named.named {
                let ident = field
                    .ident
                    .clone()
                    .expect("Expected named field to have an ident");
                let name = ident.to_string();

                // Build field metadata
                let mut meta = FieldMetadata {
                    name: name.clone(),
                    ident: ident.clone(),
                    sql_type: "TEXT".to_string(),
                    skip_insert: false,
                    is_primary_key: false,
                    is_created_at: false,
                    is_updated_at: false,
                };

                // Simplistic type mapping for example
                let ty_str = quote!(#field.ty).to_string();
                if ty_str.contains("i32") || ty_str.contains("i64") {
                    meta.sql_type = "INTEGER".into();
                } else if ty_str.contains("f32") || ty_str.contains("f64") {
                    meta.sql_type = "REAL".into();
                } else {
                    meta.sql_type = "TEXT".into();
                }

                // Check for relation attribute
                for attr in &field.attrs {
                    if attr.path().is_ident("relation") {
                        let mut foreign_key = None;
                        let mut references = None;
                        let mut nested_route = false;

                        let _ = attr.parse_nested_meta(|meta_attr| {
                            let path = meta_attr.path.get_ident().unwrap().to_string();

                            match path.as_str() {
                                "foreign_key" => {
                                    foreign_key = Some(meta_attr.value()?.parse::<syn::LitStr>()?.value());
                                }
                                "references" => {
                                    references = Some(meta_attr.value()?.parse::<syn::LitStr>()?.value());
                                }
                                "nested_route" => {
                                    let val = meta_attr.value()?.parse::<syn::LitStr>()?.value();
                                    nested_route = val == "true";
                                }
                                _ => {}
                            }
                            Ok(())
                        });

                        if let (Some(_fk), Some(refs)) = (foreign_key, references) {
                            let parts: Vec<&str> = refs.split('.').collect();
                            if parts.len() == 2 {
                                let parent_table = parts[0];
                                relation_meta.field_name = name.clone();
                                relation_meta.parent_table = parent_table.to_string();
                            }
                        }

                        let _ = nested_route;
                    }
                }

                // Mark special fields
                if name == id_field {
                    meta.is_primary_key = true;
                    meta.skip_insert = true;
                }
                if name == "created_at" {
                    meta.is_created_at = true;
                    meta.skip_insert = true;
                }
                if name == "updated_at" {
                    meta.is_updated_at = true;
                    meta.skip_insert = true;
                }

                field_metadatas.push(meta);
            }
        }
    }

    // ---------------------------------------------------------------------
    // 4) Build SQL parts
    // ---------------------------------------------------------------------
    let mut field_defs = Vec::new();
    let mut insert_fields = Vec::new();
    let mut bind_insert = Vec::new();

    let mut update_clauses = Vec::new();
    let mut bind_update = Vec::new();

    // We'll gather field names so we can validate `order_by` and use for dynamic search
    let field_names: Vec<String> = field_metadatas.iter().map(|f| f.name.clone()).collect();
    
    // Determine which fields should be searchable (exclude ids, timestamps, etc.)
    let searchable_fields: Vec<String> = field_names.iter()
        .filter(|name| {
            name != &id_field && 
            !name.ends_with("_id") && 
            *name != "created_at" && 
            *name != "updated_at" &&
            *name != "password_hash"
        })
        .cloned()
        .collect();
    
    let searchable_fields_count = searchable_fields.len();

    for (i, f) in field_metadatas.iter().enumerate() {
        // CREATE TABLE part
        if f.is_primary_key {
            field_defs.push(format!("{} INTEGER PRIMARY KEY AUTOINCREMENT", f.name));
        } else if f.is_created_at {
            field_defs.push(format!("{} TEXT DEFAULT CURRENT_TIMESTAMP", f.name));
        } else if f.is_updated_at {
            field_defs.push(format!("{} TEXT DEFAULT CURRENT_TIMESTAMP", f.name));
        } else {
            field_defs.push(format!("{} {}", f.name, f.sql_type));
        }

        // INSERT
        if !f.skip_insert {
            insert_fields.push(f.name.clone());
            let field_ident = &f.ident;
            bind_insert.push(quote! {
                q = q.bind(&item.#field_ident);
            });
        }

        // UPDATE
        if !f.is_primary_key && !f.is_created_at && !f.is_updated_at {
            let clause = if db_type == "postgres" {
                format!("{} = ${}", f.name, i + 1)
            } else {
                format!("{} = ?", f.name)
            };
            update_clauses.push(clause);

            let field_ident = &f.ident;
            bind_update.push(quote! {
                q = q.bind(&item.#field_ident);
            });
        }

        if f.is_updated_at {
            // Auto-update updated_at on each update
            update_clauses.push("updated_at = CURRENT_TIMESTAMP".to_string());
        }
    }

    let insert_placeholders = insert_fields.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let update_sql = update_clauses.join(", ");
    let insert_fields_csv = insert_fields.join(", ");
    let field_defs_sql = field_defs.join(", ");

    let relation_field = relation_meta.field_name;
    let relation_parent_table = relation_meta.parent_table;

    // Generate the search WHERE clause
    let mut search_where_parts = Vec::new();
    for field in &searchable_fields {
        search_where_parts.push(format!("{} LIKE ?", field));
    }
    let search_where_clause = search_where_parts.join(" OR ");

    // ---------------------------------------------------------------------
    // 5) Generate final code with advanced query params (page, limit, order, search)
    // ---------------------------------------------------------------------
    let expanded = quote! {
        mod #module_ident {
            use super::*;
            use actix_web::{web, HttpResponse, Responder};
            use sqlx::AnyPool;
            use very_simple_rest::core::auth::UserContext;

            // We'll use Serde to parse query params for listing
            use serde::Deserialize;

            // -----------
            // Query struct for listing items
            // -----------
            #[derive(Debug, Deserialize)]
            struct ListParams {
                // Pagination
                page: Option<usize>,
                limit: Option<usize>,

                // Sorting (e.g., ?order_by=name&order_dir=desc)
                order_by: Option<String>,
                order_dir: Option<String>,

                // Simple search term
                search: Option<String>,
            }

            impl #struct_name {
                pub fn configure(cfg: &mut web::ServiceConfig, db: AnyPool) {
                    let db = web::Data::new(db);
                    cfg.app_data(db.clone());

                    actix_web::rt::spawn(Self::create_table_if_not_exists(db.clone()));

                    cfg.service(
                        web::resource(format!("/{}", #table_name))
                            // We parse query params for listing
                            .route(web::get().to(Self::get_all))
                            .route(web::post().to(Self::create))
                    )
                    .service(
                        web::resource(format!("/{}/{{id}}", #table_name))
                            .route(web::get().to(Self::get_one))
                            .route(web::put().to(Self::update))
                            .route(web::delete().to(Self::delete))
                    );

                    if !#relation_field.is_empty() {
                        cfg.service(
                            web::resource(
                                format!("/{}/{{parent_id}}/{}", #relation_parent_table, #table_name)
                            )
                            .route(web::get().to(Self::get_by_parent_id))
                        );
                    }
                }

                async fn create_table_if_not_exists(db: web::Data<AnyPool>) {
                    let sql = format!("CREATE TABLE IF NOT EXISTS {} ({})", #table_name, #field_defs_sql);
                    let _ = sqlx::query(&sql).execute(db.get_ref()).await;
                }

                /// GET /{table_name}?page=1&limit=10&order_by=id&order_dir=asc&search=foo
                async fn get_all(
                    user: UserContext,
                    db: web::Data<AnyPool>,
                    query: web::Query<ListParams>,
                ) -> impl Responder {
                    #read_check

                    // ------- 1) Pagination -------
                    let page = query.page.unwrap_or(1).max(1);
                    let limit = query.limit.unwrap_or(10).max(1);
                    let offset = (page - 1) * limit;

                    // ------- 2) Sorting -------
                    // Validate order_by field exists in the model
                    let valid_fields = [#(#field_names),*];
                    
                    let order_by = match &query.order_by {
                        Some(col) => {
                            if valid_fields.contains(&col.as_str()) {
                                col
                            } else {
                                #id_field
                            }
                        }
                        None => #id_field,
                    };

                    // ascending or descending
                    let order_dir = match query.order_dir.as_deref() {
                        Some("desc") => "DESC",
                        _ => "ASC",
                    };

                    // ------- 3) Searching -------
                    // Dynamic search across all searchable fields
                    let mut filter_sql = String::new();
                    let has_searchable_fields = #searchable_fields_count > 0;

                    if let Some(_) = &query.search {
                        if has_searchable_fields {
                            filter_sql.push_str(" WHERE (");
                            filter_sql.push_str(#search_where_clause);
                            filter_sql.push_str(")");
                        }
                    }

                    // Combined final SQL (with search, order, limit, offset)
                    let sql = format!(
                        "SELECT * FROM {}{} ORDER BY {} {} LIMIT ? OFFSET ?",
                        #table_name, filter_sql, order_by, order_dir
                    );

                    // We build the query
                    let mut q = sqlx::query_as::<_, Self>(&sql);

                    // Bind search parameters if present
                    if let Some(search_str) = &query.search {
                        if has_searchable_fields {
                            let pattern = format!("%{}%", search_str);
                            // Bind once for each field in the WHERE clause
                            for _ in 0..#searchable_fields_count {
                                q = q.bind(pattern.clone());
                            }
                        }
                    }
                    
                    // Bind limit + offset
                    q = q.bind(limit as i64);
                    q = q.bind(offset as i64);

                    match q.fetch_all(db.get_ref()).await {
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

                    let sql = format!(
                        "INSERT INTO {} ({}) VALUES ({})",
                        #table_name,
                        #insert_fields_csv,
                        #insert_placeholders
                    );
                    let mut q = sqlx::query(&sql);
                    #(#bind_insert)*

                    match q.execute(db.get_ref()).await {
                        Ok(_) => HttpResponse::Created().finish(),
                        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
                    }
                }

                async fn update(path: web::Path<i64>, item: web::Json<Self>, user: UserContext, db: web::Data<AnyPool>) -> impl Responder {
                    #update_check

                    let sql = format!(
                        "UPDATE {} SET {} WHERE {} = ?",
                        #table_name,
                        #update_sql,
                        #id_field
                    );
                    let mut q = sqlx::query(&sql);
                    #(#bind_update)*
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

                /// Example nested route with the same advanced query usage
                async fn get_by_parent_id(
                    path: web::Path<i64>,
                    user: UserContext,
                    db: web::Data<AnyPool>,
                    query: web::Query<ListParams>,
                ) -> impl Responder {
                    #read_check

                    let parent_id = path.into_inner();

                    // pagination
                    let page = query.page.unwrap_or(1).max(1);
                    let limit = query.limit.unwrap_or(10).max(1);
                    let offset = (page - 1) * limit;

                    // sorting
                    let valid_fields = [#(#field_names),*];
                    
                    let order_by = match &query.order_by {
                        Some(col) => {
                            if valid_fields.contains(&col.as_str()) {
                                col
                            } else {
                                #id_field
                            }
                        }
                        None => #id_field,
                    };

                    let order_dir = match query.order_dir.as_deref() {
                        Some("desc") => "DESC",
                        _ => "ASC",
                    };

                    // searching - always include parent_id filter
                    let mut filter_sql = format!(" WHERE {} = ?", #relation_field);
                    let has_searchable_fields = #searchable_fields_count > 0;
                    
                    if let Some(_) = &query.search {
                        if has_searchable_fields {
                            filter_sql.push_str(" AND (");
                            filter_sql.push_str(#search_where_clause);
                            filter_sql.push_str(")");
                        }
                    }

                    let sql = format!(
                        "SELECT * FROM {}{} ORDER BY {} {} LIMIT ? OFFSET ?",
                        #table_name, filter_sql, order_by, order_dir
                    );

                    let mut q = sqlx::query_as::<_, Self>(&sql);
                    
                    // Bind parent_id
                    q = q.bind(parent_id);
                    
                    // Bind search terms if present
                    if let Some(search_str) = &query.search {
                        if has_searchable_fields {
                            let pattern = format!("%{}%", search_str);
                            // Bind once for each field in the WHERE clause
                            for _ in 0..#searchable_fields_count {
                                q = q.bind(pattern.clone());
                            }
                        }
                    }
                    
                    // Bind pagination
                    q = q.bind(limit as i64);
                    q = q.bind(offset as i64);

                    match q.fetch_all(db.get_ref()).await {
                        Ok(items) => HttpResponse::Ok().json(items),
                        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
                    }
                }
            }
        }
    };

    TokenStream::from(expanded)
}
