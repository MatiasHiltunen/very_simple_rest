use std::collections::HashSet;

use syn::{Data, DeriveInput, Fields, Lit, spanned::Spanned};

use super::model::{
    DbBackend, FieldSpec, FieldValidation, ListConfig, NumericBound, PolicyAssignment,
    PolicyFilter, PolicyFilterExpression, PolicyFilterOperator, PolicyValueSource,
    ReferentialAction, ResourceSpec, RoleRequirements, RowPolicies, RowPolicyKind, WriteModelStyle,
    default_resource_module_ident, infer_generated_value, infer_sql_type,
    validate_field_validations, validate_list_config, validate_relations, validate_row_policies,
    validate_sql_identifier,
};

pub fn parse_derive_input(input: DeriveInput) -> syn::Result<ResourceSpec> {
    let struct_ident = input.ident.clone();
    let mut table_name = struct_ident.to_string().to_lowercase();
    let mut id_field = "id".to_owned();
    let mut db = DbBackend::Sqlite;
    let mut roles = RoleRequirements::default();
    let mut policies = RowPolicies::default();
    let mut list = ListConfig::default();

    for attr in &input.attrs {
        if attr.path().is_ident("rest_api") {
            attr.parse_nested_meta(|meta| {
                let key = meta
                    .path
                    .get_ident()
                    .ok_or_else(|| meta.error("unsupported rest_api key"))?
                    .to_string();
                let lit = meta.value()?.parse::<Lit>()?;
                match (key.as_str(), lit) {
                    ("table", Lit::Str(value)) => {
                        let parsed = value.value();
                        validate_sql_identifier(&parsed, value.span(), "table name")?;
                        table_name = parsed;
                    }
                    ("id", Lit::Str(value)) => id_field = value.value(),
                    ("db", Lit::Str(value)) => db = parse_db_backend(&value.value(), value.span())?,
                    _ => return Err(meta.error("expected string literal value")),
                }
                Ok(())
            })?;
        } else if attr.path().is_ident("require_role") {
            attr.parse_nested_meta(|meta| {
                let key = meta
                    .path
                    .get_ident()
                    .ok_or_else(|| meta.error("unsupported require_role key"))?
                    .to_string();
                let lit = meta.value()?.parse::<Lit>()?;
                let value = match lit {
                    Lit::Str(value) => value.value(),
                    _ => return Err(meta.error("role values must be string literals")),
                };

                match key.as_str() {
                    "read" => roles.read = Some(value),
                    "create" => roles.create = Some(value),
                    "update" => roles.update = Some(value),
                    "delete" => roles.delete = Some(value),
                    _ => return Err(meta.error("unsupported require_role key")),
                }
                Ok(())
            })?;
        } else if attr.path().is_ident("row_policy") {
            attr.parse_nested_meta(|meta| {
                let key = meta
                    .path
                    .get_ident()
                    .ok_or_else(|| meta.error("unsupported row_policy key"))?
                    .to_string();
                let lit = meta.value()?.parse::<Lit>()?;
                match key.as_str() {
                    "read" => {
                        let value = expect_policy_string(meta.path.span(), lit)?;
                        policies.read = merge_filter_policies(
                            policies.read.take(),
                            parse_filter_policies(&value.value(), value.span())?,
                        );
                    }
                    "create" => {
                        let value = expect_policy_string(meta.path.span(), lit)?;
                        policies
                            .create
                            .extend(parse_assignment_policies(&value.value(), value.span())?);
                    }
                    "update" => {
                        let value = expect_policy_string(meta.path.span(), lit)?;
                        policies.update = merge_filter_policies(
                            policies.update.take(),
                            parse_filter_policies(&value.value(), value.span())?,
                        );
                    }
                    "delete" => {
                        let value = expect_policy_string(meta.path.span(), lit)?;
                        policies.delete = merge_filter_policies(
                            policies.delete.take(),
                            parse_filter_policies(&value.value(), value.span())?,
                        );
                    }
                    "admin_bypass" => policies.admin_bypass = parse_policy_bool(lit)?,
                    _ => return Err(meta.error("unsupported row_policy key")),
                }
                Ok(())
            })?;
        } else if attr.path().is_ident("list") {
            attr.parse_nested_meta(|meta| {
                let key = meta
                    .path
                    .get_ident()
                    .ok_or_else(|| meta.error("unsupported list key"))?
                    .to_string();
                let lit = meta.value()?.parse::<Lit>()?;
                match (key.as_str(), lit) {
                    ("default_limit", Lit::Int(value)) => {
                        list.default_limit = Some(parse_u32_literal(&value)?);
                    }
                    ("max_limit", Lit::Int(value)) => {
                        list.max_limit = Some(parse_u32_literal(&value)?);
                    }
                    _ => return Err(meta.error("list values must be integer literals")),
                }
                Ok(())
            })?;
        }
    }

    let fields = match &input.data {
        Data::Struct(data_struct) => match &data_struct.fields {
            Fields::Named(fields) => fields,
            _ => {
                return Err(syn::Error::new_spanned(
                    &input,
                    "RestApi only supports structs with named fields",
                ));
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                &input,
                "RestApi can only be derived for structs",
            ));
        }
    };

    let mut parsed_fields = Vec::with_capacity(fields.named.len());
    let mut seen_fields = HashSet::new();

    for field in &fields.named {
        let ident = field
            .ident
            .clone()
            .ok_or_else(|| syn::Error::new_spanned(field, "expected named field"))?;
        let field_name = ident.to_string();
        if !seen_fields.insert(field_name.clone()) {
            return Err(syn::Error::new_spanned(
                &ident,
                format!("duplicate field `{field_name}`"),
            ));
        }

        let relation = parse_relation(field_name.as_str(), &field.attrs)?;
        let validation = parse_validation(&field.attrs)?;
        let is_id = field_name == id_field;
        let generated = infer_generated_value(&field_name, is_id);

        parsed_fields.push(FieldSpec {
            ident,
            api_name: field_name,
            expose_in_api: true,
            unique: false,
            enum_name: None,
            enum_values: None,
            transforms: Vec::new(),
            ty: field.ty.clone(),
            list_item_ty: None,
            object_fields: None,
            sql_type: infer_sql_type(&field.ty, db),
            is_id,
            generated,
            validation,
            relation,
        });
    }

    if !parsed_fields.iter().any(|field| field.name() == id_field) {
        return Err(syn::Error::new_spanned(
            &struct_ident,
            format!("configured id field `{id_field}` does not exist"),
        ));
    }
    let parsed = ResourceSpec {
        struct_ident: struct_ident.clone(),
        impl_module_ident: default_resource_module_ident(&struct_ident),
        table_name: table_name.clone(),
        api_name: table_name.clone(),
        default_response_context: None,
        response_contexts: Vec::new(),
        id_field,
        db,
        roles: roles.with_legacy_defaults(),
        policies,
        list,
        indexes: Vec::new(),
        many_to_many: Vec::new(),
        actions: Vec::new(),
        computed_fields: Vec::new(),
        fields: parsed_fields,
        write_style: WriteModelStyle::ExistingStructWithDtos,
    };
    validate_row_policies(
        &parsed,
        std::slice::from_ref(&parsed),
        &parsed.policies,
        struct_ident.span(),
    )?;
    validate_relations(&parsed.fields, struct_ident.span())?;
    validate_field_validations(&parsed.fields, struct_ident.span())?;
    validate_list_config(&parsed.list, struct_ident.span())?;

    Ok(parsed)
}

fn parse_relation(
    field_name: &str,
    attrs: &[syn::Attribute],
) -> syn::Result<Option<super::model::RelationSpec>> {
    let mut relation = None;

    for attr in attrs {
        if !attr.path().is_ident("relation") {
            continue;
        }

        let mut references = None;
        let mut on_delete = None;
        let mut nested_route = false;

        attr.parse_nested_meta(|meta| {
            let key = meta
                .path
                .get_ident()
                .ok_or_else(|| meta.error("unsupported relation key"))?
                .to_string();
            let lit = meta.value()?.parse::<Lit>()?;

            match (key.as_str(), lit) {
                ("foreign_key", Lit::Str(value)) => {
                    let configured = value.value();
                    if configured != field_name {
                        return Err(syn::Error::new(
                            value.span(),
                            format!(
                                "custom relation foreign_key overrides are not supported; field `{}` must map to its own column name",
                                field_name
                            ),
                        ));
                    }
                }
                ("references", Lit::Str(value)) => references = Some(value.value()),
                ("on_delete", Lit::Str(value)) => {
                    on_delete = Some(parse_referential_action(&value.value(), value.span())?);
                }
                ("nested_route", Lit::Bool(value)) => nested_route = value.value(),
                ("nested_route", Lit::Str(value)) => {
                    nested_route = value.value().parse::<bool>().map_err(|_| {
                        syn::Error::new(value.span(), "nested_route must be true or false")
                    })?;
                }
                _ => return Err(meta.error("invalid relation attribute value")),
            }

            Ok(())
        })?;

        let references = references.ok_or_else(|| {
            syn::Error::new(
                attr.span(),
                "relation requires `references = \"table.field\"`",
            )
        })?;
        let (references_table, references_field) =
            parse_reference_target(&references, attr.span())?;

        relation = Some(super::model::RelationSpec {
            references_table,
            references_field,
            on_delete,
            nested_route,
        });
    }

    Ok(relation)
}

fn parse_validation(attrs: &[syn::Attribute]) -> syn::Result<FieldValidation> {
    let mut validation = FieldValidation::default();

    for attr in attrs {
        if !attr.path().is_ident("validate") {
            continue;
        }

        attr.parse_nested_meta(|meta| {
            let key = meta
                .path
                .get_ident()
                .ok_or_else(|| meta.error("unsupported validate key"))?
                .to_string();
            let lit = meta.value()?.parse::<Lit>()?;

            match key.as_str() {
                "min_length" => {
                    validation.min_length = Some(parse_length_value(
                        validation.min_length,
                        lit,
                        "min_length",
                    )?);
                }
                "max_length" => {
                    validation.max_length = Some(parse_length_value(
                        validation.max_length,
                        lit,
                        "max_length",
                    )?);
                }
                "minimum" => {
                    validation.minimum = Some(parse_numeric_value(
                        validation.minimum.as_ref(),
                        lit,
                        "minimum",
                    )?);
                }
                "maximum" => {
                    validation.maximum = Some(parse_numeric_value(
                        validation.maximum.as_ref(),
                        lit,
                        "maximum",
                    )?);
                }
                _ => return Err(meta.error("unsupported validate key")),
            }

            Ok(())
        })?;
    }

    Ok(validation)
}

fn parse_reference_target(value: &str, span: proc_macro2::Span) -> syn::Result<(String, String)> {
    let mut parts = value.split('.');
    let table = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| syn::Error::new(span, "relation reference must be `table.field`"))?;
    let field = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| syn::Error::new(span, "relation reference must be `table.field`"))?;

    if parts.next().is_some() {
        return Err(syn::Error::new(
            span,
            "relation reference must be exactly `table.field`",
        ));
    }

    validate_sql_identifier(table, span, "relation table")?;
    validate_sql_identifier(field, span, "relation field")?;

    Ok((table.to_owned(), field.to_owned()))
}

fn parse_db_backend(value: &str, span: proc_macro2::Span) -> syn::Result<DbBackend> {
    match value {
        "sqlite" | "Sqlite" => Ok(DbBackend::Sqlite),
        "postgres" | "Postgres" => Ok(DbBackend::Postgres),
        "mysql" | "Mysql" | "MySql" => Ok(DbBackend::Mysql),
        _ => Err(syn::Error::new(
            span,
            "db must be one of: sqlite, postgres, mysql",
        )),
    }
}

fn parse_length_value(existing: Option<usize>, lit: Lit, label: &str) -> syn::Result<usize> {
    let span = lit.span();
    if existing.is_some() {
        return Err(syn::Error::new(
            span,
            format!("duplicate `{label}` validation"),
        ));
    }

    match lit {
        Lit::Int(value) => value.base10_parse::<usize>().map_err(|_| {
            syn::Error::new(
                value.span(),
                format!("`{label}` must be a non-negative integer"),
            )
        }),
        _ => Err(syn::Error::new(
            span,
            format!("`{label}` must be an integer literal"),
        )),
    }
}

fn parse_numeric_value(
    existing: Option<&NumericBound>,
    lit: Lit,
    label: &str,
) -> syn::Result<NumericBound> {
    let span = lit.span();
    if existing.is_some() {
        return Err(syn::Error::new(
            span,
            format!("duplicate `{label}` validation"),
        ));
    }

    match lit {
        Lit::Int(value) => value
            .base10_parse::<i64>()
            .map(NumericBound::Integer)
            .map_err(|_| syn::Error::new(value.span(), format!("`{label}` must fit within `i64`"))),
        Lit::Float(value) => value
            .base10_parse::<f64>()
            .map(NumericBound::Float)
            .map_err(|_| syn::Error::new(value.span(), format!("invalid `{label}` value"))),
        _ => Err(syn::Error::new(
            span,
            format!("`{label}` must be a numeric literal"),
        )),
    }
}

fn parse_referential_action(
    value: &str,
    span: proc_macro2::Span,
) -> syn::Result<ReferentialAction> {
    ReferentialAction::parse(value).ok_or_else(|| {
        syn::Error::new(
            span,
            "relation on_delete must be Cascade, Restrict, SetNull, or NoAction",
        )
    })
}

fn expect_policy_string(span: proc_macro2::Span, lit: Lit) -> syn::Result<syn::LitStr> {
    match lit {
        Lit::Str(value) => Ok(value),
        _ => Err(syn::Error::new(
            span,
            "row_policy values must be string literals",
        )),
    }
}

fn parse_policy_bool(lit: Lit) -> syn::Result<bool> {
    match lit {
        Lit::Bool(value) => Ok(value.value),
        Lit::Str(value) => value
            .value()
            .parse::<bool>()
            .map_err(|_| syn::Error::new(value.span(), "admin_bypass must be true or false")),
        _ => Err(syn::Error::new(
            lit.span(),
            "admin_bypass must be a boolean literal",
        )),
    }
}

fn parse_u32_literal(lit: &syn::LitInt) -> syn::Result<u32> {
    lit.base10_parse::<u32>()
        .map_err(|_| syn::Error::new(lit.span(), "expected a positive integer that fits in u32"))
}

fn parse_filter_policies(
    value: &str,
    span: proc_macro2::Span,
) -> syn::Result<Option<PolicyFilterExpression>> {
    let policies = split_policy_entries(value, span)?
        .into_iter()
        .map(|entry| parse_filter_policy(&entry, span).map(PolicyFilterExpression::Match))
        .collect::<syn::Result<Vec<_>>>()?;
    Ok(PolicyFilterExpression::all(policies))
}

fn merge_filter_policies(
    existing: Option<PolicyFilterExpression>,
    next: Option<PolicyFilterExpression>,
) -> Option<PolicyFilterExpression> {
    match (existing, next) {
        (Some(existing), Some(next)) => PolicyFilterExpression::all(vec![existing, next]),
        (Some(existing), None) => Some(existing),
        (None, Some(next)) => Some(next),
        (None, None) => None,
    }
}

fn parse_assignment_policies(
    value: &str,
    span: proc_macro2::Span,
) -> syn::Result<Vec<PolicyAssignment>> {
    split_policy_entries(value, span)?
        .into_iter()
        .map(|entry| parse_assignment_policy(&entry, span))
        .collect()
}

fn split_policy_entries(value: &str, span: proc_macro2::Span) -> syn::Result<Vec<String>> {
    let entries = value
        .split(';')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    if entries.is_empty() {
        return Err(syn::Error::new(span, "row_policy values cannot be empty"));
    }

    Ok(entries)
}

fn parse_filter_policy(value: &str, span: proc_macro2::Span) -> syn::Result<PolicyFilter> {
    if let Some(field) = parse_legacy_policy_field(value, RowPolicyKind::Owner) {
        return Ok(PolicyFilter {
            field,
            operator: PolicyFilterOperator::Equals(PolicyValueSource::UserId),
        });
    }

    if parse_legacy_policy_field(value, RowPolicyKind::SetOwner).is_some() {
        return Err(syn::Error::new(
            span,
            "read, update, and delete row policies must use kind `Owner`",
        ));
    }

    let (field, source) = parse_policy_expression(value, span)?;
    Ok(PolicyFilter {
        field,
        operator: PolicyFilterOperator::Equals(source),
    })
}

fn parse_assignment_policy(value: &str, span: proc_macro2::Span) -> syn::Result<PolicyAssignment> {
    if let Some(field) = parse_legacy_policy_field(value, RowPolicyKind::SetOwner) {
        return Ok(PolicyAssignment {
            field,
            source: PolicyValueSource::UserId,
        });
    }

    if parse_legacy_policy_field(value, RowPolicyKind::Owner).is_some() {
        return Err(syn::Error::new(
            span,
            "create row policy must use kind `SetOwner`",
        ));
    }

    let (field, source) = parse_policy_expression(value, span)?;
    Ok(PolicyAssignment { field, source })
}

fn parse_legacy_policy_field(value: &str, kind: RowPolicyKind) -> Option<String> {
    let (parsed_kind, field) = value.split_once(':')?;
    let parsed_kind = RowPolicyKind::parse(parsed_kind.trim())?;
    if parsed_kind != kind {
        return None;
    }

    let field = field.trim();
    if field.is_empty() {
        None
    } else {
        Some(field.to_owned())
    }
}

fn parse_policy_expression(
    value: &str,
    span: proc_macro2::Span,
) -> syn::Result<(String, PolicyValueSource)> {
    let (field, source) = value
        .split_once('=')
        .ok_or_else(|| syn::Error::new(span, "row_policy values must use `field=source`"))?;
    let field = field.trim();
    if field.is_empty() {
        return Err(syn::Error::new(
            span,
            "row_policy field name cannot be empty",
        ));
    }

    let source = parse_policy_source(source, span)?;
    Ok((field.to_owned(), source))
}

fn parse_policy_source(value: &str, span: proc_macro2::Span) -> syn::Result<PolicyValueSource> {
    PolicyValueSource::parse(value).ok_or_else(|| {
        syn::Error::new(
            span,
            "row_policy source must be `user.id` or `claim.<name>`",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_row_policies_from_derive_input() {
        let input: DeriveInput = syn::parse_quote! {
            #[derive(RestApi)]
            #[rest_api(table = "post", id = "id", db = "sqlite")]
            #[row_policy(read = "owner:user_id", create = "set_owner:user_id", update = "owner:user_id", delete = "owner:user_id")]
            struct Post {
                id: Option<i64>,
                title: String,
                user_id: i64,
            }
        };

        let resource = parse_derive_input(input).expect("row policies should parse");
        let read_filters = resource
            .policies
            .iter_filters()
            .into_iter()
            .filter(|(scope, _)| *scope == "read")
            .map(|(_, filter)| filter)
            .collect::<Vec<_>>();
        assert_eq!(read_filters[0].field, "user_id");
        assert_eq!(
            resource.policies.create[0].source,
            super::super::model::PolicyValueSource::UserId
        );
    }

    #[test]
    fn rejects_invalid_create_policy_kind() {
        let input: DeriveInput = syn::parse_quote! {
            #[derive(RestApi)]
            #[row_policy(create = "owner:user_id")]
            struct Post {
                id: Option<i64>,
                user_id: i64,
            }
        };

        let error = match parse_derive_input(input) {
            Ok(_) => panic!("invalid create policy should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("SetOwner"));
    }

    #[test]
    fn parses_claim_based_row_policies_from_derive_input() {
        let input: DeriveInput = syn::parse_quote! {
            #[derive(RestApi)]
            #[row_policy(
                read = "user_id=user.id; tenant_id=claim.tenant_id",
                create = "user_id=user.id; tenant_id=claim.tenant_id",
                update = "user_id=user.id; tenant_id=claim.tenant_id",
                delete = "tenant_id=claim.tenant_id",
                admin_bypass = false
            )]
            struct Post {
                id: Option<i64>,
                user_id: i64,
                tenant_id: i64,
            }
        };

        let resource = parse_derive_input(input).expect("claim row policies should parse");
        assert!(!resource.policies.admin_bypass);
        let read_filters = resource
            .policies
            .iter_filters()
            .into_iter()
            .filter(|(scope, _)| *scope == "read")
            .map(|(_, filter)| filter)
            .collect::<Vec<_>>();
        assert_eq!(read_filters.len(), 2);
        assert_eq!(
            read_filters[1].operator,
            super::super::model::PolicyFilterOperator::Equals(
                super::super::model::PolicyValueSource::Claim("tenant_id".to_owned())
            )
        );
        assert_eq!(resource.policies.create.len(), 2);
    }

    #[test]
    fn parses_relation_on_delete_from_derive_input() {
        let input: DeriveInput = syn::parse_quote! {
            #[derive(RestApi)]
            struct Comment {
                id: Option<i64>,
                #[relation(references = "post.id", nested_route = true, on_delete = "cascade")]
                post_id: i64,
            }
        };

        let resource = parse_derive_input(input).expect("relation should parse");
        let relation = resource
            .find_field("post_id")
            .and_then(|field| field.relation.as_ref())
            .expect("relation should exist");
        assert_eq!(
            relation.on_delete,
            Some(super::super::model::ReferentialAction::Cascade)
        );
    }

    #[test]
    fn rejects_invalid_table_identifier_from_derive_input() {
        let input: DeriveInput = syn::parse_quote! {
            #[derive(RestApi)]
            #[rest_api(table = "post; DROP TABLE user;")]
            struct Post {
                id: Option<i64>,
                title: String,
            }
        };

        let error = parse_derive_input(input).expect_err("invalid table identifier should fail");
        assert!(error.to_string().contains("table name"));
        assert!(error.to_string().contains("valid SQL identifier"));
    }

    #[test]
    fn rejects_invalid_relation_identifier_from_derive_input() {
        let input: DeriveInput = syn::parse_quote! {
            #[derive(RestApi)]
            struct Comment {
                id: Option<i64>,
                #[relation(references = "post.id); DROP TABLE user;")]
                post_id: i64,
            }
        };

        let error = parse_derive_input(input).expect_err("invalid relation identifier should fail");
        assert!(error.to_string().contains("relation field"));
        assert!(error.to_string().contains("valid SQL identifier"));
    }

    #[test]
    fn parses_field_validation_from_derive_input() {
        let input: DeriveInput = syn::parse_quote! {
            #[derive(RestApi)]
            struct Post {
                id: Option<i64>,
                #[validate(min_length = 3, max_length = 32)]
                title: String,
                #[validate(minimum = 1, maximum = 10)]
                score: i64,
            }
        };

        let resource = parse_derive_input(input).expect("validation should parse");
        let title = resource.find_field("title").expect("title should exist");
        assert_eq!(title.validation.min_length, Some(3));
        assert_eq!(title.validation.max_length, Some(32));

        let score = resource.find_field("score").expect("score should exist");
        assert_eq!(
            score.validation.minimum,
            Some(super::super::model::NumericBound::Integer(1))
        );
        assert_eq!(
            score.validation.maximum,
            Some(super::super::model::NumericBound::Integer(10))
        );
    }

    #[test]
    fn parses_list_config_from_derive_input() {
        let input: DeriveInput = syn::parse_quote! {
            #[derive(RestApi)]
            #[list(default_limit = 25, max_limit = 100)]
            struct Post {
                id: Option<i64>,
                title: String,
            }
        };

        let resource = parse_derive_input(input).expect("list config should parse");
        assert_eq!(resource.list.default_limit, Some(25));
        assert_eq!(resource.list.max_limit, Some(100));
    }

    #[test]
    fn rejects_invalid_list_config_from_derive_input() {
        let input: DeriveInput = syn::parse_quote! {
            #[derive(RestApi)]
            #[list(default_limit = 50, max_limit = 10)]
            struct Post {
                id: Option<i64>,
                title: String,
            }
        };

        let error = match parse_derive_input(input) {
            Ok(_) => panic!("invalid list config should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("default_limit"));
        assert!(error.to_string().contains("max_limit"));
    }

    #[test]
    fn rejects_set_null_on_non_nullable_relation_field() {
        let input: DeriveInput = syn::parse_quote! {
            #[derive(RestApi)]
            struct Comment {
                id: Option<i64>,
                #[relation(references = "post.id", on_delete = "set_null")]
                post_id: i64,
            }
        };

        let error = match parse_derive_input(input) {
            Ok(_) => panic!("invalid relation should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("SetNull"));
        assert!(error.to_string().contains("not nullable"));
    }

    #[test]
    fn rejects_invalid_field_validation_for_string_field() {
        let input: DeriveInput = syn::parse_quote! {
            #[derive(RestApi)]
            struct Post {
                id: Option<i64>,
                #[validate(minimum = 1)]
                title: String,
            }
        };

        let error = match parse_derive_input(input) {
            Ok(_) => panic!("invalid validation should fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("title"));
        assert!(error.to_string().contains("min_length"));
        assert!(error.to_string().contains("max_length"));
    }

    #[test]
    fn rejects_custom_relation_foreign_key_override() {
        let input: DeriveInput = syn::parse_quote! {
            #[derive(RestApi)]
            struct Comment {
                id: Option<i64>,
                #[relation(foreign_key = "post_fk", references = "post.id")]
                post_id: i64,
            }
        };

        let error = match parse_derive_input(input) {
            Ok(_) => panic!("custom foreign key override should fail"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("foreign_key overrides are not supported")
        );
        assert!(error.to_string().contains("post_id"));
    }
}
