use proc_macro2::Span;
use quote::ToTokens;
use syn::Type;
use serde_json::Value as JsonValue;
use super::super::model::{
    EnumSpec, FieldTransform, FieldValidation, LengthMode, LengthValidation, NumericBound,
    RangeValidation, ReferentialAction, RelationSpec,
    GENERATED_DATE_ALIAS, GENERATED_DATETIME_ALIAS, GENERATED_DECIMAL_ALIAS,
    GENERATED_JSON_ALIAS, GENERATED_JSON_ARRAY_ALIAS, GENERATED_JSON_OBJECT_ALIAS,
    GENERATED_TIME_ALIAS, GENERATED_UUID_ALIAS,
    validate_sql_identifier,
};
use super::documents::{
    FieldTypeDocument, FieldValidationDocument, LengthValidationDocument, NumericBoundDocument,
    RangeValidationDocument, RelationDocument, ScalarType,
};
pub(super) struct ParsedFieldType {
    pub(super) ty: Type,
    pub(super) list_item_ty: Option<Type>,
    pub(super) enum_name: Option<String>,
    pub(super) enum_values: Option<Vec<String>>,
}

pub(super) fn parse_list_item_type(item_ty: &FieldTypeDocument) -> syn::Result<Type> {
    let base = match item_ty {
        FieldTypeDocument::Scalar(ScalarType::List | ScalarType::Object) => {
            return Err(syn::Error::new(
                Span::call_site(),
                "list field items cannot use `List` or `Object`; nested structured list items are not supported yet",
            ));
        }
        FieldTypeDocument::Scalar(scalar) => scalar.rust_type().to_owned(),
        FieldTypeDocument::Rust(_) => {
            return Err(syn::Error::new(
                Span::call_site(),
                "list field items must use built-in scalar type keywords",
            ));
        }
    };

    syn::parse_str::<Type>(&base).map_err(|error| {
        syn::Error::new(
            Span::call_site(),
            format!("failed to parse list item Rust type `{base}`: {error}"),
        )
    })
}

pub(super) fn parse_field_type(
    field_ty: &FieldTypeDocument,
    item_ty: Option<&FieldTypeDocument>,
    nullable: bool,
    enums: &[EnumSpec],
) -> syn::Result<ParsedFieldType> {
    let (base, list_item_ty, enum_name, enum_values) = match field_ty {
        FieldTypeDocument::Scalar(ScalarType::List) => {
            let item_ty = item_ty.ok_or_else(|| {
                syn::Error::new(
                    Span::call_site(),
                    "list fields must set `items` to a built-in scalar type keyword",
                )
            })?;
            let parsed_item_ty = parse_list_item_type(item_ty)?;
            (
                format!("Vec<{}>", parsed_item_ty.to_token_stream()),
                Some(parsed_item_ty),
                None,
                None,
            )
        }
        FieldTypeDocument::Scalar(scalar) => {
            if item_ty.is_some() {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "`items` is only supported when `type = List`",
                ));
            }
            (scalar.rust_type().to_owned(), None, None, None)
        }
        FieldTypeDocument::Rust(raw) => {
            if item_ty.is_some() {
                return Err(syn::Error::new(
                    Span::call_site(),
                    "`items` is only supported when `type = List`",
                ));
            }
            if let Some(enum_spec) = enums.iter().find(|candidate| candidate.name == *raw) {
                (
                    "String".to_owned(),
                    None,
                    Some(enum_spec.name.clone()),
                    Some(enum_spec.values.clone()),
                )
            } else {
                (raw.clone(), None, None, None)
            }
        }
    };

    let rust_type = if nullable {
        format!("Option<{base}>")
    } else {
        base
    };

    let ty = syn::parse_str::<Type>(&rust_type).map_err(|error| {
        syn::Error::new(
            Span::call_site(),
            format!("failed to parse Rust type `{rust_type}`: {error}"),
        )
    })?;

    Ok(ParsedFieldType {
        ty,
        list_item_ty,
        enum_name,
        enum_values,
    })
}

impl ScalarType {
    fn rust_type(self) -> &'static str {
        match self {
            Self::String => "String",
            Self::I32 => "i32",
            Self::I64 => "i64",
            Self::F32 => "f32",
            Self::F64 => "f64",
            Self::Bool => "bool",
            Self::DateTime => GENERATED_DATETIME_ALIAS,
            Self::Date => GENERATED_DATE_ALIAS,
            Self::Time => GENERATED_TIME_ALIAS,
            Self::Uuid => GENERATED_UUID_ALIAS,
            Self::Decimal => GENERATED_DECIMAL_ALIAS,
            Self::Json => GENERATED_JSON_ALIAS,
            Self::JsonObject => GENERATED_JSON_OBJECT_ALIAS,
            Self::JsonArray => GENERATED_JSON_ARRAY_ALIAS,
            Self::List => "Vec<String>",
            Self::Object => GENERATED_JSON_OBJECT_ALIAS,
        }
    }
}

pub(super) fn parse_relation_document(relation: RelationDocument) -> syn::Result<RelationSpec> {
    let mut parts = relation.references.split('.');
    let references_table = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                "relation references must be `table.field`",
            )
        })?;
    let references_field = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| {
            syn::Error::new(
                Span::call_site(),
                "relation references must be `table.field`",
            )
        })?;

    if parts.next().is_some() {
        return Err(syn::Error::new(
            Span::call_site(),
            "relation references must be exactly `table.field`",
        ));
    }

    validate_sql_identifier(references_table, Span::call_site(), "relation table")?;
    validate_sql_identifier(references_field, Span::call_site(), "relation field")?;

    let on_delete = relation
        .on_delete
        .as_deref()
        .map(parse_referential_action)
        .transpose()?;

    Ok(RelationSpec {
        references_table: references_table.to_owned(),
        references_field: references_field.to_owned(),
        on_delete,
        nested_route: relation.nested_route,
    })
}

pub(super) fn parse_referential_action(value: &str) -> syn::Result<ReferentialAction> {
    ReferentialAction::parse(value).ok_or_else(|| {
        syn::Error::new(
            Span::call_site(),
            "relation on_delete must be Cascade, Restrict, SetNull, or NoAction",
        )
    })
}

pub(super) fn reject_legacy_field_validation(document: Option<&JsonValue>, context: &str) -> syn::Result<()> {
    if document.is_some() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!("{context} uses legacy `validate`; rename it to `garde`"),
        ));
    }

    Ok(())
}

pub(super) fn parse_field_validation_document(
    document: Option<FieldValidationDocument>,
) -> syn::Result<FieldValidation> {
    let Some(document) = document else {
        return Ok(FieldValidation::default());
    };

    Ok(FieldValidation {
        ascii: document.ascii,
        alphanumeric: document.alphanumeric,
        email: document.email,
        url: document.url,
        ip: document.ip,
        ipv4: document.ipv4,
        ipv6: document.ipv6,
        phone_number: document.phone_number,
        credit_card: document.credit_card,
        required: document.required,
        dive: document.dive,
        contains: document.contains,
        prefix: document.prefix,
        suffix: document.suffix,
        pattern: document.pattern,
        length: document
            .length
            .map(parse_length_validation_document)
            .transpose()?,
        range: document
            .range
            .map(parse_range_validation_document)
            .transpose()?,
        inner: document
            .inner
            .map(|inner| parse_field_validation_document(Some(*inner)).map(Box::new))
            .transpose()?,
    })
}

pub(super) fn parse_length_validation_document(
    document: LengthValidationDocument,
) -> syn::Result<LengthValidation> {
    Ok(LengthValidation {
        min: document.min,
        max: document.max,
        equal: document.equal,
        mode: document
            .mode
            .as_deref()
            .map(parse_length_mode_document)
            .transpose()?,
    })
}

pub(super) fn parse_range_validation_document(
    document: RangeValidationDocument,
) -> syn::Result<RangeValidation> {
    Ok(RangeValidation {
        min: document.min.map(parse_numeric_bound_document),
        max: document.max.map(parse_numeric_bound_document),
        equal: document.equal.map(parse_numeric_bound_document),
    })
}

pub(super) fn parse_length_mode_document(value: &str) -> syn::Result<LengthMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "simple" => Ok(LengthMode::Simple),
        "bytes" => Ok(LengthMode::Bytes),
        "chars" | "characters" => Ok(LengthMode::Chars),
        "graphemes" => Ok(LengthMode::Graphemes),
        "utf16" | "utf-16" => Ok(LengthMode::Utf16),
        _ => Err(syn::Error::new(
            Span::call_site(),
            format!(
                "unsupported `garde.length.mode` value `{value}`; expected Simple, Bytes, Chars, Graphemes, or Utf16"
            ),
        )),
    }
}

pub(super) fn parse_field_transforms_document(transforms: Vec<String>) -> syn::Result<Vec<FieldTransform>> {
    transforms
        .into_iter()
        .map(|transform| match transform.as_str() {
            "Trim" | "trim" => Ok(FieldTransform::Trim),
            "Lowercase" | "lowercase" | "lower_case" | "lower-case" => {
                Ok(FieldTransform::Lowercase)
            }
            "CollapseWhitespace"
            | "collapse_whitespace"
            | "collapse-whitespace"
            | "collapsewhitespace" => Ok(FieldTransform::CollapseWhitespace),
            "Slugify" | "slugify" => Ok(FieldTransform::Slugify),
            _ => Err(syn::Error::new(
                Span::call_site(),
                format!(
                    "unknown write-time transform `{transform}`; expected one of: Trim, Lowercase, CollapseWhitespace, Slugify"
                ),
            )),
        })
        .collect()
}

pub(super) fn parse_numeric_bound_document(bound: NumericBoundDocument) -> NumericBound {
    match bound {
        NumericBoundDocument::Integer(value) => NumericBound::Integer(value),
        NumericBoundDocument::Float(value) => NumericBound::Float(value),
    }
}