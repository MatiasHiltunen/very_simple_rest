//! Compiler-free native field parsing and validation.

use anyhow::{Context, anyhow, bail};
use chrono::{DateTime, NaiveDate, NaiveTime, SecondsFormat, Utc};
use rust_decimal::Decimal;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::field::{FieldKind, FieldTransform, LengthMode, NumericBound, RuntimeField};
use crate::native_resource::RuntimeBoundValue;

/// Canonicalize temporal, UUID, and decimal text for storage.
pub fn normalize_text_field_value(kind: FieldKind, value: &str) -> anyhow::Result<String> {
    Ok(match kind {
        FieldKind::DateTime => DateTime::parse_from_rfc3339(value)
            .with_context(|| format!("invalid date-time `{value}`"))?
            .with_timezone(&Utc)
            .to_rfc3339_opts(SecondsFormat::Micros, false),
        FieldKind::Date => NaiveDate::parse_from_str(value, "%Y-%m-%d")
            .with_context(|| format!("invalid date `{value}`"))?
            .format("%Y-%m-%d")
            .to_string(),
        FieldKind::Time => value
            .parse::<NaiveTime>()
            .with_context(|| format!("invalid time `{value}`"))?
            .format("%H:%M:%S.%6f")
            .to_string(),
        FieldKind::Uuid => Uuid::parse_str(value)
            .with_context(|| format!("invalid uuid `{value}`"))?
            .as_hyphenated()
            .to_string(),
        FieldKind::Decimal => value
            .parse::<Decimal>()
            .with_context(|| format!("invalid decimal `{value}`"))?
            .normalize()
            .to_string(),
        _ => value.to_owned(),
    })
}

fn apply_field_transforms_to_text(transforms: &[FieldTransform], value: String) -> String {
    transforms
        .iter()
        .fold(value, |current, transform| match transform {
            FieldTransform::Trim => current.trim().to_owned(),
            FieldTransform::Lowercase => current.to_lowercase(),
            FieldTransform::CollapseWhitespace => {
                current.split_whitespace().collect::<Vec<_>>().join(" ")
            }
            FieldTransform::Slugify => slugify_text(current.as_str()),
        })
}

fn slugify_text(value: &str) -> String {
    let mut slug = String::new();
    let mut pending_dash = false;

    for ch in value.chars() {
        if ch.is_alphanumeric() {
            if pending_dash && !slug.is_empty() {
                slug.push('-');
            }
            pending_dash = false;
            for lower in ch.to_lowercase() {
                slug.push(lower);
            }
        } else if !slug.is_empty() {
            pending_dash = true;
        }
    }

    slug
}

/// Convert a SQL-bound scalar into its JSON representation.
pub fn bound_value_to_json(value: &RuntimeBoundValue) -> Value {
    match value {
        RuntimeBoundValue::Null => Value::Null,
        RuntimeBoundValue::Bool(value) => Value::Bool(*value),
        RuntimeBoundValue::Integer(value) => Value::from(*value),
        RuntimeBoundValue::Real(value) => {
            serde_json::Number::from_f64(*value).map_or(Value::Null, Value::Number)
        }
        RuntimeBoundValue::Text(value) => Value::String(value.clone()),
    }
}

/// Lower a literal action value into a SQL-bound scalar.
pub fn bound_value_from_action_json(value: &Value) -> anyhow::Result<RuntimeBoundValue> {
    Ok(match value {
        Value::Null => RuntimeBoundValue::Null,
        Value::Bool(value) => RuntimeBoundValue::Bool(*value),
        Value::Number(value) => {
            if let Some(integer) = value.as_i64() {
                RuntimeBoundValue::Integer(integer)
            } else if let Some(real) = value.as_f64() {
                RuntimeBoundValue::Real(real)
            } else {
                bail!("unsupported numeric action value `{value}`");
            }
        }
        Value::String(value) => RuntimeBoundValue::Text(value.clone()),
        Value::Array(_) | Value::Object(_) => {
            bail!("structured action values are not supported at runtime")
        }
    })
}

/// Parse and normalize a text query value for a native field.
pub fn parse_query_value(field: &RuntimeField, value: &str) -> anyhow::Result<RuntimeBoundValue> {
    match field.kind {
        FieldKind::Integer => value
            .parse::<i64>()
            .map(RuntimeBoundValue::Integer)
            .with_context(|| format!("invalid integer `{value}`")),
        FieldKind::Real => value
            .parse::<f64>()
            .map(RuntimeBoundValue::Real)
            .with_context(|| format!("invalid real `{value}`")),
        FieldKind::Boolean => value
            .parse::<bool>()
            .map(RuntimeBoundValue::Bool)
            .with_context(|| format!("invalid boolean `{value}`")),
        FieldKind::Text => {
            if let Some(enum_values) = field.enum_values.as_deref()
                && !enum_values.iter().any(|candidate| candidate == value)
            {
                bail!(
                    "invalid enum value `{value}`; expected one of: {}",
                    enum_values.join(", ")
                );
            }
            Ok(RuntimeBoundValue::Text(value.to_owned()))
        }
        FieldKind::DateTime
        | FieldKind::Date
        | FieldKind::Time
        | FieldKind::Uuid
        | FieldKind::Decimal => Ok(RuntimeBoundValue::Text(normalize_text_field_value(
            field.kind, value,
        )?)),
        FieldKind::Json | FieldKind::JsonObject | FieldKind::JsonArray | FieldKind::List => {
            bail!("JSON fields do not support query filters")
        }
    }
}

/// Field-path and message for a native JSON validation error.
#[derive(Debug)]
pub struct JsonFieldError {
    /// Public field path.
    pub field: String,
    /// Human-readable validation detail.
    pub message: String,
}

impl JsonFieldError {
    fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for JsonFieldError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for JsonFieldError {}

fn expected_json_field(path: &str, expected: &str) -> JsonFieldError {
    JsonFieldError::new(path, format!("Field `{path}` must be {expected}"))
}

fn invalid_json_field(path: &str, detail: impl Into<String>) -> JsonFieldError {
    JsonFieldError::new(
        path,
        format!("Field `{path}` is invalid: {}", detail.into()),
    )
}

fn measured_text_length(value: &str, mode: Option<LengthMode>) -> usize {
    match mode {
        Some(LengthMode::Chars) => value.chars().count(),
        Some(LengthMode::Graphemes) => {
            use garde::rules::length::HasGraphemes as _;

            value.num_graphemes()
        }
        Some(LengthMode::Utf16) => value.encode_utf16().count(),
        Some(LengthMode::Simple | LengthMode::Bytes) | None => value.len(),
    }
}

/// Normalize one scalar in a typed JSON list.
pub fn normalize_json_item_value(kind: FieldKind, value: &Value) -> anyhow::Result<Value> {
    match kind {
        FieldKind::Integer => value
            .as_i64()
            .map(Value::from)
            .ok_or_else(|| anyhow!("expected integer")),
        FieldKind::Real => value
            .as_f64()
            .and_then(serde_json::Number::from_f64)
            .map(Value::Number)
            .ok_or_else(|| anyhow!("expected number")),
        FieldKind::Boolean => value
            .as_bool()
            .map(Value::Bool)
            .ok_or_else(|| anyhow!("expected boolean")),
        FieldKind::Text => value
            .as_str()
            .map(|value| Value::String(value.to_owned()))
            .ok_or_else(|| anyhow!("expected string")),
        FieldKind::DateTime
        | FieldKind::Date
        | FieldKind::Time
        | FieldKind::Uuid
        | FieldKind::Decimal => {
            let value = value.as_str().ok_or_else(|| anyhow!("expected string"))?;
            Ok(Value::String(normalize_text_field_value(kind, value)?))
        }
        FieldKind::Json => Ok(value.clone()),
        FieldKind::JsonObject => {
            if matches!(value, Value::Object(_)) {
                Ok(value.clone())
            } else {
                bail!("expected object")
            }
        }
        FieldKind::JsonArray => {
            if matches!(value, Value::Array(_)) {
                Ok(value.clone())
            } else {
                bail!("expected array")
            }
        }
        FieldKind::List => bail!("list items cannot contain nested lists yet"),
    }
}

/// Normalize and validate a typed object, including nested fields.
pub fn normalize_typed_object_value(
    field: &RuntimeField,
    value: &Value,
    path: &str,
) -> Result<Value, JsonFieldError> {
    let object = value
        .as_object()
        .ok_or_else(|| expected_json_field(path, "an object"))?;
    let nested_fields = field
        .object_fields
        .as_deref()
        .ok_or_else(|| expected_json_field(path, "an object"))?;

    for key in object.keys() {
        if nested_fields
            .iter()
            .all(|candidate| candidate.api_name != *key)
        {
            let nested_path = format!("{path}.{key}");
            return Err(JsonFieldError::new(
                nested_path.clone(),
                format!("Field `{nested_path}` is not allowed"),
            ));
        }
    }

    let mut normalized = Map::new();
    for nested_field in nested_fields {
        let nested_path = format!("{path}.{}", nested_field.api_name);
        match object.get(nested_field.api_name.as_str()) {
            Some(Value::Null) => {
                if nested_field.optional {
                    normalized.insert(nested_field.api_name.clone(), Value::Null);
                } else {
                    return Err(JsonFieldError::new(
                        nested_path.clone(),
                        format!("Field `{nested_path}` must not be null"),
                    ));
                }
            }
            Some(nested_value) => {
                normalized.insert(
                    nested_field.api_name.clone(),
                    normalize_typed_field_json_value(nested_field, nested_value, &nested_path)?,
                );
            }
            None => {
                if !nested_field.optional {
                    return Err(JsonFieldError::new(
                        nested_path.clone(),
                        format!("Field `{nested_path}` is required"),
                    ));
                }
            }
        }
    }

    Ok(Value::Object(normalized))
}

#[expect(
    clippy::too_many_lines,
    clippy::float_cmp,
    reason = "preserves exact declared numeric equality in nested field validation"
)]
fn apply_nested_validation(
    field: &RuntimeField,
    value: &Value,
    path: &str,
) -> Result<(), JsonFieldError> {
    if matches!(value, Value::Null) {
        return Ok(());
    }

    if let Some(enum_values) = field.enum_values.as_deref() {
        let text = value
            .as_str()
            .ok_or_else(|| expected_json_field(path, "a string"))?;
        if !enum_values.iter().any(|candidate| candidate == text) {
            return Err(JsonFieldError::new(
                path,
                format!("Field `{path}` must be one of: {}", enum_values.join(", ")),
            ));
        }
    }

    if field.validation.is_empty() {
        return Ok(());
    }

    if let Some(length) = field.validation.length.as_ref() {
        let text = value
            .as_str()
            .ok_or_else(|| expected_json_field(path, "a string"))?;
        let measured = measured_text_length(text, length.mode);

        if let Some(min_length) = length.min
            && measured < min_length
        {
            return Err(JsonFieldError::new(
                path,
                format!("Field `{path}` must have at least {min_length} characters"),
            ));
        }
        if let Some(max_length) = length.max
            && measured > max_length
        {
            return Err(JsonFieldError::new(
                path,
                format!("Field `{path}` must have at most {max_length} characters"),
            ));
        }
        if let Some(equal) = length.equal
            && measured != equal
        {
            return Err(JsonFieldError::new(
                path,
                format!("Field `{path}` must have exactly {equal} characters"),
            ));
        }
    }

    match field.kind {
        FieldKind::Integer => {
            let actual = value
                .as_i64()
                .ok_or_else(|| expected_json_field(path, "an integer"))?;
            if let Some(range) = field.validation.range.as_ref() {
                if let Some(NumericBound::Integer(minimum)) = &range.min
                    && actual < *minimum
                {
                    return Err(JsonFieldError::new(
                        path,
                        format!("Field `{path}` must be at least {minimum}"),
                    ));
                }
                if let Some(NumericBound::Integer(maximum)) = &range.max
                    && actual > *maximum
                {
                    return Err(JsonFieldError::new(
                        path,
                        format!("Field `{path}` must be at most {maximum}"),
                    ));
                }
                if let Some(NumericBound::Integer(equal)) = &range.equal
                    && actual != *equal
                {
                    return Err(JsonFieldError::new(
                        path,
                        format!("Field `{path}` must equal {equal}"),
                    ));
                }
            }
        }
        FieldKind::Real => {
            let actual = value
                .as_f64()
                .ok_or_else(|| expected_json_field(path, "a number"))?;
            if let Some(range) = field.validation.range.as_ref() {
                if let Some(minimum) = &range.min
                    && actual < minimum.as_f64()
                {
                    return Err(JsonFieldError::new(
                        path,
                        format!("Field `{path}` must be at least {}", minimum.as_f64()),
                    ));
                }
                if let Some(maximum) = &range.max
                    && actual > maximum.as_f64()
                {
                    return Err(JsonFieldError::new(
                        path,
                        format!("Field `{path}` must be at most {}", maximum.as_f64()),
                    ));
                }
                if let Some(equal) = &range.equal
                    && actual != equal.as_f64()
                {
                    return Err(JsonFieldError::new(
                        path,
                        format!("Field `{path}` must equal {}", equal.as_f64()),
                    ));
                }
            }
        }
        _ => {}
    }

    Ok(())
}

fn normalize_typed_field_json_value(
    field: &RuntimeField,
    value: &Value,
    path: &str,
) -> Result<Value, JsonFieldError> {
    let normalized = match field.kind {
        FieldKind::Integer => value
            .as_i64()
            .map(Value::from)
            .ok_or_else(|| expected_json_field(path, "an integer"))?,
        FieldKind::Real => value
            .as_f64()
            .and_then(serde_json::Number::from_f64)
            .map(Value::Number)
            .ok_or_else(|| expected_json_field(path, "a number"))?,
        FieldKind::Boolean => value
            .as_bool()
            .map(Value::Bool)
            .ok_or_else(|| expected_json_field(path, "a boolean"))?,
        FieldKind::Text => value
            .as_str()
            .map(|value| {
                Value::String(apply_field_transforms_to_text(
                    field.transforms.as_slice(),
                    value.to_owned(),
                ))
            })
            .ok_or_else(|| expected_json_field(path, "a string"))?,
        FieldKind::DateTime
        | FieldKind::Date
        | FieldKind::Time
        | FieldKind::Uuid
        | FieldKind::Decimal => {
            let value = value
                .as_str()
                .ok_or_else(|| expected_json_field(path, "a string"))?;
            Value::String(
                normalize_text_field_value(field.kind, value)
                    .map_err(|error| invalid_json_field(path, error.to_string()))?,
            )
        }
        FieldKind::Json => value.clone(),
        FieldKind::JsonObject => {
            if field.object_fields.is_some() {
                normalize_typed_object_value(field, value, path)?
            } else if matches!(value, Value::Object(_)) {
                value.clone()
            } else {
                return Err(expected_json_field(path, "an object"));
            }
        }
        FieldKind::JsonArray => {
            if matches!(value, Value::Array(_)) {
                value.clone()
            } else {
                return Err(expected_json_field(path, "an array"));
            }
        }
        FieldKind::List => {
            let items = value
                .as_array()
                .ok_or_else(|| expected_json_field(path, "an array"))?;
            let item_kind = field
                .list_item_kind
                .ok_or_else(|| expected_json_field(path, "an array"))?;
            let normalized = items
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    normalize_json_item_value(item_kind, item).map_err(|error| {
                        invalid_json_field(&format!("{path}[{index}]"), error.to_string())
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Value::Array(normalized)
        }
    };

    apply_nested_validation(field, &normalized, path)?;
    Ok(normalized)
}

fn serialize_json_field(
    field_name: &str,
    value: &Value,
) -> Result<RuntimeBoundValue, JsonFieldError> {
    serde_json::to_string(value)
        .map(RuntimeBoundValue::Text)
        .map_err(|error| invalid_json_field(field_name, error.to_string()))
}

/// Parse a native field payload into its SQL-bound representation.
pub fn parse_json_value(
    field: &RuntimeField,
    value: &Value,
) -> Result<RuntimeBoundValue, JsonFieldError> {
    match field.kind {
        FieldKind::Integer => value
            .as_i64()
            .map(RuntimeBoundValue::Integer)
            .ok_or_else(|| expected_json_field(&field.api_name, "an integer")),
        FieldKind::Real => value
            .as_f64()
            .map(RuntimeBoundValue::Real)
            .ok_or_else(|| expected_json_field(&field.api_name, "a number")),
        FieldKind::Boolean => value
            .as_bool()
            .map(RuntimeBoundValue::Bool)
            .ok_or_else(|| expected_json_field(&field.api_name, "a boolean")),
        FieldKind::Text => value
            .as_str()
            .map(|value| {
                RuntimeBoundValue::Text(apply_field_transforms_to_text(
                    field.transforms.as_slice(),
                    value.to_owned(),
                ))
            })
            .ok_or_else(|| expected_json_field(&field.api_name, "a string")),
        FieldKind::DateTime
        | FieldKind::Date
        | FieldKind::Time
        | FieldKind::Uuid
        | FieldKind::Decimal => {
            let value = value
                .as_str()
                .ok_or_else(|| expected_json_field(&field.api_name, "a string"))?;
            Ok(RuntimeBoundValue::Text(
                normalize_text_field_value(field.kind, value)
                    .map_err(|error| invalid_json_field(&field.api_name, error.to_string()))?,
            ))
        }
        FieldKind::Json => serialize_json_field(&field.api_name, value),
        FieldKind::JsonObject => {
            let normalized = if field.object_fields.is_some() {
                normalize_typed_object_value(field, value, &field.api_name)?
            } else if matches!(value, Value::Object(_)) {
                value.clone()
            } else {
                return Err(expected_json_field(&field.api_name, "an object"));
            };
            serialize_json_field(&field.api_name, &normalized)
        }
        FieldKind::JsonArray => {
            if !matches!(value, Value::Array(_)) {
                return Err(expected_json_field(&field.api_name, "an array"));
            }
            serialize_json_field(&field.api_name, value)
        }
        FieldKind::List => {
            let items = value
                .as_array()
                .ok_or_else(|| expected_json_field(&field.api_name, "an array"))?;
            let item_kind = field
                .list_item_kind
                .ok_or_else(|| expected_json_field(&field.api_name, "an array"))?;
            let normalized = items
                .iter()
                .map(|item| normalize_json_item_value(item_kind, item))
                .collect::<anyhow::Result<Vec<_>>>()
                .map_err(|error| invalid_json_field(&field.api_name, error.to_string()))?;
            serialize_json_field(&field.api_name, &Value::Array(normalized))
        }
    }
}

/// Validate a SQL-bound value against a native field.
#[expect(
    clippy::too_many_lines,
    clippy::float_cmp,
    reason = "preserves exact declared numeric equality in native field validation"
)]
pub fn validate_bound_value(
    field: &RuntimeField,
    value: &RuntimeBoundValue,
) -> Result<(), JsonFieldError> {
    if matches!(value, RuntimeBoundValue::Null) {
        return Ok(());
    }

    if let Some(enum_values) = field.enum_values.as_deref() {
        let RuntimeBoundValue::Text(text) = value else {
            return Err(JsonFieldError::new(
                field.api_name.clone(),
                format!("Field `{}` must be a string enum value", field.api_name),
            ));
        };
        if !enum_values.iter().any(|candidate| candidate == text) {
            return Err(JsonFieldError::new(
                field.api_name.clone(),
                format!(
                    "Field `{}` must be one of: {}",
                    field.api_name,
                    enum_values.join(", ")
                ),
            ));
        }
    }

    if field.validation.is_empty() {
        return Ok(());
    }

    if let Some(length) = field.validation.length.as_ref()
        && let RuntimeBoundValue::Text(text) = value
    {
        let measured = measured_text_length(text, length.mode);

        if let Some(min_length) = length.min
            && measured < min_length
        {
            return Err(JsonFieldError::new(
                field.api_name.clone(),
                format!(
                    "Field `{}` must have at least {} characters",
                    field.api_name, min_length
                ),
            ));
        }
        if let Some(max_length) = length.max
            && measured > max_length
        {
            return Err(JsonFieldError::new(
                field.api_name.clone(),
                format!(
                    "Field `{}` must have at most {} characters",
                    field.api_name, max_length
                ),
            ));
        }
        if let Some(equal) = length.equal
            && measured != equal
        {
            return Err(JsonFieldError::new(
                field.api_name.clone(),
                format!(
                    "Field `{}` must have exactly {} characters",
                    field.api_name, equal
                ),
            ));
        }
    }

    match value {
        RuntimeBoundValue::Integer(actual) => {
            if let Some(range) = field.validation.range.as_ref() {
                if let Some(NumericBound::Integer(minimum)) = &range.min
                    && *actual < *minimum
                {
                    return Err(JsonFieldError::new(
                        field.api_name.clone(),
                        format!("Field `{}` must be at least {}", field.api_name, minimum),
                    ));
                }
                if let Some(NumericBound::Integer(maximum)) = &range.max
                    && *actual > *maximum
                {
                    return Err(JsonFieldError::new(
                        field.api_name.clone(),
                        format!("Field `{}` must be at most {}", field.api_name, maximum),
                    ));
                }
                if let Some(NumericBound::Integer(equal)) = &range.equal
                    && *actual != *equal
                {
                    return Err(JsonFieldError::new(
                        field.api_name.clone(),
                        format!("Field `{}` must equal {}", field.api_name, equal),
                    ));
                }
            }
        }
        RuntimeBoundValue::Real(actual) => {
            if let Some(range) = field.validation.range.as_ref() {
                if let Some(minimum) = &range.min
                    && *actual < minimum.as_f64()
                {
                    return Err(JsonFieldError::new(
                        field.api_name.clone(),
                        format!(
                            "Field `{}` must be at least {}",
                            field.api_name,
                            minimum.as_f64()
                        ),
                    ));
                }
                if let Some(maximum) = &range.max
                    && *actual > maximum.as_f64()
                {
                    return Err(JsonFieldError::new(
                        field.api_name.clone(),
                        format!(
                            "Field `{}` must be at most {}",
                            field.api_name,
                            maximum.as_f64()
                        ),
                    ));
                }
                if let Some(equal) = &range.equal
                    && *actual != equal.as_f64()
                {
                    return Err(JsonFieldError::new(
                        field.api_name.clone(),
                        format!("Field `{}` must equal {}", field.api_name, equal.as_f64()),
                    ));
                }
            }
        }
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::field::{
        FieldKind, FieldTransform, FieldValidation, GeneratedValue, LengthMode, LengthValidation,
        RuntimeField,
    };
    use crate::native_resource::RuntimeBoundValue;

    use super::parse_json_value;

    fn field(name: &str, kind: FieldKind) -> RuntimeField {
        RuntimeField {
            name: name.to_owned(),
            api_name: name.to_owned(),
            expose_in_api: true,
            enum_values: None,
            transforms: Vec::new(),
            kind,
            list_item_kind: None,
            object_fields: None,
            optional: false,
            generated: GeneratedValue::None,
            validation: FieldValidation::default(),
            supports_exact_filters: false,
            supports_sort: false,
            supports_range_filters: false,
        }
    }

    #[test]
    fn nested_field_uses_grapheme_length_after_transform() {
        let title = RuntimeField {
            transforms: vec![FieldTransform::Trim],
            validation: FieldValidation {
                length: Some(LengthValidation {
                    min: Some(2),
                    mode: Some(LengthMode::Graphemes),
                    ..LengthValidation::default()
                }),
                ..FieldValidation::default()
            },
            ..field("title", FieldKind::Text)
        };
        let content = RuntimeField {
            object_fields: Some(vec![title]),
            ..field("content", FieldKind::JsonObject)
        };

        let error = parse_json_value(&content, &json!({"title": "  e\u{301}  "}))
            .expect_err("one grapheme should be too short");
        assert_eq!(error.field, "content.title");

        let value = parse_json_value(&content, &json!({"title": "  e\u{301}x  "}))
            .expect("two graphemes should be accepted");
        assert_eq!(
            value,
            RuntimeBoundValue::Text("{\"title\":\"éx\"}".to_owned())
        );
    }
}
