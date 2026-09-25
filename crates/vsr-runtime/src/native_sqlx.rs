//! `SQLx` adapter for native resource row decoding.

use serde_json::{Map, Value};
use sqlx::Row;

use crate::field::{FieldKind, RuntimeField};
use crate::model::{ComputedFieldPart, ComputedFieldSpec};
use crate::native_resource::RuntimeResource;
use crate::native_validation::{normalize_json_item_value, normalize_typed_object_value};

fn parse_stored_json_value(field: &RuntimeField, value: &str) -> Result<Value, sqlx::Error> {
    let parsed =
        serde_json::from_str::<Value>(value).map_err(|error| sqlx::Error::ColumnDecode {
            index: field.name.clone(),
            source: Box::new(error),
        })?;
    match field.kind {
        FieldKind::Json => Ok(parsed),
        FieldKind::JsonObject => {
            if field.object_fields.is_some() {
                normalize_typed_object_value(field, &parsed, &field.api_name).map_err(|error| {
                    sqlx::Error::ColumnDecode {
                        index: field.name.clone(),
                        source: Box::new(error),
                    }
                })
            } else if matches!(parsed, Value::Object(_)) {
                Ok(parsed)
            } else {
                Err(sqlx::Error::ColumnDecode {
                    index: field.name.clone(),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "expected JSON object",
                    )),
                })
            }
        }
        FieldKind::JsonArray => {
            if matches!(parsed, Value::Array(_)) {
                Ok(parsed)
            } else {
                Err(sqlx::Error::ColumnDecode {
                    index: field.name.clone(),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "expected JSON array",
                    )),
                })
            }
        }
        FieldKind::List => {
            let Value::Array(items) = parsed else {
                return Err(sqlx::Error::ColumnDecode {
                    index: field.name.clone(),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "expected JSON array",
                    )),
                });
            };
            let item_kind = field
                .list_item_kind
                .ok_or_else(|| sqlx::Error::ColumnDecode {
                    index: field.name.clone(),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "missing list item kind",
                    )),
                })?;
            let normalized = items
                .iter()
                .map(|item| {
                    normalize_json_item_value(item_kind, item).map_err(|error| {
                        sqlx::Error::ColumnDecode {
                            index: field.name.clone(),
                            source: Box::new(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                error.to_string(),
                            )),
                        }
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Value::Array(normalized))
        }
        _ => Err(sqlx::Error::ColumnDecode {
            index: field.name.clone(),
            source: Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "expected JSON field",
            )),
        }),
    }
}

/// Decode a native `SQLx` row into the public resource representation.
pub fn row_to_json(
    resource: &RuntimeResource,
    row: &sqlx::any::AnyRow,
) -> Result<Value, sqlx::Error> {
    let mut map = Map::new();
    for field in &resource.fields {
        if !field.expose_in_api {
            continue;
        }
        let value = match field.kind {
            FieldKind::Integer => {
                if field.optional {
                    row.try_get::<Option<i64>, _>(field.name.as_str())?
                        .map_or(Value::Null, Value::from)
                } else {
                    Value::from(row.try_get::<i64, _>(field.name.as_str())?)
                }
            }
            FieldKind::Real => {
                let number = if field.optional {
                    row.try_get::<Option<f64>, _>(field.name.as_str())?
                } else {
                    Some(row.try_get::<f64, _>(field.name.as_str())?)
                };
                number
                    .and_then(serde_json::Number::from_f64)
                    .map_or(Value::Null, Value::Number)
            }
            FieldKind::Boolean => {
                if field.optional {
                    read_optional_bool_column(row, field.name.as_str())?
                        .map_or(Value::Null, Value::Bool)
                } else {
                    Value::Bool(read_bool_column(row, field.name.as_str())?)
                }
            }
            FieldKind::Text
            | FieldKind::DateTime
            | FieldKind::Date
            | FieldKind::Time
            | FieldKind::Uuid
            | FieldKind::Decimal => {
                if field.optional {
                    row.try_get::<Option<String>, _>(field.name.as_str())?
                        .map_or(Value::Null, Value::String)
                } else {
                    Value::String(row.try_get::<String, _>(field.name.as_str())?)
                }
            }
            FieldKind::Json | FieldKind::JsonObject | FieldKind::JsonArray | FieldKind::List => {
                if field.optional {
                    match row.try_get::<Option<String>, _>(field.name.as_str())? {
                        Some(value) => parse_stored_json_value(field, &value)?,
                        None => Value::Null,
                    }
                } else {
                    parse_stored_json_value(field, &row.try_get::<String, _>(field.name.as_str())?)?
                }
            }
        };
        map.insert(field.api_name.clone(), value);
    }
    apply_computed_fields_to_map(resource.computed_fields.as_slice(), &mut map);
    Ok(Value::Object(map))
}

fn read_bool_column(row: &sqlx::any::AnyRow, field_name: &str) -> Result<bool, sqlx::Error> {
    match row.try_get::<bool, _>(field_name) {
        Ok(value) => Ok(value),
        Err(sqlx::Error::ColumnDecode { .. }) => match row.try_get::<i64, _>(field_name) {
            Ok(value) => Ok(value != 0),
            Err(sqlx::Error::ColumnDecode { .. }) => {
                row.try_get::<i32, _>(field_name).map(|value| value != 0)
            }
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    }
}

fn read_optional_bool_column(
    row: &sqlx::any::AnyRow,
    field_name: &str,
) -> Result<Option<bool>, sqlx::Error> {
    match row.try_get::<Option<bool>, _>(field_name) {
        Ok(value) => Ok(value),
        Err(sqlx::Error::ColumnDecode { .. }) => match row.try_get::<Option<i64>, _>(field_name) {
            Ok(value) => Ok(value.map(|value| value != 0)),
            Err(sqlx::Error::ColumnDecode { .. }) => row
                .try_get::<Option<i32>, _>(field_name)
                .map(|value| value.map(|value| value != 0)),
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    }
}

fn apply_computed_fields_to_map(
    computed_fields: &[ComputedFieldSpec],
    map: &mut Map<String, Value>,
) {
    for field in computed_fields {
        let mut rendered = String::new();
        let mut missing = false;
        for part in &field.parts {
            match part {
                ComputedFieldPart::Literal(value) => rendered.push_str(value),
                ComputedFieldPart::Field(name) => match map.get(name.as_str()) {
                    Some(Value::String(value)) => rendered.push_str(value),
                    Some(Value::Number(value)) => rendered.push_str(&value.to_string()),
                    Some(Value::Bool(value)) => rendered.push_str(&value.to_string()),
                    _ => {
                        missing = true;
                        break;
                    }
                },
            }
        }
        map.insert(
            field.api_name.clone(),
            if missing {
                Value::Null
            } else {
                Value::String(rendered)
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, Value};

    use crate::model::{ComputedFieldPart, ComputedFieldSpec};

    use super::apply_computed_fields_to_map;

    #[test]
    fn computed_field_renders_scalars_and_propagates_missing_values() {
        let fields = vec![ComputedFieldSpec {
            api_name: "display".to_owned(),
            optional: false,
            parts: vec![
                ComputedFieldPart::Literal("Item ".to_owned()),
                ComputedFieldPart::Field("id".to_owned()),
                ComputedFieldPart::Literal(": ".to_owned()),
                ComputedFieldPart::Field("title".to_owned()),
            ],
        }];
        let mut item = Map::from_iter([
            ("id".to_owned(), Value::from(7)),
            ("title".to_owned(), Value::from("Ready")),
        ]);
        apply_computed_fields_to_map(&fields, &mut item);
        assert_eq!(item["display"], "Item 7: Ready");

        item.insert("title".to_owned(), Value::Null);
        apply_computed_fields_to_map(&fields, &mut item);
        assert_eq!(item["display"], Value::Null);
    }
}
