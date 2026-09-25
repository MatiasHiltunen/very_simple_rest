//! Compiler-free response context selection and projection for native resources.

use serde::Serialize;
use serde_json::{Value, json};

use crate::native_resource::RuntimeResource;

/// A native collection response before applying a named response context.
#[derive(Clone, Debug, Serialize)]
pub struct RuntimeListResponse {
    /// Items returned for the current page.
    pub items: Vec<Value>,
    /// Number of matching items before pagination.
    pub total: i64,
    /// Number of items in this page.
    pub count: usize,
    /// Requested page size.
    pub limit: Option<u32>,
    /// Numeric offset for this page.
    pub offset: u32,
    /// Numeric offset for the next page, if present.
    pub next_offset: Option<u32>,
    /// Opaque cursor for the next page, if present.
    pub next_cursor: Option<String>,
}

/// Failure to select or apply a named response context.
#[derive(Debug, Eq, PartialEq)]
pub enum ResponseProjectionError {
    /// The requested context is not defined for the resource.
    UnknownContext(String),
    /// A response item was not a JSON object.
    ExpectedObject,
}

impl RuntimeResource {
    /// Resolve an explicit or default named response context.
    pub fn response_context_fields(
        &self,
        requested: Option<&str>,
    ) -> Result<Option<&[String]>, ResponseProjectionError> {
        let context_name = requested.or(self.default_response_context.as_deref());
        match context_name {
            Some(name) => self
                .response_contexts
                .get(name)
                .map(|fields| Some(fields.as_slice()))
                .ok_or_else(|| ResponseProjectionError::UnknownContext(name.to_owned())),
            None => Ok(None),
        }
    }
}

fn project_item_fields(
    mut item: Value,
    fields: Option<&[String]>,
) -> Result<Value, ResponseProjectionError> {
    let Some(fields) = fields else {
        return Ok(item);
    };
    let Value::Object(map) = &mut item else {
        return Err(ResponseProjectionError::ExpectedObject);
    };
    map.retain(|key, _| fields.iter().any(|field| field == key));
    Ok(item)
}

/// Apply an explicit or default response context to one item.
pub fn project_item(
    resource: &RuntimeResource,
    item: Value,
    requested: Option<&str>,
) -> Result<Value, ResponseProjectionError> {
    let fields = resource.response_context_fields(requested)?;
    project_item_fields(item, fields)
}

/// Apply an explicit or default response context to collection items.
pub fn project_list(
    resource: &RuntimeResource,
    response: RuntimeListResponse,
    requested: Option<&str>,
) -> Result<Value, ResponseProjectionError> {
    let RuntimeListResponse {
        items,
        total,
        count,
        limit,
        offset,
        next_offset,
        next_cursor,
    } = response;
    let fields = resource.response_context_fields(requested)?;
    let items = items
        .into_iter()
        .map(|item| project_item_fields(item, fields))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({
        "items": items,
        "total": total,
        "count": count,
        "limit": limit,
        "offset": offset,
        "next_offset": next_offset,
        "next_cursor": next_cursor,
    }))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{ResponseProjectionError, project_item_fields};

    #[test]
    fn projection_keeps_only_selected_fields_and_rejects_non_objects() {
        let fields = ["id".to_owned(), "title".to_owned()];
        let item = json!({"id": 7, "title": "Ready", "private": "secret"});
        assert_eq!(
            project_item_fields(item, Some(&fields)).expect("object projection"),
            json!({"id": 7, "title": "Ready"})
        );
        assert_eq!(
            project_item_fields(json!([1, 2]), Some(&fields)),
            Err(ResponseProjectionError::ExpectedObject)
        );
    }
}
