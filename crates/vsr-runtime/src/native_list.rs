//! Compiler-free SQL and pagination planning for native collection routes.

use std::{collections::HashMap, sync::Arc};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    field::{FieldKind, RuntimeField},
    model::DbBackend,
    native_policy_sql::{BIND_MARKER, PlanOutcome, PolicyPrincipal, build_row_policy_plan},
    native_resource::{RuntimeBoundValue as BoundValue, RuntimeResource},
    native_response::RuntimeListResponse,
    native_validation::parse_query_value,
};

/// Collection constraint derived from a nested resource route.
#[derive(Clone)]
pub enum ListScope {
    /// Match a foreign-key field against the parent ID.
    ParentField {
        /// Child field holding the parent ID.
        field_name: String,
        /// Parent ID from the route.
        value: i64,
    },
    /// Match through a join table.
    ManyToMany {
        /// Join table name.
        through_table: String,
        /// Join field holding the parent ID.
        source_field: String,
        /// Join field holding the target ID.
        target_field: String,
        /// Parent ID from the route.
        parent_id: i64,
    },
}

/// Sort direction used by a collection query and its cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SortOrder {
    /// Ascending order.
    Asc,
    /// Descending order.
    Desc,
}

impl SortOrder {
    /// SQL keyword for the direction.
    pub fn as_sql(self) -> &'static str {
        match self {
            Self::Asc => "ASC",
            Self::Desc => "DESC",
        }
    }

    /// Lowercase spelling stored in cursors.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Asc => "asc",
            Self::Desc => "desc",
        }
    }
}

/// Scalar sort value encoded in a cursor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CursorValue {
    /// Integer sort value.
    Integer(i64),
    /// Floating point sort value.
    Real(f64),
    /// Boolean sort value.
    Boolean(bool),
    /// Text sort value.
    Text(String),
}

/// Opaque continuation position for a collection query.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CursorPayload {
    /// Public sort field name.
    pub sort: String,
    /// Sort direction spelling.
    pub order: String,
    /// ID of the final item on the page.
    pub last_id: i64,
    /// Sort value of that item.
    pub value: CursorValue,
}

/// Count and select statements with bind values and response metadata.
#[derive(Clone, Debug)]
pub struct ListQueryPlan {
    /// Count query without cursor or pagination clauses.
    pub count_sql: String,
    /// Page selection query.
    pub select_sql: String,
    /// Binds for the count query.
    pub filter_binds: Vec<BoundValue>,
    /// Binds for the page selection query.
    pub select_binds: Vec<BoundValue>,
    /// Effective page limit.
    pub limit: Option<u32>,
    /// Requested offset, or zero.
    pub offset: u32,
    /// Public sort field name.
    pub sort: String,
    /// Sort direction.
    pub order: SortOrder,
    /// Whether this page uses cursor pagination.
    pub cursor_mode: bool,
}

/// Failure classified for the HTTP adapter without carrying framework types.
#[derive(Debug)]
pub enum ListPlanError {
    /// Invalid client query.
    BadRequest {
        /// Stable response code.
        code: &'static str,
        /// Client-facing message.
        message: String,
    },
    /// Required principal values are unavailable.
    Forbidden {
        /// Stable response code.
        code: &'static str,
        /// Client-facing message.
        message: String,
    },
    /// Invalid lowered metadata or internal planning failure.
    Internal(String),
}

impl ListPlanError {
    fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::BadRequest {
            code,
            message: message.into(),
        }
    }

    fn forbidden(code: &'static str, message: impl Into<String>) -> Self {
        Self::Forbidden {
            code,
            message: message.into(),
        }
    }

    fn internal_error(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }
}

fn field_by_api_name<'a>(resource: &'a RuntimeResource, name: &str) -> Option<&'a RuntimeField> {
    resource
        .api_field_index
        .get(name)
        .and_then(|index| resource.fields.get(*index))
}

fn placeholder(backend: DbBackend, index: usize) -> String {
    backend.placeholder(index)
}

fn render_condition_with_placeholders(
    condition: &str,
    backend: DbBackend,
    start_index: usize,
) -> String {
    let mut rendered = String::new();
    let mut remaining = condition;
    let mut index = start_index;
    while let Some(position) = remaining.find(BIND_MARKER) {
        rendered.push_str(&remaining[..position]);
        rendered.push_str(&placeholder(backend, index));
        remaining = &remaining[position + BIND_MARKER.len()..];
        index += 1;
    }
    rendered.push_str(remaining);
    rendered
}

fn supports_contains_filters(field: &RuntimeField) -> bool {
    if field.enum_values.is_some() {
        return false;
    }
    !matches!(
        field.kind,
        FieldKind::Integer
            | FieldKind::Real
            | FieldKind::Boolean
            | FieldKind::DateTime
            | FieldKind::Date
            | FieldKind::Time
            | FieldKind::Uuid
            | FieldKind::Decimal
            | FieldKind::Json
            | FieldKind::JsonObject
            | FieldKind::JsonArray
            | FieldKind::List
    )
}

fn list_contains_pattern(value: &str) -> String {
    let lowered = value.to_lowercase();
    let mut pattern = String::with_capacity(lowered.len() + 2);
    pattern.push('%');
    for ch in lowered.chars() {
        match ch {
            '%' | '_' | '\\' => {
                pattern.push('\\');
                pattern.push(ch);
            }
            _ => pattern.push(ch),
        }
    }
    pattern.push('%');
    pattern
}

fn bind_markers(count: usize) -> String {
    (0..count)
        .map(|_| BIND_MARKER)
        .collect::<Vec<_>>()
        .join(", ")
}

fn parse_filter_in_values(value: &str, max_values: usize) -> Result<Vec<&str>, ListPlanError> {
    let values = value.split(',').map(str::trim).collect::<Vec<_>>();
    if values.is_empty() || values.iter().any(|value| value.is_empty()) || values.len() > max_values
    {
        return Err(ListPlanError::bad_request(
            "invalid_query",
            "Query parameters are invalid",
        ));
    }
    Ok(values)
}

fn parse_sort_order(value: &str) -> Option<SortOrder> {
    match value {
        "asc" => Some(SortOrder::Asc),
        "desc" => Some(SortOrder::Desc),
        _ => None,
    }
}

/// Decode a client-provided cursor or classify it as an invalid request.
pub fn decode_cursor(value: &str) -> Result<CursorPayload, ListPlanError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ListPlanError::bad_request("invalid_cursor", "Cursor is not valid"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| ListPlanError::bad_request("invalid_cursor", "Cursor is not valid"))
}

/// Encode a continuation cursor from the last returned item.
pub fn encode_cursor(payload: &CursorPayload) -> Result<String, ListPlanError> {
    let json = serde_json::to_vec(payload)
        .map_err(|error| ListPlanError::internal_error(error.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(json))
}

/// Build the count and select queries for a native collection request.
pub fn build_list_plan(
    resource: &RuntimeResource,
    resources: &[Arc<RuntimeResource>],
    mut query: HashMap<String, String>,
    principal: &PolicyPrincipal<'_>,
    is_admin: bool,
    scope: Option<&ListScope>,
    skip_static_read_policy: bool,
    max_filter_in_values: usize,
) -> Result<ListQueryPlan, ListPlanError> {
    let requested_limit = query
        .remove("limit")
        .map(|value| value.parse::<u32>())
        .transpose()
        .map_err(|_| ListPlanError::bad_request("invalid_query", "Query parameters are invalid"))?;
    let offset = query
        .remove("offset")
        .map(|value| value.parse::<u32>())
        .transpose()
        .map_err(|_| ListPlanError::bad_request("invalid_query", "Query parameters are invalid"))?;
    let cursor = query.remove("cursor");
    let sort = query.remove("sort");
    let order = query.remove("order");
    query.remove("context");

    if cursor.is_some() && offset.is_some() {
        return Err(ListPlanError::bad_request(
            "invalid_cursor",
            "`cursor` cannot be combined with `offset`",
        ));
    }
    if cursor.is_some() && (sort.is_some() || order.is_some()) {
        return Err(ListPlanError::bad_request(
            "invalid_cursor",
            "`cursor` cannot be combined with `sort` or `order`",
        ));
    }

    let default_limit = resource.default_limit;
    let max_limit = resource.max_limit;
    let effective_limit = match (requested_limit.or(default_limit), max_limit) {
        (Some(limit), Some(max_limit)) => Some(limit.min(max_limit)),
        (Some(limit), None) => Some(limit),
        (None, _) => None,
    };

    let sort_supplied = sort.is_some();
    let order_supplied = order.is_some();
    let cursor_payload = match cursor.as_deref() {
        Some(value) => Some(decode_cursor(value)?),
        None => None,
    };

    let (sort_field, sort_order, cursor_mode) = if let Some(cursor_payload) = &cursor_payload {
        let sort_field = cursor_payload.sort.clone();
        let sort_order = parse_sort_order(cursor_payload.order.as_str())
            .ok_or_else(|| ListPlanError::bad_request("invalid_cursor", "Cursor is not valid"))?;
        (sort_field, sort_order, true)
    } else {
        let sort_field = sort.unwrap_or_else(|| resource.id_api_name.clone());
        let sort_order = match order {
            Some(order) => parse_sort_order(order.as_str()).ok_or_else(|| {
                ListPlanError::bad_request("invalid_query", "Query parameters are invalid")
            })?,
            None => SortOrder::Asc,
        };
        if !sort_supplied && order_supplied {
            return Err(ListPlanError::bad_request(
                "invalid_sort",
                "`order` requires `sort`",
            ));
        }
        (sort_field, sort_order, false)
    };

    let sort_field_spec = field_by_api_name(resource, sort_field.as_str()).ok_or_else(|| {
        ListPlanError::bad_request("invalid_query", "Query parameters are invalid")
    })?;
    if !sort_field_spec.supports_sort {
        return Err(ListPlanError::bad_request(
            "invalid_sort",
            "Unsupported sort field",
        ));
    }
    if cursor_mode && effective_limit.is_none() {
        return Err(ListPlanError::bad_request(
            "invalid_cursor",
            "`cursor` requires `limit` or a configured `default_limit`",
        ));
    }
    if cursor_mode && effective_limit == Some(0) {
        return Err(ListPlanError::bad_request(
            "invalid_cursor",
            "`cursor` requires `limit` to be greater than 0",
        ));
    }
    if cursor_mode
        && sort_field != resource.id_api_name
        && (!sort_field_spec.supports_sort || sort_field_spec.optional)
    {
        return Err(ListPlanError::bad_request(
            "invalid_cursor",
            format!("Cursor pagination does not support nullable sort field `{sort_field}`"),
        ));
    }

    let mut conditions = Vec::new();
    let mut filter_binds = Vec::new();
    let mut select_only_conditions = Vec::new();
    let mut select_only_binds = Vec::new();

    if let Some(scope) = scope {
        match scope {
            ListScope::ParentField { field_name, value } => {
                conditions.push(format!("{field_name} = {}", BIND_MARKER));
                filter_binds.push(BoundValue::Integer(*value));
            }
            ListScope::ManyToMany {
                through_table,
                source_field,
                target_field,
                parent_id,
            } => {
                conditions.push(format!(
                    "EXISTS (SELECT 1 FROM {through_table} WHERE {through_table}.{target_field} = {}.{} AND {through_table}.{source_field} = {BIND_MARKER})",
                    resource.table_name,
                    resource.id_field
                ));
                filter_binds.push(BoundValue::Integer(*parent_id));
            }
        }
    }

    if resource.policies.has_read_filters()
        && !(resource.policies.admin_bypass && is_admin)
        && !skip_static_read_policy
    {
        match build_row_policy_plan(
            resource,
            resources,
            resource
                .policies
                .read
                .as_ref()
                .expect("read filters checked"),
            principal,
        )
        .map_err(|error| ListPlanError::internal_error(error.to_string()))?
        {
            PlanOutcome::Resolved(plan) => {
                conditions.push(plan.condition);
                filter_binds.extend(plan.binds);
            }
            PlanOutcome::Indeterminate => {
                return Err(ListPlanError::forbidden(
                    "missing_claim",
                    "Missing required principal values for row policy",
                ));
            }
        }
    }

    for field in &resource.fields {
        if !field.expose_in_api {
            continue;
        }
        if field.supports_exact_filters {
            let exact_name = format!("filter_{}", field.api_name);
            if let Some(value) = query.remove(exact_name.as_str()) {
                let parsed = parse_query_value(field, value.as_str()).map_err(|_| {
                    ListPlanError::bad_request("invalid_query", "Query parameters are invalid")
                })?;
                conditions.push(format!("{} = {}", field.name, BIND_MARKER));
                filter_binds.push(parsed);
            }

            if resource.filterable_in.contains(field.name.as_str()) {
                let in_name = format!("filter_{}__in", field.api_name);
                if let Some(value) = query.remove(in_name.as_str()) {
                    let values = parse_filter_in_values(value.as_str(), max_filter_in_values)?;
                    conditions.push(format!(
                        "{} IN ({})",
                        field.name,
                        bind_markers(values.len())
                    ));
                    for value in values {
                        let parsed = parse_query_value(field, value).map_err(|_| {
                            ListPlanError::bad_request(
                                "invalid_query",
                                "Query parameters are invalid",
                            )
                        })?;
                        filter_binds.push(parsed);
                    }
                }
            }
        }

        if supports_contains_filters(field) {
            let contains_name = format!("filter_{}_contains", field.api_name);
            if let Some(value) = query.remove(contains_name.as_str()) {
                conditions.push(format!(
                    "LOWER({}) LIKE {} ESCAPE '\\'",
                    field.name, BIND_MARKER
                ));
                filter_binds.push(BoundValue::Text(list_contains_pattern(value.as_str())));
            }
        }

        if field.supports_exact_filters && field.supports_range_filters {
            for (suffix, operator) in [("_gt", ">"), ("_gte", ">="), ("_lt", "<"), ("_lte", "<=")] {
                let name = format!("filter_{}{}", field.api_name, suffix);
                if let Some(value) = query.remove(name.as_str()) {
                    let parsed = parse_query_value(field, value.as_str()).map_err(|_| {
                        ListPlanError::bad_request("invalid_query", "Query parameters are invalid")
                    })?;
                    conditions.push(format!("{} {} {}", field.name, operator, BIND_MARKER));
                    filter_binds.push(parsed);
                }
            }
        }
    }

    if !query.is_empty() {
        return Err(ListPlanError::bad_request(
            "invalid_query",
            "Query parameters are invalid",
        ));
    }

    if let Some(cursor_payload) = &cursor_payload {
        let comparator = if sort_order == SortOrder::Asc {
            ">"
        } else {
            "<"
        };
        if sort_field == resource.id_api_name {
            if !matches!(cursor_payload.value, CursorValue::Integer(_)) {
                return Err(ListPlanError::bad_request(
                    "invalid_cursor",
                    "Cursor does not match the current sort field",
                ));
            }
            select_only_conditions
                .push(format!("{} {comparator} {BIND_MARKER}", resource.id_field));
            select_only_binds.push(BoundValue::Integer(cursor_payload.last_id));
        } else {
            let cursor_value = match (&sort_field_spec.kind, &cursor_payload.value) {
                (FieldKind::Integer, CursorValue::Integer(value)) => BoundValue::Integer(*value),
                (FieldKind::Real, CursorValue::Real(value)) => BoundValue::Real(*value),
                (FieldKind::Boolean, CursorValue::Boolean(value)) => BoundValue::Bool(*value),
                (_, CursorValue::Text(value)) => BoundValue::Text(value.clone()),
                _ => {
                    return Err(ListPlanError::bad_request(
                        "invalid_cursor",
                        "Cursor does not match the current sort field",
                    ));
                }
            };
            select_only_conditions.push(format!(
                "(({} {comparator} {BIND_MARKER}) OR ({} = {BIND_MARKER} AND {} {comparator} {BIND_MARKER}))",
                sort_field_spec.name,
                sort_field_spec.name,
                resource.id_field
            ));
            select_only_binds.push(cursor_value.clone());
            select_only_binds.push(cursor_value);
            select_only_binds.push(BoundValue::Integer(cursor_payload.last_id));
        }
    }

    let count_condition = if conditions.is_empty() {
        None
    } else {
        Some(render_condition_with_placeholders(
            conditions.join(" AND ").as_str(),
            resource.db,
            1,
        ))
    };
    let count_sql = if let Some(condition) = count_condition {
        format!(
            "SELECT COUNT(*) FROM {} WHERE {}",
            resource.table_name, condition
        )
    } else {
        format!("SELECT COUNT(*) FROM {}", resource.table_name)
    };

    let mut select_conditions = conditions.clone();
    select_conditions.extend(select_only_conditions);
    let mut select_binds = filter_binds.clone();
    select_binds.extend(select_only_binds);

    let mut select_sql = format!("SELECT * FROM {}", resource.table_name);
    if !select_conditions.is_empty() {
        select_sql.push_str(" WHERE ");
        select_sql.push_str(
            render_condition_with_placeholders(
                select_conditions.join(" AND ").as_str(),
                resource.db,
                1,
            )
            .as_str(),
        );
    }
    select_sql.push_str(" ORDER BY ");
    select_sql.push_str(sort_field_spec.name.as_str());
    select_sql.push(' ');
    select_sql.push_str(sort_order.as_sql());
    if sort_field != resource.id_api_name {
        select_sql.push_str(", ");
        select_sql.push_str(resource.id_field.as_str());
        select_sql.push(' ');
        select_sql.push_str(sort_order.as_sql());
    }

    let query_limit = effective_limit.map(|limit| {
        if cursor_mode {
            limit.saturating_add(1)
        } else {
            limit
        }
    });
    if let Some(query_limit) = query_limit {
        let placeholder_index = select_binds.len() + 1;
        select_sql.push_str(" LIMIT ");
        select_sql.push_str(placeholder(resource.db, placeholder_index).as_str());
        select_binds.push(BoundValue::Integer(query_limit as i64));
    }
    if let Some(offset) = offset {
        if effective_limit.is_none() {
            return Err(ListPlanError::bad_request(
                "invalid_pagination",
                "`offset` requires `limit`",
            ));
        }
        let placeholder_index = select_binds.len() + 1;
        select_sql.push_str(" OFFSET ");
        select_sql.push_str(placeholder(resource.db, placeholder_index).as_str());
        select_binds.push(BoundValue::Integer(offset as i64));
    }

    Ok(ListQueryPlan {
        count_sql,
        select_sql,
        filter_binds,
        select_binds,
        limit: effective_limit,
        offset: offset.unwrap_or(0),
        sort: sort_field,
        order: sort_order,
        cursor_mode,
    })
}

fn cursor_value_for_item(
    resource: &RuntimeResource,
    item: &Value,
    sort: &str,
) -> Result<CursorValue, ListPlanError> {
    let field = field_by_api_name(resource, sort).ok_or_else(|| {
        ListPlanError::internal_error(format!(
            "field `{sort}` not found in `{}`",
            resource.api_name
        ))
    })?;
    let value = item.get(sort).ok_or_else(|| {
        ListPlanError::internal_error(format!("missing sort field `{sort}` in response item"))
    })?;
    match (&field.kind, value) {
        (FieldKind::Integer, Value::Number(value)) => {
            value.as_i64().map(CursorValue::Integer).ok_or_else(|| {
                ListPlanError::internal_error("invalid integer cursor value".to_owned())
            })
        }
        (FieldKind::Real, Value::Number(value)) => value
            .as_f64()
            .map(CursorValue::Real)
            .ok_or_else(|| ListPlanError::internal_error("invalid real cursor value".to_owned())),
        (FieldKind::Boolean, Value::Bool(value)) => Ok(CursorValue::Boolean(*value)),
        (_, Value::String(value)) => Ok(CursorValue::Text(value.clone())),
        (_, Value::Number(value)) if sort == resource.id_api_name => value
            .as_i64()
            .map(CursorValue::Integer)
            .ok_or_else(|| ListPlanError::internal_error("invalid id cursor value".to_owned())),
        _ => Err(ListPlanError::internal_error(format!(
            "unsupported cursor value for field `{sort}`"
        ))),
    }
}

fn id_for_item(resource: &RuntimeResource, item: &Value) -> Result<i64, ListPlanError> {
    item.get(resource.id_api_name.as_str())
        .and_then(Value::as_i64)
        .ok_or_else(|| {
            ListPlanError::internal_error("missing persisted id in list item".to_owned())
        })
}

/// Build pagination metadata and the continuation cursor for a selected page.
pub fn finalize_list_response(
    resource: &RuntimeResource,
    plan: ListQueryPlan,
    total: i64,
    mut items: Vec<Value>,
) -> Result<RuntimeListResponse, ListPlanError> {
    let mut has_more = false;
    if plan.cursor_mode {
        if let Some(limit) = plan.limit
            && items.len() > limit as usize
        {
            has_more = true;
            items.pop();
        }
    } else if plan.limit.is_some() && plan.limit != Some(0) {
        has_more = (plan.offset as i64) + (items.len() as i64) < total;
    }

    let next_offset = if !plan.cursor_mode && has_more {
        Some(plan.offset + items.len() as u32)
    } else {
        None
    };

    let next_cursor = if has_more {
        match items.last() {
            Some(item) => Some(encode_cursor(&CursorPayload {
                sort: plan.sort.clone(),
                order: plan.order.as_str().to_owned(),
                last_id: id_for_item(resource, item)?,
                value: cursor_value_for_item(resource, item, plan.sort.as_str())?,
            })?),
            None => None,
        }
    } else {
        None
    };

    Ok(RuntimeListResponse {
        count: items.len(),
        items,
        limit: plan.limit,
        next_cursor,
        next_offset,
        offset: plan.offset,
        total,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use serde_json::json;

    use super::*;
    use crate::{
        authz::{RoleRequirements, policy::RowPolicies},
        field::{FieldValidation, GeneratedValue},
    };

    fn resource() -> Arc<RuntimeResource> {
        let fields = [("id", FieldKind::Integer), ("title", FieldKind::Text)]
            .into_iter()
            .map(|(name, kind)| RuntimeField {
                name: name.into(),
                api_name: name.into(),
                expose_in_api: true,
                enum_values: None,
                transforms: Vec::new(),
                kind,
                list_item_kind: None,
                object_fields: None,
                optional: false,
                generated: GeneratedValue::None,
                validation: FieldValidation::default(),
                supports_exact_filters: true,
                supports_sort: true,
                supports_range_filters: false,
            })
            .collect::<Vec<_>>();
        let indexes: HashMap<_, _> = fields
            .iter()
            .enumerate()
            .map(|(index, field)| (field.name.clone(), index))
            .collect();
        Arc::new(RuntimeResource {
            resource_name: "Note".into(),
            table_name: "note".into(),
            api_name: "note".into(),
            default_response_context: None,
            id_field: "id".into(),
            id_api_name: "id".into(),
            db: DbBackend::Sqlite,
            roles: RoleRequirements::default(),
            policies: RowPolicies::default(),
            default_limit: None,
            max_limit: None,
            filterable_in: BTreeSet::new(),
            count_endpoint: true,
            create_assignment_sources: HashMap::new(),
            fields,
            field_index: indexes.clone(),
            api_field_index: indexes,
            response_contexts: HashMap::new(),
            computed_fields: Vec::new(),
            create_fields: Vec::new(),
            update_field_names: Vec::new(),
            actions: Vec::new(),
            audit: None,
            is_audit_sink: false,
            read_requires_auth: false,
            hybrid: None,
            nested_relations: Vec::new(),
            many_to_many_routes: Vec::new(),
        })
    }

    #[test]
    fn filtered_list_cursor_preserves_count_and_bind_order() {
        let resource = resource();
        let resources = [resource.clone()];
        let claims = BTreeMap::new();
        let principal = PolicyPrincipal {
            user_id: 0,
            claims: &claims,
        };
        let query = HashMap::from([
            ("filter_title_contains".into(), "HI".into()),
            ("limit".into(), "2".into()),
            ("sort".into(), "title".into()),
            ("order".into(), "desc".into()),
        ]);
        let first = build_list_plan(
            &resource, &resources, query, &principal, false, None, false, 32,
        )
        .unwrap();
        assert!(first.count_sql.contains("LOWER(title) LIKE ?"));
        assert!(
            first
                .select_sql
                .contains("ORDER BY title DESC, id DESC LIMIT ?")
        );
        assert_eq!(first.filter_binds, vec![BoundValue::Text("%hi%".into())]);
        assert_eq!(
            first.select_binds,
            vec![BoundValue::Text("%hi%".into()), BoundValue::Integer(2)]
        );

        let response = finalize_list_response(
            &resource,
            first,
            3,
            vec![
                json!({ "id": 1, "title": "high" }),
                json!({ "id": 2, "title": "hill" }),
            ],
        )
        .unwrap();
        assert_eq!(response.next_offset, Some(2));
        let cursor = response.next_cursor.expect("another page exists");
        let next = build_list_plan(
            &resource,
            &resources,
            HashMap::from([
                ("filter_title_contains".into(), "HI".into()),
                ("limit".into(), "2".into()),
                ("cursor".into(), cursor),
            ]),
            &principal,
            false,
            None,
            false,
            32,
        )
        .unwrap();
        assert!(next.cursor_mode);
        assert_eq!(
            next.count_sql,
            "SELECT COUNT(*) FROM note WHERE LOWER(title) LIKE ? ESCAPE '\\'"
        );
        assert_eq!(
            next.select_binds,
            vec![
                BoundValue::Text("%hi%".into()),
                BoundValue::Text("hill".into()),
                BoundValue::Text("hill".into()),
                BoundValue::Integer(2),
                BoundValue::Integer(3),
            ]
        );
    }
}
