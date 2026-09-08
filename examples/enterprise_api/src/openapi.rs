//! Describe the implemented adapter, not the legacy compiler's Actix/auth surface.
use crate::{
    config::Config,
    contract::{Contract, Kind, Resource},
};
use serde_json::{Map, Value, json};

fn object(resource: &Resource, config: &Config, writable: bool, partial: bool) -> Value {
    let mut properties = Map::new();
    for field in &resource.fields {
        if writable && resource.controlled(&field.name) {
            continue;
        }
        let mut schema = match field.kind {
            Kind::String => {
                json!({"type":"string","minLength":1,"maxLength":config.max_string_chars})
            }
            Kind::I64 => json!({"type":"integer","format":"int64"}),
            Kind::Bool => json!({"type":"boolean"}),
        };
        if !writable && resource.controlled(&field.name) {
            schema["readOnly"] = json!(true);
        }
        if field.references.is_some() {
            schema["minimum"] = json!(1);
        }
        properties.insert(field.name.clone(), schema);
    }
    let required: Vec<_> = if partial {
        vec![]
    } else {
        properties.keys().cloned().collect()
    };
    json!({"type":"object","properties":properties,"additionalProperties":false,"required":required,"minProperties":1})
}

fn operation(id: &str, tag: &str, code: &str, schema: Option<Value>) -> Value {
    let mut success = json!({"description":"Successful response"});
    if let Some(schema) = schema {
        success["content"] = json!({"application/json":{"schema":schema}});
    }
    let mut responses = Map::from_iter([(code.into(), success)]);
    for (code, description) in [
        ("400", "Invalid input"),
        ("401", "Invalid or revoked identity"),
        ("403", "Missing current grant"),
        ("404", "Missing or invisible resource"),
        ("409", "Resource conflict"),
        ("412", "Stale or mismatched ETag"),
        ("413", "Body limit exceeded"),
        ("415", "Unsupported content type"),
        ("428", "If-Match required"),
        ("503", "Capacity, deadline or dependency failure"),
    ] {
        responses.insert(code.into(),json!({"description":description,"content":{"application/json":{"schema":{"type":"object","properties":{"error":{"type":"string"}},"required":["error"]}}}}));
    }
    json!({"operationId":id,"tags":[tag],"responses":responses})
}

fn pagination(config: &Config) -> Value {
    json!([
        {"name":"after","in":"query","schema":{"type":"integer","format":"int64","minimum":0,"default":0}},
        {"name":"limit","in":"query","schema":{"type":"integer","minimum":1,"maximum":config.max_page_size,"default":config.max_page_size.min(25)}}
    ])
}

pub(super) fn document(contract: &Contract, config: &Config) -> Value {
    let mut paths = Map::new();
    let mut schemas = Map::new();
    for resource in &contract.resources {
        schemas.insert(
            resource.name.clone(),
            object(resource, config, false, false),
        );
        let row = json!({"$ref":format!("#/components/schemas/{}",resource.name)});
        let page = json!({"type":"object","properties":{"data":{"type":"array","items":row},"next_after":{"type":["integer","null"],"format":"int64"}},"required":["data","next_after"]});
        let mut list = operation(
            &format!("list_{}", resource.table),
            &resource.name,
            "200",
            Some(page),
        );
        list["parameters"] = pagination(config);
        let mut create = operation(
            &format!("create_{}", resource.table),
            &resource.name,
            "201",
            Some(row.clone()),
        );
        create["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":object(resource,config,true,false)}}});
        create["responses"]["201"]["headers"] =
            json!({"ETag":{"schema":{"type":"string"}},"Location":{"schema":{"type":"string"}}});
        paths.insert(
            format!("/api/v1/{}", resource.table),
            json!({"get":list,"post":create}),
        );
        let mut get = operation(
            &format!("get_{}", resource.table),
            &resource.name,
            "200",
            Some(row.clone()),
        );
        get["responses"]["200"]["headers"] = json!({"ETag":{"schema":{"type":"string"}}});
        let precondition = json!([{"name":"If-Match","in":"header","required":true,"schema":{"type":"string"},"description":"Exact ETag returned by GET, POST or PATCH"}]);
        let mut patch = operation(
            &format!("update_{}", resource.table),
            &resource.name,
            "200",
            Some(row),
        );
        patch["parameters"] = precondition.clone();
        patch["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":object(resource,config,true,true)}}});
        patch["responses"]["200"]["headers"] = json!({"ETag":{"schema":{"type":"string"}}});
        let mut delete = operation(
            &format!("delete_{}", resource.table),
            &resource.name,
            "204",
            None,
        );
        delete["parameters"] = precondition;
        paths.insert(format!("/api/v1/{}/{{id}}",resource.table),json!({
            "parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"integer","format":"int64","minimum":1}}],
            "get":get,"patch":patch,"delete":delete
        }));
    }
    let session = operation(
        "current_session",
        "Identity",
        "200",
        Some(
            json!({"type":"object","properties":{"user_id":{"type":"integer"},"tenant_id":{"type":"integer"},"roles":{"type":"array","items":{"type":"string"}}}}),
        ),
    );
    paths.insert("/api/v1/session".into(), json!({"get":session}));
    let mut audit = operation(
        "list_audit_events",
        "Audit",
        "200",
        Some(
            json!({"type":"object","properties":{"data":{"type":"array","items":{"type":"object"}}}}),
        ),
    );
    audit["parameters"] = pagination(config);
    audit["description"] = json!(
        "Requires a current tenant-specific auditor grant; excludes tokens and business payloads."
    );
    paths.insert("/api/v1/audit".into(), json!({"get":audit}));
    json!({"openapi":"3.1.0","info":{"title":"Enterprise Operations API","version":"1.0.0"},"security":[{"bearer":[]}],"paths":paths,
        "components":{"schemas":schemas,"securitySchemes":{"bearer":{"type":"http","scheme":"bearer","bearerFormat":"JWT (ES256, at+jwt)"}}}})
}
