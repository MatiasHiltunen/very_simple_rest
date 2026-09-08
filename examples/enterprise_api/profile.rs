//! Fail closed on EON options this example cannot enforce. Canonical parsing,
//! validation and SQL generation still belong to rest_macro_core.
#![allow(dead_code)] // These DTOs validate shape; the compiler supplies values.
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    module: String,
    db: String,
    security: Security,
    resources: Vec<Resource>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Security {
    access: Access,
    requests: Requests,
    auth: Auth,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Access {
    default_read: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Requests {
    json_max_bytes: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Auth {
    issuer: String,
    audience: String,
    access_token_ttl_seconds: i64,
    claims: BTreeMap<String, Claim>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    r#type: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Resource {
    name: String,
    roles: Roles,
    policies: Policies,
    indexes: Vec<Index>,
    fields: Vec<Field>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Roles {
    read: String,
    create: String,
    update: String,
    delete: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policies {
    admin_bypass: bool,
    read: Group,
    create: Vec<Assignment>,
    update: Group,
    delete: Group,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Group {
    One(Predicate),
    All(Vec<Predicate>),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Predicate {
    field: String,
    equals: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Assignment {
    field: String,
    value: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    fields: Vec<String>,
    #[serde(default)]
    unique: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Field {
    name: String,
    r#type: String,
    #[serde(default)]
    relation: Option<Relation>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Relation {
    references: String,
    on_delete: String,
}
