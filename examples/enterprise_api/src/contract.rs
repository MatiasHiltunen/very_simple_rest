//! Build-time-validated, framework-neutral subset of the existing EON model.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contract {
    pub issuer: String,
    pub audience: String,
    pub token_ttl: i64,
    pub max_body_bytes: usize,
    pub resources: Vec<Resource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub name: String,
    pub table: String,
    pub fields: Vec<Field>,
    pub read: Rule,
    pub create: Rule,
    pub update: Rule,
    pub delete: Rule,
    pub assignments: Vec<Filter>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub kind: Kind,
    pub references: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Kind {
    String,
    I64,
    Bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub role: String,
    pub filters: Vec<Filter>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Filter {
    pub field: String,
    pub source: Source,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Source {
    Tenant,
    User,
}

impl Resource {
    pub fn controlled(&self, field: &str) -> bool {
        field == "id" || self.assignments.iter().any(|a| a.field == field)
    }
}
