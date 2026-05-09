//! Row policy types and inherent helpers.
//!
//! Captures the row-level policy DSL (`PolicyFilterExpression`, `RowPolicies`,
//! and friends) along with the helpers used to traverse them. Validators
//! against `ResourceSpec` live in `validators.rs`; this module keeps the data
//! shapes plus structural traversals only.

use std::collections::BTreeSet;

use crate::auth::AuthClaimType;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum RowPolicyKind {
    Owner,
    SetOwner,
}

impl RowPolicyKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "owner" => Some(Self::Owner),
            "set_owner" | "setowner" | "set-owner" => Some(Self::SetOwner),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyValueSource {
    UserId,
    Claim(String),
    InputField(String),
}

impl PolicyValueSource {
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value == "user.id" {
            Some(Self::UserId)
        } else {
            value
                .strip_prefix("claim.")
                .and_then(|claim| {
                    if claim.is_empty() {
                        None
                    } else {
                        Some(Self::Claim(claim.to_owned()))
                    }
                })
                .or_else(|| {
                    value.strip_prefix("input.").and_then(|field| {
                        if field.is_empty() {
                            None
                        } else {
                            Some(Self::InputField(field.to_owned()))
                        }
                    })
                })
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyLiteralValue {
    String(String),
    I64(i64),
    Bool(bool),
}

impl PolicyLiteralValue {
    pub fn claim_type(&self) -> AuthClaimType {
        match self {
            Self::String(_) => AuthClaimType::String,
            Self::I64(_) => AuthClaimType::I64,
            Self::Bool(_) => AuthClaimType::Bool,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyComparisonValue {
    Source(PolicyValueSource),
    Literal(PolicyLiteralValue),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyFilter {
    pub field: String,
    pub operator: PolicyFilterOperator,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyFilterOperator {
    Equals(PolicyComparisonValue),
    IsNull,
    IsNotNull,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyExistsCondition {
    Match(PolicyFilter),
    CurrentRowField { field: String, row_field: String },
    All(Vec<PolicyExistsCondition>),
    Any(Vec<PolicyExistsCondition>),
    Not(Box<PolicyExistsCondition>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyExistsFilter {
    pub resource: String,
    pub condition: PolicyExistsCondition,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyFilterExpression {
    Match(PolicyFilter),
    All(Vec<PolicyFilterExpression>),
    Any(Vec<PolicyFilterExpression>),
    Not(Box<PolicyFilterExpression>),
    Exists(PolicyExistsFilter),
}

impl PolicyFilterExpression {
    pub fn all(expressions: Vec<Self>) -> Option<Self> {
        match expressions.len() {
            0 => None,
            1 => expressions.into_iter().next(),
            _ => Some(Self::All(expressions)),
        }
    }

    pub fn any(expressions: Vec<Self>) -> Option<Self> {
        match expressions.len() {
            0 => None,
            1 => expressions.into_iter().next(),
            _ => Some(Self::Any(expressions)),
        }
    }

    pub fn collect_filters<'a>(&'a self, filters: &mut Vec<&'a PolicyFilter>) {
        match self {
            Self::Match(filter) => filters.push(filter),
            Self::All(expressions) | Self::Any(expressions) => {
                for expression in expressions {
                    expression.collect_filters(filters);
                }
            }
            Self::Not(expression) => expression.collect_filters(filters),
            Self::Exists(filter) => filter.condition.collect_filters(filters),
        }
    }

    pub fn collect_controlled_fields(&self, fields: &mut BTreeSet<String>) {
        match self {
            Self::Match(filter) => {
                fields.insert(filter.field.clone());
            }
            Self::All(expressions) | Self::Any(expressions) => {
                for expression in expressions {
                    expression.collect_controlled_fields(fields);
                }
            }
            Self::Not(expression) => expression.collect_controlled_fields(fields),
            Self::Exists(filter) => filter.condition.collect_controlled_fields(fields),
        }
    }

    pub fn collect_exists_index_targets(&self, targets: &mut Vec<(String, String)>) {
        match self {
            Self::Match(_) => {}
            Self::All(expressions) | Self::Any(expressions) => {
                for expression in expressions {
                    expression.collect_exists_index_targets(targets);
                }
            }
            Self::Not(expression) => expression.collect_exists_index_targets(targets),
            Self::Exists(filter) => filter
                .condition
                .collect_exists_index_targets(&filter.resource, targets),
        }
    }
}

impl PolicyExistsCondition {
    pub fn all(expressions: Vec<Self>) -> Option<Self> {
        match expressions.len() {
            0 => None,
            1 => expressions.into_iter().next(),
            _ => Some(Self::All(expressions)),
        }
    }

    pub fn any(expressions: Vec<Self>) -> Option<Self> {
        match expressions.len() {
            0 => None,
            1 => expressions.into_iter().next(),
            _ => Some(Self::Any(expressions)),
        }
    }

    pub fn collect_filters<'a>(&'a self, filters: &mut Vec<&'a PolicyFilter>) {
        match self {
            Self::Match(filter) => filters.push(filter),
            Self::CurrentRowField { .. } => {}
            Self::All(expressions) | Self::Any(expressions) => {
                for expression in expressions {
                    expression.collect_filters(filters);
                }
            }
            Self::Not(expression) => expression.collect_filters(filters),
        }
    }

    pub fn collect_controlled_fields(&self, fields: &mut BTreeSet<String>) {
        match self {
            Self::Match(_) => {}
            Self::CurrentRowField { row_field, .. } => {
                fields.insert(row_field.clone());
            }
            Self::All(expressions) | Self::Any(expressions) => {
                for expression in expressions {
                    expression.collect_controlled_fields(fields);
                }
            }
            Self::Not(expression) => expression.collect_controlled_fields(fields),
        }
    }

    pub fn collect_exists_index_targets(
        &self,
        resource: &str,
        targets: &mut Vec<(String, String)>,
    ) {
        match self {
            Self::Match(condition) => {
                targets.push((resource.to_owned(), condition.field.clone()));
            }
            Self::CurrentRowField { field, .. } => {
                targets.push((resource.to_owned(), field.clone()));
            }
            Self::All(expressions) | Self::Any(expressions) => {
                for expression in expressions {
                    expression.collect_exists_index_targets(resource, targets);
                }
            }
            Self::Not(expression) => expression.collect_exists_index_targets(resource, targets),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyAssignment {
    pub field: String,
    pub source: PolicyValueSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RowPolicies {
    pub admin_bypass: bool,
    pub read: Option<PolicyFilterExpression>,
    pub create_require: Option<PolicyFilterExpression>,
    pub create: Vec<PolicyAssignment>,
    pub update: Option<PolicyFilterExpression>,
    pub delete: Option<PolicyFilterExpression>,
}

impl Default for RowPolicies {
    fn default() -> Self {
        Self {
            admin_bypass: true,
            read: None,
            create_require: None,
            create: Vec::new(),
            update: None,
            delete: None,
        }
    }
}

impl RowPolicies {
    pub fn has_read_filters(&self) -> bool {
        self.read.is_some()
    }

    pub fn has_create_require_filters(&self) -> bool {
        self.create_require.is_some()
    }

    pub fn has_update_filters(&self) -> bool {
        self.update.is_some()
    }

    pub fn has_delete_filters(&self) -> bool {
        self.delete.is_some()
    }

    pub fn iter_filters(&self) -> Vec<(&'static str, &PolicyFilter)> {
        let mut filters = Vec::new();
        collect_scope_filters("read", self.read.as_ref(), &mut filters);
        collect_scope_filters("create.require", self.create_require.as_ref(), &mut filters);
        collect_scope_filters("update", self.update.as_ref(), &mut filters);
        collect_scope_filters("delete", self.delete.as_ref(), &mut filters);
        filters
    }

    pub fn controlled_filter_fields(&self) -> BTreeSet<String> {
        let mut fields = BTreeSet::new();
        collect_scope_controlled_fields(self.read.as_ref(), &mut fields);
        collect_scope_controlled_fields(self.update.as_ref(), &mut fields);
        collect_scope_controlled_fields(self.delete.as_ref(), &mut fields);
        fields
    }

    pub fn iter_assignments(&self) -> impl Iterator<Item = (&'static str, &PolicyAssignment)> {
        self.create.iter().map(|policy| ("create", policy))
    }

    pub fn exists_index_targets(&self) -> Vec<(String, String)> {
        let mut targets = Vec::new();
        collect_scope_exists_index_targets(self.read.as_ref(), &mut targets);
        collect_scope_exists_index_targets(self.create_require.as_ref(), &mut targets);
        collect_scope_exists_index_targets(self.update.as_ref(), &mut targets);
        collect_scope_exists_index_targets(self.delete.as_ref(), &mut targets);
        targets
    }
}

pub(super) fn read_filter_uses_principal_values(
    filter: Option<&PolicyFilterExpression>,
) -> bool {
    let Some(filter) = filter else {
        return false;
    };

    let mut filters = Vec::new();
    filter.collect_filters(&mut filters);
    filters.iter().any(|filter| {
        matches!(
            &filter.operator,
            PolicyFilterOperator::Equals(PolicyComparisonValue::Source(
                PolicyValueSource::UserId | PolicyValueSource::Claim(_)
            ))
        )
    })
}

fn collect_scope_filters<'a>(
    scope: &'static str,
    expression: Option<&'a PolicyFilterExpression>,
    filters: &mut Vec<(&'static str, &'a PolicyFilter)>,
) {
    let Some(expression) = expression else {
        return;
    };
    let mut scoped_filters = Vec::new();
    expression.collect_filters(&mut scoped_filters);
    filters.extend(scoped_filters.into_iter().map(|filter| (scope, filter)));
}

fn collect_scope_controlled_fields(
    expression: Option<&PolicyFilterExpression>,
    fields: &mut BTreeSet<String>,
) {
    let Some(expression) = expression else {
        return;
    };
    expression.collect_controlled_fields(fields);
}

fn collect_scope_exists_index_targets(
    expression: Option<&PolicyFilterExpression>,
    targets: &mut Vec<(String, String)>,
) {
    let Some(expression) = expression else {
        return;
    };
    expression.collect_exists_index_targets(targets);
}
