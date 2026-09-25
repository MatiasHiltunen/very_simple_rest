//! Row policy types and inherent helpers.
//!
//! Captures the row-level policy DSL (`PolicyFilterExpression`, `RowPolicies`,
//! and friends) along with the helpers used to traverse them. Validators
//! against `ResourceSpec` live in `validators.rs`; this module keeps the data
//! shapes plus structural traversals only.

use std::collections::BTreeSet;

use crate::auth::settings::AuthClaimType;

/// Legacy row-policy shorthand accepted in service definitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum RowPolicyKind {
    /// Restrict rows to the current owner.
    Owner,
    /// Assign the owner during creation.
    SetOwner,
}

impl RowPolicyKind {
    /// Parse the spelling used in a service definition.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "owner" => Some(Self::Owner),
            "set_owner" | "setowner" | "set-owner" => Some(Self::SetOwner),
            _ => None,
        }
    }
}

/// Value supplied by the authenticated principal or request input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyValueSource {
    /// Current principal's ID.
    UserId,
    /// Named claim on the principal.
    Claim(String),
    /// Named field in the request body.
    InputField(String),
}

impl PolicyValueSource {
    /// Parse a `user.id`, `claim.*`, or `input.*` source.
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

/// Literal used as a policy comparison value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyLiteralValue {
    /// Text literal.
    String(String),
    /// Integer literal.
    I64(i64),
    /// Boolean literal.
    Bool(bool),
}

impl PolicyLiteralValue {
    /// Return the claim type compatible with this literal.
    pub fn claim_type(&self) -> AuthClaimType {
        match self {
            Self::String(_) => AuthClaimType::String,
            Self::I64(_) => AuthClaimType::I64,
            Self::Bool(_) => AuthClaimType::Bool,
        }
    }
}

/// Right-hand side of a policy comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyComparisonValue {
    /// Principal or request value.
    Source(PolicyValueSource),
    /// Fixed literal.
    Literal(PolicyLiteralValue),
}

/// Comparison against a field in the current row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyFilter {
    /// Field being compared.
    pub field: String,
    /// Comparison operation.
    pub operator: PolicyFilterOperator,
}

/// Operation used to test a row field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyFilterOperator {
    /// Compare for equality.
    Equals(PolicyComparisonValue),
    /// Require SQL NULL.
    IsNull,
    /// Require a non-NULL value.
    IsNotNull,
}

/// Condition evaluated against a related row in an existence check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyExistsCondition {
    /// Compare a field in the related row.
    Match(PolicyFilter),
    /// Compare a related-row field with a field in the current row.
    CurrentRowField {
        /// Field in the related row.
        field: String,
        /// Field in the current row.
        row_field: String,
    },
    /// Require every nested condition.
    All(Vec<PolicyExistsCondition>),
    /// Require at least one nested condition.
    Any(Vec<PolicyExistsCondition>),
    /// Negate a nested condition.
    Not(Box<PolicyExistsCondition>),
}

/// Existence check against another resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyExistsFilter {
    /// Related resource name.
    pub resource: String,
    /// Condition applied to its rows.
    pub condition: PolicyExistsCondition,
}

/// Boolean expression controlling row access.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyFilterExpression {
    /// Test one row field.
    Match(PolicyFilter),
    /// Require all child expressions.
    All(Vec<PolicyFilterExpression>),
    /// Require at least one child expression.
    Any(Vec<PolicyFilterExpression>),
    /// Negate a child expression.
    Not(Box<PolicyFilterExpression>),
    /// Require a matching related row.
    Exists(PolicyExistsFilter),
}

impl PolicyFilterExpression {
    /// Combine expressions with AND, omitting an empty group.
    pub fn all(expressions: Vec<Self>) -> Option<Self> {
        match expressions.len() {
            0 => None,
            1 => expressions.into_iter().next(),
            _ => Some(Self::All(expressions)),
        }
    }

    /// Combine expressions with OR, omitting an empty group.
    pub fn any(expressions: Vec<Self>) -> Option<Self> {
        match expressions.len() {
            0 => None,
            1 => expressions.into_iter().next(),
            _ => Some(Self::Any(expressions)),
        }
    }

    /// Collect comparisons from this expression and its descendants.
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

    /// Collect fields in the current row that this expression controls.
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

    /// Collect related-resource fields that benefit from an existence index.
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
    /// Combine conditions with AND, omitting an empty group.
    pub fn all(expressions: Vec<Self>) -> Option<Self> {
        match expressions.len() {
            0 => None,
            1 => expressions.into_iter().next(),
            _ => Some(Self::All(expressions)),
        }
    }

    /// Combine conditions with OR, omitting an empty group.
    pub fn any(expressions: Vec<Self>) -> Option<Self> {
        match expressions.len() {
            0 => None,
            1 => expressions.into_iter().next(),
            _ => Some(Self::Any(expressions)),
        }
    }

    /// Collect comparisons from this condition and its descendants.
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

    /// Collect fields in the current row read by this condition.
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

    /// Collect related-resource fields that benefit from an existence index.
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

/// Value assigned to a field when a create policy succeeds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyAssignment {
    /// Field receiving the value.
    pub field: String,
    /// Source of the value.
    pub source: PolicyValueSource,
}

/// Row access filters and create assignments for one resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RowPolicies {
    /// Allow an administrator to skip row filters.
    pub admin_bypass: bool,
    /// Filter for reads.
    pub read: Option<PolicyFilterExpression>,
    /// Precondition for creation.
    pub create_require: Option<PolicyFilterExpression>,
    /// Values assigned during creation.
    pub create: Vec<PolicyAssignment>,
    /// Filter for updates.
    pub update: Option<PolicyFilterExpression>,
    /// Filter for deletes.
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
    /// Whether a read filter is present.
    pub fn has_read_filters(&self) -> bool {
        self.read.is_some()
    }

    /// Whether a create precondition is present.
    pub fn has_create_require_filters(&self) -> bool {
        self.create_require.is_some()
    }

    /// Whether an update filter is present.
    pub fn has_update_filters(&self) -> bool {
        self.update.is_some()
    }

    /// Whether a delete filter is present.
    pub fn has_delete_filters(&self) -> bool {
        self.delete.is_some()
    }

    /// Return every comparison with its operation name.
    pub fn iter_filters(&self) -> Vec<(&'static str, &PolicyFilter)> {
        let mut filters = Vec::new();
        collect_scope_filters("read", self.read.as_ref(), &mut filters);
        collect_scope_filters("create.require", self.create_require.as_ref(), &mut filters);
        collect_scope_filters("update", self.update.as_ref(), &mut filters);
        collect_scope_filters("delete", self.delete.as_ref(), &mut filters);
        filters
    }

    /// Return current-row fields controlled by read, update, or delete filters.
    pub fn controlled_filter_fields(&self) -> BTreeSet<String> {
        let mut fields = BTreeSet::new();
        collect_scope_controlled_fields(self.read.as_ref(), &mut fields);
        collect_scope_controlled_fields(self.update.as_ref(), &mut fields);
        collect_scope_controlled_fields(self.delete.as_ref(), &mut fields);
        fields
    }

    /// Return create assignments with their operation name.
    pub fn iter_assignments(&self) -> impl Iterator<Item = (&'static str, &PolicyAssignment)> {
        self.create.iter().map(|policy| ("create", policy))
    }

    /// Return related-resource fields used by existence checks.
    pub fn exists_index_targets(&self) -> Vec<(String, String)> {
        let mut targets = Vec::new();
        collect_scope_exists_index_targets(self.read.as_ref(), &mut targets);
        collect_scope_exists_index_targets(self.create_require.as_ref(), &mut targets);
        collect_scope_exists_index_targets(self.update.as_ref(), &mut targets);
        collect_scope_exists_index_targets(self.delete.as_ref(), &mut targets);
        targets
    }
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

#[cfg(test)]
mod tests {
    use super::{
        PolicyComparisonValue, PolicyExistsCondition, PolicyExistsFilter, PolicyFilter,
        PolicyFilterExpression, PolicyFilterOperator, PolicyValueSource, RowPolicies,
    };

    #[test]
    fn nested_exists_traversal_keeps_row_fields_and_related_index_targets() {
        let policies = RowPolicies {
            read: Some(PolicyFilterExpression::All(vec![
                PolicyFilterExpression::Match(PolicyFilter {
                    field: "owner_id".into(),
                    operator: PolicyFilterOperator::Equals(PolicyComparisonValue::Source(
                        PolicyValueSource::UserId,
                    )),
                }),
                PolicyFilterExpression::Exists(PolicyExistsFilter {
                    resource: "membership".into(),
                    condition: PolicyExistsCondition::All(vec![
                        PolicyExistsCondition::Match(PolicyFilter {
                            field: "member_id".into(),
                            operator: PolicyFilterOperator::Equals(PolicyComparisonValue::Source(
                                PolicyValueSource::UserId,
                            )),
                        }),
                        PolicyExistsCondition::CurrentRowField {
                            field: "organization_id".into(),
                            row_field: "org_id".into(),
                        },
                    ]),
                }),
            ])),
            ..RowPolicies::default()
        };

        assert_eq!(
            policies
                .controlled_filter_fields()
                .into_iter()
                .collect::<Vec<_>>(),
            ["org_id", "owner_id"]
        );
        assert_eq!(
            policies.exists_index_targets(),
            [
                ("membership".into(), "member_id".into()),
                ("membership".into(), "organization_id".into()),
            ]
        );
        assert_eq!(
            policies
                .iter_filters()
                .into_iter()
                .map(|(_, filter)| filter.field.as_str())
                .collect::<Vec<_>>(),
            ["owner_id", "member_id"]
        );
    }
}
