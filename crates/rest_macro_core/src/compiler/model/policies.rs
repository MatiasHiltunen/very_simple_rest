//! Compatibility re-exports for runtime-owned row policy models.

pub use vsr_runtime::authz::policy::{
    PolicyAssignment, PolicyComparisonValue, PolicyExistsCondition, PolicyExistsFilter,
    PolicyFilter, PolicyFilterExpression, PolicyFilterOperator, PolicyLiteralValue,
    PolicyValueSource, RowPolicies, RowPolicyKind,
};

pub(super) fn read_filter_uses_principal_values(filter: Option<&PolicyFilterExpression>) -> bool {
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
