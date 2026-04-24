//! Authorization trait seams.
//!
//! VSR's authorization model is hybrid: it combines compile-time RBAC
//! (roles and permissions declared in `.eon`) with runtime scoped assignments
//! (grants created at runtime via the authz API). Row-level policies add
//! per-row access filtering on top.
//!
//! # Key traits
//!
//! | Trait | Purpose |
//! |---|---|
//! | [`AuthzEngine`] | Evaluate an access request → `PolicyDecision` |
//!
//! # Extension points
//!
//! The default `BuiltinAuthzEngine` implements the full hybrid + RBAC + row
//! policy model in Rust. Future adapters:
//! - `OpaAuthzEngine` — delegates to an OPA (Open Policy Agent) sidecar.
//! - `CedarAuthzEngine` — uses AWS Cedar for policy evaluation.
//! These are placeholders behind `authz-opa` / `authz-cedar` features.

use std::{collections::HashMap, future::Future};
use vsr_core::error::VsrResult;

// Re-export the identity type shared with the auth module.
pub use crate::auth::AuthenticatedIdentity;

// ─── Authorization request ────────────────────────────────────────────────────

/// The action being checked against the authorization policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthzAction {
    /// Read one or more records.
    Read,
    /// Create a new record.
    Create,
    /// Update an existing record.
    Update,
    /// Delete a record.
    Delete,
    /// A named custom action declared in `.eon`.
    Custom(String),
}

impl std::fmt::Display for AuthzAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthzAction::Read => f.write_str("read"),
            AuthzAction::Create => f.write_str("create"),
            AuthzAction::Update => f.write_str("update"),
            AuthzAction::Delete => f.write_str("delete"),
            AuthzAction::Custom(s) => f.write_str(s),
        }
    }
}

/// Additional context provided to the authorization engine alongside the
/// identity and action.
///
/// Row-level policy evaluation may need field values from the row being
/// accessed. The engine accesses them here rather than re-fetching.
#[derive(Debug, Default)]
pub struct AuthzContext {
    /// Fields from the row being accessed, keyed by field name.
    pub row_fields: HashMap<String, serde_json::Value>,
    /// The name of the resource being accessed (e.g. `"Post"`, `"Invoice"`).
    pub resource_name: String,
    /// Scoped assignments for this user, pre-loaded to avoid double queries.
    /// If `None`, the engine is responsible for loading them.
    pub preloaded_assignments: Option<Vec<ScopedAssignment>>,
}

/// A runtime-created scoped assignment (grant).
///
/// Assignments are created via the `authz grants` CLI and stored in the
/// `_vsr_authz_assignments` table. They augment the compile-time RBAC model.
#[derive(Debug, Clone)]
pub struct ScopedAssignment {
    /// Unique assignment ID.
    pub id: String,
    /// The scope name (maps to a `.eon` `authorization.scopes` entry).
    pub scope: String,
    /// The value of the scope binding (e.g. a tenant ID).
    pub scope_value: String,
    /// The role granted within this scope.
    pub role: String,
    /// When the assignment expires (Unix timestamp). `None` = never.
    pub expires_at: Option<i64>,
}

// ─── Policy decision ──────────────────────────────────────────────────────────

/// The result of an authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The action is permitted.
    Allow,
    /// The action is denied.
    Deny {
        /// A structured reason code (stable, suitable for logging/audit).
        code: DenyCode,
        /// A human-readable explanation (not shown to end users; for logs).
        reason: String,
    },
}

impl PolicyDecision {
    /// Returns `true` if the decision is `Allow`.
    pub fn is_allowed(&self) -> bool {
        matches!(self, PolicyDecision::Allow)
    }

    /// Returns `true` if the decision is `Deny`.
    pub fn is_denied(&self) -> bool {
        !self.is_allowed()
    }
}

/// Structured deny reason codes. Stable across VSR versions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DenyCode {
    /// No matching RBAC rule was found.
    NoMatchingRule,
    /// The identity lacks the required role.
    InsufficientRole,
    /// A row-level policy condition was not satisfied.
    RowPolicyViolation,
    /// The required scoped assignment was not found or has expired.
    MissingScopedAssignment,
    /// The action is not defined for this resource.
    UnknownAction,
    /// The resource itself does not exist.
    ResourceNotFound,
}

// ─── AuthzEngine trait ────────────────────────────────────────────────────────

/// Evaluates authorization requests.
///
/// The engine is called once per request, after authentication. It receives
/// the authenticated identity, the resource name, the action being attempted,
/// and any additional context (row fields, preloaded assignments).
///
/// # Default implementation
///
/// `BuiltinAuthzEngine` (in `rest_macro_core`, moving to `vsr-runtime` in
/// Phase 3) implements the full VSR hybrid + RBAC + row-policy model.
///
/// # Extension
///
/// Swap the engine by providing a different impl behind `authz-opa` /
/// `authz-cedar` features without changing any handler code.
pub trait AuthzEngine: Send + Sync + 'static {
    /// Evaluate whether `identity` may perform `action` on `resource`.
    ///
    /// This is the hot path — called on every protected request. Keep
    /// implementations allocation-light in the fast path.
    fn evaluate(
        &self,
        identity: &AuthenticatedIdentity,
        action: AuthzAction,
        context: &AuthzContext,
    ) -> impl Future<Output = VsrResult<PolicyDecision>> + Send;

    /// Explain the decision for a simulated (offline) input.
    ///
    /// Like `evaluate` but populates a detailed trace for `vsr authz simulate`.
    /// The default implementation calls `evaluate` and returns a minimal trace.
    fn simulate(
        &self,
        identity: &AuthenticatedIdentity,
        action: AuthzAction,
        context: &AuthzContext,
    ) -> impl Future<Output = VsrResult<AuthzTrace>> + Send;
}

/// A step-by-step trace of an authorization evaluation.
///
/// Used by `vsr authz explain` and `vsr authz simulate` to show operators
/// exactly which rules fired, in which order, and why.
#[derive(Debug, Clone)]
pub struct AuthzTrace {
    /// The final decision.
    pub decision: PolicyDecision,
    /// Ordered list of steps the engine executed.
    pub steps: Vec<AuthzTraceStep>,
}

/// A single step in an [`AuthzTrace`].
#[derive(Debug, Clone)]
pub struct AuthzTraceStep {
    /// Human-readable description of this step.
    pub description: String,
    /// Whether this step contributed to allowing or denying.
    pub outcome: Option<PolicyDecision>,
}
