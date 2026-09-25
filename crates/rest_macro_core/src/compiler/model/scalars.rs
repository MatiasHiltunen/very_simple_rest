//! Foundational scalar / temporal / database-backend types used throughout
//! the compiler model.
//!
//! These types have no dependencies on other compiler-model modules and are
//! safe to import from anywhere else in the model layer.

pub use vsr_runtime::authz::{ResourceAccess, ResourceReadAccess, RoleRequirements};
pub use vsr_runtime::field::GeneratedValue;
pub use vsr_runtime::model::{DbBackend, GeneratedTemporalKind, StructuredScalarKind};

pub const GENERATED_DATETIME_ALIAS: &str = "__VsrDateTimeUtc";
pub const GENERATED_DATE_ALIAS: &str = "__VsrNaiveDate";
pub const GENERATED_TIME_ALIAS: &str = "__VsrNaiveTime";
pub const GENERATED_UUID_ALIAS: &str = "__VsrUuid";
pub const GENERATED_DECIMAL_ALIAS: &str = "__VsrDecimal";
pub const GENERATED_JSON_ALIAS: &str = "__VsrJson";
pub const GENERATED_JSON_OBJECT_ALIAS: &str = "__VsrJsonObject";
pub const GENERATED_JSON_ARRAY_ALIAS: &str = "__VsrJsonArray";
