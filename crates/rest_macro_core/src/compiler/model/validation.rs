//! Field validation, transform, list, build, and client config types.
//!
//! These are the leaf data shapes referenced from `FieldSpec`, `ResourceSpec`,
//! and `ServiceSpec`. They have no dependencies on other compiler-model
//! modules and so can be safely imported anywhere in the model layer.

pub use vsr_runtime::field::{
    FieldTransform, FieldValidation, LengthMode, LengthValidation, NumericBound, RangeValidation,
};
pub use vsr_runtime::resource::ListConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteModelStyle {
    ExistingStructWithDtos,
    GeneratedStructWithDtos,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildLtoMode {
    Thin,
    Fat,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReleaseBuildConfig {
    pub lto: Option<BuildLtoMode>,
    pub codegen_units: Option<u32>,
    pub strip_debug_symbols: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BuildArtifactPathConfig {
    pub path: Option<String>,
    pub env: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClientValueConfig {
    pub value: Option<String>,
    pub env: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TsClientAutomationConfig {
    pub on_build: bool,
    pub self_test: bool,
    pub self_test_report: BuildArtifactPathConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TsClientConfig {
    pub output_dir: BuildArtifactPathConfig,
    pub package_name: ClientValueConfig,
    pub server_url: Option<String>,
    pub emit_js: bool,
    pub include_builtin_auth: bool,
    pub exclude_tables: Vec<String>,
    pub automation: TsClientAutomationConfig,
}

impl Default for TsClientConfig {
    fn default() -> Self {
        Self {
            output_dir: BuildArtifactPathConfig::default(),
            package_name: ClientValueConfig::default(),
            server_url: None,
            emit_js: false,
            include_builtin_auth: true,
            exclude_tables: Vec::new(),
            automation: TsClientAutomationConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClientsConfig {
    pub ts: TsClientConfig,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BuildCacheCleanupStrategy {
    #[default]
    Reuse,
    CleanBeforeBuild,
    RemoveOnSuccess,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildCacheArtifactConfig {
    pub root: Option<String>,
    pub env: Option<String>,
    pub cleanup: BuildCacheCleanupStrategy,
}

impl Default for BuildCacheArtifactConfig {
    fn default() -> Self {
        Self {
            root: None,
            env: None,
            cleanup: BuildCacheCleanupStrategy::Reuse,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BuildArtifactsConfig {
    pub binary: BuildArtifactPathConfig,
    pub bundle: BuildArtifactPathConfig,
    pub cache: BuildCacheArtifactConfig,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BuildConfig {
    pub target_cpu_native: bool,
    pub release: ReleaseBuildConfig,
    pub artifacts: BuildArtifactsConfig,
}
