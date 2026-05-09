//! Field validation, transform, list, build, and client config types.
//!
//! These are the leaf data shapes referenced from `FieldSpec`, `ResourceSpec`,
//! and `ServiceSpec`. They have no dependencies on other compiler-model
//! modules and so can be safely imported anywhere in the model layer.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LengthMode {
    Simple,
    Bytes,
    Chars,
    Graphemes,
    Utf16,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct LengthValidation {
    pub min: Option<usize>,
    pub max: Option<usize>,
    pub equal: Option<usize>,
    pub mode: Option<LengthMode>,
}

impl LengthValidation {
    pub fn is_empty(&self) -> bool {
        self.min.is_none() && self.max.is_none() && self.equal.is_none() && self.mode.is_none()
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct RangeValidation {
    pub min: Option<NumericBound>,
    pub max: Option<NumericBound>,
    pub equal: Option<NumericBound>,
}

impl RangeValidation {
    pub fn is_empty(&self) -> bool {
        self.min.is_none() && self.max.is_none() && self.equal.is_none()
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct FieldValidation {
    pub ascii: bool,
    pub alphanumeric: bool,
    pub email: bool,
    pub url: bool,
    pub ip: bool,
    pub ipv4: bool,
    pub ipv6: bool,
    pub phone_number: bool,
    pub credit_card: bool,
    pub required: bool,
    pub dive: bool,
    pub contains: Option<String>,
    pub prefix: Option<String>,
    pub suffix: Option<String>,
    pub pattern: Option<String>,
    pub length: Option<LengthValidation>,
    pub range: Option<RangeValidation>,
    pub inner: Option<Box<FieldValidation>>,
}

impl FieldValidation {
    pub fn is_empty(&self) -> bool {
        !self.ascii
            && !self.alphanumeric
            && !self.email
            && !self.url
            && !self.ip
            && !self.ipv4
            && !self.ipv6
            && !self.phone_number
            && !self.credit_card
            && !self.required
            && !self.dive
            && self.contains.is_none()
            && self.prefix.is_none()
            && self.suffix.is_none()
            && self.pattern.is_none()
            && self
                .length
                .as_ref()
                .map(LengthValidation::is_empty)
                .unwrap_or(true)
            && self
                .range
                .as_ref()
                .map(RangeValidation::is_empty)
                .unwrap_or(true)
            && self.inner.is_none()
    }

    pub fn has_string_rules(&self) -> bool {
        self.ascii
            || self.alphanumeric
            || self.email
            || self.url
            || self.ip
            || self.ipv4
            || self.ipv6
            || self.phone_number
            || self.credit_card
            || self.contains.is_some()
            || self.prefix.is_some()
            || self.suffix.is_some()
            || self.pattern.is_some()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListConfig {
    pub default_limit: Option<u32>,
    pub max_limit: Option<u32>,
    pub filterable_in: Vec<String>,
    pub count_endpoint: bool,
    /// Maximum number of values allowed in any `filter_field__in` query parameter.
    /// Propagated from `security.requests.max_filter_in_values` at service load time.
    pub max_filter_in_values: Option<usize>,
}

impl Default for ListConfig {
    fn default() -> Self {
        Self {
            default_limit: None,
            max_limit: None,
            filterable_in: Vec::new(),
            count_endpoint: true,
            max_filter_in_values: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum NumericBound {
    Integer(i64),
    Float(f64),
}

impl NumericBound {
    pub fn as_f64(&self) -> f64 {
        match self {
            Self::Integer(value) => *value as f64,
            Self::Float(value) => *value,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteModelStyle {
    ExistingStructWithDtos,
    GeneratedStructWithDtos,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FieldTransform {
    Trim,
    Lowercase,
    CollapseWhitespace,
    Slugify,
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
