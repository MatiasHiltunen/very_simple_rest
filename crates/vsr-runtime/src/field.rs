//! Compiler-independent field validation and generated-value models used at runtime.

/// Unit used to measure text length limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LengthMode {
    /// Historical byte-counting mode.
    Simple,
    /// UTF-8 bytes.
    Bytes,
    /// Unicode scalar values.
    Chars,
    /// Extended grapheme clusters.
    Graphemes,
    /// UTF-16 code units.
    Utf16,
}

/// Optional minimum, maximum, or exact text length.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LengthValidation {
    /// Inclusive minimum length.
    pub min: Option<usize>,
    /// Inclusive maximum length.
    pub max: Option<usize>,
    /// Exact required length.
    pub equal: Option<usize>,
    /// Length unit; absent uses historical byte counting.
    pub mode: Option<LengthMode>,
}

impl LengthValidation {
    /// Whether no length constraint or mode was configured.
    pub fn is_empty(&self) -> bool {
        self.min.is_none() && self.max.is_none() && self.equal.is_none() && self.mode.is_none()
    }
}

/// Optional numeric range constraints.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RangeValidation {
    /// Inclusive minimum value.
    pub min: Option<NumericBound>,
    /// Inclusive maximum value.
    pub max: Option<NumericBound>,
    /// Exact required value.
    pub equal: Option<NumericBound>,
}

impl RangeValidation {
    /// Whether no numeric constraint was configured.
    pub fn is_empty(&self) -> bool {
        self.min.is_none() && self.max.is_none() && self.equal.is_none()
    }
}

/// Field rules lowered from the service schema and enforced at runtime.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FieldValidation {
    /// Require ASCII characters.
    pub ascii: bool,
    /// Require alphanumeric characters.
    pub alphanumeric: bool,
    /// Require an email address.
    pub email: bool,
    /// Require a URL.
    pub url: bool,
    /// Require an IP address.
    pub ip: bool,
    /// Require an IPv4 address.
    pub ipv4: bool,
    /// Require an IPv6 address.
    pub ipv6: bool,
    /// Require a phone number.
    pub phone_number: bool,
    /// Require a credit-card number.
    pub credit_card: bool,
    /// Require a present value.
    pub required: bool,
    /// Apply nested validation to collection items.
    pub dive: bool,
    /// Required substring.
    pub contains: Option<String>,
    /// Required prefix.
    pub prefix: Option<String>,
    /// Required suffix.
    pub suffix: Option<String>,
    /// Required regular-expression pattern.
    pub pattern: Option<String>,
    /// Text length constraints.
    pub length: Option<LengthValidation>,
    /// Numeric range constraints.
    pub range: Option<RangeValidation>,
    /// Rules applied to nested values.
    pub inner: Option<Box<FieldValidation>>,
}

impl FieldValidation {
    /// Whether no validation rule was configured.
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

    /// Whether any text-content rule was configured.
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

/// Integer or floating-point validation bound.
#[derive(Clone, Debug, PartialEq)]
pub enum NumericBound {
    /// Integer bound.
    Integer(i64),
    /// Floating-point bound.
    Float(f64),
}

impl NumericBound {
    /// Convert either bound to floating point for comparisons.
    pub fn as_f64(&self) -> f64 {
        match self {
            Self::Integer(value) => *value as f64,
            Self::Float(value) => *value,
        }
    }
}

/// Text normalization applied before persistence.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FieldTransform {
    /// Remove leading and trailing whitespace.
    Trim,
    /// Convert to lowercase.
    Lowercase,
    /// Replace repeated whitespace with a single space.
    CollapseWhitespace,
    /// Convert text into a URL-friendly slug.
    Slugify,
}

/// Database-generated field value policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize)]
pub enum GeneratedValue {
    /// The application supplies the value.
    #[default]
    None,
    /// Database-generated integer ID.
    AutoIncrement,
    /// Creation timestamp generated by the database.
    CreatedAt,
    /// Update timestamp generated by the database.
    UpdatedAt,
}

impl GeneratedValue {
    /// Whether inserts must omit the field value.
    pub fn skip_insert(self) -> bool {
        matches!(
            self,
            Self::AutoIncrement | Self::CreatedAt | Self::UpdatedAt
        )
    }

    /// Whether updates must omit the field value.
    pub fn skip_update_bind(self) -> bool {
        matches!(
            self,
            Self::AutoIncrement | Self::CreatedAt | Self::UpdatedAt
        )
    }
}
