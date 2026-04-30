//! Shared error types and diagnostic machinery for the VSR workspace.
//!
//! All VSR crates use [`VsrError`] as their cross-boundary error type.
//! Within a crate, strongly-typed errors are preferred; [`VsrError`] is the
//! transport layer that crosses crate boundaries.
//!
//! [`Diagnostic`] is the richer form used by the compiler pipeline: every
//! parse or semantic error carries a stable [`ErrorCode`], a source span,
//! and optionally a machine-readable suggested fix.

use std::fmt;

// ─── Error codes ─────────────────────────────────────────────────────────────

/// A stable error code string (e.g. `"EON-E0023"`).
///
/// Codes are:
/// - Guaranteed stable across patch releases.
/// - Documented at `docs/errors/<code>.html`.
/// - URL-resolvable so AI agents and CI pipelines can fetch the canonical
///   explanation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ErrorCode(pub &'static str);

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

// ─── Source spans ─────────────────────────────────────────────────────────────

/// A source location attached to a compiler or runtime diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    /// Path to the source file, relative to the workspace root.
    /// Path to the source file, relative to the workspace root.
    pub file: String,
    /// 1-based line number.
    pub line: u32,
    /// 1-based column (byte offset within the line).
    pub column: u32,
    /// The raw source text of the offending region (may be empty).
    pub snippet: String,
}

impl Span {
    /// Create a `Span` with an empty snippet.
    pub fn new(file: impl Into<String>, line: u32, column: u32) -> Self {
        Self {
            file: file.into(),
            line,
            column,
            snippet: String::new(),
        }
    }

    /// Attach a raw source snippet to the span for display in diagnostics.
    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.snippet = snippet.into();
        self
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.file, self.line, self.column)
    }
}

// ─── Diagnostics ─────────────────────────────────────────────────────────────

/// Severity level of a [`Diagnostic`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    /// Compilation or validation failed; the operation cannot proceed.
    Error,
    /// Something suspicious was found; the operation can still proceed.
    Warning,
    /// Supplementary context attached to an error or warning.
    Note,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Error => f.write_str("error"),
            Severity::Warning => f.write_str("warning"),
            Severity::Note => f.write_str("note"),
        }
    }
}

/// A structured diagnostic message from the parser or codegen pipeline.
///
/// Unlike a bare `VsrError`, every `Diagnostic` has:
/// - A stable [`ErrorCode`] (searchable, URL-resolvable).
/// - An optional source [`Span`] (file, line, column, snippet).
/// - An optional `suggested_fix` expressed as a human-readable string or, for
///   mechanical fixes, a structured replacement.
///
/// Diagnostics are emitted as JSON on `vsr check --json` so that AI agents
/// and CI pipelines can consume them without parsing human text.
#[derive(Debug, Clone)]
pub struct Diagnostic {
    /// Stable error code (e.g. `EON-E0023`).
    pub code: ErrorCode,
    /// How serious the issue is.
    pub severity: Severity,
    /// Human-readable description of the problem.
    pub message: String,
    /// The source location where the problem was detected, if known.
    pub span: Option<Span>,
    /// A human-readable hint for fixing the issue. Mechanical fixes (e.g.
    /// "rename `foo` to `bar`") should be expressed as structured data in
    /// future, but a plain string is enough to start.
    pub suggested_fix: Option<String>,
}

impl Diagnostic {
    /// Create an error-level diagnostic with the given stable code and message.
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            severity: Severity::Error,
            message: message.into(),
            span: None,
            suggested_fix: None,
        }
    }

    /// Create a warning-level diagnostic.
    pub fn warning(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            severity: Severity::Warning,
            message: message.into(),
            span: None,
            suggested_fix: None,
        }
    }

    /// Attach a source span to the diagnostic.
    pub fn with_span(mut self, span: Span) -> Self {
        self.span = Some(span);
        self
    }

    /// Attach a suggested fix message.
    pub fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.suggested_fix = Some(fix.into());
        self
    }

    /// Returns `true` if the severity is [`Severity::Error`].
    pub fn is_error(&self) -> bool {
        self.severity == Severity::Error
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}]: {}", self.severity, self.code, self.message)?;
        if let Some(span) = &self.span {
            write!(f, "\n  --> {span}")?;
            if !span.snippet.is_empty() {
                write!(f, "\n  | {}", span.snippet)?;
            }
        }
        if let Some(fix) = &self.suggested_fix {
            write!(f, "\n  help: {fix}")?;
        }
        Ok(())
    }
}

// ─── Top-level error type ─────────────────────────────────────────────────────

/// The top-level error type for all VSR crates.
///
/// Crate-internal code uses strongly-typed errors. This type is the common
/// transport when errors cross crate boundaries. It is `#[non_exhaustive]`
/// so we can add variants without breaking downstream `match` expressions.
#[derive(Debug)]
#[non_exhaustive]
pub enum VsrError {
    /// One or more `.eon` parse or semantic validation errors.
    Parse(Vec<Diagnostic>),

    /// A runtime configuration error.
    ///
    /// `key` names the configuration key that was missing or malformed
    /// (e.g. `"DATABASE_URL"`).
    Config {
        /// Human-readable description of the configuration problem.
        message: String,
        /// The configuration key that was missing or invalid, if applicable
        /// (e.g. `"DATABASE_URL"`).
        key: Option<String>,
    },

    /// A database error. The message is always sanitised — no passwords or
    /// user-supplied query parameters are included.
    Database(String),

    /// Secret retrieval failed.
    Secret {
        /// Logical name of the secret that could not be resolved.
        name: String,
        /// Why resolution failed (provider error, not found, etc.).
        reason: String,
    },

    /// An I/O error from the filesystem or network.
    Io(std::io::Error),

    /// Any other error that has not yet been given a dedicated variant.
    ///
    /// Library code should avoid this variant; use a dedicated variant and
    /// add it here when the pattern recurs.
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl fmt::Display for VsrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VsrError::Parse(diags) => {
                for d in diags {
                    writeln!(f, "{d}")?;
                }
                Ok(())
            }
            VsrError::Config { message, key: Some(k) } => {
                write!(f, "configuration error for '{k}': {message}")
            },
            VsrError::Config { message, key: None } => {
                write!(f, "configuration error: {message}")
            },
            VsrError::Database(msg) => write!(f, "database error: {msg}"),
            VsrError::Secret { name, reason } => {
                write!(f, "secret '{name}': {reason}")
            }
            VsrError::Io(e) => write!(f, "I/O error: {e}"),
            VsrError::Other(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for VsrError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VsrError::Io(e) => Some(e),
            VsrError::Other(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

impl From<std::io::Error> for VsrError {
    fn from(e: std::io::Error) -> Self {
        VsrError::Io(e)
    }
}

/// Convenience alias used throughout the workspace.
pub type VsrResult<T> = Result<T, VsrError>;
