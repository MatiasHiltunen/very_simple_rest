//! Foundational scalar / temporal / database-backend types used throughout
//! the compiler model.
//!
//! These types have no dependencies on other compiler-model modules and are
//! safe to import from anywhere else in the model layer.

pub const GENERATED_DATETIME_ALIAS: &str = "__VsrDateTimeUtc";
pub const GENERATED_DATE_ALIAS: &str = "__VsrNaiveDate";
pub const GENERATED_TIME_ALIAS: &str = "__VsrNaiveTime";
pub const GENERATED_UUID_ALIAS: &str = "__VsrUuid";
pub const GENERATED_DECIMAL_ALIAS: &str = "__VsrDecimal";
pub const GENERATED_JSON_ALIAS: &str = "__VsrJson";
pub const GENERATED_JSON_OBJECT_ALIAS: &str = "__VsrJsonObject";
pub const GENERATED_JSON_ARRAY_ALIAS: &str = "__VsrJsonArray";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StructuredScalarKind {
    DateTime,
    Date,
    Time,
    Uuid,
    Decimal,
    Json,
    JsonObject,
    JsonArray,
}

impl StructuredScalarKind {
    pub fn sql_type(self, db: DbBackend) -> &'static str {
        match (self, db) {
            (_, DbBackend::Sqlite | DbBackend::Postgres) => "TEXT",
            (Self::DateTime, DbBackend::Mysql) => "VARCHAR(64)",
            (Self::Date, DbBackend::Mysql) => "VARCHAR(10)",
            (Self::Time, DbBackend::Mysql) => "VARCHAR(15)",
            (Self::Uuid, DbBackend::Mysql) => "CHAR(36)",
            (Self::Decimal, DbBackend::Mysql) => "VARCHAR(80)",
            (Self::Json | Self::JsonObject | Self::JsonArray, DbBackend::Mysql) => "TEXT",
        }
    }

    pub fn openapi_format(self) -> Option<&'static str> {
        match self {
            Self::DateTime => Some("date-time"),
            Self::Date => Some("date"),
            Self::Time => Some("time"),
            Self::Uuid => Some("uuid"),
            Self::Decimal => Some("decimal"),
            Self::Json | Self::JsonObject | Self::JsonArray => None,
        }
    }

    pub fn supports_range_filters(self) -> bool {
        matches!(self, Self::DateTime | Self::Date | Self::Time)
    }

    pub fn supports_sort(self) -> bool {
        !matches!(
            self,
            Self::Decimal | Self::Json | Self::JsonObject | Self::JsonArray
        )
    }

    pub fn supports_exact_filters(self) -> bool {
        !matches!(self, Self::Json | Self::JsonObject | Self::JsonArray)
    }

    pub fn generated_temporal_kind(self) -> Option<GeneratedTemporalKind> {
        match self {
            Self::DateTime => Some(GeneratedTemporalKind::DateTime),
            Self::Date => Some(GeneratedTemporalKind::Date),
            Self::Time => Some(GeneratedTemporalKind::Time),
            Self::Uuid | Self::Decimal | Self::Json | Self::JsonObject | Self::JsonArray => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedTemporalKind {
    DateTime,
    Date,
    Time,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize)]
pub enum DbBackend {
    #[default]
    Sqlite,
    Postgres,
    Mysql,
}

impl DbBackend {
    pub fn placeholder(self, index: usize) -> String {
        match self {
            Self::Postgres => format!("${index}"),
            Self::Sqlite | Self::Mysql => "?".to_owned(),
        }
    }

    pub fn primary_key_sql(self, field_name: &str) -> String {
        match self {
            Self::Sqlite => format!("{field_name} INTEGER PRIMARY KEY AUTOINCREMENT"),
            Self::Postgres => format!("{field_name} BIGSERIAL PRIMARY KEY"),
            Self::Mysql => format!("{field_name} BIGINT AUTO_INCREMENT PRIMARY KEY"),
        }
    }

    pub fn generated_temporal_expression(
        self,
        kind: Option<GeneratedTemporalKind>,
    ) -> &'static str {
        match kind {
            Some(GeneratedTemporalKind::DateTime) => match self {
                Self::Sqlite => "(STRFTIME('%Y-%m-%dT%H:%M:%f000+00:00', 'now'))",
                Self::Postgres => {
                    "(TO_CHAR(CURRENT_TIMESTAMP AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US') || '+00:00')"
                }
                Self::Mysql => "(DATE_FORMAT(UTC_TIMESTAMP(6), '%Y-%m-%dT%H:%i:%s.%f+00:00'))",
            },
            Some(GeneratedTemporalKind::Date) => match self {
                Self::Sqlite => "(DATE('now'))",
                Self::Postgres => "(TO_CHAR(CURRENT_DATE, 'YYYY-MM-DD'))",
                Self::Mysql => "(DATE_FORMAT(UTC_DATE(), '%Y-%m-%d'))",
            },
            Some(GeneratedTemporalKind::Time) => match self {
                Self::Sqlite => "(STRFTIME('%H:%M:%f000', 'now'))",
                Self::Postgres => {
                    "(TO_CHAR(CURRENT_TIMESTAMP AT TIME ZONE 'UTC', 'HH24:MI:SS.US'))"
                }
                Self::Mysql => "(DATE_FORMAT(UTC_TIMESTAMP(6), '%H:%i:%s.%f'))",
            },
            None => "CURRENT_TIMESTAMP",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Deserialize)]
pub enum GeneratedValue {
    #[default]
    None,
    AutoIncrement,
    CreatedAt,
    UpdatedAt,
}

impl GeneratedValue {
    pub fn skip_insert(self) -> bool {
        matches!(
            self,
            Self::AutoIncrement | Self::CreatedAt | Self::UpdatedAt
        )
    }

    pub fn skip_update_bind(self) -> bool {
        matches!(
            self,
            Self::AutoIncrement | Self::CreatedAt | Self::UpdatedAt
        )
    }
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct RoleRequirements {
    pub read: Option<String>,
    pub create: Option<String>,
    pub update: Option<String>,
    pub delete: Option<String>,
}

impl RoleRequirements {
    pub fn with_legacy_defaults(mut self) -> Self {
        if self.create.is_none() {
            self.create = self.update.clone();
        }
        self
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ResourceReadAccess {
    #[default]
    Inferred,
    Public,
    Authenticated,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceAccess {
    pub read: ResourceReadAccess,
}
