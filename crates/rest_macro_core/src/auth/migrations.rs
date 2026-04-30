use std::collections::HashSet;

use super::settings::{AuthClaimType, AuthSettings};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthDbBackend {
    Sqlite,
    Postgres,
    Mysql,
}

impl AuthDbBackend {
    pub fn from_database_url(database_url: &str) -> Option<Self> {
        if database_url.starts_with("postgres:") || database_url.starts_with("postgresql:") {
            Some(Self::Postgres)
        } else if database_url.starts_with("mysql:") || database_url.starts_with("mariadb:") {
            Some(Self::Mysql)
        } else if database_url.starts_with("sqlite:")
            || database_url.starts_with("turso:")
            || database_url.starts_with("turso-local:")
        {
            Some(Self::Sqlite)
        } else {
            None
        }
    }

    pub(crate) fn id_column_sql(self) -> &'static str {
        match self {
            Self::Sqlite => "id INTEGER PRIMARY KEY AUTOINCREMENT",
            Self::Postgres => "id BIGSERIAL PRIMARY KEY",
            Self::Mysql => "id BIGINT AUTO_INCREMENT PRIMARY KEY",
        }
    }

    pub(crate) fn email_column_sql(self) -> &'static str {
        match self {
            Self::Sqlite | Self::Postgres => "email TEXT NOT NULL UNIQUE",
            Self::Mysql => "email VARCHAR(255) NOT NULL UNIQUE",
        }
    }

    pub(crate) fn password_hash_column_sql(self) -> &'static str {
        match self {
            Self::Sqlite | Self::Postgres => "password_hash TEXT NOT NULL",
            Self::Mysql => "password_hash VARCHAR(255) NOT NULL",
        }
    }

    pub(crate) fn role_column_sql(self) -> &'static str {
        match self {
            Self::Sqlite | Self::Postgres => "role TEXT NOT NULL",
            Self::Mysql => "role VARCHAR(64) NOT NULL",
        }
    }

    pub(crate) fn auth_claim_column_sql(self, column_name: &str, ty: AuthClaimType) -> String {
        let quoted = self.quote_ident(column_name);
        let sql = match ty {
            AuthClaimType::I64 => match self {
                Self::Sqlite => "INTEGER".to_owned(),
                Self::Postgres | Self::Mysql => "BIGINT".to_owned(),
            },
            AuthClaimType::String => match self {
                Self::Sqlite | Self::Postgres => "TEXT".to_owned(),
                Self::Mysql => "VARCHAR(255)".to_owned(),
            },
            AuthClaimType::Bool => match self {
                Self::Sqlite | Self::Mysql => "INTEGER NOT NULL DEFAULT 0".to_owned(),
                Self::Postgres => "BOOLEAN NOT NULL DEFAULT FALSE".to_owned(),
            },
        };
        format!("{quoted} {sql}")
    }

    pub(crate) fn optional_datetime_column_sql(self, column_name: &str) -> String {
        match self {
            Self::Sqlite | Self::Postgres => format!("{column_name} TEXT"),
            Self::Mysql => format!("{column_name} VARCHAR(64)"),
        }
    }

    pub(crate) fn required_datetime_column_sql(self, column_name: &str) -> String {
        format!(
            "{} NOT NULL DEFAULT {}",
            self.optional_datetime_column_sql(column_name),
            self.current_timestamp_expression()
        )
    }

    pub(crate) fn token_hash_column_sql(self) -> &'static str {
        match self {
            Self::Sqlite | Self::Postgres => "token_hash TEXT NOT NULL",
            Self::Mysql => "token_hash VARCHAR(64) NOT NULL",
        }
    }

    pub(crate) fn token_purpose_column_sql(self) -> &'static str {
        match self {
            Self::Sqlite | Self::Postgres => "purpose TEXT NOT NULL",
            Self::Mysql => "purpose VARCHAR(64) NOT NULL",
        }
    }

    pub(crate) fn requested_email_column_sql(self) -> &'static str {
        match self {
            Self::Sqlite | Self::Postgres => "requested_email TEXT",
            Self::Mysql => "requested_email VARCHAR(255)",
        }
    }

    pub(crate) fn foreign_key_id_column_sql(self, column_name: &str) -> &'static str {
        let _ = column_name;
        match self {
            Self::Sqlite => "user_id INTEGER NOT NULL",
            Self::Postgres | Self::Mysql => "user_id BIGINT NOT NULL",
        }
    }

    pub(crate) fn current_timestamp_expression(self) -> &'static str {
        match self {
            Self::Sqlite => "(STRFTIME('%Y-%m-%dT%H:%M:%f000+00:00', 'now'))",
            Self::Postgres => {
                "(TO_CHAR(CURRENT_TIMESTAMP AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US') || '+00:00')"
            }
            Self::Mysql => "(DATE_FORMAT(UTC_TIMESTAMP(6), '%Y-%m-%dT%H:%i:%s.%f+00:00'))",
        }
    }

    pub(crate) fn quote_ident(self, ident: &str) -> String {
        match self {
            Self::Sqlite | Self::Postgres => format!("\"{}\"", ident.replace('"', "\"\"")),
            Self::Mysql => format!("`{}`", ident.replace('`', "``")),
        }
    }
}

pub fn auth_user_table_ident(backend: AuthDbBackend) -> String {
    backend.quote_ident("user")
}

pub fn auth_migration_sql(backend: AuthDbBackend) -> String {
    let quoted_user = auth_user_table_ident(backend);
    format!(
        "-- Generated by very_simple_rest for built-in auth.\n\n\
         CREATE TABLE {quoted_user} (\n\
             {},\n\
             {},\n\
             {},\n\
             {}\n\
         );\n\n\
         CREATE INDEX idx_user_role ON {quoted_user} (role);\n",
        backend.id_column_sql(),
        backend.email_column_sql(),
        backend.password_hash_column_sql(),
        backend.role_column_sql(),
        quoted_user = quoted_user,
    )
}

pub fn auth_management_migration_sql(backend: AuthDbBackend) -> String {
    let email_verified_at = backend.optional_datetime_column_sql("email_verified_at");
    let created_at = backend.optional_datetime_column_sql("created_at");
    let updated_at = backend.optional_datetime_column_sql("updated_at");
    let token_created_at = backend.required_datetime_column_sql("created_at");
    let token_expires_at = backend.optional_datetime_column_sql("expires_at");
    let token_used_at = backend.optional_datetime_column_sql("used_at");
    let now = backend.current_timestamp_expression();
    let quoted_user = auth_user_table_ident(backend);

    format!(
        "-- Generated by very_simple_rest for built-in auth management.\n\n\
         ALTER TABLE {quoted_user} ADD COLUMN {email_verified_at};\n\
         ALTER TABLE {quoted_user} ADD COLUMN {created_at};\n\
         ALTER TABLE {quoted_user} ADD COLUMN {updated_at};\n\
         UPDATE {quoted_user} SET created_at = {now} WHERE created_at IS NULL;\n\
         UPDATE {quoted_user} SET updated_at = COALESCE(updated_at, created_at, {now}) WHERE updated_at IS NULL;\n\n\
         CREATE TABLE auth_user_token (\n\
             {id_column},\n\
             {user_id_column},\n\
             {purpose_column},\n\
             {token_hash_column},\n\
             {requested_email_column},\n\
             {expires_at_column},\n\
             {used_at_column},\n\
             {created_at_column},\n\
             CONSTRAINT {fk_name} FOREIGN KEY ({quoted_user_id}) REFERENCES {quoted_user} ({quoted_user_pk}) ON DELETE CASCADE\n\
         );\n\n\
         CREATE UNIQUE INDEX idx_auth_user_token_hash ON auth_user_token (token_hash);\n\
         CREATE INDEX idx_auth_user_token_user_purpose ON auth_user_token (user_id, purpose);\n",
        id_column = backend.id_column_sql(),
        user_id_column = backend.foreign_key_id_column_sql("user_id"),
        purpose_column = backend.token_purpose_column_sql(),
        token_hash_column = backend.token_hash_column_sql(),
        requested_email_column = backend.requested_email_column_sql(),
        expires_at_column = token_expires_at,
        used_at_column = token_used_at,
        created_at_column = token_created_at,
        now = now,
        quoted_user = quoted_user,
        fk_name = backend.quote_ident("fk_auth_user_token_user"),
        quoted_user_id = backend.quote_ident("user_id"),
        quoted_user_pk = backend.quote_ident("id"),
    )
}

pub fn auth_claim_migration_sql(backend: AuthDbBackend, settings: &AuthSettings) -> String {
    let mut seen_columns = HashSet::new();
    let statements = settings
        .claims
        .values()
        .filter_map(|mapping| {
            if is_builtin_auth_user_column(&mapping.column)
                || !seen_columns.insert(mapping.column.clone())
            {
                return None;
            }

            Some(format!(
                "ALTER TABLE {} ADD COLUMN {};",
                auth_user_table_ident(backend),
                backend.auth_claim_column_sql(&mapping.column, mapping.ty)
            ))
        })
        .collect::<Vec<_>>();

    if statements.is_empty() {
        String::new()
    } else {
        format!(
            "-- Generated by very_simple_rest for built-in auth claim columns.\n\n{}\n",
            statements.join("\n")
        )
    }
}

pub(crate) fn is_builtin_auth_user_column(column_name: &str) -> bool {
    matches!(
        column_name,
        "id" | "email"
            | "password_hash"
            | "role"
            | "email_verified_at"
            | "created_at"
            | "updated_at"
    )
}
