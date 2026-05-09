//! Compiler-model unit tests.
//!
//! Exercises validators and small helpers in isolation. Integration tests for
//! the full parse/codegen path live under the workspace's top-level `tests/`
//! directory; this module covers the model layer only.

use super::{
    GeneratedTemporalKind, GeneratedValue, generated_temporal_kind_for_field,
    validate_security_config,
};
use crate::auth::{AuthJwtAlgorithm, AuthJwtSettings, AuthJwtVerificationKey, AuthSettings};
use crate::secret::SecretRef;
use crate::security::SecurityConfig;
use proc_macro2::Span;
use syn::parse_str;

#[test]
fn rejects_combined_structured_and_legacy_jwt_config() {
    let security = SecurityConfig {
        auth: AuthSettings {
            jwt: Some(AuthJwtSettings {
                algorithm: AuthJwtAlgorithm::EdDsa,
                active_kid: Some("current".to_owned()),
                signing_key: SecretRef::env_or_file("JWT_SIGNING_KEY"),
                verification_keys: vec![AuthJwtVerificationKey {
                    kid: "current".to_owned(),
                    key: SecretRef::env_or_file("JWT_VERIFYING_KEY"),
                }],
            }),
            jwt_secret: Some(SecretRef::env_or_file("JWT_SECRET")),
            ..AuthSettings::default()
        },
        ..SecurityConfig::default()
    };

    let error =
        validate_security_config(&security, Span::call_site()).expect_err("config should fail");
    assert!(
        error
            .to_string()
            .contains("`security.auth.jwt` cannot be combined with `security.auth.jwt_secret`")
    );
}

#[test]
fn rejects_asymmetric_jwt_without_verification_keys() {
    let security = SecurityConfig {
        auth: AuthSettings {
            jwt: Some(AuthJwtSettings {
                algorithm: AuthJwtAlgorithm::EdDsa,
                active_kid: None,
                signing_key: SecretRef::env_or_file("JWT_SIGNING_KEY"),
                verification_keys: Vec::new(),
            }),
            jwt_secret: None,
            ..AuthSettings::default()
        },
        ..SecurityConfig::default()
    };

    let error =
        validate_security_config(&security, Span::call_site()).expect_err("config should fail");
    let message = error.to_string();
    assert!(message.contains("security.auth.jwt.verification_keys"));
    assert!(message.contains("asymmetric"));
}

#[test]
fn rejects_active_kid_not_present_in_verification_keys() {
    let security = SecurityConfig {
        auth: AuthSettings {
            jwt: Some(AuthJwtSettings {
                algorithm: AuthJwtAlgorithm::EdDsa,
                active_kid: Some("current".to_owned()),
                signing_key: SecretRef::env_or_file("JWT_SIGNING_KEY"),
                verification_keys: vec![AuthJwtVerificationKey {
                    kid: "previous".to_owned(),
                    key: SecretRef::env_or_file("JWT_VERIFYING_KEY_PREVIOUS"),
                }],
            }),
            jwt_secret: None,
            ..AuthSettings::default()
        },
        ..SecurityConfig::default()
    };

    let error =
        validate_security_config(&security, Span::call_site()).expect_err("config should fail");
    let message = error.to_string();
    assert!(message.contains("security.auth.jwt.active_kid"));
    assert!(message.contains("unknown verification key"));
    assert!(message.contains("current"));
}

#[test]
fn generated_string_timestamps_default_to_datetime_expressions() {
    let ty = parse_str("String").expect("type should parse");

    assert_eq!(
        generated_temporal_kind_for_field(&ty, GeneratedValue::CreatedAt),
        Some(GeneratedTemporalKind::DateTime)
    );
    assert_eq!(
        generated_temporal_kind_for_field(&ty, GeneratedValue::UpdatedAt),
        Some(GeneratedTemporalKind::DateTime)
    );
    assert_eq!(
        generated_temporal_kind_for_field(&ty, GeneratedValue::None),
        None
    );
}

#[test]
fn generated_temporal_kind_preserves_explicit_temporal_types() {
    let date_ty = parse_str("Date").expect("type should parse");
    let time_ty = parse_str("Time").expect("type should parse");

    assert_eq!(
        generated_temporal_kind_for_field(&date_ty, GeneratedValue::CreatedAt),
        Some(GeneratedTemporalKind::Date)
    );
    assert_eq!(
        generated_temporal_kind_for_field(&time_ty, GeneratedValue::UpdatedAt),
        Some(GeneratedTemporalKind::Time)
    );
}
