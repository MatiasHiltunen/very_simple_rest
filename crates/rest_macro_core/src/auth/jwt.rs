use std::sync::Arc;

use actix_web::{HttpRequest, Responder};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use dotenvy::dotenv;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, EllipticCurve, EllipticCurveKeyParameters,
    EllipticCurveKeyType, Jwk, JwkSet, KeyAlgorithm, OctetKeyPairParameters, OctetKeyPairType,
    PublicKeyUse,
};
use jsonwebtoken::{
    DecodingKey, EncodingKey, Header, Validation, decode_header,
};

use crate::secret::{SecretRef, load_secret};

use super::settings::{AuthJwtAlgorithm, AuthJwtVerificationKey, AuthSettings};
use super::helpers::auth_settings_from_request;

pub(crate) fn load_jwt_key_material(secret: &SecretRef, label: &str) -> Result<Arc<[u8]>, String> {
    let _ = dotenv();

    load_secret(secret, label)
        .map(|value| Arc::<[u8]>::from(value.into_bytes()))
        .map_err(|error| error.to_string())
}

pub(crate) fn load_jwt_secret(secret: &SecretRef) -> Result<Arc<[u8]>, String> {
    load_jwt_key_material(secret, "JWT secret")
}

pub(crate) fn configured_legacy_jwt_secret(settings: &AuthSettings) -> Result<Arc<[u8]>, String> {
    let secret_ref = super::settings::auth_jwt_signing_secret_ref(settings)
        .cloned()
        .unwrap_or_else(|| SecretRef::env_or_file("JWT_SECRET"));
    load_jwt_secret(&secret_ref)
}

pub(crate) fn load_jwt_encoding_key(
    algorithm: AuthJwtAlgorithm,
    secret: &SecretRef,
    label: &str,
) -> Result<Arc<EncodingKey>, String> {
    let material = load_jwt_key_material(secret, label)?;
    let key = match algorithm {
        AuthJwtAlgorithm::Hs256 | AuthJwtAlgorithm::Hs384 | AuthJwtAlgorithm::Hs512 => {
            Ok(EncodingKey::from_secret(material.as_ref()))
        }
        AuthJwtAlgorithm::Es256 | AuthJwtAlgorithm::Es384 => {
            EncodingKey::from_ec_pem(material.as_ref()).map_err(|error| {
                format!(
                    "{label} must be a valid EC private PEM for {}: {error}",
                    algorithm_name(algorithm)
                )
            })
        }
        AuthJwtAlgorithm::EdDsa => EncodingKey::from_ed_pem(material.as_ref()).map_err(|error| {
            format!("{label} must be a valid Ed25519 private PEM for EdDSA: {error}")
        }),
    }?;
    Ok(Arc::new(key))
}

pub(crate) fn load_jwt_decoding_key(
    algorithm: AuthJwtAlgorithm,
    secret: &SecretRef,
    label: &str,
) -> Result<Arc<DecodingKey>, String> {
    let material = load_jwt_key_material(secret, label)?;
    let key = match algorithm {
        AuthJwtAlgorithm::Hs256 | AuthJwtAlgorithm::Hs384 | AuthJwtAlgorithm::Hs512 => {
            Ok(DecodingKey::from_secret(material.as_ref()))
        }
        AuthJwtAlgorithm::Es256 | AuthJwtAlgorithm::Es384 => {
            DecodingKey::from_ec_pem(material.as_ref()).map_err(|error| {
                format!(
                    "{label} must be a valid EC public PEM for {}: {error}",
                    algorithm_name(algorithm)
                )
            })
        }
        AuthJwtAlgorithm::EdDsa => DecodingKey::from_ed_pem(material.as_ref()).map_err(|error| {
            format!("{label} must be a valid Ed25519 public PEM for EdDSA: {error}")
        }),
    }?;
    Ok(Arc::new(key))
}

pub(crate) fn configured_jwt_signer(
    settings: &AuthSettings,
) -> Result<(Header, Arc<EncodingKey>), String> {
    if let Some(jwt) = &settings.jwt {
        let mut header = Header::new(jwt.algorithm.jsonwebtoken());
        header.kid = jwt.active_kid.clone();
        let key = load_jwt_encoding_key(jwt.algorithm, &jwt.signing_key, "JWT signing key")?;
        Ok((header, key))
    } else {
        let secret = configured_legacy_jwt_secret(settings)?;
        Ok((
            Header::default(),
            Arc::new(EncodingKey::from_secret(secret.as_ref())),
        ))
    }
}

pub(crate) fn configured_jwt_decoding_key(
    token: &str,
    settings: &AuthSettings,
) -> Result<(Arc<DecodingKey>, Validation), String> {
    if let Some(jwt) = &settings.jwt {
        let header =
            decode_header(token).map_err(|error| format!("invalid JWT header: {error}"))?;
        if header.alg != jwt.algorithm.jsonwebtoken() {
            return Err(format!(
                "token header algorithm `{:?}` does not match configured `{}`",
                header.alg,
                algorithm_name(jwt.algorithm)
            ));
        }

        let decoding_key = if jwt.verification_keys.is_empty() {
            if let (Some(active_kid), Some(header_kid)) =
                (jwt.active_kid.as_deref(), header.kid.as_deref())
                && active_kid != header_kid
            {
                return Err(format!(
                    "token kid `{header_kid}` does not match configured active kid `{active_kid}`"
                ));
            }
            load_jwt_decoding_key(jwt.algorithm, &jwt.signing_key, "JWT signing key")?
        } else if let Some(header_kid) = header.kid.as_deref() {
            let key = jwt
                .verification_keys
                .iter()
                .find(|key| key.kid == header_kid)
                .ok_or_else(|| format!("unknown JWT key id `{header_kid}`"))?;
            load_jwt_decoding_key(jwt.algorithm, &key.key, "JWT verification key")?
        } else if jwt.verification_keys.len() == 1 {
            let key = &jwt.verification_keys[0];
            load_jwt_decoding_key(jwt.algorithm, &key.key, "JWT verification key")?
        } else {
            return Err("JWT token is missing a `kid` header".to_owned());
        };

        Ok((
            decoding_key,
            validation_for_settings(settings, jwt.algorithm),
        ))
    } else {
        let secret = configured_legacy_jwt_secret(settings)?;
        Ok((
            Arc::new(DecodingKey::from_secret(secret.as_ref())),
            validation_for_settings(settings, AuthJwtAlgorithm::Hs256),
        ))
    }
}

pub(crate) fn algorithm_name(algorithm: AuthJwtAlgorithm) -> &'static str {
    match algorithm {
        AuthJwtAlgorithm::Hs256 => "HS256",
        AuthJwtAlgorithm::Hs384 => "HS384",
        AuthJwtAlgorithm::Hs512 => "HS512",
        AuthJwtAlgorithm::Es256 => "ES256",
        AuthJwtAlgorithm::Es384 => "ES384",
        AuthJwtAlgorithm::EdDsa => "EdDSA",
    }
}

pub fn ensure_jwt_secret_configured() -> Result<(), String> {
    ensure_jwt_secret_configured_with_settings(&AuthSettings::default())
}

pub fn ensure_jwt_secret_configured_with_settings(settings: &AuthSettings) -> Result<(), String> {
    let _ = configured_jwt_signer(settings)?;
    if let Some(jwt) = &settings.jwt {
        for verification_key in &jwt.verification_keys {
            let _ = load_jwt_decoding_key(
                jwt.algorithm,
                &verification_key.key,
                "JWT verification key",
            )?;
        }
    }
    Ok(())
}

pub(crate) fn configured_public_jwks(settings: &AuthSettings) -> Result<Option<JwkSet>, String> {
    let Some(jwt) = &settings.jwt else {
        return Ok(None);
    };
    if jwt.algorithm.is_symmetric() || jwt.verification_keys.is_empty() {
        return Ok(None);
    }

    let mut keys = Vec::with_capacity(jwt.verification_keys.len());
    for verification_key in &jwt.verification_keys {
        keys.push(configured_public_jwk(jwt.algorithm, verification_key)?);
    }
    Ok(Some(JwkSet { keys }))
}

fn configured_public_jwk(
    algorithm: AuthJwtAlgorithm,
    verification_key: &AuthJwtVerificationKey,
) -> Result<Jwk, String> {
    let decoding_key =
        load_jwt_decoding_key(algorithm, &verification_key.key, "JWT verification key")?;
    let common = CommonParameters {
        public_key_use: Some(PublicKeyUse::Signature),
        key_algorithm: Some(jwk_key_algorithm(algorithm)),
        key_id: Some(verification_key.kid.clone()),
        ..Default::default()
    };

    let algorithm = match algorithm {
        AuthJwtAlgorithm::Es256 => {
            let (x, y) = extract_ec_public_coordinates(decoding_key.as_bytes(), 32, "ES256")?;
            AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve: EllipticCurve::P256,
                x,
                y,
            })
        }
        AuthJwtAlgorithm::Es384 => {
            let (x, y) = extract_ec_public_coordinates(decoding_key.as_bytes(), 48, "ES384")?;
            AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve: EllipticCurve::P384,
                x,
                y,
            })
        }
        AuthJwtAlgorithm::EdDsa => AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
            key_type: OctetKeyPairType::OctetKeyPair,
            curve: EllipticCurve::Ed25519,
            x: URL_SAFE_NO_PAD.encode(decoding_key.as_bytes()),
        }),
        AuthJwtAlgorithm::Hs256 | AuthJwtAlgorithm::Hs384 | AuthJwtAlgorithm::Hs512 => {
            return Err(format!(
                "public JWKS is not available for symmetric `{}` JWT configuration",
                algorithm_name(algorithm)
            ));
        }
    };

    Ok(Jwk { common, algorithm })
}

fn jwk_key_algorithm(algorithm: AuthJwtAlgorithm) -> KeyAlgorithm {
    match algorithm {
        AuthJwtAlgorithm::Hs256 => KeyAlgorithm::HS256,
        AuthJwtAlgorithm::Hs384 => KeyAlgorithm::HS384,
        AuthJwtAlgorithm::Hs512 => KeyAlgorithm::HS512,
        AuthJwtAlgorithm::Es256 => KeyAlgorithm::ES256,
        AuthJwtAlgorithm::Es384 => KeyAlgorithm::ES384,
        AuthJwtAlgorithm::EdDsa => KeyAlgorithm::EdDSA,
    }
}

fn extract_ec_public_coordinates(
    public_key: &[u8],
    coordinate_len: usize,
    label: &str,
) -> Result<(String, String), String> {
    let expected_len = 1 + coordinate_len * 2;
    if public_key.len() != expected_len || public_key.first().copied() != Some(0x04) {
        return Err(format!(
            "JWT verification key must be an uncompressed {label} public key"
        ));
    }
    let x = &public_key[1..1 + coordinate_len];
    let y = &public_key[1 + coordinate_len..];
    Ok((URL_SAFE_NO_PAD.encode(x), URL_SAFE_NO_PAD.encode(y)))
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct Claims {
    pub sub: i64,
    pub roles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    pub exp: usize,
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
}

pub(crate) fn validation_for_settings(
    settings: &AuthSettings,
    algorithm: AuthJwtAlgorithm,
) -> Validation {
    let mut validation = Validation::new(algorithm.jsonwebtoken());
    let mut required = vec!["exp"];

    if let Some(audience) = &settings.audience {
        validation.set_audience(&[audience.as_str()]);
        required.push("aud");
    } else {
        validation.validate_aud = false;
    }

    if let Some(issuer) = &settings.issuer {
        validation.set_issuer(&[issuer.as_str()]);
        required.push("iss");
    }

    validation.set_required_spec_claims(&required);
    validation
}

pub async fn jwks(req: HttpRequest) -> impl Responder {
    use crate::errors;
    let settings = auth_settings_from_request(&req);
    match configured_public_jwks(&settings) {
        Ok(Some(jwks)) => actix_web::HttpResponse::Ok().json(jwks),
        Ok(None) => errors::not_found("JWKS is not configured for this service"),
        Err(message) => errors::internal_error(message),
    }
}
