//! Signature verification establishes identity, never database permissions.
use crate::{Error, config::Config, contract::Contract};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vsr_runtime::http::RequestContext;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub tenant_id: i64,
    pub ver: i64,
    pub jti: String,
    pub iss: String,
    pub aud: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
}

impl Claims {
    pub fn user_id(&self) -> Option<i64> {
        self.sub.parse().ok().filter(|id| *id > 0)
    }
}

pub struct Verifier {
    keys: HashMap<String, DecodingKey>,
    validation: Validation,
    max_ttl: i64,
}

impl Verifier {
    pub fn new(config: &Config, contract: &Contract) -> Result<Self, Error> {
        let mut keys = HashMap::new();
        for key in &config.verification_keys {
            keys.insert(
                key.kid.clone(),
                DecodingKey::from_ec_pem(&std::fs::read(&key.pem_file)?)?,
            );
        }
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[&contract.issuer]);
        validation.set_audience(&[&contract.audience]);
        validation.set_required_spec_claims(&["exp", "nbf", "iss", "aud", "sub"]);
        validation.leeway = 0;
        validation.validate_nbf = true;
        Ok(Self {
            keys,
            validation,
            max_ttl: contract.token_ttl,
        })
    }

    pub fn verify(&self, ctx: &RequestContext) -> Option<Claims> {
        let mut values = ctx.headers.get_all("authorization");
        let value = std::str::from_utf8(values.next()?).ok()?;
        if values.next().is_some() {
            return None;
        }
        let (scheme, token) = value.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("bearer")
            || token.is_empty()
            || token.len() > 8192
            || token.bytes().any(|b| b.is_ascii_whitespace())
        {
            return None;
        }
        let header = decode_header(token).ok()?;
        if header.alg != Algorithm::ES256 || header.typ.as_deref() != Some("at+jwt") {
            return None;
        }
        let key = self.keys.get(header.kid.as_ref()?)?;
        let claims: Claims = decode(token, key, &self.validation).ok()?.claims;
        let user = claims.user_id()?;
        let now = now();
        if claims.sub != user.to_string()
            || claims.tenant_id <= 0
            || claims.ver <= 0
            || claims.jti.is_empty()
            || claims.jti.len() > 128
            || claims.iat < 0
            || claims.iat > now
            || claims.nbf < claims.iat
            || claims.exp <= now
            || claims.exp <= claims.iat
            || claims.exp.saturating_sub(claims.iat) > self.max_ttl
        {
            return None;
        }
        Some(claims)
    }
}

pub fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
    .unwrap_or(i64::MAX)
}
