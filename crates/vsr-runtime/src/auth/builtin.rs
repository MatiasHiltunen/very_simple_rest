//! Built-in token policy, independent of HTTP frameworks, key loading and SQL.

use super::{
    AuthenticatedIdentity,
    request::{AuthFailure, RequestAuthenticator},
};
use crate::http::HeaderFields;
use cookie::Cookie;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, future::Future};

/// Existing built-in JWT wire format. A backend MUST verify its signature,
/// algorithm, expiry, issuer and audience before returning this value.
#[derive(Clone, Serialize, Deserialize)]
pub struct AccessClaims {
    /// Opaque account revision fingerprint; never put password material in a JWT.
    #[serde(
        default,
        rename = "_vsr_auth_state",
        skip_serializing_if = "Option::is_none"
    )]
    pub auth_state: Option<String>,
    /// Numeric account identifier used by existing generated resources.
    pub sub: i64,
    /// Roles validated against live state for built-in accounts.
    pub roles: Vec<String>,
    /// Configured issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Configured audience.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// Expiry, checked by the signature verifier.
    pub exp: usize,
    /// Application claims preserved for row policy evaluation.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Fields that invalidate existing built-in tokens when changed.
/// Intentionally not Debug: this contains a salted password hash.
pub struct AccountState<'a> {
    /// Account ID.
    pub id: i64,
    /// Current email.
    pub email: &'a str,
    /// Current salted password hash.
    pub password_hash: &'a str,
    /// Current role.
    pub role: &'a str,
    /// Current mapped application claims.
    pub claims: &'a BTreeMap<String, Value>,
    /// Email verification revision.
    pub email_verified_at: Option<&'a str>,
    /// Account creation revision.
    pub created_at: Option<&'a str>,
    /// Management revision, including changes later reverted.
    pub updated_at: Option<&'a str>,
}

impl AccountState<'_> {
    /// Byte-compatible with tokens issued before this extraction.
    pub fn fingerprint(&self) -> String {
        let state = serde_json::json!([
            self.id,
            self.email,
            self.password_hash,
            self.role,
            self.claims,
            self.email_verified_at,
            self.created_at,
            self.updated_at
        ]);
        hex::encode(Sha256::digest(state.to_string().as_bytes()))
    }
}

/// Infrastructure adapter: retain configured key rotation and existing DB drivers
/// without bringing parser, SQL or framework types into the policy layer.
pub trait AccessBackend: Send + Sync + 'static {
    /// Cryptographically verify before returning claims. Do not return decoded-only JWTs.
    fn verify(&self, token: &str) -> Result<AccessClaims, AuthFailure>;

    /// Load the current fingerprint on every request. None means deleted/not found.
    fn account_state(
        &self,
        user_id: i64,
    ) -> impl Future<Output = Result<Option<String>, AuthFailure>> + Send;
}

/// Whether a verified token must also match a live built-in account.
#[derive(Clone, Copy)]
pub enum AccountStatePolicy {
    /// Built-in accounts: missing state or account is always rejected.
    Required,
    /// Explicit external-token compatibility; check state whenever present.
    IfPresent,
}

/// Cookie names are trusted server configuration, not request-controlled values.
#[derive(Clone)]
pub struct CookiePolicy {
    /// Session access-token cookie.
    pub session_name: String,
    /// Double-submit CSRF cookie.
    pub csrf_cookie_name: String,
    /// Double-submit CSRF request header.
    pub csrf_header_name: String,
}

/// Shared request policy. Key and database operations remain injected adapters.
pub struct BuiltinRequestAuth<B> {
    backend: B,
    state_policy: AccountStatePolicy,
    cookies: Option<CookiePolicy>,
}

impl<B: AccessBackend> BuiltinRequestAuth<B> {
    /// Built-in authentication always requires live account state by default.
    pub fn new(backend: B, cookies: Option<CookiePolicy>) -> Self {
        Self {
            backend,
            state_policy: AccountStatePolicy::Required,
            cookies,
        }
    }

    /// Explicit compatibility mode for externally issued JWTs. This must not be
    /// chosen for built-in account routes.
    #[must_use]
    pub fn with_state_policy(mut self, policy: AccountStatePolicy) -> Self {
        self.state_policy = policy;
        self
    }
}

impl<B: AccessBackend> RequestAuthenticator for BuiltinRequestAuth<B> {
    async fn authenticate(
        &self,
        method: &str,
        headers: &HeaderFields,
    ) -> Result<AuthenticatedIdentity, AuthFailure> {
        let token = request_token(method, headers, self.cookies.as_ref())?;
        let claims = self.backend.verify(&token)?;
        if claims.sub <= 0 {
            return Err(AuthFailure::InvalidToken);
        }
        if matches!(self.state_policy, AccountStatePolicy::Required) || claims.auth_state.is_some()
        {
            let expected = claims
                .auth_state
                .as_deref()
                .ok_or(AuthFailure::RevokedToken)?;
            let current = self
                .backend
                .account_state(claims.sub)
                .await?
                .ok_or(AuthFailure::RevokedToken)?;
            if expected != current {
                return Err(AuthFailure::RevokedToken);
            }
        }
        Ok(AuthenticatedIdentity {
            user_id: claims.sub.to_string(),
            email: None,
            is_admin: claims.roles.iter().any(|role| role == "admin"),
            roles: claims.roles,
            claims: claims.extra.into_iter().collect(),
            expires_at: Some(i64::try_from(claims.exp).map_err(|_| AuthFailure::InvalidToken)?),
        })
    }
}

/// Credential precedence is explicit: a present Authorization header must be a
/// single valid Bearer value. It never falls back to a cookie after an error.
pub fn request_token(
    method: &str,
    headers: &HeaderFields,
    cookies: Option<&CookiePolicy>,
) -> Result<String, AuthFailure> {
    let mut values = headers.get_all("authorization");
    if let Some(value) = values.next() {
        if values.next().is_some() {
            return Err(AuthFailure::InvalidToken);
        }
        let value = std::str::from_utf8(value).map_err(|_| AuthFailure::InvalidToken)?;
        let (scheme, token) = value.split_once(' ').ok_or(AuthFailure::InvalidToken)?;
        let token = token.trim_start_matches(' ');
        if !scheme.eq_ignore_ascii_case("Bearer")
            || token.is_empty()
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(&b))
        {
            return Err(AuthFailure::InvalidToken);
        }
        return Ok(token.to_owned());
    }
    let Some(policy) = cookies else {
        return Err(AuthFailure::MissingToken);
    };
    let token = unique_cookie(headers, &policy.session_name)
        .map_err(|()| AuthFailure::InvalidToken)?
        .filter(|token| !token.is_empty())
        .ok_or(AuthFailure::MissingToken)?;
    if request_needs_csrf(method) {
        validate_cookie_csrf(headers, policy)?;
    }
    Ok(token)
}

/// Preserve the existing safe-method set; extension methods require CSRF.
pub fn request_needs_csrf(method: &str) -> bool {
    !matches!(method, "GET" | "HEAD" | "OPTIONS" | "TRACE")
}

/// Reject duplicate CSRF cookies/headers, even if their values happen to agree.
pub fn validate_cookie_csrf(
    headers: &HeaderFields,
    policy: &CookiePolicy,
) -> Result<(), AuthFailure> {
    let cookie = unique_cookie(headers, &policy.csrf_cookie_name)
        .map_err(|()| AuthFailure::InvalidCsrf)?
        .ok_or(AuthFailure::InvalidCsrf)?;
    let mut values = headers.get_all(&policy.csrf_header_name);
    let header = values.next().ok_or(AuthFailure::InvalidCsrf)?;
    if values.next().is_some() || cookie.trim().is_empty() || header != cookie.as_bytes() {
        return Err(AuthFailure::InvalidCsrf);
    }
    Ok(())
}

fn unique_cookie(headers: &HeaderFields, name: &str) -> Result<Option<String>, ()> {
    let mut found = None;
    for value in headers.get_all("cookie") {
        let text = std::str::from_utf8(value).map_err(|_| ())?;
        // Use the same parser/decoding as Actix, but reject ambiguous names.
        for part in text
            .split(';')
            .map(str::trim)
            .filter(|part| !part.is_empty())
        {
            let cookie = Cookie::parse_encoded(part).map_err(|_| ())?;
            if cookie.name() == name {
                if found.is_some() {
                    return Err(());
                }
                found = Some(cookie.value().to_owned());
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    fn cookies() -> CookiePolicy {
        CookiePolicy {
            session_name: "session".into(),
            csrf_cookie_name: "csrf".into(),
            csrf_header_name: "x-csrf-token".into(),
        }
    }

    fn fields(values: &[(&str, &str)]) -> HeaderFields {
        let mut fields = HeaderFields::default();
        for (name, value) in values {
            fields.append(name, value).unwrap();
        }
        fields
    }

    #[test]
    fn bearer_precedence_is_unambiguous() {
        for bearer in ["Bearer abc.def", "bearer abc.def", "BEARER   abc.def"] {
            let headers = fields(&[("authorization", bearer), ("cookie", "session=ignored")]);
            assert_eq!(
                request_token("POST", &headers, Some(&cookies())).unwrap(),
                "abc.def"
            );
        }
        for bearer in [
            "",
            "Basic abc",
            "Bearer",
            "Bearer ",
            "Bearer a b",
            "Bearer a,b",
            "Bearer\tabc",
        ] {
            let headers = fields(&[
                ("authorization", bearer),
                ("cookie", "session=valid; csrf=x"),
                ("x-csrf-token", "x"),
            ]);
            assert_eq!(
                request_token("POST", &headers, Some(&cookies())).unwrap_err(),
                AuthFailure::InvalidToken
            );
        }
        let headers = fields(&[
            ("authorization", "Bearer abc"),
            ("Authorization", "Bearer abc"),
        ]);
        assert_eq!(
            request_token("GET", &headers, None).unwrap_err(),
            AuthFailure::InvalidToken
        );
        let mut headers = HeaderFields::default();
        headers.append("authorization", [0x80]).unwrap();
        assert_eq!(
            request_token("GET", &headers, None).unwrap_err(),
            AuthFailure::InvalidToken
        );
        assert_eq!(
            request_token("GET", &HeaderFields::default(), None).unwrap_err(),
            AuthFailure::MissingToken
        );
    }

    #[test]
    fn cookies_decode_once_and_reject_duplicates() {
        let headers = fields(&[
            ("cookie", "session=a%2Eb%252E; csrf=a%2Bb"),
            ("x-csrf-token", "a+b"),
        ]);
        assert_eq!(
            request_token("POST", &headers, Some(&cookies())).unwrap(),
            "a.b%2E"
        );
        for values in [
            vec![("cookie", "session=one; session=two")],
            vec![("cookie", "session=one"), ("cookie", "session=one")],
            vec![("cookie", "session=one; %73ession=two")],
            vec![("cookie", "session=one; malformed")],
        ] {
            assert_eq!(
                request_token("GET", &fields(&values), Some(&cookies())).unwrap_err(),
                AuthFailure::InvalidToken
            );
        }
    }

    #[test]
    fn cookie_mutations_require_exactly_one_csrf_pair() {
        let headers = fields(&[("cookie", "session=abc")]);
        for method in ["GET", "HEAD", "OPTIONS", "TRACE"] {
            assert_eq!(
                request_token(method, &headers, Some(&cookies())).unwrap(),
                "abc"
            );
        }
        for method in ["POST", "PUT", "PATCH", "DELETE", "CUSTOM", "get"] {
            assert_eq!(
                request_token(method, &headers, Some(&cookies())).unwrap_err(),
                AuthFailure::InvalidCsrf
            );
        }
        for values in [
            vec![("cookie", "session=abc; csrf=x")],
            vec![("cookie", "session=abc; csrf=x"), ("x-csrf-token", "y")],
            vec![
                ("cookie", "session=abc; csrf=x; csrf=x"),
                ("x-csrf-token", "x"),
            ],
            vec![
                ("cookie", "session=abc; csrf=x"),
                ("x-csrf-token", "x"),
                ("X-CSRF-Token", "x"),
            ],
            vec![("cookie", "session=abc; csrf="), ("x-csrf-token", "")],
        ] {
            assert_eq!(
                request_token("POST", &fields(&values), Some(&cookies())).unwrap_err(),
                AuthFailure::InvalidCsrf
            );
        }
        let headers = fields(&[
            ("cookie", "session=abc"),
            ("cookie", "csrf=x"),
            ("x-csrf-token", "x"),
        ]);
        assert_eq!(
            request_token("POST", &headers, Some(&cookies())).unwrap(),
            "abc"
        );
    }

    struct Backend {
        claims: AccessClaims,
        state: Arc<Mutex<Result<Option<String>, AuthFailure>>>,
        reads: Arc<AtomicUsize>,
    }
    impl AccessBackend for Backend {
        fn verify(&self, token: &str) -> Result<AccessClaims, AuthFailure> {
            if token == "verified" {
                Ok(self.claims.clone())
            } else {
                Err(AuthFailure::InvalidToken)
            }
        }
        async fn account_state(&self, _: i64) -> Result<Option<String>, AuthFailure> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.state.lock().unwrap().clone()
        }
    }

    fn claims() -> AccessClaims {
        AccessClaims {
            sub: 7,
            roles: vec!["editor".into()],
            iss: None,
            aud: None,
            exp: 2_000_000_000,
            auth_state: Some("initial".into()),
            extra: BTreeMap::from([("tenant_id".into(), Value::from(42))]),
        }
    }

    #[tokio::test]
    async fn live_state_is_checked_every_time_and_fails_closed() {
        let state = Arc::new(Mutex::new(Ok(Some("initial".into()))));
        let reads = Arc::new(AtomicUsize::new(0));
        let auth = BuiltinRequestAuth::new(
            Backend {
                claims: claims(),
                state: state.clone(),
                reads: reads.clone(),
            },
            None,
        );
        let headers = fields(&[("authorization", "Bearer verified")]);
        for _ in 0..2 {
            let user = auth.authenticate("GET", &headers).await.unwrap();
            assert_eq!(user.user_id, "7");
            assert_eq!(user.claims["tenant_id"], 42);
            assert!(!user.is_admin);
            assert_eq!(user.expires_at, Some(2_000_000_000));
        }
        assert_eq!(reads.load(Ordering::SeqCst), 2);
        for (value, expected) in [
            (Ok(Some("changed".into())), AuthFailure::RevokedToken),
            (Ok(None), AuthFailure::RevokedToken),
            (
                Err(AuthFailure::AccountValidation),
                AuthFailure::AccountValidation,
            ),
        ] {
            *state.lock().unwrap() = value;
            assert_eq!(
                auth.authenticate("GET", &headers).await.unwrap_err(),
                expected
            );
        }
        let before = reads.load(Ordering::SeqCst);
        assert_eq!(
            auth.authenticate("GET", &fields(&[("authorization", "Bearer invalid")]))
                .await
                .unwrap_err(),
            AuthFailure::InvalidToken
        );
        assert_eq!(reads.load(Ordering::SeqCst), before);
    }

    #[tokio::test]
    async fn external_compatibility_is_explicit_and_never_skips_present_state() {
        let backend = |claims| Backend {
            claims,
            state: Arc::new(Mutex::new(Ok(None))),
            reads: Arc::new(AtomicUsize::new(0)),
        };
        let headers = fields(&[("authorization", "Bearer verified")]);
        let mut no_state = claims();
        no_state.auth_state = None;
        let auth = BuiltinRequestAuth::new(backend(no_state.clone()), None);
        assert_eq!(
            auth.authenticate("GET", &headers).await.unwrap_err(),
            AuthFailure::RevokedToken
        );
        let auth = BuiltinRequestAuth::new(backend(no_state), None)
            .with_state_policy(AccountStatePolicy::IfPresent);
        assert!(auth.authenticate("GET", &headers).await.is_ok());
        let auth = BuiltinRequestAuth::new(backend(claims()), None)
            .with_state_policy(AccountStatePolicy::IfPresent);
        assert_eq!(
            auth.authenticate("GET", &headers).await.unwrap_err(),
            AuthFailure::RevokedToken
        );
        for id in [0, -1] {
            let mut claims = claims();
            claims.sub = id;
            let auth = BuiltinRequestAuth::new(backend(claims), None);
            assert_eq!(
                auth.authenticate("GET", &headers).await.unwrap_err(),
                AuthFailure::InvalidToken
            );
        }
    }

    #[test]
    fn fingerprint_keeps_the_existing_wire_contract() {
        let claims = BTreeMap::from([("tenant_id".into(), Value::from(42))]);
        let state = AccountState {
            id: 7,
            email: "user@example.test",
            password_hash: "salted-hash",
            role: "editor",
            claims: &claims,
            email_verified_at: None,
            created_at: Some("created"),
            updated_at: Some("revision"),
        };
        let old_bytes = br#"[7,"user@example.test","salted-hash","editor",{"tenant_id":42},null,"created","revision"]"#;
        assert_eq!(state.fingerprint(), hex::encode(Sha256::digest(old_bytes)));
        let mut changed = state;
        changed.updated_at = Some("new-revision");
        assert_ne!(
            changed.fingerprint(),
            hex::encode(Sha256::digest(old_bytes))
        );
    }
}
