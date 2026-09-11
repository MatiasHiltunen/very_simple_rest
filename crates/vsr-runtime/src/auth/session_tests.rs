use super::*;
use crate::http::ResponseBody;

fn policy() -> SessionCookiePolicy {
    SessionCookiePolicy {
        request: CookiePolicy {
            session_name: "session".into(),
            csrf_cookie_name: "csrf".into(),
            csrf_header_name: "x-csrf-token".into(),
        },
        path: "/api".into(),
        secure: true,
        same_site: SessionSameSite::Strict,
    }
}

fn headers(values: &[(&str, &str)]) -> HeaderFields {
    let mut headers = HeaderFields::default();
    for (name, value) in values {
        headers.append(name, value).unwrap();
    }
    headers
}

fn cookies(response: &ResponseEnvelope) -> Vec<Cookie<'static>> {
    response
        .headers
        .get_all("set-cookie")
        .map(|value| Cookie::parse(std::str::from_utf8(value).unwrap().to_owned()).unwrap())
        .collect()
}

fn json_body(response: &ResponseEnvelope) -> serde_json::Value {
    match &response.body {
        ResponseBody::Bytes(bytes) => serde_json::from_slice(bytes).unwrap(),
        ResponseBody::Json(value) => value.clone(),
        _ => panic!("JSON response"),
    }
}

#[test]
fn cookie_attributes_and_deletion_scope_match_for_every_mode() {
    for same_site in [
        SessionSameSite::Strict,
        SessionSameSite::Lax,
        SessionSameSite::None,
    ] {
        for secure in [false, true] {
            if same_site == SessionSameSite::None && !secure {
                continue;
            }
            let config = SessionCookiePolicy {
                secure,
                same_site,
                ..policy()
            };
            let service = SessionPresentation::new(Some(config)).unwrap();
            let response = service
                .login_with("signed.token", 600, |bytes| {
                    bytes.fill(42);
                    Ok(())
                })
                .unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(
                response.headers.get("cache-control"),
                Some(b"no-store".as_slice())
            );
            let body = json_body(&response);
            let csrf = body["csrf_token"].as_str().unwrap();
            assert_eq!(csrf, "2a".repeat(32));
            assert_eq!(body["token"], "signed.token");
            let issued = cookies(&response);
            let expected_site = match same_site {
                SessionSameSite::Lax => SameSite::Lax,
                SessionSameSite::Strict => SameSite::Strict,
                SessionSameSite::None => SameSite::None,
            };
            assert_eq!(issued.len(), 2);
            for (cookie, http_only) in issued.iter().zip([true, false]) {
                assert_eq!(cookie.path(), Some("/api"));
                assert_eq!(cookie.secure().unwrap_or(false), secure);
                assert_eq!(cookie.http_only().unwrap_or(false), http_only);
                assert_eq!(cookie.same_site(), Some(expected_site));
                assert_eq!(cookie.max_age(), Some(Duration::seconds(600)));
                assert_eq!(cookie.domain(), None);
            }
            assert_eq!(issued[0].value(), "signed.token");
            assert_eq!(issued[1].value(), csrf);
            let request = headers(&[
                ("cookie", &format!("session=signed.token; csrf={csrf}")),
                ("x-csrf-token", csrf),
            ]);
            let response = service.logout(&request).unwrap();
            assert_eq!(response.status, 204);
            assert!(matches!(response.body, ResponseBody::Empty));
            assert_eq!(
                response.headers.get("cache-control"),
                Some(b"no-store".as_slice())
            );
            for (expired, issued) in cookies(&response).iter().zip(issued) {
                assert_eq!(expired.name(), issued.name());
                assert_eq!(expired.path(), issued.path());
                assert_eq!(expired.secure(), issued.secure());
                assert_eq!(expired.same_site(), issued.same_site());
                assert_eq!(expired.http_only(), issued.http_only());
                assert_eq!(expired.domain(), None);
                assert_eq!(expired.value(), "");
                assert_eq!(expired.max_age(), Some(Duration::ZERO));
            }
        }
    }
}

#[test]
fn configuration_rejects_ambiguous_names_attributes_and_insecure_prefixes() {
    let mut invalid = Vec::new();
    for name in [
        "",
        " ",
        "a b",
        "a=b",
        "a;b",
        "a,b",
        "\"name\"",
        "a\r\nx",
        "%73ession",
        "session%",
        "nonascii-\u{e9}",
    ] {
        let mut value = policy();
        value.request.session_name = name.into();
        invalid.push(value);
        let mut value = policy();
        value.request.csrf_cookie_name = name.into();
        invalid.push(value);
    }
    for header in [
        "",
        "invalid header",
        "cookie",
        "Set-Cookie",
        "AUTHORIZATION",
        "x-csrf\r\n",
    ] {
        let mut value = policy();
        value.request.csrf_header_name = header.into();
        invalid.push(value);
    }
    for path in [
        "",
        "relative",
        "/a; Domain=evil.test",
        "/a\r\n",
        "/a b",
        "/a?b",
        "/a#b",
        "/a\\b",
    ] {
        invalid.push(SessionCookiePolicy {
            path: path.into(),
            ..policy()
        });
    }
    let mut same_name = policy();
    same_name.request.csrf_cookie_name = same_name.request.session_name.clone();
    invalid.push(same_name);
    invalid.push(SessionCookiePolicy {
        same_site: SessionSameSite::None,
        secure: false,
        ..policy()
    });
    for name in ["__Host-session", "__Secure-session"] {
        for csrf in [false, true] {
            let mut value = policy();
            if csrf {
                value.request.csrf_cookie_name = name.into();
            } else {
                value.request.session_name = name.into();
            }
            value.secure = false;
            invalid.push(value);
        }
    }
    let mut host = policy();
    host.request.session_name = "__Host-session".into();
    invalid.push(host.clone()); // Scoped path is not allowed with this prefix.
    host.path = "/".into();
    assert!(SessionPresentation::new(Some(host)).is_ok());
    for config in invalid {
        assert!(matches!(
            SessionPresentation::new(Some(config)),
            Err(AccountError::Configuration)
        ));
    }
    let mut case_sensitive = policy();
    case_sensitive.request.csrf_cookie_name = "SESSION".into();
    case_sensitive.request.csrf_header_name = "X-CSRF-Token".into();
    assert!(SessionPresentation::new(Some(case_sensitive)).is_ok());
}

#[test]
fn token_entropy_ttl_and_size_failures_never_return_partial_cookies() {
    let service = SessionPresentation::new(Some(policy())).unwrap();
    assert!(matches!(
        service.login_with("token", 60, |_| Err(AccountError::TokenGeneration)),
        Err(AccountError::TokenGeneration)
    ));
    for token in [
        "",
        "unsafe;token",
        "unsafe\r\ntoken",
        "percent%2Etoken",
        "white space",
    ] {
        assert!(matches!(
            service.login_with(token, 60, |_| panic!("invalid input must precede entropy")),
            Err(AccountError::TokenGeneration)
        ));
    }
    for ttl in [0, -1, i64::MIN] {
        assert!(matches!(
            service.login_with("token", ttl, |_| panic!("invalid TTL must precede entropy")),
            Err(AccountError::Configuration)
        ));
    }
    assert!(matches!(
        service.login(&"a".repeat(4096), 60),
        Err(AccountError::Configuration)
    ));
    let mut too_large = policy();
    too_large.request.csrf_cookie_name = "x".repeat(4096);
    assert!(matches!(
        SessionPresentation::new(Some(too_large))
            .unwrap()
            .login("token", 60),
        Err(AccountError::Configuration)
    ));
    let first = service.login("token", 60).unwrap();
    let second = service.login("token", 60).unwrap();
    assert_ne!(cookies(&first)[1].value(), cookies(&second)[1].value());
}

#[test]
fn logout_requires_unique_csrf_for_any_session_even_with_bearer_credentials() {
    let service = SessionPresentation::new(Some(policy())).unwrap();
    for values in [
        vec![("cookie", "session=token")],
        vec![("cookie", "session=")],
        vec![
            ("cookie", "session=old; session=old; csrf=x"),
            ("x-csrf-token", "x"),
        ],
        vec![
            ("cookie", "session=old; %73ession=old; csrf=x"),
            ("x-csrf-token", "x"),
        ],
        vec![
            ("cookie", "session=old; csrf=x"),
            ("cookie", "session=old"),
            ("x-csrf-token", "x"),
        ],
        vec![
            ("cookie", "session=old; csrf=x; csrf=x"),
            ("x-csrf-token", "x"),
        ],
        vec![
            ("cookie", "session=old; csrf=x"),
            ("x-csrf-token", "x"),
            ("X-CSRF-Token", "x"),
        ],
        vec![("cookie", "session=old; csrf=x"), ("x-csrf-token", "wrong")],
        vec![("cookie", "session=old; malformed"), ("x-csrf-token", "x")],
        vec![("cookie", "malformed")],
        vec![("cookie", "session=old; csrf="), ("x-csrf-token", "")],
    ] {
        let mut request = headers(&values);
        request.append("authorization", "Bearer token").unwrap();
        let error = service.logout(&request).unwrap_err();
        assert_eq!(error, AccountError::Auth(AuthFailure::InvalidCsrf));
        assert_eq!(error.response().status, 403);
        assert_eq!(error.response().headers.get_all("set-cookie").count(), 0);
    }
    for session in ["", "expired.token", "invalid-token"] {
        let request = headers(&[
            ("cookie", &format!("session={session}; csrf=a%2Bb")),
            ("x-csrf-token", "a+b"),
        ]);
        assert_eq!(service.logout(&request).unwrap().status, 204);
    }
    assert_eq!(
        service
            .logout(&headers(&[("cookie", "unrelated=value")]))
            .unwrap()
            .status,
        204
    );
}

#[test]
fn bearer_only_responses_do_not_read_cookies_or_generate_csrf_secrets() {
    let service = SessionPresentation::new(None).unwrap();
    let response = service
        .login_with("signed.token", 1, |_| {
            panic!("bearer-only login needs no entropy")
        })
        .unwrap();
    assert_eq!(response.headers.get_all("set-cookie").count(), 0);
    let body = json_body(&response);
    assert_eq!(body, serde_json::json!({"token": "signed.token"}));
    let response = service
        .logout(&headers(&[("cookie", "malformed")]))
        .unwrap();
    assert_eq!(response.status, 204);
    assert_eq!(response.headers.get_all("set-cookie").count(), 0);
}
