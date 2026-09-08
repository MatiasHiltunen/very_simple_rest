use std::collections::{HashMap, HashSet};

use vsr_core::error::{VsrError, VsrResult};

use super::{Handler, HttpMethod, RequestContext, ResponseEnvelope, RouteRegistry};

struct Route {
    path: String,
    handlers: HashMap<HttpMethod, Handler>,
}

/// Validated, framework-neutral route table backed by matchit's routing trie.
/// Both transports dispatch through this table to keep routing semantics identical.
#[derive(Default)]
pub struct RouteTable {
    router: matchit::Router<usize>,
    paths: HashMap<String, usize>,
    routes: Vec<Route>,
}

impl RouteTable {
    /// Validate and collect legacy vector registrations before binding a listener.
    pub fn from_routes(routes: Vec<(HttpMethod, String, Handler)>) -> VsrResult<Self> {
        let mut table = Self::default();
        for (method, path, handler) in routes {
            table.add_route(method, &path, handler)?;
        }
        Ok(table)
    }

    /// Route an already bounded request. HEAD falls back to GET; OPTIONS reports
    /// supported methods unless explicitly registered. No match returns 404.
    pub async fn dispatch(&self, mut context: RequestContext) -> ResponseEnvelope {
        let Ok(matched) = self.router.at(&context.path) else {
            return ResponseEnvelope::error(404, "Not found");
        };
        let route = &self.routes[*matched.value];
        let mut captures = HashMap::new();
        for (name, value) in matched.params.iter() {
            let Ok(value) = decode_capture(value) else {
                return ResponseEnvelope::error(400, "Invalid path encoding");
            };
            captures.insert(name.to_owned(), value);
        }
        context.path_params = captures;
        context.matched_route = Some(route.path.clone());
        let handler = route.handlers.get(&context.method).or_else(|| {
            (context.method == HttpMethod::Head)
                .then(|| route.handlers.get(&HttpMethod::Get))
                .flatten()
        });
        if let Some(handler) = handler {
            return handler(context).await;
        }
        let mut methods: Vec<_> = route.handlers.keys().map(ToString::to_string).collect();
        if route.handlers.contains_key(&HttpMethod::Get) {
            methods.push("HEAD".to_owned());
        }
        methods.push("OPTIONS".to_owned());
        methods.sort();
        methods.dedup();
        let mut response = if context.method == HttpMethod::Options {
            ResponseEnvelope::status(204)
        } else {
            ResponseEnvelope::error(405, "Method not allowed")
        };
        response
            .headers
            .append("allow", methods.join(", "))
            .expect("validated methods");
        response
    }
}

impl RouteRegistry for RouteTable {
    fn add_route(&mut self, method: HttpMethod, path: &str, handler: Handler) -> VsrResult<()> {
        validate_path(path)?;
        ::http::Method::from_bytes(method.to_string().as_bytes())
            .map_err(|_| invalid("invalid route method"))?;
        if let Some(index) = self.paths.get(path) {
            let handlers = &mut self.routes[*index].handlers;
            if handlers.contains_key(&method) {
                return Err(invalid("duplicate method/path registration"));
            }
            handlers.insert(method, handler);
            return Ok(());
        }
        let index = self.routes.len();
        self.router
            .insert(path, index)
            .map_err(|e| invalid(&format!("invalid or conflicting route: {e}")))?;
        self.paths.insert(path.to_owned(), index);
        self.routes.push(Route {
            path: path.to_owned(),
            handlers: HashMap::from([(method, handler)]),
        });
        Ok(())
    }
}

fn invalid(message: &str) -> VsrError {
    VsrError::Other(message.to_owned().into())
}

fn validate_path(path: &str) -> VsrResult<()> {
    if !path.starts_with('/') || path.contains(['?', '#', '%']) || path.contains("//") {
        return Err(invalid(
            "routes must be absolute paths without queries, fragments or escapes",
        ));
    }
    if matches!(path, "/healthz" | "/readyz") {
        return Err(invalid("health probe paths are reserved"));
    }
    let segments: Vec<_> = path.split('/').skip(1).collect();
    let mut captures = HashSet::new();
    for (index, segment) in segments.iter().enumerate() {
        if let Some(capture) = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
            let (name, tail) = capture
                .strip_prefix('*')
                .map_or((capture, false), |name| (name, true));
            if name.is_empty()
                || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
                || (tail && index + 1 != segments.len())
            {
                return Err(invalid(
                    "invalid route capture; use {name} or a terminal {*tail}",
                ));
            }
            if !captures.insert(name) {
                return Err(invalid("route capture names must be unique"));
            }
        } else if segment.contains(['{', '}', '*', ':']) || segment.chars().any(char::is_whitespace)
        {
            return Err(invalid(
                "regex and partial-segment captures are not supported",
            ));
        } else if !segment
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-._~!$&'()+,;=@".contains(&c))
        {
            return Err(invalid(
                "static route segments must contain unescaped ASCII URI path characters",
            ));
        }
    }
    Ok(())
}

pub(super) fn valid_percent_encoding(value: &str) -> bool {
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%'
            && !(bytes.next().is_some_and(|c| c.is_ascii_hexdigit())
                && bytes.next().is_some_and(|c| c.is_ascii_hexdigit()))
        {
            return false;
        }
    }
    true
}

fn decode_capture(value: &str) -> Result<String, ()> {
    if !valid_percent_encoding(value) {
        return Err(());
    }
    percent_encoding::percent_decode_str(value)
        .decode_utf8()
        .map(|s| s.into_owned())
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::make_handler;

    #[test]
    fn registration_rejects_conflicts_before_binding() {
        let handler = make_handler(|_| async { ResponseEnvelope::status(200) });
        let mut routes = RouteTable::default();
        routes
            .add_route(HttpMethod::Get, "/users/{id}", handler.clone())
            .unwrap();
        assert!(
            routes
                .add_route(HttpMethod::Post, "/users/{id}", handler.clone())
                .is_ok()
        );
        for path in [
            "/users/{id}",
            "/users/{other}",
            "/healthz",
            "/readyz",
            "/{x:.*}",
            "/foo-{id}",
            "/{*tail}/x",
            "/{id}/{id}",
            "/{id}/{*id}",
            "/invalid\0path",
            "/non-ascii-\u{e9}",
            "/invalid[segment]",
            "relative",
        ] {
            assert!(
                routes
                    .add_route(HttpMethod::Get, path, handler.clone())
                    .is_err(),
                "{path}"
            );
        }
    }

    #[test]
    fn captures_are_decoded_exactly_once() {
        assert_eq!(decode_capture("a%20b").unwrap(), "a b");
        assert_eq!(decode_capture("%252F").unwrap(), "%2F");
        assert_eq!(decode_capture("a+b").unwrap(), "a+b");
        assert!(decode_capture("%FF").is_err());
        assert!(decode_capture("%2").is_err());
    }
}
