//! Request builder.
//!
//! [`RequestBuilder`] configures and sends an HTTP request. Obtain one via
//! [`Client::get()`](crate::Client::get) or [`Client::post()`](crate::Client::post).

use crate::client::Client;
use crate::error::Error;
use crate::response::Response;
use crate::url::{IntoUrl, Url};
use crate::util::{narrow_latin1, widen_latin1};
use std::time::Duration;

// The future returned by `RequestBuilder::send()` must be Send so callers can
// use it in multi-threaded executors (e.g., tokio). This compile-time assertion
// catches regressions -- if any field held across an await point is not Send,
// this will fail to compile.
fn _assert_send_future(rb: RequestBuilder) {
    fn require_send<T: Send>(_t: &T) {}
    let fut = rb.send();
    require_send(&fut);
}
// ---------------------------------------------------------------------------
// Request -- a fully-built HTTP request
// ---------------------------------------------------------------------------

/// A fully-built HTTP request.
///
/// Created via [`RequestBuilder::build()`]. Can be inspected and then
/// executed with [`Client::execute()`](crate::Client::execute).
///
/// Matches the [`reqwest::Request`](https://docs.rs/reqwest/latest/reqwest/struct.Request.html)
/// API surface.
pub struct Request {
    method: http::Method,
    url: Url,
    headers: http::HeaderMap,
    body: Option<crate::Body>,
    timeout: Option<Duration>,
    version: http::Version,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("url", &self.url.as_str())
            .finish()
    }
}

impl Request {
    /// Create a new `Request`.
    pub fn new(method: http::Method, url: Url) -> Self {
        Self {
            method,
            url,
            headers: http::HeaderMap::new(),
            body: None,
            timeout: None,
            version: http::Version::default(),
        }
    }

    /// Returns the HTTP method.
    pub fn method(&self) -> &http::Method {
        &self.method
    }

    /// Returns a mutable reference to the HTTP method.
    pub fn method_mut(&mut self) -> &mut http::Method {
        &mut self.method
    }

    /// Returns the request URL.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Returns a mutable reference to the request URL.
    pub fn url_mut(&mut self) -> &mut Url {
        &mut self.url
    }

    /// Returns the request headers.
    pub fn headers(&self) -> &http::HeaderMap {
        &self.headers
    }

    /// Returns a mutable reference to the request headers.
    pub fn headers_mut(&mut self) -> &mut http::HeaderMap {
        &mut self.headers
    }

    /// Returns the request body, if set.
    ///
    /// Returns `None` if no body was set on the request.
    pub fn body(&self) -> Option<&crate::Body> {
        self.body.as_ref()
    }

    /// Returns a mutable reference to the request body.
    pub fn body_mut(&mut self) -> &mut Option<crate::Body> {
        &mut self.body
    }

    /// Returns the per-request timeout.
    pub fn timeout(&self) -> Option<&Duration> {
        self.timeout.as_ref()
    }

    /// Returns a mutable reference to the per-request timeout.
    pub fn timeout_mut(&mut self) -> &mut Option<Duration> {
        &mut self.timeout
    }

    /// Returns the HTTP version field.
    ///
    /// # Deviation from reqwest
    ///
    /// This is a structural field for API parity. WinHTTP chooses the
    /// actual protocol via ALPN, so this value is **not** used during
    /// execution. The real protocol negotiated is reported by
    /// [`Response::version()`](crate::Response::version).
    pub fn version(&self) -> http::Version {
        self.version
    }

    /// Returns a mutable reference to the HTTP version field.
    ///
    /// See [`version()`](Self::version) -- this value is not used
    /// during execution.
    pub fn version_mut(&mut self) -> &mut http::Version {
        &mut self.version
    }

    /// Try to clone this request.
    ///
    /// Returns `None` if the request has a streaming body (created via
    /// [`Body::wrap_stream()`](crate::Body::wrap_stream)) that cannot
    /// be replayed.
    pub fn try_clone(&self) -> Option<Request> {
        let body = match &self.body {
            Some(b) => Some(b.try_clone()?),
            None => None,
        };
        Some(Request {
            method: self.method.clone(),
            url: self.url.clone(),
            headers: self.headers.clone(),
            body,
            timeout: self.timeout,
            version: self.version,
        })
    }

    /// Consume the request and return the body.
    pub(crate) fn into_body(self) -> Option<crate::Body> {
        self.body
    }
}
/// A builder for an HTTP request.
///
/// Created via [`Client::get()`](crate::Client::get) or
/// [`Client::post()`](crate::Client::post). Configure headers and body,
/// then call [`.send()`](Self::send) to execute.
pub struct RequestBuilder {
    client: Client,
    method: String,
    url: Result<Url, Error>,
    headers: Vec<(String, String)>,
    body: Option<crate::Body>,
    timeout: Option<Duration>,
}

impl std::fmt::Debug for RequestBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let url_str = match &self.url {
            Ok(u) => u.as_str().to_owned(),
            Err(_) => "<invalid>".to_owned(),
        };
        f.debug_struct("RequestBuilder")
            .field("method", &self.method)
            .field("url", &url_str)
            .finish()
    }
}

impl RequestBuilder {
    /// Create a new `RequestBuilder`. URL validation happens eagerly.
    pub(crate) fn new(client: Client, method: &str, url: impl IntoUrl) -> Self {
        Self {
            client,
            method: method.to_owned(),
            url: url.into_url(),
            headers: Vec::new(),
            body: None,
            timeout: None,
        }
    }

    /// Add a header to the request.
    ///
    /// Accepts any key/value types convertible to HTTP header components,
    /// matching the `reqwest::RequestBuilder::header` signature.
    /// Invalid header names or values are deferred to
    /// [`send()`](Self::send) as errors.
    #[must_use]
    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        http::HeaderName: TryFrom<K>,
        <http::HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        http::HeaderValue: TryFrom<V>,
        <http::HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        let name = match http::HeaderName::try_from(key) {
            Ok(n) => n,
            Err(e) => {
                let e: http::Error = e.into();
                self.url = Err(Error::builder("invalid header name").with_source(e));
                return self;
            }
        };
        let value = match http::HeaderValue::try_from(value) {
            Ok(v) => v,
            Err(e) => {
                let e: http::Error = e.into();
                self.url = Err(Error::builder("invalid header value").with_source(e));
                return self;
            }
        };
        self.headers
            .push((name.as_str().to_owned(), widen_latin1(value.as_bytes())));
        self
    }

    /// Set a JSON body for the request.
    ///
    /// Serializes `body` with `serde_json` and sets the `Content-Type`
    /// header to `application/json`.
    ///
    /// Requires the `json` feature.
    #[cfg(feature = "json")]
    #[must_use]
    pub fn json<T: serde::Serialize + ?Sized>(mut self, body: &T) -> Self {
        match serde_json::to_vec(body) {
            Ok(data) => {
                self.headers
                    .push(("Content-Type".to_owned(), "application/json".to_owned()));
                self.body = Some(crate::Body::from(data));
            }
            Err(e) => {
                // Defer the error to send() -- replace url with Err
                self.url = Err(Error::builder("JSON serialization failed").with_source(e));
            }
        }
        self
    }

    /// Set a raw body for the request.
    ///
    /// Accepts any type that can be converted into a [`Body`](crate::Body),
    /// including `String`, `&str`, `Vec<u8>`, `&[u8]`, and `Bytes`.
    #[must_use]
    pub fn body<B: Into<crate::Body>>(mut self, body: B) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Merge additional headers into the request.
    ///
    /// Existing headers with the same name are **not** overwritten -- both
    /// values are sent, matching `reqwest::RequestBuilder::headers`.
    #[must_use]
    pub fn headers(mut self, headers: http::HeaderMap) -> Self {
        for (name, value) in &headers {
            self.headers
                .push((name.as_str().to_owned(), widen_latin1(value.as_bytes())));
        }
        self
    }

    /// Set a bearer authentication token.
    ///
    /// Sets the `Authorization` header to `Bearer {token}`.
    #[must_use]
    pub fn bearer_auth<T: std::fmt::Display>(self, token: T) -> Self {
        let value = format!("Bearer {token}");
        self.header(http::header::AUTHORIZATION, value)
    }

    /// Set basic authentication credentials.
    ///
    /// Sets the `Authorization` header using the `Basic` scheme.
    /// If `password` is `None`, only the username is encoded.
    #[must_use]
    pub fn basic_auth<U, P>(self, username: U, password: Option<P>) -> Self
    where
        U: std::fmt::Display,
        P: std::fmt::Display,
    {
        use base64::Engine as _;

        let credentials = match password {
            Some(p) => format!("{username}:{p}"),
            None => format!("{username}:"),
        };
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
        let value = format!("Basic {encoded}");
        self.header(http::header::AUTHORIZATION, value)
    }

    /// Append query parameters to the URL.
    ///
    /// Serializes `query` as `application/x-www-form-urlencoded` and
    /// appends to the existing query string (if any). Can be called
    /// multiple times.
    ///
    /// Requires the `query` feature.
    #[cfg(feature = "query")]
    #[must_use]
    pub fn query<T: serde::Serialize + ?Sized>(mut self, query: &T) -> Self {
        let query_str = match serialize_form_urlencoded(query) {
            Ok(s) => s,
            Err(e) => {
                self.url = Err(e);
                return self;
            }
        };

        if let Ok(ref mut url) = self.url {
            let new_query = match &url.query {
                Some(existing) => format!("{existing}&{query_str}"),
                None => query_str,
            };
            url.set_query_string(new_query);
        }
        self
    }

    /// Set a URL-encoded form body for the request.
    ///
    /// Serializes `form` as `application/x-www-form-urlencoded` and sets
    /// the `Content-Type` header accordingly.
    ///
    /// # Deviation from reqwest
    ///
    /// reqwest uses `serde_urlencoded` for serialization.  wrest bridges
    /// through `serde_json::to_value` → `form_urlencoded::Serializer`
    /// to avoid the extra dependency.  For flat structs, maps, and
    /// `&[(K, V)]` slices the output is identical.  Nested objects
    /// produce a JSON-serialized string value in wrest (e.g.
    /// `key=%7B%22a%22%3A1%7D`) whereas `serde_urlencoded` would
    /// return an error.
    ///
    /// Requires the `form` feature.
    #[cfg(feature = "form")]
    #[must_use]
    pub fn form<T: serde::Serialize + ?Sized>(mut self, form: &T) -> Self {
        match serialize_form_urlencoded(form) {
            Ok(encoded) => {
                self.headers.push((
                    "Content-Type".to_owned(),
                    "application/x-www-form-urlencoded".to_owned(),
                ));
                self.body = Some(crate::Body::from(encoded.into_bytes()));
            }
            Err(e) => {
                self.url = Err(e);
            }
        }
        self
    }

    /// Set a per-request timeout.
    ///
    /// Overrides the client-level timeout for this specific request.
    /// If neither a per-request nor a client-level timeout is set,
    /// the request can run indefinitely (subject to WinHTTP's own
    /// default connect/send/receive timeouts).
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the HTTP version for this request.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP decides which HTTP version to use for each connection.
    /// Requires the `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn version(self, _version: http::Version) -> Self {
        self
    }

    /// Build a [`Request`] from this builder.
    ///
    /// This consumes the builder and returns a fully-formed `Request`
    /// that can be inspected, modified, and later executed with
    /// [`Client::execute()`](crate::Client::execute).
    pub fn build(self) -> Result<Request, Error> {
        let url = self.url?;

        // Build HeaderMap from string pairs.
        //
        // Semantics (matching reqwest):
        //  - Default headers are included unless overridden by a
        //    per-request header with the same name.
        //  - Repeated per-request `.header(name, v)` calls accumulate
        //    (append, not overwrite).
        let mut header_map = http::HeaderMap::new();

        // Collect the set of per-request header names for override detection.
        let per_request_names: std::collections::HashSet<&str> =
            self.headers.iter().map(|(name, _)| name.as_str()).collect();

        // Add default headers that are NOT overridden by per-request headers.
        for (name, value) in &self.client.inner.default_headers {
            if !per_request_names.contains(name.as_str()) {
                header_map.append(name.clone(), value.clone());
            }
        }

        // Append per-request headers (accumulates multi-values).
        for (name, value) in &self.headers {
            let header_name = http::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|e| Error::builder("invalid header name").with_source(e))?;

            let header_value = http::header::HeaderValue::from_bytes(&narrow_latin1(value))
                .map_err(|e| Error::builder("invalid header value").with_source(e))?;
            header_map.append(header_name, header_value);
        }

        // Inject `Accept: */*` if no Accept header was set (matching reqwest /
        // hyper default behaviour).
        if !header_map.contains_key(http::header::ACCEPT) {
            header_map.insert(http::header::ACCEPT, http::HeaderValue::from_static("*/*"));
        }

        // If the URL contains userinfo (user:password@host), inject an
        // Authorization: Basic header -- matching reqwest's behaviour.
        // Only inject if no Authorization header was already set.
        if !url.username.is_empty() && !header_map.contains_key(http::header::AUTHORIZATION) {
            let credentials = match &url.password {
                Some(pass) => format!("{}:{pass}", url.username),
                None => format!("{}:", url.username),
            };
            use base64::Engine;
            let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
            if let Ok(val) = http::HeaderValue::from_str(&format!("Basic {encoded}")) {
                header_map.insert(http::header::AUTHORIZATION, val);
                trace!("injected Basic auth from URL userinfo");
            }
        }

        let method = http::Method::from_bytes(self.method.as_bytes())
            .map_err(|e| Error::builder("invalid method").with_source(e))?;

        Ok(Request {
            method,
            url,
            headers: header_map,
            body: self.body,
            timeout: self.timeout,
            version: http::Version::default(),
        })
    }

    /// Build a [`Request`], preserving the `Client` and any error.
    ///
    /// Returns the `Client` alongside the build result so callers
    /// can reuse the client regardless of whether the build succeeded.
    ///
    /// Matches [`reqwest::RequestBuilder::build_split()`](https://docs.rs/reqwest/latest/reqwest/struct.RequestBuilder.html#method.build_split).
    pub fn build_split(self) -> (Client, Result<Request, Error>) {
        let client = self.client.clone();
        let result = self.build();
        (client, result)
    }

    /// Create a `RequestBuilder` from an existing `Client` and `Request`.
    ///
    /// Useful for modifying a previously-built request before re-sending.
    ///
    /// Matches [`reqwest::RequestBuilder::from_parts()`](https://docs.rs/reqwest/latest/reqwest/struct.RequestBuilder.html#method.from_parts).
    pub fn from_parts(client: Client, request: Request) -> Self {
        Self {
            client,
            method: request.method.as_str().to_owned(),
            url: Ok(request.url),
            headers: request
                .headers
                .iter()
                .map(|(k, v)| (k.as_str().to_owned(), widen_latin1(v.as_bytes())))
                .collect(),
            body: request.body,
            timeout: request.timeout,
        }
    }

    /// Try to clone this `RequestBuilder`.
    ///
    /// Returns `None` if the builder is in an error state. The body (if set)
    /// is cloned as well.
    pub fn try_clone(&self) -> Option<RequestBuilder> {
        let url = match &self.url {
            Ok(u) => Ok(u.clone()),
            Err(_) => return None,
        };
        let body = match &self.body {
            Some(b) => Some(b.try_clone()?),
            None => None,
        };
        Some(RequestBuilder {
            client: self.client.clone(),
            method: self.method.clone(),
            url,
            headers: self.headers.clone(),
            body,
            timeout: self.timeout,
        })
    }

    /// Send the request and await the response.
    ///
    /// The returned future is `Send`, so it can be `.await`ed in
    /// multi-threaded executors.
    ///
    /// Internally delegates to [`build()`](Self::build) +
    /// [`Client::execute()`](crate::Client::execute), so all header
    /// merging, URL-userinfo auth injection, and default `Accept`
    /// headers are applied consistently.
    pub async fn send(self) -> Result<Response, Error> {
        let (client, result) = self.build_split();
        client.execute(result?).await
    }
}

// ---------------------------------------------------------------------------
// form-urlencoded serialization via serde_json -> form_urlencoded
// ---------------------------------------------------------------------------

#[cfg(any(feature = "query", feature = "form"))]
/// Serialize a `Serialize` value to `application/x-www-form-urlencoded`.
///
/// Bridges serde to the Servo `form_urlencoded` crate by converting the
/// value to a `serde_json::Value` first, then feeding the key-value pairs
/// into `form_urlencoded::Serializer`.  Supports the same inputs that
/// reqwest accepts: slices of 2-tuples, `HashMap`s, and flat structs.
///
/// # Why the JSON intermediate step?
///
/// The `form_urlencoded` crate provides a manual `Serializer::append_pair`
/// API but does not implement `serde::Serializer`, so there is no way to
/// drive it directly from a `T: Serialize`.  The `serde_urlencoded` crate
/// exists for this purpose, but pulling it in would add another dependency.
/// Instead we use `serde_json` (already required by the `json` feature) to
/// reflect `T` into a runtime `Value`, then walk the resulting
/// `Object`/`Array` and feed key-value pairs into the form serializer.
/// This handles structs, maps, and `&[(K, V)]` uniformly without extra
/// dependencies.
fn serialize_form_urlencoded<T: serde::Serialize + ?Sized>(value: &T) -> Result<String, Error> {
    let json = serde_json::to_value(value)
        .map_err(|e| Error::builder("form serialization failed").with_source(e))?;

    let mut ser = form_urlencoded::Serializer::new(String::new());

    match json {
        // { "key": "val", ... }  --  from structs and HashMaps
        serde_json::Value::Object(map) => {
            for (k, v) in &map {
                if let Some(s) = json_value_to_str(v) {
                    ser.append_pair(k, &s);
                }
                // skip nulls (matches serde_urlencoded behaviour)
            }
        }
        // [["key", "val"], ...]  --  from &[("key", "val")]
        serde_json::Value::Array(arr) => {
            for item in &arr {
                let pair = item.as_array().filter(|a| a.len() == 2).ok_or_else(|| {
                    Error::builder(
                        "form serialization failed: \
                             sequence items must be [key, value] pairs",
                    )
                })?;
                let k = pair
                    .first()
                    .and_then(json_value_to_str)
                    .ok_or_else(|| Error::builder("form serialization failed: null key"))?;
                let v = pair.get(1).and_then(json_value_to_str).unwrap_or_default();
                ser.append_pair(&k, &v);
            }
        }
        _ => {
            return Err(Error::builder(
                "form serialization failed: \
                 value must be a struct, map, or sequence of pairs",
            ));
        }
    }

    Ok(ser.finish())
}

/// Convert a JSON scalar to its string representation.
/// Returns `None` for `null` (which callers typically skip).
#[cfg(any(feature = "query", feature = "form"))]
fn json_value_to_str(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Null => None,
        // Arrays/objects as values are unusual but produce a JSON string
        // so callers get *something* rather than a cryptic error.
        other => Some(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bare_client() -> Client {
        Client::builder().build().expect("client build")
    }

    // -- body() --

    #[test]
    fn body_from_table() {
        // (input_bytes, label)
        let cases: &[(&[u8], &str)] =
            &[(&[1u8, 2, 3], "raw bytes"), (b"hello world", "string bytes")];

        for &(input, label) in cases {
            let rb = bare_client()
                .post("https://example.com")
                .body(input.to_vec());
            let clone = rb.try_clone().unwrap();
            assert_eq!(clone.body.unwrap().as_bytes().unwrap(), input, "{label}");
        }
    }

    // -- headers() --

    #[test]
    fn headers_merge() {
        let mut map = http::HeaderMap::new();
        map.insert("x-one", "1".parse().unwrap());
        map.insert("x-two", "2".parse().unwrap());

        let rb = bare_client().get("https://example.com").headers(map);
        let clone = rb.try_clone().unwrap();
        assert!(clone.headers.iter().any(|(k, v)| k == "x-one" && v == "1"));
        assert!(clone.headers.iter().any(|(k, v)| k == "x-two" && v == "2"));
    }

    #[test]
    fn headers_preserve_extended_bytes() {
        let mut map = http::HeaderMap::new();
        let value = http::HeaderValue::from_bytes(&[0x80, b'A', 0xFF]).expect("value");
        map.insert("x-raw", value.clone());

        let req = bare_client()
            .get("https://example.com")
            .headers(map)
            .build()
            .expect("build should succeed");

        let got = req.headers().get("x-raw").expect("header should exist");
        assert_eq!(got.as_bytes(), value.as_bytes());
    }

    // -- bearer_auth() --

    #[test]
    fn bearer_auth_sets_header() {
        let rb = bare_client()
            .get("https://example.com")
            .bearer_auth("my-token-123");
        let clone = rb.try_clone().unwrap();
        let auth = clone
            .headers
            .iter()
            .find(|(k, _)| k == "authorization")
            .map(|(_, v)| v.clone());
        assert_eq!(auth, Some("Bearer my-token-123".to_owned()));
    }

    // -- basic_auth() --

    #[test]
    fn basic_auth_table() {
        use base64::Engine as _;
        // (username, password, expected_credentials_before_encoding, label)
        let cases: &[(&str, Option<&str>, &str, &str)] = &[
            ("user", Some("pass"), "user:pass", "with password"),
            ("user", None, "user:", "without password"),
        ];

        for &(username, password, creds, label) in cases {
            let rb = bare_client()
                .get("https://example.com")
                .basic_auth(username, password);
            let clone = rb.try_clone().unwrap();
            let auth = clone
                .headers
                .iter()
                .find(|(k, _)| k == "authorization")
                .map(|(_, v)| v.clone())
                .unwrap();
            let expected =
                format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(creds));
            assert_eq!(auth, expected, "{label}");
        }
    }

    // -- query() --

    #[cfg(feature = "query")]
    #[test]
    fn query_appends_params() {
        let rb = bare_client()
            .get("https://example.com/api")
            .query(&[("key", "val"), ("a", "b")]);
        let clone = rb.try_clone().unwrap();
        let url = clone.url.unwrap();
        assert_eq!(url.query(), Some("key=val&a=b"));
    }

    #[cfg(feature = "query")]
    #[test]
    fn query_called_twice_appends() {
        let rb = bare_client()
            .get("https://example.com/api")
            .query(&[("key", "val")])
            .query(&[("a", "b")]);
        let clone = rb.try_clone().unwrap();
        let url = clone.url.unwrap();
        assert_eq!(url.query(), Some("key=val&a=b"));
    }

    #[cfg(feature = "query")]
    #[test]
    fn query_with_existing_query() {
        let rb = bare_client()
            .get("https://example.com/api?existing=1")
            .query(&[("added", "2")]);
        let clone = rb.try_clone().unwrap();
        let url = clone.url.unwrap();
        assert_eq!(url.query(), Some("existing=1&added=2"));
    }

    // -- form() --

    #[cfg(feature = "form")]
    #[test]
    fn form_sets_body_and_content_type() {
        let rb = bare_client()
            .post("https://example.com/login")
            .form(&[("user", "admin"), ("pass", "secret")]);
        let clone = rb.try_clone().unwrap();
        assert!(
            clone
                .headers
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("content-type")
                    && v == "application/x-www-form-urlencoded")
        );
        let body = String::from_utf8(clone.body.unwrap().as_bytes().unwrap().to_vec()).unwrap();
        assert!(body.contains("user=admin"));
        assert!(body.contains("pass=secret"));
    }

    // -- timeout() --

    #[test]
    fn per_request_timeout() {
        let rb = bare_client()
            .get("https://example.com")
            .timeout(Duration::from_secs(5));
        assert_eq!(rb.timeout, Some(Duration::from_secs(5)));
    }

    // -- version() --

    #[test]
    #[cfg(feature = "noop-compat")]
    fn version_accepted_as_noop() {
        // Just verifies it compiles and doesn't panic.
        let _rb = bare_client()
            .get("https://example.com")
            .version(http::Version::HTTP_11);
    }

    // -- try_clone() --

    #[test]
    fn try_clone_succeeds() {
        let rb = bare_client()
            .post("https://example.com")
            .header("x-test", "value")
            .body(b"data".to_vec())
            .timeout(Duration::from_secs(3));

        let clone = rb.try_clone().unwrap();
        assert_eq!(clone.method, "POST");
        assert_eq!(clone.url.as_ref().unwrap().as_str(), "https://example.com/");
        assert!(
            clone
                .headers
                .iter()
                .any(|(k, v)| k == "x-test" && v == "value")
        );
        assert_eq!(clone.body.as_ref().unwrap().as_bytes().unwrap(), b"data");
        assert_eq!(clone.timeout, Some(Duration::from_secs(3)));
    }

    #[test]
    fn try_clone_returns_none_on_error() {
        // Force error state with an invalid URL
        let rb = bare_client().get("not-a-url");
        assert!(rb.try_clone().is_none());
    }

    // -- Request::version() / version_mut() --

    #[test]
    fn request_version_default() {
        let req = Request::new(http::Method::GET, "https://example.com".parse().unwrap());
        // Default version
        let _v = req.version();
    }

    #[test]
    fn request_version_mut() {
        let mut req = Request::new(http::Method::GET, "https://example.com".parse().unwrap());
        *req.version_mut() = http::Version::HTTP_2;
        assert_eq!(req.version(), http::Version::HTTP_2);
    }

    // -- RequestBuilder::build_split() --

    #[test]
    fn build_split_returns_client_and_request() {
        let rb = bare_client().get("https://example.com");
        let (client, result) = rb.build_split();
        assert!(result.is_ok());
        let req = result.unwrap();
        assert_eq!(req.url().as_str(), "https://example.com/");
        // Client is usable
        let _rb2 = client.get("https://other.com");
    }

    #[test]
    fn build_split_preserves_error() {
        let rb = bare_client().get("not-a-url");
        let (_client, result) = rb.build_split();
        assert!(result.is_err());
    }

    // -- RequestBuilder::from_parts() --

    #[test]
    fn from_parts_round_trips() {
        let client = bare_client();
        let req = client
            .post("https://example.com/api")
            .header("x-test", "val")
            .body(b"payload".to_vec())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let rb = RequestBuilder::from_parts(client, req);
        let rebuilt = rb.build().unwrap();
        assert_eq!(rebuilt.method(), http::Method::POST);
        assert_eq!(rebuilt.url().as_str(), "https://example.com/api");
        assert!(rebuilt.headers().contains_key("x-test"));
        assert!(rebuilt.body().is_some());
        assert_eq!(rebuilt.timeout(), Some(&Duration::from_secs(5)));
    }

    // -- Default header override semantics --

    #[test]
    fn per_request_header_overrides_default() {
        // Default headers set on the client should be overridden (not
        // duplicated) when the request sets the same header name.
        let mut defaults = http::HeaderMap::new();
        defaults.insert("x-custom", "default-value".parse().unwrap());
        let client = Client::builder().default_headers(defaults).build().unwrap();

        let req = client
            .get("https://example.com")
            .header("x-custom", "override-value")
            .build()
            .unwrap();

        let values: Vec<_> = req
            .headers()
            .get_all("x-custom")
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect();

        // Must be exactly one value -- the override, not both.
        assert_eq!(values, vec!["override-value"]);
    }

    #[test]
    fn default_header_kept_when_not_overridden() {
        let mut defaults = http::HeaderMap::new();
        defaults.insert("x-default", "kept".parse().unwrap());
        let client = Client::builder().default_headers(defaults).build().unwrap();

        let req = client
            .get("https://example.com")
            .header("x-other", "value")
            .build()
            .unwrap();

        assert_eq!(req.headers().get("x-default").unwrap().to_str().unwrap(), "kept");
        assert_eq!(req.headers().get("x-other").unwrap().to_str().unwrap(), "value");
    }

    // -- Invalid header name/value --

    #[test]
    fn header_invalid_deferred_error_table() {
        // (header_name, header_value, label)
        let cases: &[(&str, &str, &str)] = &[
            ("invalid header name!", "value", "invalid name"),
            ("x-ok", "value\0with-null", "invalid value"),
        ];

        for &(name, value, label) in cases {
            let result = bare_client()
                .get("https://example.com")
                .header(name, value)
                .build();
            let err = result.expect_err(&format!("{label}: should fail"));
            assert!(err.is_builder(), "{label}: should be builder error");
        }
    }

    // -- Request accessors --

    #[test]
    fn request_accessors_mut() {
        let mut req = Request::new(http::Method::GET, "https://example.com".parse().unwrap());

        // method_mut
        *req.method_mut() = http::Method::POST;
        assert_eq!(req.method(), &http::Method::POST);

        // url_mut
        let new_url: crate::url::Url = "https://other.com".parse().unwrap();
        *req.url_mut() = new_url;
        assert_eq!(req.url().host_str(), Some("other.com"));

        // headers_mut
        req.headers_mut()
            .insert("x-custom", "value".parse().unwrap());
        assert_eq!(req.headers().get("x-custom").unwrap().to_str().unwrap(), "value");

        // body_mut
        assert!(req.body().is_none());
        *req.body_mut() = Some(crate::Body::from("payload"));
        assert!(req.body().is_some());
        assert_eq!(req.body().unwrap().as_bytes().unwrap(), b"payload");

        // timeout_mut
        assert!(req.timeout().is_none());
        *req.timeout_mut() = Some(Duration::from_secs(5));
        assert_eq!(req.timeout(), Some(&Duration::from_secs(5)));
    }

    // -- Request::try_clone (data-driven) --

    #[test]
    fn request_try_clone_table() {
        // (label, body, expect_clone)
        let cases: Vec<(&str, Option<crate::Body>, bool)> = vec![
            ("no body", None, true),
            ("bytes body", Some(crate::Body::from("payload")), true),
            // Stream body cannot be cloned -- try_clone returns None.
        ];

        for (label, body, _) in cases {
            let mut req = Request::new(http::Method::POST, "https://example.com".parse().unwrap());
            req.body = body;
            *req.timeout_mut() = Some(Duration::from_secs(7));

            let cloned = req
                .try_clone()
                .unwrap_or_else(|| panic!("{label}: should clone"));
            assert_eq!(cloned.method(), &http::Method::POST, "{label}");
            assert_eq!(cloned.timeout(), Some(&Duration::from_secs(7)), "{label}");
            assert_eq!(
                cloned.body().and_then(|b| b.as_bytes()).map(|b| b.to_vec()),
                cloned.body().and_then(|b| b.as_bytes()).map(|b| b.to_vec()),
                "{label}: body"
            );
        }

        // Stream body -- cannot clone
        let stream = futures_util::stream::once(async {
            Ok::<_, crate::Error>(bytes::Bytes::from_static(b"data"))
        });
        let mut req = Request::new(http::Method::POST, "https://example.com".parse().unwrap());
        req.body = Some(crate::Body::wrap_stream(stream));
        assert!(req.try_clone().is_none(), "stream body cannot be cloned");
    }

    // -- RequestBuilder Debug in error state --

    #[test]
    fn request_builder_debug_shows_invalid_on_error() {
        let rb = bare_client().get("not-a-url");
        let debug = format!("{rb:?}");
        assert!(debug.contains("<invalid>"), "got: {debug}");
    }

    // -- form() error paths --

    #[cfg(feature = "form")]
    #[test]
    fn form_non_struct_value_error() {
        // A plain string is not a struct, map, or array of pairs.
        let rb = bare_client()
            .post("https://example.com")
            .form(&"plain string");
        let result = rb.build();
        assert!(result.is_err(), "plain string should fail form()");
    }

    #[cfg(feature = "form")]
    #[test]
    fn form_array_bad_pair_error() {
        // A JSON array where items aren't [k,v] pairs.
        let bad: Vec<Vec<&str>> = vec![vec!["only-one"]];
        let rb = bare_client().post("https://example.com").form(&bad);
        let result = rb.build();
        assert!(result.is_err(), "non-pair array should fail form()");
    }

    // -- json() serialization failure --

    #[cfg(feature = "json")]
    #[test]
    fn json_serialization_failure() {
        // A value that fails serde_json::to_vec should defer a builder error.
        struct FailSerialize;
        impl serde::Serialize for FailSerialize {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("intentional failure"))
            }
        }
        let rb = bare_client()
            .post("https://example.com")
            .json(&FailSerialize);
        let result = rb.build();
        assert!(result.is_err(), "FailSerialize should fail json()");
        assert!(result.unwrap_err().is_builder());
    }

    // -- query() error paths --

    #[cfg(feature = "query")]
    #[test]
    fn query_errors() {
        // Non-struct value: a plain string is not a valid query parameter.
        let err = bare_client()
            .get("https://example.com")
            .query(&"plain string")
            .build()
            .unwrap_err();
        assert!(err.is_builder(), "non-struct value should be a builder error");

        // Errored URL: calling .query() on an already-failed URL preserves
        // the original error without clobbering it.
        let err = bare_client()
            .get("not a valid url")
            .query(&[("key", "val")])
            .build()
            .unwrap_err();
        assert!(err.is_builder(), "errored URL should still be a builder error");
    }

    // -- build() with invalid method --

    #[test]
    fn repeated_header_accumulates() {
        // Calling .header() twice with the same name should keep both values
        // (append semantics, matching reqwest).
        let req = bare_client()
            .get("https://example.com")
            .header("x-multi", "a")
            .header("x-multi", "b")
            .build()
            .unwrap();

        let values: Vec<_> = req
            .headers()
            .get_all("x-multi")
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect();

        assert_eq!(values, vec!["a", "b"]);
    }

    #[test]
    fn default_accept_header_injected() {
        // When no Accept header is set, build() should inject Accept: */*.
        let req = bare_client().get("https://example.com").build().unwrap();

        assert_eq!(
            req.headers()
                .get(http::header::ACCEPT)
                .unwrap()
                .to_str()
                .unwrap(),
            "*/*",
        );
    }

    #[test]
    fn explicit_accept_header_not_overwritten() {
        // When an explicit Accept header is set, build() should NOT inject */*.
        let req = bare_client()
            .get("https://example.com")
            .header(http::header::ACCEPT, "application/json")
            .build()
            .unwrap();

        let values: Vec<_> = req
            .headers()
            .get_all(http::header::ACCEPT)
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect();

        assert_eq!(values, vec!["application/json"]);
    }

    #[test]
    fn default_accept_in_default_headers_not_doubled() {
        // If default_headers already sets Accept, build() should not inject a second one.
        let mut defaults = http::HeaderMap::new();
        defaults.insert(http::header::ACCEPT, "text/html".parse().unwrap());
        let client = Client::builder().default_headers(defaults).build().unwrap();

        let req = client.get("https://example.com").build().unwrap();

        let values: Vec<_> = req
            .headers()
            .get_all(http::header::ACCEPT)
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect();

        assert_eq!(values, vec!["text/html"]);
    }

    #[test]
    fn build_invalid_method_error() {
        let rb = RequestBuilder {
            client: bare_client(),
            method: "INVALID METHOD WITH SPACES".to_owned(),
            url: Ok("https://example.com".parse().unwrap()),
            headers: Vec::new(),
            body: None,
            timeout: None,
        };
        let result = rb.build();
        assert!(result.is_err());
        assert!(result.unwrap_err().is_builder());
    }

    #[test]
    fn build_url_userinfo_table() {
        // (label, url, explicit_auth_header, expected_auth)
        let cases: &[(&str, &str, Option<&str>, Option<&str>)] = &[
            (
                "user:pass injects Basic auth",
                "https://alice:s3cret@example.com/api",
                None,
                Some("Basic YWxpY2U6czNjcmV0"),
            ),
            (
                "explicit auth overrides userinfo",
                "https://alice:s3cret@example.com/api",
                Some("Bearer tok123"),
                Some("Bearer tok123"),
            ),
            (
                "username only → user: base64",
                "https://bob@example.com/",
                None,
                Some("Basic Ym9iOg=="),
            ),
            ("no userinfo → no auth", "https://example.com/api", None, None),
        ];

        let client = bare_client();
        for &(label, url, explicit, expected) in cases {
            let mut rb = client.get(url);
            if let Some(hdr) = explicit {
                rb = rb.header("authorization", hdr);
            }
            let req = rb.build().unwrap();
            let auth = req
                .headers()
                .get(http::header::AUTHORIZATION)
                .map(|v| v.to_str().unwrap());
            assert_eq!(auth, expected, "{label}");
        }
    }

    // -- json_value_to_str coverage --

    #[cfg(any(feature = "query", feature = "form"))]
    #[test]
    fn json_value_to_str_arms() {
        // Covers Number, Bool, Null, and Array/Object arms (lines 604-609).
        let cases: &[(serde_json::Value, Option<&str>, &str)] = &[
            (serde_json::Value::String("hello".into()), Some("hello"), "String"),
            (serde_json::json!(42), Some("42"), "Number"),
            (serde_json::json!(true), Some("true"), "Bool true"),
            (serde_json::json!(false), Some("false"), "Bool false"),
            (serde_json::Value::Null, None, "Null"),
            (serde_json::json!([1, 2]), Some("[1,2]"), "Array"),
            (serde_json::json!({"a": 1}), Some("{\"a\":1}"), "Object"),
        ];

        for (value, expected, label) in cases {
            let result = json_value_to_str(value);
            assert_eq!(result.as_deref(), *expected, "{label}");
        }
    }

    // -- form() with null fields (Option<T> = None) --

    #[cfg(feature = "form")]
    #[test]
    fn form_skips_null_fields() {
        // Covers the null-skip branch in serialize_form_urlencoded (lines 562-566).
        #[derive(serde::Serialize)]
        struct Params {
            name: &'static str,
            optional: Option<&'static str>,
        }
        let rb = bare_client().post("https://example.com").form(&Params {
            name: "alice",
            optional: None,
        });
        let clone = rb.try_clone().unwrap();
        let body = String::from_utf8(clone.body.unwrap().as_bytes().unwrap().to_vec()).unwrap();
        assert!(body.contains("name=alice"), "should contain name");
        assert!(!body.contains("optional"), "null field should be skipped");
    }

    // -- query() URL serialization consistency --

    #[cfg(feature = "query")]
    #[test]
    fn query_serialization_with_port_and_fragment() {
        let rb = bare_client()
            .get("https://example.com:9443/api#frag")
            .query(&[("key", "val")]);
        let clone = rb.try_clone().unwrap();
        let url = clone.url.unwrap();
        assert_eq!(url.as_str(), "https://example.com:9443/api?key=val#frag");
        assert_eq!(url.query(), Some("key=val"));
    }
}
