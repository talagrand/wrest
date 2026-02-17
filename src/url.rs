//! URL parsing and types.
//!
//! Provides a public [`Url`] type that matches a subset of
//! [`url::Url`](https://docs.rs/url/latest/url/struct.Url.html)'s method
//! signatures -- but without pulling in the `url` crate and its transitive
//! dependencies (ICU4X, idna, percent-encoding, etc.).  Backed by
//! `WinHttpCrackUrl` for parsing.
//!
//! Also provides [`IntoUrl`] (public trait) for eagerly validating URLs at
//! request-build time, matching reqwest semantics.
//!
//! # Limitations
//!
//! Because parsing is backed by WinHTTP rather than a full WHATWG-compliant
//! URL parser:
//!
//! - **Scheme restriction:** only `http` and `https` schemes are accepted.
//! - **No IDNA:** international domain names are not punycode-encoded.
//! - **Userinfo extracted manually:** `WinHttpCrackUrl` strips
//!   `user:password@` from HTTP(S) URLs, so wrest extracts it from the
//!   raw string before cracking.  [`Url::username`] and [`Url::password`]
//!   return the percent-decoded values.  When a URL contains userinfo,
//!   [`RequestBuilder::build()`](crate::RequestBuilder::build) injects an
//!   `Authorization: Basic` header automatically (matching reqwest).

use crate::Error;

// ---------------------------------------------------------------------------
// Url -- public type matching a subset of url::Url
// ---------------------------------------------------------------------------

/// A parsed URL.
///
/// Provides the same accessor methods as the commonly-used subset of
/// [`url::Url`](https://docs.rs/url/latest/url/struct.Url.html), so callers
/// can switch between the two types with minimal code changes -- but without
/// pulling in the `url` crate and its ~10 transitive dependencies (ICU4X,
/// idna, percent-encoding, ...).
///
/// Backed by `WinHttpCrackUrl` for parsing.  Only `http` and `https` schemes
/// are supported.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Url {
    /// The serialized URL string.
    pub(crate) serialized: String,
    /// Scheme, lowercased (`"http"` or `"https"`).
    pub(crate) scheme: String,
    /// The hostname (e.g., `"example.com"`).
    pub(crate) host: String,
    /// Port number (always present -- default port filled in by WinHttpCrackUrl
    /// when not explicit in the URL).
    pub(crate) port: u16,
    /// Whether the port differs from the scheme's default (80 / 443), which
    /// serves as a proxy for "was the port explicitly written in the URL".
    pub(crate) explicit_port: bool,
    /// Path component (e.g., `"/api/v1"`).  Always starts with `/`.
    pub(crate) path: String,
    /// Query string without the leading `?`, if present.
    pub(crate) query: Option<String>,
    /// Fragment without the leading `#`, if present.
    pub(crate) fragment: Option<String>,
    /// `true` for https, `false` for http.
    pub(crate) is_https: bool,
    /// Combined path + query string for `WinHttpOpenRequest`.
    /// Fragment is intentionally excluded -- WinHTTP does not send it.
    pub(crate) path_and_query: String,
    /// Username from the `user:password@host` portion, percent-decoded.
    /// Empty string when not present (matching `url::Url::username()`).
    pub(crate) username: String,
    /// Password from the `user:password@host` portion, percent-decoded.
    /// `None` when not present.
    pub(crate) password: Option<String>,
}

impl Url {
    /// Return the serialized URL as a string slice.
    ///
    /// Equivalent to `url::Url::as_str()`.
    pub fn as_str(&self) -> &str {
        &self.serialized
    }

    /// Return the URL scheme (e.g., `"http"` or `"https"`).
    ///
    /// Equivalent to `url::Url::scheme()`.
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Return the host as a string, if present.
    ///
    /// Always `Some` for `http`/`https` URLs.
    /// Equivalent to `url::Url::host_str()`.
    pub fn host_str(&self) -> Option<&str> {
        Some(&self.host)
    }

    /// Return the port number if it was explicitly specified in the URL.
    ///
    /// Returns `None` when the URL uses the scheme's default port (80 for
    /// http, 443 for https).  Equivalent to `url::Url::port()`.
    pub fn port(&self) -> Option<u16> {
        if self.explicit_port {
            Some(self.port)
        } else {
            None
        }
    }

    /// Return the port number, falling back to the scheme's well-known
    /// default (80 for http, 443 for https).
    ///
    /// Equivalent to `url::Url::port_or_known_default()`.
    pub fn port_or_known_default(&self) -> Option<u16> {
        Some(self.port)
    }

    /// Return the path component (e.g., `"/api/v1"`).
    ///
    /// Equivalent to `url::Url::path()`.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Return the query string without the leading `?`, if present.
    ///
    /// Equivalent to `url::Url::query()`.
    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }

    /// Return the fragment without the leading `#`, if present.
    ///
    /// Equivalent to `url::Url::fragment()`.
    pub fn fragment(&self) -> Option<&str> {
        self.fragment.as_deref()
    }

    /// Parse a URL string.
    ///
    /// Equivalent to `url::Url::parse()`. Only `http` and `https` schemes
    /// are supported.
    pub fn parse(url: &str) -> Result<Self, Error> {
        Url::parse_impl(url)
    }

    /// Join a relative URL against this base URL.
    ///
    /// Equivalent to `url::Url::join()`. Handles relative paths,
    /// absolute paths, and full URLs. Dot-segments (`..`, `.`) are
    /// resolved per RFC 3986 §5.2.4.
    pub fn join(&self, input: &str) -> Result<Self, Error> {
        // If input is already an absolute URL, just parse it directly
        if input.starts_with("http://") || input.starts_with("https://") {
            return Url::parse_impl(input);
        }

        // Build the resolved URL
        let raw_path = if input.starts_with('/') {
            // Absolute path -- replace path entirely
            input.to_owned()
        } else {
            // Relative path -- resolve against current path's directory
            let base_path = match self.path.rfind('/') {
                Some(pos) => self.path.get(..=pos).unwrap_or("/"),
                None => "/",
            };
            format!("{base_path}{input}")
        };

        // Resolve dot-segments per RFC 3986 §5.2.4
        let resolved_path = remove_dot_segments(&raw_path);

        let mut base = format!("{}://{}", self.scheme, self.host);
        if self.explicit_port {
            base.push_str(&format!(":{}", self.port));
        }
        let resolved = format!("{base}{resolved_path}");

        Url::parse_impl(&resolved)
    }

    /// Return the username component of the URL, if present.
    ///
    /// Returns `""` when no userinfo is present in the URL.
    /// Equivalent to `url::Url::username()`.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Return the password component of the URL, if present.
    ///
    /// Returns `None` when no password is present in the URL.
    /// Equivalent to `url::Url::password()`.
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.serialized)
    }
}

impl std::fmt::Debug for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Url").field(&self.serialized).finish()
    }
}

impl AsRef<str> for Url {
    fn as_ref(&self) -> &str {
        &self.serialized
    }
}

impl std::str::FromStr for Url {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Url::parse_impl(s)
    }
}

impl PartialOrd for Url {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Url {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.serialized.cmp(&other.serialized)
    }
}

impl TryFrom<&str> for Url {
    type Error = crate::Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Url::parse_impl(s)
    }
}

impl TryFrom<String> for Url {
    type Error = crate::Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Url::parse_impl(&s)
    }
}

// ---------------------------------------------------------------------------
// IntoUrl
// ---------------------------------------------------------------------------

/// Sealing module -- prevents external crates from implementing [`IntoUrl`].
mod private {
    pub trait Sealed {}
    impl Sealed for &str {}
    impl Sealed for String {}
    impl Sealed for &String {}
    impl Sealed for super::Url {}
    impl Sealed for &super::Url {}
}

/// A trait for types that can be converted to a validated URL.
///
/// Implemented for `&str`, `String`, and [`Url`].  Invalid URLs produce an
/// [`Error`] at request-build time -- not inside `send()`.
///
/// This trait is sealed -- it cannot be implemented outside of `wrest`,
/// matching `reqwest::IntoUrl`.
pub trait IntoUrl: private::Sealed {
    /// Convert this value into a validated [`Url`].
    fn into_url(self) -> Result<Url, Error>;
}

impl IntoUrl for &str {
    fn into_url(self) -> Result<Url, Error> {
        Url::parse_impl(self)
    }
}

impl IntoUrl for String {
    fn into_url(self) -> Result<Url, Error> {
        Url::parse_impl(&self)
    }
}

impl IntoUrl for &String {
    fn into_url(self) -> Result<Url, Error> {
        Url::parse_impl(self)
    }
}

impl IntoUrl for Url {
    fn into_url(self) -> Result<Url, Error> {
        Ok(self)
    }
}

impl IntoUrl for &Url {
    fn into_url(self) -> Result<Url, Error> {
        Ok(self.clone())
    }
}

impl Url {
    /// Parse a URL string using `WinHttpCrackUrl`.
    ///
    /// This is the sole constructor. Every `Url` is always fully cracked -- the
    /// WinHTTP-specific fields (`is_https`, `path_and_query`) are populated
    /// eagerly so downstream code never needs a separate conversion step.
    pub(crate) fn parse_impl(url: &str) -> Result<Self, Error> {
        // Extract fragment from the original URL before WinHttpCrackUrl,
        // which escapes '#' to '%23' under ICU_ESCAPE.
        let (url_for_crack, fragment) = match url.find('#') {
            Some(pos) => {
                let frag = url.get(pos + 1..).unwrap_or("");
                (
                    url.get(..pos).unwrap_or(""),
                    if frag.is_empty() {
                        None
                    } else {
                        Some(frag.to_owned())
                    },
                )
            }
            None => (url, None),
        };

        // Extract userinfo (user:password@) before WinHttpCrackUrl, which
        // strips it from HTTP(S) URLs. We parse it manually from the raw
        // string: look for `://`, then find `@` before the next `/`.
        let (url_without_userinfo, username, password) = extract_userinfo(url_for_crack);

        let cracked = crate::abi::winhttp_crack_url(url_without_userinfo.as_ref())?;

        let scheme = cracked.scheme;
        let is_https = scheme.eq_ignore_ascii_case("https");
        if !is_https && !scheme.eq_ignore_ascii_case("http") {
            return Err(Error::builder(format!("unsupported URL scheme: {scheme}")));
        }
        let scheme_lower = scheme.to_ascii_lowercase();

        let host = cracked.host;
        let port = cracked.port;
        let default_port: u16 = if is_https { 443 } else { 80 };
        let explicit_port = port != default_port;

        let raw_path = cracked.path;
        let extra = cracked.extra;

        let path = if raw_path.is_empty() {
            "/".to_owned()
        } else {
            raw_path
        };

        let (query, _) = parse_extra(&extra);

        // path_and_query excludes the fragment -- WinHTTP does not send it.
        let path_and_query = if extra.is_empty() {
            path.clone()
        } else {
            format!("{path}{extra}")
        };

        // Rebuild serialized from the cracked (percent-encoded) components
        // so that `as_str()` agrees with `path()`, `query()`, etc.
        // WinHttpCrackUrl with ICU_ESCAPE normalises path/query encoding;
        // using the original input would leave `as_str()` returning the
        // raw string while `path()` returns the encoded version (QOI-4).
        let mut serialized = format!("{scheme_lower}://{host}");
        if explicit_port {
            use std::fmt::Write;
            write!(serialized, ":{port}").expect("write to String is infallible");
        }
        serialized.push_str(&path_and_query);
        if let Some(ref frag) = fragment {
            serialized.push('#');
            serialized.push_str(frag);
        }

        Ok(Url {
            serialized,
            scheme: scheme_lower,
            host,
            port,
            explicit_port,
            path,
            query,
            fragment,
            is_https,
            path_and_query,
            username,
            password,
        })
    }

    /// Update the query string and re-serialize the URL.
    ///
    /// Replaces any existing query string. Updates `path_and_query` and
    /// `serialized` to stay consistent with the other fields.
    #[cfg_attr(all(not(feature = "query"), not(test)), expect(dead_code))]
    pub(crate) fn set_query_string(&mut self, query: String) {
        self.query = Some(query);
        self.path_and_query = match &self.query {
            Some(q) => format!("{}?{q}", self.path),
            None => self.path.clone(),
        };
        let mut serialized = format!("{}://{}", self.scheme, self.host);
        if self.explicit_port {
            use std::fmt::Write;
            write!(serialized, ":{}", self.port).expect("write to String is infallible");
        }
        serialized.push_str(&self.path_and_query);
        if let Some(ref frag) = self.fragment {
            serialized.push('#');
            serialized.push_str(frag);
        }
        self.serialized = serialized;
    }
}

/// Extract userinfo (`user:password@`) from a URL string.
///
/// WinHTTP's `WinHttpCrackUrl` strips userinfo from HTTP(S) URLs, so we
/// extract it manually before cracking. Returns `(url_without_userinfo,
/// username, password)`.
///
/// The returned URL has the `user:password@` portion removed so that
/// `WinHttpCrackUrl` can parse the remainder normally. Username and
/// password are percent-decoded.
///
/// Examples:
///   `http://alice:s3cret@host/path` → `("http://host/path", "alice", Some("s3cret"))`
///   `http://alice@host/path`        → `("http://host/path", "alice", None)`
///   `http://host/path`              → `("http://host/path", "", None)`
fn extract_userinfo(url: &str) -> (std::borrow::Cow<'_, str>, String, Option<String>) {
    // Find the authority start ("://")
    let authority_start = match url.find("://") {
        Some(pos) => pos + 3,
        None => return (std::borrow::Cow::Borrowed(url), String::new(), None),
    };

    let authority = &url[authority_start..];

    // Find the end of the authority (first '/' or end of string)
    let authority_end = authority.find('/').unwrap_or(authority.len());
    let authority_part = &authority[..authority_end];

    // Look for '@' in the authority -- this separates userinfo from host
    let at_pos = match authority_part.rfind('@') {
        Some(pos) => pos,
        None => return (std::borrow::Cow::Borrowed(url), String::new(), None),
    };

    let userinfo = &authority_part[..at_pos];
    let (raw_user, raw_pass) = match userinfo.find(':') {
        Some(colon) => (&userinfo[..colon], Some(&userinfo[colon + 1..])),
        None => (userinfo, None),
    };

    let username = percent_decode(raw_user);
    let password = raw_pass.map(percent_decode);

    // Reconstruct the URL without userinfo
    let host_onwards = &authority[at_pos + 1..];
    let cleaned = format!("{}{host_onwards}", &url[..authority_start]);

    (std::borrow::Cow::Owned(cleaned), username, password)
}

/// Percent-decode a string (e.g. `%40` → `@`).
fn percent_decode(input: &str) -> String {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2]))
        {
            out.push(hi << 4 | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// Convert an ASCII hex character to its nibble value.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Remove dot-segments from a path per RFC 3986 §5.2.4.
///
/// Collapses `.` (current directory) and `..` (parent directory) segments,
/// producing a normalised absolute path.
fn remove_dot_segments(path: &str) -> String {
    let mut output: Vec<&str> = Vec::new();

    for segment in path.split('/') {
        match segment {
            "." => {
                // Current directory -- skip
            }
            ".." => {
                // Parent directory -- pop the last segment (if any)
                output.pop();
            }
            s => {
                output.push(s);
            }
        }
    }

    let mut result = output.join("/");

    // Ensure the path starts with '/' for absolute paths
    if !result.starts_with('/') {
        result.insert(0, '/');
    }

    // Preserve trailing slash when input ended with /. or /..
    if (path.ends_with("/.") || path.ends_with("/..")) && !result.ends_with('/') {
        result.push('/');
    }

    result
}

/// Decompose the "extra info" string from `WinHttpCrackUrl` into optional
/// query and fragment components.
///
/// The extra info contains everything after the URL path:
///   `?key=val&a=b#section`  ->  query=`Some("key=val&a=b")`, fragment=`Some("section")`
///   `#section`              ->  query=`None`, fragment=`Some("section")`
///   `?key=val`              ->  query=`Some("key=val")`, fragment=`None`
///   (empty)                 ->  query=`None`, fragment=`None`
fn parse_extra(extra: &str) -> (Option<String>, Option<String>) {
    if extra.is_empty() {
        return (None, None);
    }

    // Split at the first '#' to separate the fragment.
    let (before_frag, fragment) = match extra.find('#') {
        Some(pos) => {
            let frag = extra.get(pos + 1..).unwrap_or("");
            (
                extra.get(..pos).unwrap_or(""),
                if frag.is_empty() {
                    None
                } else {
                    Some(frag.to_owned())
                },
            )
        }
        None => (extra, None),
    };

    // Extract query (everything after the leading '?').
    let query = if let Some(q) = before_frag.strip_prefix('?') {
        if q.is_empty() {
            None
        } else {
            Some(q.to_owned())
        }
    } else {
        None
    };

    (query, fragment)
}

// ---------------------------------------------------------------------------
// Serde support
// ---------------------------------------------------------------------------

#[cfg(feature = "json")]
impl serde::Serialize for Url {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "json")]
impl<'de> serde::Deserialize<'de> for Url {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Url::parse(&s).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Url parsing tests (data-driven) --

    /// Each entry: (input, is_https, host, port, path_and_query).
    const PARSE_CASES: &[(&str, bool, &str, u16, &str)] = &[
        ("https://example.com/api/v1?id=42", true, "example.com", 443, "/api/v1?id=42"),
        ("http://localhost:8080/test", false, "localhost", 8080, "/test"),
        ("https://example.com", true, "example.com", 443, "/"),
        ("http://example.com", false, "example.com", 80, "/"),
        ("https://example.com/path/to/resource", true, "example.com", 443, "/path/to/resource"),
        ("https://example.com:9443/secure", true, "example.com", 9443, "/secure"),
    ];

    #[test]
    fn parse_urls() {
        for &(input, is_https, host, port, pq) in PARSE_CASES {
            let parsed = input.into_url().unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(parsed.is_https, is_https, "{input}: is_https");
            assert_eq!(parsed.host, host, "{input}: host");
            assert_eq!(parsed.port, port, "{input}: port");
            assert_eq!(parsed.path_and_query, pq, "{input}: path_and_query");
        }
    }

    #[test]
    fn parse_url_with_fragment() {
        let parsed = "https://example.com/page#section".into_url().unwrap();
        assert!(parsed.path_and_query.starts_with("/page"));
    }

    #[test]
    fn parse_url_with_query_and_fragment() {
        let parsed = "https://example.com/api?key=val&a=b#frag"
            .into_url()
            .unwrap();
        assert!(parsed.path_and_query.contains("key=val"));
        assert!(parsed.path_and_query.contains("a=b"));
    }

    /// URLs that should fail to parse.
    const PARSE_ERROR_CASES: &[&str] = &["not a url", "ftp://example.com/file"];

    #[test]
    fn invalid_urls_return_error() {
        for &input in PARSE_ERROR_CASES {
            assert!(input.into_url().is_err(), "expected Err for: {input}");
        }
    }

    // -- IntoUrl impls --

    #[test]
    fn into_url_for_string_types() {
        let s = String::from("https://example.com/test");
        // &str
        let a = "https://example.com/test".into_url().unwrap();
        // String
        let b = s.clone().into_url().unwrap();
        // &String
        let c = (&s).into_url().unwrap();
        for url in [&a, &b, &c] {
            assert_eq!(url.host, "example.com", "host mismatch for {}", url.as_str());
        }
    }

    // -- Url public API tests --

    #[test]
    fn url_accessors() {
        let url = "https://example.com:9443/api/v1?key=val#sect"
            .into_url()
            .unwrap();
        assert_eq!(url.as_str(), "https://example.com:9443/api/v1?key=val#sect");
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.port(), Some(9443));
        assert_eq!(url.port_or_known_default(), Some(9443));
        assert_eq!(url.path(), "/api/v1");
        assert_eq!(url.query(), Some("key=val"));
        assert_eq!(url.fragment(), Some("sect"));
    }

    #[test]
    fn url_default_port_returns_none() {
        let url = "https://example.com/path".into_url().unwrap();
        assert_eq!(url.port(), None);
        assert_eq!(url.port_or_known_default(), Some(443));
    }

    #[test]
    fn url_http_default_port() {
        let url = "http://example.com/path".into_url().unwrap();
        assert_eq!(url.port(), None);
        assert_eq!(url.port_or_known_default(), Some(80));
    }

    #[test]
    fn url_display() {
        let url = "https://example.com/path".into_url().unwrap();
        assert_eq!(format!("{url}"), "https://example.com/path");
    }

    #[test]
    fn url_debug() {
        let url = "https://example.com/path".into_url().unwrap();
        let debug = format!("{url:?}");
        assert!(debug.starts_with("Url("));
        assert!(debug.contains("https://example.com/path"));
    }

    #[test]
    fn url_clone_eq() {
        let a = "https://example.com/path".into_url().unwrap();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn url_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let u1 = "https://example.com/path".into_url().unwrap();
        let u2 = "https://example.com/path".into_url().unwrap();
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        u1.hash(&mut h1);
        u2.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn into_url_for_url_type() {
        let url = "https://example.com/test".into_url().unwrap();
        let url2 = url.into_url().unwrap();
        assert_eq!(url2.as_str(), "https://example.com/test");
        assert!(url2.is_https);
        assert_eq!(url2.path_and_query, "/test");
    }

    #[test]
    fn into_url_for_url_ref() {
        let url = "https://example.com/test?q=1".into_url().unwrap();
        let url2 = (&url).into_url().unwrap();
        assert_eq!(url2.as_str(), "https://example.com/test?q=1");
        assert_eq!(url2.path_and_query, "/test?q=1");
    }

    #[test]
    fn url_path_query_fragment_combinations() {
        // (input, expected_path, expected_query, expected_fragment)
        let cases: &[(&str, &str, Option<&str>, Option<&str>)] = &[
            ("https://example.com/page#section", "/page", None, Some("section")),
            ("https://example.com/search?q=test", "/search", Some("q=test"), None),
            ("https://example.com/path", "/path", None, None),
            // Fragment only, no query — covers parse_extra fragment-no-query branch
            ("https://example.com/#frag", "/", None, Some("frag")),
            // Query and fragment — covers full parse_extra path
            ("https://example.com/?q=1#sect", "/", Some("q=1"), Some("sect")),
            // Empty fragment (hash only) — covers frag.is_empty() -> None
            ("https://example.com/page#", "/page", None, None),
            // Empty query (question mark only) — covers q.is_empty() -> None
            ("https://example.com/page?", "/page", None, None),
            // Both empty — covers both empty branches
            ("https://example.com/page?#", "/page", None, None),
        ];

        for &(input, path, query, fragment) in cases {
            let url = Url::parse(input).unwrap();
            assert_eq!(url.path(), path, "{input}: path");
            assert_eq!(url.query(), query, "{input}: query");
            assert_eq!(url.fragment(), fragment, "{input}: fragment");
        }
    }

    #[test]
    fn url_as_ref_str() {
        let url: Url = "https://example.com/path".into_url().unwrap();
        let s: &str = url.as_ref();
        assert_eq!(s, "https://example.com/path");
    }

    #[test]
    fn url_from_str() {
        use std::str::FromStr;
        let url = Url::from_str("https://example.com/api").unwrap();
        assert_eq!(url.as_str(), "https://example.com/api");
    }

    #[test]
    fn url_from_str_invalid() {
        use std::str::FromStr;
        let err = Url::from_str("not a url");
        assert!(err.is_err());
    }

    #[test]
    fn url_ordering() {
        let a: Url = "https://aaa.com".into_url().unwrap();
        let b: Url = "https://bbb.com".into_url().unwrap();

        // Ord
        assert!(a < b);
        assert!(b > a);
        assert_eq!(a.cmp(&a), std::cmp::Ordering::Equal);

        // PartialOrd
        assert_eq!(a.partial_cmp(&b), Some(std::cmp::Ordering::Less));

        // Vec::sort
        let mut urls: Vec<Url> = vec![
            "https://zzz.com".into_url().unwrap(),
            "https://aaa.com".into_url().unwrap(),
            "https://mmm.com".into_url().unwrap(),
        ];
        urls.sort();
        assert_eq!(urls[0].as_str(), "https://aaa.com/");
        assert_eq!(urls[2].as_str(), "https://zzz.com/");
    }

    // -- Url::parse() tests --

    // NOTE: Url::parse() valid-input coverage is provided by `parse_urls`
    // (via PARSE_CASES) above. Invalid-input coverage is provided by
    // `invalid_urls_return_error` (via PARSE_ERROR_CASES).

    // -- TryFrom tests --

    #[test]
    fn url_try_from_valid() {
        let from_str = Url::try_from("https://example.com/path").unwrap();
        let from_string = Url::try_from(String::from("https://example.com/path")).unwrap();
        assert_eq!(from_str.as_str(), "https://example.com/path");
        assert_eq!(from_string.as_str(), "https://example.com/path");
    }

    #[test]
    fn url_try_from_invalid() {
        let err = Url::try_from("not valid");
        assert!(err.is_err());
    }

    /// Each entry: (base, reference, expected_path).
    /// For absolute-URL references, expected_path is the full URL.
    const JOIN_CASES: &[(&str, &str, &str)] = &[
        // Absolute URL replaces everything
        ("https://example.com/api/v1", "https://other.com/new", "https://other.com/new"),
        // Absolute path
        ("https://example.com/api/v1", "/new/path", "/new/path"),
        // Relative path
        ("https://example.com/api/v1", "v2", "/api/v2"),
        // Dot segments
        ("https://example.com/a/b/c", "./d", "/a/b/d"),
        ("https://example.com/a/b/c", "../d", "/a/d"),
        ("https://example.com/a/b/c/d", "../../e", "/a/e"),
        ("https://example.com/a", "../../b", "/b"),
        ("https://example.com/old/path", "/a/b/../c", "/a/c"),
        // Trailing dot/dotdot
        ("https://example.com/a/b/c", ".", "/a/b/"),
        ("https://example.com/a/b/c", "..", "/a/"),
    ];

    #[test]
    fn url_join() {
        for &(base_str, reference, expected) in JOIN_CASES {
            let base = Url::parse(base_str).unwrap();
            let joined = base
                .join(reference)
                .unwrap_or_else(|e| panic!("join({base_str:?}, {reference:?}): {e}"));
            if expected.starts_with("https://") {
                // Absolute URL -- compare full URL
                assert_eq!(joined.as_str(), expected, "join({base_str:?}, {reference:?})");
            } else {
                // Path comparison
                assert_eq!(joined.path(), expected, "join({base_str:?}, {reference:?})");
            }
        }
    }

    #[test]
    fn url_join_preserves_custom_port() {
        let base = Url::parse("https://example.com:9443/api").unwrap();
        let joined = base.join("/other").unwrap();
        assert_eq!(joined.port(), Some(9443));
        assert_eq!(joined.path(), "/other");
    }

    // -- username/password tests --

    #[test]
    fn url_username_password() {
        // (input, expected_username, expected_password)
        let cases: &[(&str, &str, Option<&str>)] = &[
            // No userinfo
            ("https://example.com", "", None),
            // Full credentials
            ("https://alice:s3cret@example.com/path", "alice", Some("s3cret")),
            // Username only
            ("http://bob@example.com", "bob", None),
            // Percent-encoded: %40 = @, %3A = :
            ("https://user%40domain:p%3Ass@example.com/", "user@domain", Some("p:ss")),
            // Empty password (user:@)
            ("https://user:@example.com/", "user", Some("")),
            // Uppercase hex A-F: %41='A', %4F='O' — covers hex_nibble A-F branch
            ("https://user%41%62:p%4Fss@example.com/", "userAb", Some("pOss")),
            // Lowercase hex a-f: %5A='Z', %6a='j' — covers hex_nibble a-f branch
            ("https://%5A%6a@example.com/", "Zj", None),
        ];

        for &(input, username, password) in cases {
            let url = Url::parse(input).unwrap();
            assert_eq!(url.username(), username, "{input}: username");
            assert_eq!(url.password(), password, "{input}: password");
        }
    }

    #[test]
    fn url_userinfo_stripped_from_serialization() {
        // Credentials should NOT appear in the serialized URL
        let url = Url::parse("https://alice:s3cret@example.com/path").unwrap();
        assert!(!url.as_str().contains("alice"));
        assert!(!url.as_str().contains("s3cret"));
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.path(), "/path");
    }

    #[test]
    fn extract_userinfo_table() {
        // (input, expected_cleaned, expected_user, expected_pass)
        let cases: &[(&str, &str, &str, Option<&str>)] = &[
            ("https://example.com/path", "https://example.com/path", "", None),
            ("https://alice:pw@host:8080/path", "https://host:8080/path", "alice", Some("pw")),
            ("http://user@host", "http://host", "user", None),
        ];

        for &(input, cleaned, user, pass) in cases {
            let (actual_cleaned, actual_user, actual_pass) = extract_userinfo(input);
            assert_eq!(actual_cleaned.as_ref(), cleaned, "{input}: cleaned");
            assert_eq!(actual_user, user, "{input}: username");
            assert_eq!(actual_pass.as_deref(), pass, "{input}: password");
        }
    }

    #[test]
    #[cfg(feature = "json")]
    fn url_serialize() {
        let url = Url::parse("https://example.com/path?q=1").unwrap();
        let json = serde_json::to_string(&url).unwrap();
        assert_eq!(json, "\"https://example.com/path?q=1\"");
    }

    #[test]
    #[cfg(feature = "json")]
    fn url_deserialize() {
        let url: Url = serde_json::from_str("\"https://example.com/path\"").unwrap();
        assert_eq!(url.as_str(), "https://example.com/path");
    }

    #[test]
    #[cfg(feature = "json")]
    fn url_roundtrip() {
        let original = Url::parse("https://example.com/api?key=val#frag").unwrap();
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: Url = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    #[cfg(feature = "json")]
    fn url_deserialize_invalid() {
        let result: Result<Url, _> = serde_json::from_str("\"not a valid url\"");
        assert!(result.is_err());
    }

    // -- set_query_string --

    #[test]
    fn set_query_string_table() {
        // (input_url, new_query, expected_query, expected_as_str, expected_path_and_query, label)
        let cases: &[(&str, &str, &str, &str, &str, &str)] = &[
            (
                "https://example.com/api",
                "key=val",
                "key=val",
                "https://example.com/api?key=val",
                "/api?key=val",
                "adds query",
            ),
            (
                "https://example.com:9443/api#frag",
                "a=1&b=2",
                "a=1&b=2",
                "https://example.com:9443/api?a=1&b=2#frag",
                "/api?a=1&b=2",
                "with port and fragment",
            ),
            (
                "https://example.com/api?old=1",
                "new=2",
                "new=2",
                "https://example.com/api?new=2",
                "/api?new=2",
                "replaces existing",
            ),
        ];

        for &(input, query, exp_query, exp_str, exp_pq, label) in cases {
            let mut url = Url::parse(input).unwrap();
            url.set_query_string(query.to_owned());
            assert_eq!(url.query(), Some(exp_query), "{label}: query()");
            assert_eq!(url.as_str(), exp_str, "{label}: as_str()");
            assert_eq!(url.path_and_query, exp_pq, "{label}: path_and_query");
        }
    }
}
