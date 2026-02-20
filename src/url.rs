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
// ParseError
// ---------------------------------------------------------------------------

/// An error type for URL parsing failures.
///
/// Returned by [`Url::parse`], [`Url::join`],
/// [`FromStr`](std::str::FromStr), and
/// [`TryFrom`] implementations on [`Url`].
///
/// # Variant names
///
/// The variant names mirror [`url::ParseError`](https://docs.rs/url/latest/url/enum.ParseError.html) so that code which
/// pattern-matches on specific variants can compile against both crates
/// without changes.  Because parsing is backed by WinHTTP's
/// `WinHttpCrackUrl`, only a subset of variants are actually produced at
/// runtime:
///
/// | Variant                            | Produced by wrest? |
/// |------------------------------------|--------------------|
/// | `EmptyHost`                        | No  |
/// | `IdnaError`                        | No  |
/// | `InvalidPort`                      | No  |
/// | `InvalidIpv4Address`               | No  |
/// | `InvalidIpv6Address`               | No  |
/// | `InvalidDomainCharacter`           | No  |
/// | `RelativeUrlWithoutBase`           | No  |
/// | `RelativeUrlWithCannotBeABaseBase` | No  |
/// | `SetHostOnCannotBeABaseUrl`        | No  |
/// | `Overflow`                         | No  |
/// | `InvalidUrl`                       | Yes (wrest-specific catch-all for WinHTTP parse failures) |
/// | `UnsupportedScheme`                | Yes (wrest-specific, no `url` equivalent) |
///
/// Variants marked "No" exist for pattern-matching compatibility and will
/// never be returned by wrest's parser.  Code that just propagates with `?`
/// is unaffected regardless.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// The URL has an empty host.
    EmptyHost,

    /// An internationalized domain name contained invalid characters.
    IdnaError,

    /// The port number is invalid.
    InvalidPort,

    /// The IPv4 address is invalid.
    InvalidIpv4Address,

    /// The IPv6 address is invalid.
    InvalidIpv6Address,

    /// The domain contains invalid characters.
    InvalidDomainCharacter,

    /// A relative URL was provided where an absolute URL was expected.
    RelativeUrlWithoutBase,

    /// A relative URL with a cannot-be-a-base base was provided.
    RelativeUrlWithCannotBeABaseBase,

    /// Cannot set host on a cannot-be-a-base URL.
    SetHostOnCannotBeABaseUrl,

    /// The URL is too large to be parsed.
    Overflow,

    /// The URL could not be parsed.
    ///
    /// This is a **wrest-specific** catch-all for any parse failure reported
    /// by WinHTTP's `WinHttpCrackUrl` that does not map to a more specific
    /// variant.  It has no `url::ParseError` equivalent.
    InvalidUrl,

    /// The URL scheme is not `http` or `https`.
    ///
    /// This variant is **wrest-specific** and has no `url::ParseError`
    /// equivalent.  Only `http` and `https` schemes are supported because
    /// parsing is backed by WinHTTP.
    UnsupportedScheme,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::EmptyHost => f.write_str("empty host"),
            ParseError::IdnaError => f.write_str("invalid international domain name"),
            ParseError::InvalidPort => f.write_str("invalid port number"),
            ParseError::InvalidIpv4Address => f.write_str("invalid IPv4 address"),
            ParseError::InvalidIpv6Address => f.write_str("invalid IPv6 address"),
            ParseError::InvalidDomainCharacter => f.write_str("invalid domain character"),
            ParseError::RelativeUrlWithoutBase => f.write_str("relative URL without a base"),
            ParseError::RelativeUrlWithCannotBeABaseBase => {
                f.write_str("relative URL with a cannot-be-a-base base")
            }
            ParseError::SetHostOnCannotBeABaseUrl => {
                f.write_str("a cannot-be-a-base URL doesn't have a host to set")
            }
            ParseError::Overflow => f.write_str("URLs more than 4 GB are not supported"),
            ParseError::InvalidUrl => f.write_str("invalid URL"),
            ParseError::UnsupportedScheme => f.write_str("unsupported URL scheme"),
        }
    }
}

impl std::error::Error for ParseError {}

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

    /// Return the serialized URL without the fragment component.
    fn serialized_without_fragment(&self) -> String {
        match self.serialized.split_once('#') {
            Some((before, _)) => before.to_owned(),
            None => self.serialized.clone(),
        }
    }

    /// Parse a URL string.
    ///
    /// Equivalent to `url::Url::parse()`. Only `http` and `https` schemes
    /// are supported.
    ///
    /// Returns [`ParseError`] on failure, matching `url::Url::parse()` which
    /// returns `url::ParseError`.
    pub fn parse(url: &str) -> Result<Self, ParseError> {
        Url::parse_impl(url)
    }

    /// Join a relative URL against this base URL.
    ///
    /// Equivalent to `url::Url::join()`. Handles relative paths,
    /// absolute paths, scheme-relative URLs, query-only references,
    /// fragment-only references, and full URLs. Dot-segments (`..`, `.`)
    /// are resolved per RFC 3986 §5.2.4.
    ///
    /// # Reference types
    ///
    /// | Input form           | Example              | Behaviour                                 |
    /// |----------------------|----------------------|-------------------------------------------|
    /// | Absolute URL         | `https://other/path` | Parsed independently                      |
    /// | Scheme-relative      | `//other/path`       | Uses base scheme                          |
    /// | Absolute path        | `/new/path`          | Replaces path, preserves authority        |
    /// | Relative path        | `sub/page`           | Merged with base path directory           |
    /// | Query-only           | `?q=1`               | Preserves base path                       |
    /// | Fragment-only        | `#sec`               | Preserves base path & query               |
    /// | Empty                | `""`                 | Returns base URL                          |
    pub fn join(&self, input: &str) -> Result<Self, ParseError> {
        // RFC 3986 §5.2.2: Reference Resolution

        // Empty input returns the base URL unchanged.
        if input.is_empty() {
            return Url::parse_impl(&self.serialized);
        }

        // If input is an absolute URL, parse it directly.
        if input.starts_with("http://") || input.starts_with("https://") {
            return Url::parse_impl(input);
        }

        // Scheme-relative: //authority/path...
        if input.starts_with("//") {
            let resolved = format!("{}:{input}", self.scheme);
            return Url::parse_impl(&resolved);
        }

        // Split input into path, query, and fragment components.
        let (input_path, input_query, input_fragment) = split_reference(input);

        // Fragment-only: #fragment
        if input_path.is_empty() && input_query.is_none() {
            // Return base URL with the new fragment.
            let mut base_str = self.serialized_without_fragment();
            if let Some(frag) = input_fragment {
                base_str.push('#');
                base_str.push_str(frag);
            }
            return Url::parse_impl(&base_str);
        }

        // Query-only: ?query (possibly with fragment)
        if input_path.is_empty() && input_query.is_some() {
            // Preserve base path, replace query (and fragment).
            let mut base_str = format!("{}://{}", self.scheme, self.host,);
            if self.explicit_port {
                base_str.push_str(&format!(":{}", self.port));
            }
            base_str.push_str(&self.path);
            if let Some(q) = input_query {
                base_str.push('?');
                base_str.push_str(q);
            }
            if let Some(f) = input_fragment {
                base_str.push('#');
                base_str.push_str(f);
            }
            return Url::parse_impl(&base_str);
        }

        // Path reference (absolute or relative).
        let merged_path = if input_path.starts_with('/') {
            // Absolute path -- replace entirely.
            input_path.to_owned()
        } else {
            // Relative path -- merge with base path's directory.
            // `parse_impl` guarantees `path` starts with '/', so
            // `rsplit_once('/')` always succeeds; `unwrap_or` gives a
            // safe fallback if it ever didn't.
            let base_dir = self.path.rsplit_once('/').map_or("", |(dir, _)| dir);
            format!("{base_dir}/{input_path}")
        };

        let resolved_path = remove_dot_segments(&merged_path);

        let mut resolved = format!("{}://{}", self.scheme, self.host);
        if self.explicit_port {
            resolved.push_str(&format!(":{}", self.port));
        }
        resolved.push_str(&resolved_path);
        if let Some(q) = input_query {
            resolved.push('?');
            resolved.push_str(q);
        }
        if let Some(f) = input_fragment {
            resolved.push('#');
            resolved.push_str(f);
        }

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
    /// Matches `url::Url`'s derived Debug format so that diagnostic output is
    /// identical regardless of whether the native or reqwest backend is active.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // url::Url shows host as `Some(Domain("..."))` for http/https.
        struct HostDebug<'a>(&'a str);
        impl std::fmt::Debug for HostDebug<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                // Matches `Some(Domain("example.com"))`.
                write!(f, "Some(Domain({:?}))", self.0)
            }
        }

        f.debug_struct("Url")
            .field("scheme", &self.scheme)
            .field("cannot_be_a_base", &false)
            .field("username", &self.username)
            .field("password", &self.password)
            .field("host", &HostDebug(&self.host))
            .field("port", &self.port())
            .field("path", &self.path)
            .field("query", &self.query)
            .field("fragment", &self.fragment)
            .finish()
    }
}

impl AsRef<str> for Url {
    fn as_ref(&self) -> &str {
        &self.serialized
    }
}

impl From<Url> for String {
    fn from(url: Url) -> Self {
        url.serialized
    }
}

impl std::str::FromStr for Url {
    type Err = ParseError;

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
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Url::parse_impl(s)
    }
}

impl TryFrom<String> for Url {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Url::parse_impl(&s)
    }
}

// ---------------------------------------------------------------------------
// IntoUrl
// ---------------------------------------------------------------------------

/// Supertrait that carries the actual `into_url()` method.
///
/// This trait is `pub` inside the crate but is **not** re-exported from the
/// crate root, so external callers cannot import it and therefore cannot
/// call `into_url()` directly -- matching `reqwest::into_url::IntoUrlSealed`.
///
/// It also serves as a seal: because external crates cannot name
/// `IntoUrlSealed`, they cannot implement [`IntoUrl`].
pub trait IntoUrlSealed {
    /// Convert this value into a validated [`Url`].
    fn into_url(self) -> Result<Url, Error>;
}

/// A trait for types that can be converted to a validated URL.
///
/// Implemented for `&str`, `String`, and [`Url`].  Invalid URLs produce an
/// [`Error`] at request-build time -- not inside `send()`.
///
/// This trait is sealed and cannot be implemented outside of `wrest`.
pub trait IntoUrl: IntoUrlSealed {}

impl IntoUrlSealed for &str {
    fn into_url(self) -> Result<Url, Error> {
        Url::parse_impl(self).map_err(Error::from)
    }
}
impl IntoUrl for &str {}

impl IntoUrlSealed for String {
    fn into_url(self) -> Result<Url, Error> {
        Url::parse_impl(&self).map_err(Error::from)
    }
}
impl IntoUrl for String {}

impl IntoUrlSealed for &String {
    fn into_url(self) -> Result<Url, Error> {
        Url::parse_impl(self).map_err(Error::from)
    }
}
impl IntoUrl for &String {}

impl IntoUrlSealed for Url {
    fn into_url(self) -> Result<Url, Error> {
        Ok(self)
    }
}
impl IntoUrl for Url {}

impl IntoUrlSealed for &Url {
    fn into_url(self) -> Result<Url, Error> {
        Ok(self.clone())
    }
}
impl IntoUrl for &Url {}

impl Url {
    /// Parse a URL string using `WinHttpCrackUrl`.
    ///
    /// This is the sole constructor. Every `Url` is always fully cracked -- the
    /// WinHTTP-specific fields (`is_https`, `path_and_query`) are populated
    /// eagerly so downstream code never needs a separate conversion step.
    pub(crate) fn parse_impl(url: &str) -> Result<Self, ParseError> {
        // Extract fragment from the original URL before WinHttpCrackUrl,
        // which escapes '#' to '%23' under ICU_ESCAPE.
        let (url_for_crack, fragment) = match url.split_once('#') {
            Some((before, frag)) => (
                before,
                if frag.is_empty() {
                    None
                } else {
                    Some(frag.to_owned())
                },
            ),
            None => (url, None),
        };

        // Extract userinfo (user:password@) before WinHttpCrackUrl, which
        // strips it from HTTP(S) URLs. We parse it manually from the raw
        // string: look for `://`, then find `@` before the next `/`.
        let (url_without_userinfo, username, password) = extract_userinfo(url_for_crack);

        let cracked = crate::abi::winhttp_crack_url(url_without_userinfo.as_ref())
            .map_err(|_| ParseError::InvalidUrl)?;

        let scheme = cracked.scheme;
        let is_https = scheme.eq_ignore_ascii_case("https");
        if !is_https && !scheme.eq_ignore_ascii_case("http") {
            return Err(ParseError::UnsupportedScheme);
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

        let query = extract_query_from_extra(&extra);

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
        let mut serialized = if explicit_port {
            format!("{scheme_lower}://{host}:{port}")
        } else {
            format!("{scheme_lower}://{host}")
        };
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
        self.path_and_query = format!("{}?{query}", self.path);
        self.query = Some(query);
        let mut serialized = if self.explicit_port {
            format!("{}://{}:{}", self.scheme, self.host, self.port)
        } else {
            format!("{}://{}", self.scheme, self.host)
        };
        serialized.push_str(&self.path_and_query);
        if let Some(ref frag) = self.fragment {
            serialized.push('#');
            serialized.push_str(frag);
        }
        self.serialized = serialized;
    }

    /// Build a `Url` directly from an [`http::Uri`] without re-parsing.
    ///
    /// The URI's scheme, authority, path and query are already validated
    /// by the `http` crate, so we construct the `Url` from parts
    /// instead of serializing and re-cracking through `WinHttpCrackUrl`.
    pub(crate) fn from_http_uri(uri: &http::Uri) -> Result<Self, ParseError> {
        let scheme = uri.scheme_str().ok_or(ParseError::RelativeUrlWithoutBase)?;
        let is_https = scheme.eq_ignore_ascii_case("https");
        if !is_https && !scheme.eq_ignore_ascii_case("http") {
            return Err(ParseError::UnsupportedScheme);
        }
        let scheme_lower = scheme.to_ascii_lowercase();

        let authority = uri.authority().ok_or(ParseError::EmptyHost)?;
        let host = authority.host().to_owned();
        if host.is_empty() {
            return Err(ParseError::EmptyHost);
        }

        let default_port: u16 = if is_https { 443 } else { 80 };
        let port = authority.port_u16().unwrap_or(default_port);
        let explicit_port = authority.port_u16().is_some();

        let (path, query) = match uri.path_and_query() {
            Some(pq) => {
                let p = pq.path();
                let path = if p.is_empty() {
                    "/".to_owned()
                } else {
                    p.to_owned()
                };
                let query = pq.query().map(|q| q.to_owned());
                (path, query)
            }
            None => ("/".to_owned(), None),
        };

        let path_and_query = match &query {
            Some(q) => format!("{path}?{q}"),
            None => path.clone(),
        };

        // Extract userinfo from the authority (RFC 3986 §3.2.1).
        let auth_str = authority.as_str();
        let (username, password) = match auth_str.split_once('@') {
            Some((userinfo, _)) => match userinfo.split_once(':') {
                Some((u, p)) => (percent_decode(u), Some(percent_decode(p))),
                None => (percent_decode(userinfo), None),
            },
            None => (String::new(), None),
        };

        // http::Uri does not carry fragments.
        let fragment = None;

        let mut serialized = if explicit_port {
            format!("{scheme_lower}://{host}:{port}")
        } else {
            format!("{scheme_lower}://{host}")
        };
        serialized.push_str(&path_and_query);

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

    /// Convert this `Url` into an [`http::Uri`] from parts (no string roundtrip).
    ///
    /// Fragments are dropped because `http::Uri` does not carry them.
    pub(crate) fn to_http_uri(&self) -> Result<http::Uri, http::Error> {
        let authority = if self.explicit_port {
            format!("{}:{}", self.host, self.port)
        } else {
            self.host.clone()
        };
        http::Uri::builder()
            .scheme(self.scheme.as_str())
            .authority(authority.as_str())
            .path_and_query(self.path_and_query.as_str())
            .build()
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
    // Find the authority start ("://") -- RFC 3986 §3.2.
    let (scheme_colon_slashes, authority_and_rest) = match url.split_once("://") {
        Some((scheme, rest)) => (scheme, rest),
        None => return (std::borrow::Cow::Borrowed(url), String::new(), None),
    };

    // Split authority from path/query/fragment at the first '/'
    let authority_part = match authority_and_rest.split_once('/') {
        Some((auth, _)) => auth,
        None => authority_and_rest,
    };

    // Look for '@' in the authority -- this separates userinfo from host.
    let (userinfo, _host_part) = match authority_part.rsplit_once('@') {
        Some(parts) => parts,
        None => return (std::borrow::Cow::Borrowed(url), String::new(), None),
    };

    let (raw_user, raw_pass) = match userinfo.split_once(':') {
        Some((user, pass)) => (user, Some(pass)),
        None => (userinfo, None),
    };

    let username = percent_decode(raw_user);
    let password = raw_pass.map(percent_decode);

    // Reconstruct the URL without userinfo: skip past "userinfo@".
    // We already found '@' in `authority_part` above, so `split_once('@')`
    // on the full `authority_and_rest` always succeeds.
    let after_at = authority_and_rest
        .split_once('@')
        .map_or(authority_and_rest, |(_, rest)| rest);
    let cleaned = format!("{scheme_colon_slashes}://{after_at}");

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

/// Split a URI reference into `(path, query, fragment)` components
/// per RFC 3986 §3 syntax:
///
/// ```text
/// URI-reference = [ path ] [ "?" query ] [ "#" fragment ]
/// ```
///
/// Supports the forms used by `Url::join`:
/// - `""` → `("", None, None)`
/// - `"#frag"` → `("", None, Some("frag"))`
/// - `"?q=1"` → `("", Some("q=1"), None)`
/// - `"?q=1#f"` → `("", Some("q=1"), Some("f"))`
/// - `"path?q=1#f"` → `("path", Some("q=1"), Some("f"))`
/// - `"/abs"` → `("/abs", None, None)`
fn split_reference(input: &str) -> (&str, Option<&str>, Option<&str>) {
    // Split off fragment first (RFC 3986 §3.5).
    let (before_frag, fragment) = match input.split_once('#') {
        Some((before, f)) => (before, if f.is_empty() { None } else { Some(f) }),
        None => (input, None),
    };

    // Split path and query (RFC 3986 §3.4).
    let (path, query) = match before_frag.split_once('?') {
        Some((p, q)) => (p, if q.is_empty() { None } else { Some(q) }),
        None => (before_frag, None),
    };

    (path, query, fragment)
}

/// Extract the query string from the "extra info" returned by
/// `WinHttpCrackUrl`.
///
/// The extra info contains everything after the URL path. Because
/// `parse_impl` strips the fragment *before* calling `WinHttpCrackUrl`,
/// the extra info only ever contains an optional query string:
///   `?key=val&a=b`  ->  `Some("key=val&a=b")`
///   `?`             ->  `None`
///   (empty)         ->  `None`
fn extract_query_from_extra(extra: &str) -> Option<String> {
    let q = extra.strip_prefix('?')?;
    if q.is_empty() {
        None
    } else {
        Some(q.to_owned())
    }
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
        // Matches url::Url derived Debug: `Url { scheme: ..., host: Some(Domain("...")), ... }`
        assert!(debug.starts_with("Url { "), "expected struct debug: {debug}");
        assert!(debug.contains("scheme: \"https\""), "scheme: {debug}");
        assert!(debug.contains("host: Some(Domain(\"example.com\"))"), "host: {debug}");
        assert!(debug.contains("path: \"/path\""), "path: {debug}");
        assert!(debug.contains("port: None"), "default port should be None: {debug}");
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
            // Fragment only, no query
            ("https://example.com/#frag", "/", None, Some("frag")),
            // Query and fragment
            ("https://example.com/?q=1#sect", "/", Some("q=1"), Some("sect")),
            // Empty fragment (hash only) -- covers frag.is_empty() -> None
            ("https://example.com/page#", "/page", None, None),
            // Empty query (question mark only) -- covers q.is_empty() -> None
            ("https://example.com/page?", "/page", None, None),
            // Both empty -- covers both empty branches
            ("https://example.com/page?#", "/page", None, None),
            // Query present + empty fragment -- covers frag.is_empty() with query
            ("https://example.com/path?q=1#", "/path", Some("q=1"), None),
            // Empty query + fragment present -- covers q.is_empty() with frag
            ("https://example.com/path?#frag", "/path", None, Some("frag")),
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
    // `parse_error_table` (via PARSE_ERROR_TABLE).

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

    /// Each entry: (base, reference, expected_full_url, label).
    const JOIN_CASES: &[(&str, &str, &str, &str)] = &[
        // -- Absolute URL replaces everything --
        (
            "https://example.com/api/v1",
            "https://other.com/new",
            "https://other.com/new",
            "absolute url",
        ),
        // -- Scheme-relative --
        (
            "https://example.com/api/v1",
            "//other.com/path",
            "https://other.com/path",
            "scheme-relative",
        ),
        (
            "http://example.com/a",
            "//cdn.example.com/js/app.js",
            "http://cdn.example.com/js/app.js",
            "scheme-relative preserves http",
        ),
        // -- Absolute path --
        (
            "https://example.com/api/v1",
            "/new/path",
            "https://example.com/new/path",
            "absolute path",
        ),
        // -- Relative path --
        (
            "https://example.com/api/v1",
            "v2",
            "https://example.com/api/v2",
            "relative path (sibling)",
        ),
        // -- Dot segments --
        ("https://example.com/a/b/c", "./d", "https://example.com/a/b/d", "dot-segment ./"),
        ("https://example.com/a/b/c", "../d", "https://example.com/a/d", "dot-segment ../"),
        ("https://example.com/a/b/c/d", "../../e", "https://example.com/a/e", "dot-segment ../../"),
        ("https://example.com/a", "../../b", "https://example.com/b", "dot-segment past root"),
        (
            "https://example.com/old/path",
            "/a/b/../c",
            "https://example.com/a/c",
            "dot-segment in absolute path",
        ),
        // -- Trailing dot/dotdot --
        ("https://example.com/a/b/c", ".", "https://example.com/a/b/", "trailing dot"),
        ("https://example.com/a/b/c", "..", "https://example.com/a/", "trailing dotdot"),
        // -- Empty input → returns base URL --
        (
            "https://example.com/a/b?q=1#f",
            "",
            "https://example.com/a/b?q=1#f",
            "empty input returns base",
        ),
        // -- Query-only --
        (
            "https://example.com/a/b",
            "?q=1",
            "https://example.com/a/b?q=1",
            "query-only preserves path",
        ),
        (
            "https://example.com/a/b?old=1",
            "?new=2",
            "https://example.com/a/b?new=2",
            "query-only replaces query",
        ),
        (
            "https://example.com/a/b",
            "?q=1#sec",
            "https://example.com/a/b?q=1#sec",
            "query with fragment",
        ),
        // -- Fragment-only --
        (
            "https://example.com/a/b?q=1",
            "#sec2",
            "https://example.com/a/b?q=1#sec2",
            "fragment-only preserves path+query",
        ),
        (
            "https://example.com/a/b#old",
            "#new",
            "https://example.com/a/b#new",
            "fragment-only replaces fragment",
        ),
        // -- Relative path with query and fragment --
        (
            "https://example.com/a/b",
            "c?q=1#f",
            "https://example.com/a/c?q=1#f",
            "relative path with query+fragment",
        ),
        // -- Absolute path with query --
        (
            "https://example.com/a/b",
            "/x/y?q=1",
            "https://example.com/x/y?q=1",
            "absolute path with query",
        ),
    ];

    #[test]
    fn url_join() {
        for &(base_str, reference, expected, label) in JOIN_CASES {
            let base = Url::parse(base_str).unwrap();
            let joined = base
                .join(reference)
                .unwrap_or_else(|e| panic!("{label}: join({base_str:?}, {reference:?}): {e}"));
            assert_eq!(joined.as_str(), expected, "{label}: join({base_str:?}, {reference:?})",);
        }
    }

    #[test]
    fn url_join_preserves_custom_port() {
        let base = Url::parse("https://example.com:9443/api").unwrap();
        let joined = base.join("/other").unwrap();
        assert_eq!(joined.port(), Some(9443));
        assert_eq!(joined.path(), "/other");

        // Scheme-relative should NOT preserve port
        let joined2 = base.join("//other.com/path").unwrap();
        assert_eq!(joined2.host_str(), Some("other.com"));

        // Query-only should preserve port
        let joined3 = base.join("?q=1").unwrap();
        assert_eq!(joined3.port(), Some(9443));
        assert_eq!(joined3.query(), Some("q=1"));
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
            // Uppercase hex A-F: %41='A', %4F='O' -- covers hex_nibble A-F branch
            ("https://user%41%62:p%4Fss@example.com/", "userAb", Some("pOss")),
            // Lowercase hex a-f: %5A='Z', %6a='j' -- covers hex_nibble a-f branch
            ("https://%5A%6a@example.com/", "Zj", None),
            // Invalid hex -- %GG passes through literally (covers hex_nibble None)
            ("http://user%GG:pass@example.com/path", "user%GG", Some("pass")),
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

    // -- ParseError (data-driven) --

    /// (input, expected_variant, expected_display, label)
    const PARSE_ERROR_TABLE: &[(&str, ParseError, &str, &str)] = &[
        (
            "ftp://example.com/file",
            ParseError::UnsupportedScheme,
            "unsupported URL scheme",
            "unsupported scheme",
        ),
        ("not a url", ParseError::InvalidUrl, "invalid URL", "invalid url (catch-all)"),
    ];

    #[test]
    fn parse_error_table() {
        for &(input, expected, display, label) in PARSE_ERROR_TABLE {
            // Url::parse
            let err = Url::parse(input).unwrap_err();
            assert_eq!(err, expected, "{label}: variant");
            assert_eq!(err.to_string(), display, "{label}: Display");

            // FromStr
            let err2: ParseError = input.parse::<Url>().unwrap_err();
            assert_eq!(err2, expected, "{label}: FromStr variant");

            // TryFrom<&str>
            let err3 = Url::try_from(input).unwrap_err();
            assert_eq!(err3, expected, "{label}: TryFrom<&str> variant");

            // TryFrom<String>
            let err4 = Url::try_from(input.to_owned()).unwrap_err();
            assert_eq!(err4, expected, "{label}: TryFrom<String> variant");

            // Conversion to crate::Error
            let crate_err: crate::Error = err.into();
            assert!(crate_err.is_builder(), "{label}: is_builder");
            assert!(
                crate_err.to_string().contains("builder error"),
                "{label}: contains 'builder error'",
            );
            use std::error::Error as _;
            let source = crate_err.source().expect("should have source");
            assert!(source.to_string().contains(display), "{label}: source contains Display text",);
        }
    }

    /// All url::ParseError-mirrored variants have matching Display strings.
    #[test]
    fn parse_error_display_parity() {
        let cases: &[(ParseError, &str)] = &[
            (ParseError::EmptyHost, "empty host"),
            (ParseError::IdnaError, "invalid international domain name"),
            (ParseError::InvalidPort, "invalid port number"),
            (ParseError::InvalidIpv4Address, "invalid IPv4 address"),
            (ParseError::InvalidIpv6Address, "invalid IPv6 address"),
            (ParseError::InvalidDomainCharacter, "invalid domain character"),
            (ParseError::RelativeUrlWithoutBase, "relative URL without a base"),
            (
                ParseError::RelativeUrlWithCannotBeABaseBase,
                "relative URL with a cannot-be-a-base base",
            ),
            (
                ParseError::SetHostOnCannotBeABaseUrl,
                "a cannot-be-a-base URL doesn't have a host to set",
            ),
            (ParseError::Overflow, "URLs more than 4 GB are not supported"),
            (ParseError::InvalidUrl, "invalid URL"),
            (ParseError::UnsupportedScheme, "unsupported URL scheme"),
        ];
        for (variant, expected) in cases {
            assert_eq!(variant.to_string(), *expected, "{variant:?}");
        }
    }

    #[test]
    fn parse_error_traits() {
        // std::error::Error
        fn assert_std_error<T: std::error::Error>() {}
        assert_std_error::<ParseError>();

        // Debug, Clone, Copy, PartialEq, Eq
        let err = ParseError::UnsupportedScheme;
        let cloned = err;
        let copied = cloned; // Copy
        assert_eq!(format!("{err:?}"), format!("{copied:?}"));
    }

    // -- From<Url> for String --

    #[test]
    fn url_into_string() {
        let url = Url::parse("https://example.com/path?q=1").unwrap();
        let s: String = url.into();
        assert_eq!(s, "https://example.com/path?q=1");
    }

    // -- from_http_uri / to_http_uri --

    #[test]
    fn http_uri_conversion() {
        // (label, input, (scheme, host, port, explicit_port), (path, query), (user, pass), contains)
        type TestCase<'a> = (
            &'a str,
            &'a str,
            (&'a str, &'a str, u16, Option<u16>),
            (&'a str, Option<&'a str>),
            (&'a str, Option<&'a str>),
            &'a str,
        );

        let ok_cases: &[TestCase<'_>] = &[
            (
                "basic https",
                "https://example.com/search?q=rust",
                ("https", "example.com", 443, None),
                ("/search", Some("q=rust")),
                ("", None),
                "https://example.com/search?q=rust",
            ),
            (
                "http default port",
                "http://example.com/index",
                ("http", "example.com", 80, None),
                ("/index", None),
                ("", None),
                "http://example.com/index",
            ),
            (
                "explicit port",
                "https://example.com:8443/p",
                ("https", "example.com", 8443, Some(8443)),
                ("/p", None),
                ("", None),
                ":8443",
            ),
            (
                "userinfo with password",
                "https://user:pass@example.com/x",
                ("https", "example.com", 443, None),
                ("/x", None),
                ("user", Some("pass")),
                "https://example.com/x",
            ),
            (
                "userinfo without password",
                "https://alice@example.com/y",
                ("https", "example.com", 443, None),
                ("/y", None),
                ("alice", None),
                "https://example.com/y",
            ),
            (
                "port + query roundtrip",
                "https://example.com:4433/api?v=2",
                ("https", "example.com", 4433, Some(4433)),
                ("/api", Some("v=2")),
                ("", None),
                ":4433",
            ),
        ];

        for &(
            label,
            input,
            (scheme, host, port, explicit_port),
            (path, query),
            (user, pass),
            contains,
        ) in ok_cases
        {
            let uri: http::Uri = input
                .parse()
                .unwrap_or_else(|e| panic!("{label}: parse URI: {e}"));
            let url =
                Url::from_http_uri(&uri).unwrap_or_else(|e| panic!("{label}: from_http_uri: {e}"));
            assert_eq!(url.scheme(), scheme, "{label}: scheme");
            assert_eq!(url.host_str(), Some(host), "{label}: host");
            assert_eq!(url.port_or_known_default(), Some(port), "{label}: port");
            assert_eq!(url.port(), explicit_port, "{label}: explicit_port");
            assert_eq!(url.path(), path, "{label}: path");
            assert_eq!(url.query(), query, "{label}: query");
            assert_eq!(url.username(), user, "{label}: username");
            assert_eq!(url.password(), pass, "{label}: password");
            assert!(url.as_str().contains(contains), "{label}: serialized contains {contains:?}");

            // Roundtrip: from_http_uri → to_http_uri preserves scheme + authority + path_and_query
            let back = url
                .to_http_uri()
                .unwrap_or_else(|e| panic!("{label}: to_http_uri: {e}"));
            assert_eq!(back.scheme_str(), uri.scheme_str(), "{label}: roundtrip scheme");
            // Authority comparison skips userinfo (http::Uri builder doesn't inject it)
            assert_eq!(
                back.path_and_query().map(|pq| pq.as_str()),
                uri.path_and_query().map(|pq| pq.as_str()),
                "{label}: roundtrip path_and_query"
            );
        }

        // Error cases: (label, URI, expected error)
        let err_cases: &[(&str, http::Uri, ParseError)] = &[
            (
                "unsupported scheme",
                "ftp://example.com/file".parse().unwrap(),
                ParseError::UnsupportedScheme,
            ),
            ("no scheme", http::Uri::from_static("/relative"), ParseError::RelativeUrlWithoutBase),
        ];

        for (label, uri, expected) in err_cases {
            let err = Url::from_http_uri(uri).unwrap_err();
            assert_eq!(err, *expected, "{label}");
        }
    }
}
