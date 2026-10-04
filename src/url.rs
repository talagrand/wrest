//! URL parsing and types.
//!
//! Provides a public [`Url`] type that matches a subset of
//! [`url::Url`](https://docs.rs/url/latest/url/struct.Url.html)'s method
//! signatures without embedding Unicode/IDNA tables. `fluent-uri` provides
//! strict RFC 3986/3987 parsing and reference resolution; ICU
//! provides UTS #46 conversion for non-ASCII domain names.
//!
//! Also provides [`IntoUrl`] (public trait) for eagerly validating URLs at
//! request-build time, matching reqwest semantics.
//!
//! # Limitations
//!
//! This parser accepts valid HTTP(S) URIs and IRIs rather than implementing
//! WHATWG error recovery for malformed browser input:
//!
//! - **Scheme restriction:** the native WinHTTP transport supports only
//!   `http` and `https`.
//! - **Unicode domains:** require ICU, shipped in Windows 10 version 1903+.
//! - **Strict input:** malformed percent escapes and invalid RFC syntax are
//!   rejected instead of repaired.
//! - **Sanitized userinfo:** unlike `url::Url`, Wrest stores userinfo
//!   percent-encoded and omits it from serialization during parsing. Request
//!   construction converts the decoded octets into `Authorization: Basic`,
//!   then removes the userinfo, matching reqwest's request behavior.

use crate::{Error, abi};
use fluent_uri::pct_enc::{Encoder, encoder::RegName};

// ---------------------------------------------------------------------------
// ParseError
// ---------------------------------------------------------------------------

/// An error type for URL parsing failures.
///
/// Returned by [`Url::parse`], [`Url::join`], and
/// [`FromStr`](std::str::FromStr).
///
/// # Variant names
///
/// The variant names mirror [`url::ParseError`](https://docs.rs/url/latest/url/enum.ParseError.html) so that code which
/// pattern-matches on specific variants can compile against both crates
/// without changes. Only a subset of variants is produced by Wrest's strict
/// HTTP(S) RFC parser:
///
/// | Variant                            | Produced by wrest? |
/// |------------------------------------|--------------------|
/// | `EmptyHost`                        | Yes |
/// | `IdnaError`                        | Yes |
/// | `InvalidPort`                      | Yes |
/// | `InvalidIpv4Address`               | No  |
/// | `InvalidIpv6Address`               | Yes |
/// | `InvalidDomainCharacter`           | Yes (decoded host is not a valid RFC registered name) |
/// | `RelativeUrlWithoutBase`           | Yes (`http::Uri` conversion) |
/// | `RelativeUrlWithCannotBeABaseBase` | No  |
/// | `SetHostOnCannotBeABaseUrl`        | No  |
/// | `Overflow`                         | No  |
/// | `InvalidUrl`                       | Yes (wrest-specific catch-all for RFC parse failures) |
/// | `UnsupportedScheme`                | Yes (wrest-specific, no `url` equivalent) |
///
/// Variants marked "No" exist for pattern-matching compatibility and will
/// never be returned by wrest's parser.  Code that just propagates with `?`
/// is unaffected regardless.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// The URL has an empty host.
    EmptyHost,

    /// An internationalized domain name contained invalid characters, or the
    /// system could not process Unicode domain names.
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
    /// This is a **wrest-specific** catch-all for RFC parse failures that do
    /// not map to a more specific variant. It has no `url::ParseError`
    /// equivalent.
    InvalidUrl,

    /// The URL scheme is not `http` or `https`.
    ///
    /// This variant is **wrest-specific** and has no `url::ParseError`
    /// equivalent.  Only `http` and `https` schemes are supported because
    /// that is what is supported by the native WinHTTP transport.
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
/// pulling in the `url` crate and its Unicode/IDNA tables.
///
/// Backed by `fluent-uri` and Windows system ICU. Only `http` and `https` schemes are supported.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Url {
    /// The serialized URL string.
    pub(crate) serialized: String,
    /// Scheme, lowercased (`"http"` or `"https"`).
    pub(crate) scheme: String,
    /// The hostname (e.g., `"example.com"`).
    pub(crate) host: String,
    /// Effective transport port, including the HTTP(S) default.
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
    /// Percent-encoded username from the `user:password@host` portion.
    /// Empty string when not present.
    pub(crate) username: String,
    /// Percent-encoded password from the `user:password@host` portion.
    /// `None` when not present.
    pub(crate) password: Option<crate::redact::Redacted<String>>,
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
    /// | Input form           | Example              | Behavior                                  |
    /// |----------------------|----------------------|-------------------------------------------|
    /// | Absolute URL         | `https://other/path` | Parsed independently                      |
    /// | Scheme-relative      | `//other/path`       | Uses base scheme                          |
    /// | Absolute path        | `/new/path`          | Replaces path, preserves authority        |
    /// | Relative path        | `sub/page`           | Merged with base path directory           |
    /// | Query-only           | `?q=1`               | Preserves base path                       |
    /// | Fragment-only        | `#sec`               | Preserves base path & query               |
    /// | Empty                | `""`                 | Inherits path/query and removes fragment  |
    pub fn join(&self, input: &str) -> Result<Self, ParseError> {
        let base_without_fragment = self.serialized_without_fragment();
        let base =
            fluent_uri::Iri::parse(base_without_fragment.as_str()).map_err(map_fluent_error)?;
        let reference = fluent_uri::IriRef::parse(input).map_err(map_fluent_error)?;
        let inherits_userinfo = reference.scheme().is_none() && reference.authority().is_none();
        if inherits_userinfo && reference.path().as_str().is_empty() {
            let encoded = reference.to_uri_ref();
            let mut joined = self.clone();
            if let Some(query) = encoded.query() {
                joined.query = Some(query.as_str().to_owned());
            }
            joined.fragment = encoded
                .fragment()
                .map(|fragment| fragment.as_str().to_owned());
            joined.rebuild_serialized();
            return Ok(joined);
        }
        let resolved = reference
            .resolve_against(&base)
            .map_err(|_| ParseError::InvalidUrl)?;
        let mut joined = Url::parse_impl(resolved.as_str())?;
        if inherits_userinfo {
            joined.username.clone_from(&self.username);
            joined.password.clone_from(&self.password);
        }
        Ok(joined)
    }

    /// Return the host as a domain name, if applicable.
    ///
    /// Returns `None` if the host is an IP address.
    /// Equivalent to `url::Url::domain()`.
    pub fn domain(&self) -> Option<&str> {
        // If the host string parses as an IP address, it's not a domain.
        if self.host.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }
        // Bracket-wrapped IPv6 like `[::1]`
        if self.host.starts_with('[') {
            return None;
        }
        Some(&self.host)
    }

    /// Return whether this URL has a host.
    ///
    /// Always `true` for HTTP/HTTPS URLs.
    /// Equivalent to `url::Url::has_host()`.
    pub fn has_host(&self) -> bool {
        true
    }

    /// Return whether this URL has an authority component.
    ///
    /// Always `true` for HTTP/HTTPS URLs.
    /// Equivalent to `url::Url::has_authority()`.
    pub fn has_authority(&self) -> bool {
        true
    }

    /// Return whether this URL cannot be a base.
    ///
    /// Always `false` for HTTP/HTTPS URLs.
    /// Equivalent to `url::Url::cannot_be_a_base()`.
    pub fn cannot_be_a_base(&self) -> bool {
        false
    }

    /// Return an iterator over the path segments.
    ///
    /// Always `Some` for HTTP/HTTPS URLs (they cannot be
    /// "cannot-be-a-base" URLs).
    /// Equivalent to `url::Url::path_segments()`.
    pub fn path_segments(&self) -> Option<std::str::Split<'_, char>> {
        // Strip the leading '/' then split (matching url::Url behavior
        // which yields "" for the first empty segment rather than a
        // leading empty string).
        let path = self.path.strip_prefix('/').unwrap_or(&self.path);
        Some(path.split('/'))
    }

    /// Return the percent-encoded username component of the URL.
    ///
    /// Returns `""` when no userinfo is present in the URL.
    /// Equivalent to `url::Url::username()`.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Return the percent-encoded password component of the URL, if present.
    ///
    /// Returns `None` when no password is present in the URL.
    /// Equivalent to `url::Url::password()`.
    pub fn password(&self) -> Option<&str> {
        self.password.as_ref().map(|r| r.expose().as_str())
    }
}

impl std::fmt::Display for Url {
    // `serialized` is built sans userinfo at parse time; no password leak via `{}`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.serialized)
    }
}

impl std::fmt::Debug for Url {
    /// Closely matches `url::Url`'s derived Debug format so that
    /// diagnostic output is identical regardless of which backend is
    /// active. The `password` field is redacted, however, unlike the `url` crate.
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
        Url::parse_impl(self).map_err(Error::builder)
    }
}
impl IntoUrl for &str {}

impl IntoUrlSealed for String {
    fn into_url(self) -> Result<Url, Error> {
        Url::parse_impl(&self).map_err(Error::builder)
    }
}
impl IntoUrl for String {}

impl IntoUrlSealed for &String {
    fn into_url(self) -> Result<Url, Error> {
        Url::parse_impl(self).map_err(Error::builder)
    }
}
impl IntoUrl for &String {}

impl IntoUrlSealed for Url {
    fn into_url(self) -> Result<Url, Error> {
        Ok(self)
    }
}
impl IntoUrl for Url {}

impl Url {
    /// Parse an HTTP(S) URI or IRI.
    ///
    /// `fluent-uri` validates and separates the RFC components. Non-ASCII
    /// registered names are converted with the UTS #46 APIs from system ICU.
    pub(crate) fn parse_impl(url: &str) -> Result<Self, ParseError> {
        let parsed = fluent_uri::Iri::parse(url).map_err(map_fluent_error)?;
        let scheme = parsed.scheme().as_str().to_ascii_lowercase();
        let is_https = scheme.eq_ignore_ascii_case("https");
        if !is_https && !scheme.eq_ignore_ascii_case("http") {
            return Err(ParseError::UnsupportedScheme);
        }
        let authority = parsed.authority().ok_or(ParseError::EmptyHost)?;
        if authority.host().is_empty() {
            return Err(ParseError::EmptyHost);
        }
        let host = match authority.host_parsed() {
            fluent_uri::component::Host::Ipv4(address) => address.to_string(),
            fluent_uri::component::Host::Ipv6(address) => format!("[{address}]"),
            fluent_uri::component::Host::IpvFuture { .. } => authority.host().to_owned(),
            fluent_uri::component::Host::RegName(name) => normalize_registered_name(name.as_str())?,
        };
        let default_port: u16 = if is_https { 443 } else { 80 };
        let parsed_port = authority
            .port_to_u16()
            .map_err(|_| ParseError::InvalidPort)?;
        let port = parsed_port.unwrap_or(default_port);
        let explicit_port = parsed_port.is_some_and(|port| port != default_port);

        let encoded = parsed.to_uri();
        let encoded_authority = encoded.authority().ok_or(ParseError::EmptyHost)?;
        let (username, password) = match encoded_authority.userinfo() {
            Some(userinfo) => match userinfo.as_str().split_once(':') {
                Some((user, "")) => (user.to_owned(), None),
                Some((user, password)) => (user.to_owned(), Some(password.to_owned())),
                None => (userinfo.as_str().to_owned(), None),
            },
            None => Default::default(),
        };
        let password = password.map(crate::redact::Redacted::new);

        let path = if encoded.path().as_str().is_empty() {
            "/".to_owned()
        } else {
            encoded.path().as_str().to_owned()
        };
        let query = encoded.query().map(|query| query.as_str().to_owned());
        let fragment = encoded
            .fragment()
            .map(|fragment| fragment.as_str().to_owned());
        let path_and_query = query
            .as_ref()
            .map_or_else(|| path.clone(), |query| format!("{path}?{query}"));

        let mut serialized = format!("{scheme}://{host}");
        if explicit_port {
            serialized.push(':');
            serialized.push_str(&port.to_string());
        }
        serialized.push_str(&path_and_query);
        if let Some(fragment) = &fragment {
            serialized.push('#');
            serialized.push_str(fragment);
        }

        Ok(Url {
            serialized,
            scheme,
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

    /// Update or clear the query string and re-serialize the URL.
    ///
    /// Replaces any existing query string. Updates `path_and_query` and
    /// `serialized` to stay consistent with the other fields.
    #[cfg_attr(all(not(feature = "query"), not(test)), expect(dead_code))]
    pub(crate) fn set_query(&mut self, query: Option<String>) {
        self.query = query;
        self.rebuild_serialized();
    }

    pub(crate) fn take_decoded_userinfo(&mut self) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
        if self.username.is_empty() && self.password.is_none() {
            return None;
        }

        let decode = |input: &str| percent_encoding::percent_decode_str(input).collect();
        let username = decode(&self.username);
        let password = self
            .password
            .as_ref()
            .map(|password| decode(password.expose()));
        self.username.clear();
        self.password = None;
        Some((username, password))
    }
    fn rebuild_serialized(&mut self) {
        self.path_and_query = self
            .query
            .as_ref()
            .map_or_else(|| self.path.clone(), |query| format!("{}?{query}", self.path));
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

    /// Build a `Url` from an absolute [`http::Uri`].
    ///
    /// The `http` crate has already validated its URI syntax. Routing the
    /// serialized form through the common parser applies the same scheme,
    /// authority, and host policy as other inputs.
    pub(crate) fn from_http_uri(uri: &http::Uri) -> Result<Self, ParseError> {
        if uri.scheme().is_none() {
            return Err(ParseError::RelativeUrlWithoutBase);
        }
        Self::parse_impl(&uri.to_string())
    }

    /// Convert this `Url` into an [`http::Uri`] from parts (no string roundtrip).
    ///
    /// Fragments are dropped because `http::Uri` does not carry them.
    ///
    /// In practice this conversion cannot fail: the scheme, authority, and
    /// path-and-query components were already validated during `Url`
    /// construction, so they satisfy `http::Uri`'s requirements.
    /// The `Result` exists only because the `http::Uri` builder API is
    /// generically fallible.
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

fn map_fluent_error(error: fluent_uri::ParseError) -> ParseError {
    match error.kind() {
        fluent_uri::ParseErrorKind::InvalidIpv6Addr => ParseError::InvalidIpv6Address,
        fluent_uri::ParseErrorKind::InvalidPctEncodedOctet
        | fluent_uri::ParseErrorKind::UnexpectedChar => ParseError::InvalidUrl,
    }
}

fn normalize_registered_name(host: &str) -> Result<String, ParseError> {
    let decoded = percent_decode(host)?;
    if decoded
        .chars()
        .any(|ch| ch.is_ascii() && !RegName::TABLE.allows(ch))
    {
        return Err(ParseError::InvalidDomainCharacter);
    }
    if decoded.is_ascii() {
        return Ok(decoded.to_ascii_lowercase());
    }

    let ascii = abi::idna_to_ascii(&decoded).map_err(|_| ParseError::IdnaError)?;
    if !ascii.chars().all(|ch| RegName::TABLE.allows(ch)) {
        return Err(ParseError::IdnaError);
    }
    Ok(ascii)
}

/// Percent-decode a UTF-8 string (e.g. `%40` to `@`).
fn percent_decode(input: &str) -> Result<String, ParseError> {
    percent_encoding::percent_decode_str(input)
        .decode_utf8()
        .map(std::borrow::Cow::into_owned)
        .map_err(|_| ParseError::InvalidUrl)
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

    #[test]
    fn percent_decode_matches_url_userinfo_expectations() {
        assert_eq!(percent_decode("alice%40example.com").unwrap(), "alice@example.com");
        assert_eq!(percent_decode("literal%ZZpercent").unwrap(), "literal%ZZpercent");
        assert_eq!(percent_decode("%FF").unwrap_err(), ParseError::InvalidUrl);
        let mut url = Url::parse("https://%FF@example.com").unwrap();
        assert_eq!(url.username(), "%FF");
        assert_eq!(url.take_decoded_userinfo(), Some((vec![0xFF], None)));
        assert_eq!(url.username(), "");
        assert_eq!(url.password(), None);
    }

    #[test]
    fn unicode_domains_use_system_uts46() {
        let result = Url::parse("https://faß.de/path");
        if crate::abi::is_icu_idna_available() {
            let url = result.unwrap();
            assert_eq!(url.host_str(), Some("xn--fa-hia.de"));
            assert_eq!(url.as_str(), "https://xn--fa-hia.de/path");
        } else {
            assert_eq!(result.unwrap_err(), ParseError::IdnaError);
        }
    }

    #[test]
    fn encoded_and_ascii_registered_names_do_not_require_icu() {
        let valid = [
            ("https://%65xample.com/", "example.com"),
            ("https://%2Dfoo.com/", "-foo.com"),
            ("https://xn--/", "xn--"),
        ];
        for (input, expected_host) in valid {
            assert_eq!(Url::parse(input).unwrap().host_str(), Some(expected_host), "{input}");
        }

        let invalid = [
            "https://example%2Fattacker.com/",
            "https://exa%22mple.com/",
            "https://exa%60mple.com/",
            "https://exa%7Bmple.com/",
            "https://exa%7Dmple.com/",
        ];
        for input in invalid {
            assert_eq!(
                Url::parse(input).unwrap_err(),
                ParseError::InvalidDomainCharacter,
                "{input}"
            );
        }
    }

    // -- Url parsing tests (data-driven) --

    /// (input, host, port, path, query, fragment)
    type ParseCase =
        (&'static str, &'static str, u16, &'static str, Option<&'static str>, Option<&'static str>);

    /// RFC-3986-valid URLs that must parse without changing component meaning.
    const PARSE_CASES: &[ParseCase] = &[
        // Basic structure
        ("https://example.com/api/v1?id=42", "example.com", 443, "/api/v1", Some("id=42"), None),
        ("http://localhost:8080/test", "localhost", 8080, "/test", None, None),
        ("https://example.com", "example.com", 443, "/", None, None),
        ("http://example.com", "example.com", 80, "/", None, None),
        ("https://[v1.addr]/resource", "[v1.addr]", 443, "/resource", None, None),
        (
            "https://example.com/path/to/resource",
            "example.com",
            443,
            "/path/to/resource",
            None,
            None,
        ),
        ("https://example.com:9443/secure", "example.com", 9443, "/secure", None, None),
        // Fragment
        ("https://example.com/page#section", "example.com", 443, "/page", None, Some("section")),
        // Query + fragment
        (
            "https://example.com/api?key=val&a=b#frag",
            "example.com",
            443,
            "/api",
            Some("key=val&a=b"),
            Some("frag"),
        ),
        // Percent-encoding preservation (no double-encoding)
        (
            "http://tlu.dl.delivery.mp.microsoft.com/files/abc123?P1=123&P2=404&P3=2&P4=cLS1G9%2btest%2fvalue%3d%3d",
            "tlu.dl.delivery.mp.microsoft.com",
            80,
            "/files/abc123",
            Some("P1=123&P2=404&P3=2&P4=cLS1G9%2btest%2fvalue%3d%3d"),
            None,
        ),
        // %25 (encoded percent) survives round-trip in all components
        ("https://example.com/%25?%25#%25", "example.com", 443, "/%25", Some("%25"), Some("%25")),
        // Mixed encoded and literal characters
        (
            "https://example.com/a%2Fb?x=%3D#y%23z",
            "example.com",
            443,
            "/a%2Fb",
            Some("x=%3D"),
            Some("y%23z"),
        ),
    ];

    #[test]
    fn parse_urls() {
        for &(input, host, port, path, query, fragment) in PARSE_CASES {
            let parsed = input.into_url().unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(parsed.host, host, "{input}: host");
            assert_eq!(parsed.port, port, "{input}: port");
            assert_eq!(parsed.path(), path, "{input}: path");
            assert_eq!(parsed.query(), query, "{input}: query");
            assert_eq!(parsed.fragment(), fragment, "{input}: fragment");
            // No spurious double-encoding.
            assert!(
                !parsed.as_str().contains("%25") || input.contains("%25"),
                "{input}: spurious %25 in as_str(): {}",
                parsed.as_str()
            );
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
        // Matches url::Url derived Debug: `Url { scheme: ..., host: Some(Domain("...")), ... }`
        assert!(debug.starts_with("Url { "), "expected struct debug: {debug}");
        assert!(debug.contains("scheme: \"https\""), "scheme: {debug}");
        assert!(debug.contains("host: Some(Domain(\"example.com\"))"), "host: {debug}");
        assert!(debug.contains("path: \"/path\""), "path: {debug}");
        assert!(debug.contains("port: None"), "default port should be None: {debug}");
    }

    #[test]
    fn url_debug_redacts_password() {
        // `Url::Debug` must not leak the password field -- panic messages,
        // `dbg!`, and `tracing` events with `?error` formatters all reach
        // Debug.
        let url: Url = "https://alice:s3cret@example.com/path".parse().unwrap();
        let debug = format!("{url:?}");
        assert!(!debug.contains("s3cret"), "Debug must redact password: {debug}");
        assert!(
            debug.contains("password: Some(\"<redacted>\")"),
            "Debug should preserve Some/None shape with placeholder: {debug}"
        );
        // Username is not a secret in the URL spec; keep it visible.
        assert!(debug.contains("username: \"alice\""), "username should remain visible: {debug}");
        // Display path stays clean as well.
        assert_eq!(format!("{url}"), "https://example.com/path");
        // No-password URLs render `password: None`.
        let nopw: Url = "https://example.com/path".parse().unwrap();
        assert!(format!("{nopw:?}").contains("password: None"), "no-password URL should show None");
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
            ("https://example.com/page#", "/page", None, Some("")),
            ("https://example.com/page?", "/page", Some(""), None),
            ("https://example.com/page?#", "/page", Some(""), Some("")),
            ("https://example.com/path?q=1#", "/path", Some("q=1"), Some("")),
            ("https://example.com/path?#frag", "/path", Some(""), Some("frag")),
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
        // -- Percent-encoded dot-segments (RFC 3986 §5.2.4 + §6.2.2.2) --
        // `%2e` / `%2E` are dot-equivalent for segment classification.
        // `%2f` (encoded slash) is NOT a separator -- it stays inside
        // whatever segment it appears in (matching WinHTTP wire behavior).
        (
            "https://example.com/base/a/b/",
            "%2e%2e/secret",
            "https://example.com/base/a/secret",
            "percent-encoded ../ traversal",
        ),
        (
            "https://example.com/base/",
            "%2e%2e%2fsecret",
            "https://example.com/base/%2e%2e%2fsecret",
            "%2f stays encoded -- not a separator (single opaque segment)",
        ),
        (
            "https://example.com/a/b/c",
            "%2E%2E/d",
            "https://example.com/a/d",
            "uppercase %2E%2E as ..",
        ),
        (
            "https://example.com/a/b/c",
            "a/%2e/b",
            "https://example.com/a/b/a/b",
            "%2e as . in middle",
        ),
        (
            "https://example.com/a/b/c",
            "%2e%2E/d",
            "https://example.com/a/d",
            "mixed-case %2e%2E as ..",
        ),
        (
            "https://example.com/a/b/c",
            ".%2e/d",
            "https://example.com/a/d",
            "mixed literal+encoded .%2e as ..",
        ),
        (
            "https://example.com/a/b/c",
            "%2e./d",
            "https://example.com/a/d",
            "mixed encoded+literal %2e. as ..",
        ),
        (
            "https://example.com/a/b/c",
            "%2ex",
            "https://example.com/a/b/%2ex",
            "%2ex is not a dot-segment",
        ),
        (
            "https://example.com/a/b/c",
            "%2e%2e%2e/d",
            "https://example.com/a/b/%2e%2e%2e/d",
            "%2e%2e%2e (three dots) is not a dot-segment",
        ),
        (
            "https://example.com/a/b/c",
            "%2e",
            "https://example.com/a/b/",
            "trailing %2e preserves trailing slash",
        ),
        (
            "https://example.com/a/b/c",
            "%2e%2e",
            "https://example.com/a/",
            "trailing %2e%2e preserves trailing slash",
        ),
        // -- Empty input inherits everything except the fragment --
        (
            "https://example.com/a/b?q=1#f",
            "",
            "https://example.com/a/b?q=1",
            "empty input removes fragment",
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
    fn empty_path_references_preserve_base_dot_segments() {
        let cases = [
            ("https://example.com/a/../b?old=1#old", "", "https://example.com/a/../b?old=1"),
            ("https://example.com/a/../b?old=1#old", "?new=1", "https://example.com/a/../b?new=1"),
            (
                "https://example.com/a/../b?old=1#old",
                "#new",
                "https://example.com/a/../b?old=1#new",
            ),
            (
                "https://example.com/a/%2e%2e/b?old=1#old",
                "?new=1",
                "https://example.com/a/%2e%2e/b?new=1",
            ),
        ];

        for (base, reference, expected) in cases {
            let base = Url::parse(base).unwrap();
            assert_eq!(base.join(reference).unwrap().as_str(), expected, "{reference:?}");
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
            ("https://user%40domain:p%3Ass@example.com/", "user%40domain", Some("p%3Ass")),
            ("https://caf%C3%A9:p%40ss@example.com/", "caf%C3%A9", Some("p%40ss")),
            // Empty password (user:@)
            ("https://user:@example.com/", "user", None),
            // Empty userinfo
            ("https://@example.com/", "", None),
            // Empty username with password
            ("https://:secret@example.com/", "", Some("secret")),
            // Percent-encoded unreserved characters remain encoded.
            ("https://user%41%62:p%4Fss@example.com/", "user%41%62", Some("p%4Fss")),
            // Percent-escape hex digit casing is preserved.
            ("https://%5A%6a@example.com/", "%5A%6a", None),
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

    // -- set_query --

    #[test]
    fn set_query_table() {
        // (input_url, new_query, expected_query, expected_as_str, expected_path_and_query, label)
        type Case<'a> = (&'a str, Option<&'a str>, Option<&'a str>, &'a str, &'a str, &'a str);
        let cases: &[Case<'_>] = &[
            (
                "https://example.com/api",
                Some("key=val"),
                Some("key=val"),
                "https://example.com/api?key=val",
                "/api?key=val",
                "adds query",
            ),
            (
                "https://example.com:9443/api#frag",
                Some("a=1&b=2"),
                Some("a=1&b=2"),
                "https://example.com:9443/api?a=1&b=2#frag",
                "/api?a=1&b=2",
                "with port and fragment",
            ),
            (
                "https://example.com/api?old=1",
                Some("new=2"),
                Some("new=2"),
                "https://example.com/api?new=2",
                "/api?new=2",
                "replaces existing",
            ),
            (
                "https://example.com/api?#frag",
                None,
                None,
                "https://example.com/api#frag",
                "/api",
                "clears query",
            ),
        ];

        for &(input, query, exp_query, exp_str, exp_pq, label) in cases {
            let mut url = Url::parse(input).unwrap();
            url.set_query(query.map(str::to_owned));
            assert_eq!(url.query(), exp_query, "{label}: query()");
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
        (
            "https://user%GG:pass@example.com/path",
            ParseError::InvalidUrl,
            "invalid URL",
            "invalid percent encoding in userinfo",
        ),
    ];

    #[test]
    fn parse_error_table() {
        for (input, expected, display, label) in PARSE_ERROR_TABLE {
            // Url::parse
            let err = Url::parse(input).unwrap_err();
            assert_eq!(&err, expected, "{label}: variant");
            assert_eq!(err.to_string(), *display, "{label}: Display");

            // FromStr
            let err2: ParseError = input.parse::<Url>().unwrap_err();
            assert_eq!(&err2, expected, "{label}: FromStr variant");
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

        // Debug, Clone, PartialEq, Eq
        let err = ParseError::UnsupportedScheme;
        let cloned = err.clone();
        assert_eq!(format!("{err:?}"), format!("{cloned:?}"));
    }

    // -- trivial accessors --

    #[test]
    fn url_trivial_accessors() {
        let url = Url::parse("https://example.com").unwrap();
        assert!(url.has_host());
        assert!(url.has_authority());
        assert!(!url.cannot_be_a_base());
    }

    #[test]
    fn url_domain_table() {
        let cases: &[(&str, Option<&str>)] = &[
            ("https://example.com/path", Some("example.com")),
            ("https://sub.example.co.uk", Some("sub.example.co.uk")),
            ("https://127.0.0.1/path", None),
            ("https://[::1]/path", None),
            ("https://0.0.0.0", None),
        ];
        for &(input, expected) in cases {
            let url = Url::parse(input).unwrap();
            assert_eq!(url.domain(), expected, "domain() for {input}");
        }
    }

    #[test]
    fn url_path_segments_table() {
        let cases: &[(&str, &[&str])] = &[
            ("https://example.com/a/b/c", &["a", "b", "c"]),
            ("https://example.com/", &[""]),
            ("https://example.com/one", &["one"]),
            ("https://example.com/a/b/", &["a", "b", ""]),
        ];
        for &(input, expected) in cases {
            let url = Url::parse(input).unwrap();
            let segs: Vec<&str> = url.path_segments().unwrap().collect();
            assert_eq!(segs, expected, "path_segments() for {input}");
        }
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
            (
                "http default port explicit",
                "http://example.com:80/path",
                ("http", "example.com", 80, None),
                ("/path", None),
                ("", None),
                "http://example.com/path",
            ),
            (
                "https default port explicit",
                "https://example.com:443/path",
                ("https", "example.com", 443, None),
                ("/path", None),
                ("", None),
                "https://example.com/path",
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

            // Roundtrip: from_http_uri -> to_http_uri preserves scheme + authority + path_and_query
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
            ("empty host", http::Uri::from_static("http://:8080/path"), ParseError::EmptyHost),
        ];

        for (label, uri, expected) in err_cases {
            let err = Url::from_http_uri(uri).unwrap_err();
            assert_eq!(err, *expected, "{label}");
        }
    }
}
