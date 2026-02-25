//! Proxy configuration from environment variables.
//!
//! Reads `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` env vars once at
//! [`Client`](crate::Client) build time and caches the result. Per-request
//! proxy resolution checks the cached `NO_PROXY` list against each request's
//! target host.
//!
//! Also provides public [`Proxy`] and [`NoProxy`] types matching reqwest's API.

use crate::util::read_env_var;

// ---------------------------------------------------------------------------
// Public types -- match reqwest::Proxy / reqwest::NoProxy
// ---------------------------------------------------------------------------

/// A proxy configuration.
///
/// Matches the [`reqwest::Proxy`](https://docs.rs/reqwest/latest/reqwest/struct.Proxy.html)
/// API surface. Pass to [`ClientBuilder::proxy()`](crate::ClientBuilder::proxy).
///
/// # Example
///
/// ```rust,ignore
/// use wrest::Proxy;
///
/// let proxy = Proxy::all("http://proxy:8080").unwrap();
/// let client = wrest::Client::builder()
///     .proxy(proxy)
///     .build()?;
/// ```
#[derive(Debug, Clone)]
pub struct Proxy {
    kind: ProxyKind,
    url: String,
    /// Optional Basic-auth credentials for the proxy.
    creds: Option<(String, String)>,
}

#[derive(Debug, Clone)]
enum ProxyKind {
    /// Proxy all traffic (both HTTP and HTTPS).
    All,
    /// Proxy HTTP traffic only.
    Http,
    /// Proxy HTTPS traffic only.
    Https,
}

/// Validate a proxy URL string.
///
/// Requires the URL to have an `http://` or `https://` scheme and a
/// non-empty host component.  `socks5://` is explicitly rejected because
/// WinHTTP does not support SOCKS proxies.  Returns the URL as-is on
/// success.
fn validate_proxy_url(url: &str) -> crate::Result<()> {
    if url.is_empty() {
        return Err(crate::Error::builder("proxy URL must not be empty"));
    }
    // Reject SOCKS -- WinHTTP only supports HTTP CONNECT proxies.
    if url.starts_with("socks5://") || url.starts_with("socks4://") {
        return Err(crate::Error::builder(format!(
            "SOCKS proxies are not supported by WinHTTP -- got {url:?}"
        )));
    }
    // Strip the scheme prefix and validate a host follows
    let rest = if let Some(r) = url.strip_prefix("http://") {
        r
    } else if let Some(r) = url.strip_prefix("https://") {
        r
    } else {
        return Err(crate::Error::builder(format!(
            "proxy URL must start with http:// or https:// -- got {url:?}"
        )));
    };
    // After the scheme there must be at least one host character
    let host_part = rest.split('/').next().unwrap_or("");
    let host_part = host_part.split(':').next().unwrap_or("");
    if host_part.is_empty() {
        return Err(crate::Error::builder(format!("proxy URL has no host -- got {url:?}")));
    }
    Ok(())
}

impl Proxy {
    /// Shared constructor: validate + build.
    fn new_validated(kind: ProxyKind, url: &str) -> crate::Result<Self> {
        validate_proxy_url(url)?;
        Ok(Self {
            kind,
            url: url.to_owned(),
            creds: None,
        })
    }

    /// Proxy all HTTP and HTTPS traffic through the given URL.
    ///
    /// The URL must have an `http://` or `https://` scheme.
    /// SOCKS proxies are not supported by WinHTTP.
    pub fn all(url: &str) -> crate::Result<Self> {
        Self::new_validated(ProxyKind::All, url)
    }

    /// Proxy HTTP traffic through the given URL.
    ///
    /// The URL must have an `http://` or `https://` scheme.
    /// SOCKS proxies are not supported by WinHTTP.
    pub fn http(url: &str) -> crate::Result<Self> {
        Self::new_validated(ProxyKind::Http, url)
    }

    /// Proxy HTTPS traffic through the given URL.
    ///
    /// The URL must have an `http://` or `https://` scheme.
    /// SOCKS proxies are not supported by WinHTTP.
    pub fn https(url: &str) -> crate::Result<Self> {
        Self::new_validated(ProxyKind::Https, url)
    }

    /// Apply this proxy to a [`ProxyConfig`], merging with existing env-based config.
    pub(crate) fn apply_to(self, config: &mut ProxyConfig) {
        match self.kind {
            ProxyKind::All => {
                config.http_proxy_url = Some(self.url.clone());
                config.https_proxy_url = Some(self.url);
                config.http_proxy_creds = self.creds.clone();
                config.https_proxy_creds = self.creds;
            }
            ProxyKind::Http => {
                config.http_proxy_url = Some(self.url);
                config.http_proxy_creds = self.creds;
            }
            ProxyKind::Https => {
                config.https_proxy_url = Some(self.url);
                config.https_proxy_creds = self.creds;
            }
        }
    }

    /// Set proxy credentials using HTTP Basic authentication.
    ///
    /// The credentials are passed to WinHTTP via
    /// [`WinHttpSetCredentials`](https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpsettcredentials)
    /// on each request that uses this proxy.
    ///
    /// Matches [`reqwest::Proxy::basic_auth()`](https://docs.rs/reqwest/latest/reqwest/struct.Proxy.html#method.basic_auth).
    #[must_use]
    pub fn basic_auth(mut self, username: &str, password: &str) -> Proxy {
        self.creds = Some((username.to_owned(), password.to_owned()));
        self
    }

    /// Adds a `No Proxy` exclusion list to this Proxy.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// wrest applies no-proxy rules at the `ClientBuilder` level
    /// rather than per-`Proxy`.  Use
    /// [`ClientBuilder::no_proxy()`](crate::ClientBuilder::no_proxy)
    /// or the `NO_PROXY` env var instead.  Requires the `noop-compat`
    /// feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn no_proxy(self, _no_proxy: Option<NoProxy>) -> Proxy {
        self
    }
}

/// A matcher for hosts that should bypass the proxy.
///
/// Matches [`reqwest::NoProxy`](https://docs.rs/reqwest/latest/reqwest/struct.NoProxy.html).
///
/// # Example
///
/// ```rust,ignore
/// use wrest::NoProxy;
///
/// let no_proxy = NoProxy::from_string("localhost,.internal.corp").unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct NoProxy {
    /// Only consumed via `apply_to` (test-only) -- in production,
    /// `Proxy::no_proxy()` is a no-op and bypass patterns come from
    /// `ProxyConfig::from_env()` directly.
    #[cfg_attr(not(test), expect(dead_code))]
    patterns: Vec<NoProxyPattern>,
}

impl NoProxy {
    /// Parse a comma-separated list of `NO_PROXY` patterns.
    ///
    /// Returns `None` if the input is empty or contains only whitespace,
    /// matching [`reqwest::NoProxy::from_string()`](https://docs.rs/reqwest/latest/reqwest/struct.NoProxy.html#method.from_string).
    ///
    /// Supports the same syntax as the `NO_PROXY` environment variable:
    /// exact hostnames, domain suffixes (`.example.com`), and `*` for all.
    pub fn from_string(s: &str) -> Option<Self> {
        let patterns = parse_no_proxy(s);
        if patterns.is_empty() {
            None
        } else {
            Some(Self { patterns })
        }
    }

    /// Read from the `NO_PROXY` environment variable.
    pub fn from_env() -> Option<Self> {
        let raw = read_env_var("NO_PROXY")?;
        Self::from_string(&raw)
    }

    /// Apply this no-proxy list to a [`ProxyConfig`].
    #[cfg(test)]
    pub(crate) fn apply_to(self, config: &mut ProxyConfig) {
        config.no_proxy = self.patterns;
    }
}

impl Default for NoProxy {
    /// Create an empty no-proxy configuration that matches nothing.
    fn default() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// Cached proxy configuration, read from environment variables at build time.
#[derive(Debug, Clone)]
pub(crate) struct ProxyConfig {
    /// Proxy URL for HTTP targets (from `HTTP_PROXY` or `http_proxy`).
    pub http_proxy_url: Option<String>,
    /// Proxy URL for HTTPS targets (from `HTTPS_PROXY` or `https_proxy`).
    pub https_proxy_url: Option<String>,
    /// Parsed `NO_PROXY` patterns (from `NO_PROXY` or `no_proxy`).
    pub no_proxy: Vec<NoProxyPattern>,
    /// Optional Basic-auth credentials for the HTTP proxy.
    pub http_proxy_creds: Option<(String, String)>,
    /// Optional Basic-auth credentials for the HTTPS proxy.
    pub https_proxy_creds: Option<(String, String)>,
}

/// What proxy action to take for a given request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProxyAction {
    /// Connect directly, bypassing all proxies (`NO_PROXY` match).
    Direct,
    /// Use the specified proxy URL (`HTTP_PROXY` / `HTTPS_PROXY`),
    /// with optional Basic-auth credentials `(username, password)`.
    Named(String, Option<(String, String)>),
    /// Use OS auto-detection (WPAD/PAC + system settings).
    Automatic,
}

/// A single pattern from the `NO_PROXY` environment variable.
#[derive(Debug, Clone)]
pub(crate) enum NoProxyPattern {
    /// `*` -- bypass proxy for all hosts.
    Wildcard,
    /// Exact hostname match (case-insensitive).
    Exact(String),
    /// Domain suffix match (e.g., `.example.com` matches `foo.example.com`).
    /// Stored without leading dot, lowercased.
    DomainSuffix(String),
}

impl ProxyConfig {
    /// Read proxy configuration from environment variables.
    ///
    /// All env vars are read once and cached. Changes to env vars after
    /// this call are not reflected -- matching reqwest semantics.
    pub fn from_env() -> Self {
        let http_proxy_url = read_env_var("HTTP_PROXY");
        let https_proxy_url = read_env_var("HTTPS_PROXY");
        let no_proxy_raw = read_env_var("NO_PROXY");
        let no_proxy = no_proxy_raw.map(|s| parse_no_proxy(&s)).unwrap_or_default();

        trace!(
            http_proxy = http_proxy_url.as_deref().unwrap_or("<none>"),
            https_proxy = https_proxy_url.as_deref().unwrap_or("<none>"),
            no_proxy_count = no_proxy.len(),
            "proxy config from env",
        );

        Self {
            http_proxy_url,
            https_proxy_url,
            no_proxy,
            http_proxy_creds: None,
            https_proxy_creds: None,
        }
    }

    /// Create a config with no proxy (direct connections only).
    pub fn none() -> Self {
        Self {
            http_proxy_url: None,
            https_proxy_url: None,
            no_proxy: Vec::new(),
            http_proxy_creds: None,
            https_proxy_creds: None,
        }
    }

    /// Create a config that ignores env-var proxy settings.
    ///
    /// Unlike [`from_env()`](Self::from_env), this starts with no
    /// proxy URLs and no bypass list. Used by
    /// [`ClientBuilder::no_proxy()`](crate::ClientBuilder::no_proxy).
    pub fn none_from_env() -> Self {
        Self::none()
    }

    /// Resolve the proxy action for a given request.
    ///
    /// Checks the cached `NO_PROXY` patterns against `host`, then falls
    /// back to the cached proxy URL for the request scheme.
    pub fn resolve(&self, host: &str, is_https: bool) -> ProxyAction {
        // 1. Check NO_PROXY patterns
        if self.no_proxy.iter().any(|p| p.matches(host)) {
            trace!(host, "proxy resolve: NO_PROXY match -> Direct");
            return ProxyAction::Direct;
        }

        // 2. Use cached proxy URL for the target scheme
        let (proxy_url, proxy_creds) = if is_https {
            (&self.https_proxy_url, &self.https_proxy_creds)
        } else {
            (&self.http_proxy_url, &self.http_proxy_creds)
        };
        if let Some(url) = proxy_url {
            return ProxyAction::Named(url.clone(), proxy_creds.clone());
        }

        // 3. Fall back to OS auto-detection
        ProxyAction::Automatic
    }
}

impl NoProxyPattern {
    /// Check if this pattern matches the given hostname.
    pub fn matches(&self, host: &str) -> bool {
        let host_lower = host.to_ascii_lowercase();
        match self {
            NoProxyPattern::Wildcard => true,
            NoProxyPattern::Exact(exact) => host_lower == *exact,
            NoProxyPattern::DomainSuffix(suffix) => {
                // "example.com" matches "example.com" and "foo.example.com"
                host_lower == *suffix || host_lower.ends_with(&format!(".{suffix}"))
            }
        }
    }
}

/// Parse the `NO_PROXY` env var value into a list of patterns.
fn parse_no_proxy(value: &str) -> Vec<NoProxyPattern> {
    value
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            if s == "*" {
                NoProxyPattern::Wildcard
            } else if let Some(suffix) = s.strip_prefix('.') {
                // ".example.com" -> suffix match on "example.com"
                NoProxyPattern::DomainSuffix(suffix.to_ascii_lowercase())
            } else if s.contains('.') {
                // "example.com" -> matches both exact and as suffix
                // (e.g., "example.com" matches "foo.example.com")
                NoProxyPattern::DomainSuffix(s.to_ascii_lowercase())
            } else {
                // "localhost", "myhost" -> exact match only
                NoProxyPattern::Exact(s.to_ascii_lowercase())
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- NoProxyPattern matching --

    #[test]
    fn no_proxy_pattern_matches() {
        // (pattern, host, expected_match)
        let cases: &[(NoProxyPattern, &str, bool)] = &[
            // Wildcard matches everything
            (NoProxyPattern::Wildcard, "example.com", true),
            (NoProxyPattern::Wildcard, "anything.at.all", true),
            // Exact: case-insensitive, no subdomain matching
            (NoProxyPattern::Exact("localhost".into()), "localhost", true),
            (NoProxyPattern::Exact("localhost".into()), "LOCALHOST", true),
            (NoProxyPattern::Exact("localhost".into()), "Localhost", true),
            (NoProxyPattern::Exact("localhost".into()), "localhost.localdomain", false),
            // DomainSuffix: exact + subdomain, case-insensitive
            (NoProxyPattern::DomainSuffix("example.com".into()), "example.com", true),
            (NoProxyPattern::DomainSuffix("example.com".into()), "foo.example.com", true),
            (NoProxyPattern::DomainSuffix("example.com".into()), "bar.foo.example.com", true),
            (NoProxyPattern::DomainSuffix("example.com".into()), "notexample.com", false),
            (NoProxyPattern::DomainSuffix("example.com".into()), "example.com.evil.com", false),
            (NoProxyPattern::DomainSuffix("example.com".into()), "EXAMPLE.COM", true),
            (NoProxyPattern::DomainSuffix("example.com".into()), "FOO.Example.Com", true),
        ];

        for (pat, host, expected) in cases {
            assert_eq!(pat.matches(host), *expected, "{pat:?}.matches({host:?})");
        }
    }

    // -- parse_no_proxy --

    #[test]
    fn parse_no_proxy_lengths() {
        // (input, expected_pattern_count)
        let cases: &[(&str, usize)] = &[
            ("*", 1),
            (".example.com", 1),
            ("example.com", 1),
            ("localhost, .internal.corp, example.com", 3),
            ("localhost,,, .example.com,", 2),
            ("", 0),
        ];

        for &(input, expected_len) in cases {
            let patterns = parse_no_proxy(input);
            assert_eq!(patterns.len(), expected_len, "parse_no_proxy({input:?}).len()");
        }
    }

    #[test]
    fn parse_no_proxy_matching_behavior() {
        // Verify parsed patterns match expected hosts
        // (input, host_to_test, expected_match)
        let cases: &[(&str, &str, bool)] = &[
            ("*", "anything", true),
            (".example.com", "foo.example.com", true),
            (".example.com", "example.com", true),
            ("example.com", "example.com", true),
            ("example.com", "foo.example.com", true),
            ("localhost", "localhost", true),
            ("localhost", "foo.localhost", false),
        ];

        for &(input, host, expected) in cases {
            let patterns = parse_no_proxy(input);
            assert!(!patterns.is_empty(), "parse_no_proxy({input:?}) should not be empty");
            assert_eq!(
                patterns[0].matches(host),
                expected,
                "parse_no_proxy({input:?})[0].matches({host:?})"
            );
        }
    }

    // -- ProxyConfig::resolve (data-driven) --

    /// Helper to build a `ProxyConfig` from optional proxy URLs and no_proxy patterns.
    fn config(
        http: Option<&str>,
        https: Option<&str>,
        no_proxy: Vec<NoProxyPattern>,
    ) -> ProxyConfig {
        ProxyConfig {
            http_proxy_url: http.map(String::from),
            https_proxy_url: https.map(String::from),
            no_proxy,
            http_proxy_creds: None,
            https_proxy_creds: None,
        }
    }

    #[test]
    fn resolve_table() {
        let cases: &[(ProxyConfig, &str, bool, ProxyAction)] = &[
            // No env vars -> Automatic
            (config(None, None, vec![]), "example.com", true, ProxyAction::Automatic),
            // HTTPS uses https_proxy
            (
                config(Some("http://http-proxy:8080"), Some("http://https-proxy:8080"), vec![]),
                "example.com",
                true,
                ProxyAction::Named("http://https-proxy:8080".into(), None),
            ),
            // HTTP uses http_proxy
            (
                config(Some("http://http-proxy:8080"), Some("http://https-proxy:8080"), vec![]),
                "example.com",
                false,
                ProxyAction::Named("http://http-proxy:8080".into(), None),
            ),
            // no_proxy match -> Direct
            (
                config(
                    Some("http://proxy:8080"),
                    Some("http://proxy:8080"),
                    vec![NoProxyPattern::DomainSuffix("internal.corp".into())],
                ),
                "api.internal.corp",
                true,
                ProxyAction::Direct,
            ),
            // Wildcard no_proxy -> Direct
            (
                config(
                    Some("http://proxy:8080"),
                    Some("http://proxy:8080"),
                    vec![NoProxyPattern::Wildcard],
                ),
                "anything.com",
                true,
                ProxyAction::Direct,
            ),
        ];

        for (cfg, host, is_https, expected) in cases {
            let actual = cfg.resolve(host, *is_https);
            assert_eq!(actual, *expected, "resolve({host:?}, is_https={is_https})");
        }
    }

    #[test]
    fn resolve_priority_no_proxy_before_named() {
        // Even when proxy URLs are set, NO_PROXY takes precedence
        let cfg = config(
            Some("http://proxy:8080"),
            Some("http://proxy:8080"),
            vec![NoProxyPattern::DomainSuffix("example.com".into())],
        );
        assert_eq!(cfg.resolve("api.example.com", false), ProxyAction::Direct);
        // But non-matching host still uses proxy
        assert_eq!(
            cfg.resolve("other.com", false),
            ProxyAction::Named("http://proxy:8080".into(), None)
        );
    }

    // -- parse_no_proxy: Exact vs DomainSuffix --

    #[test]
    fn parse_no_proxy_exact_vs_domain_suffix() {
        // (input, host, expected_match, description)
        let cases: &[(&str, &str, bool, &str)] = &[
            // No dot -> Exact -> no subdomain matching
            ("localhost", "localhost", true, "exact self-match"),
            ("localhost", "foo.localhost", false, "exact rejects subdomain"),
            // Has dot -> DomainSuffix -> matches exact + subdomains
            ("example.com", "example.com", true, "suffix exact match"),
            ("example.com", "foo.example.com", true, "suffix subdomain match"),
        ];

        for &(input, host, expected, desc) in cases {
            let patterns = parse_no_proxy(input);
            assert_eq!(patterns.len(), 1);
            assert_eq!(
                patterns[0].matches(host),
                expected,
                "{desc}: parse_no_proxy({input:?})[0].matches({host:?})"
            );
        }
    }

    // -- from_env: env var reading and caching --
    //
    // Windows env vars are case-insensitive, so the uppercase-vs-lowercase
    // priority in `from_env` (`HTTPS_PROXY` before `https_proxy`) is a no-op
    // on this platform. We only test that values are read and cached.
    //
    // A static mutex serialises tests that mutate the process env.

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Helper to run a closure with specific env vars set, then restore originals.
    ///
    /// # Safety note
    /// `std::env::set_var` / `remove_var` are `unsafe` in edition 2024 because
    /// modifying env vars is not thread-safe. The caller must hold `ENV_LOCK`.
    fn with_env_vars<F: FnOnce()>(vars: &[(&str, Option<&str>)], f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // Save originals
        let saved: Vec<(&str, Option<String>)> = vars
            .iter()
            .map(|(k, _)| (*k, std::env::var(k).ok()))
            .collect();

        // Set requested values
        for (k, v) in vars {
            // SAFETY: test-only; serialised by ENV_LOCK.
            unsafe {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }

        f();

        // Restore originals
        for (k, orig) in &saved {
            // SAFETY: test-only; serialised by ENV_LOCK.
            unsafe {
                match orig {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    #[test]
    fn from_env_reads_proxy_vars() {
        with_env_vars(
            &[
                ("HTTPS_PROXY", Some("http://proxy:8080")),
                ("HTTP_PROXY", Some("http://http-proxy:8080")),
                ("NO_PROXY", None),
            ],
            || {
                let config = ProxyConfig::from_env();
                assert_eq!(config.https_proxy_url.as_deref(), Some("http://proxy:8080"));
                assert_eq!(config.http_proxy_url.as_deref(), Some("http://http-proxy:8080"));
            },
        );
    }

    #[test]
    fn from_env_cached_at_build_time() {
        with_env_vars(
            &[
                ("HTTPS_PROXY", Some("http://proxy:8080")),
                ("HTTP_PROXY", None),
                ("NO_PROXY", Some("internal.corp")),
            ],
            || {
                let config = ProxyConfig::from_env();
                assert_eq!(config.https_proxy_url.as_deref(), Some("http://proxy:8080"));

                // Change env vars after build -- config should be unaffected
                // SAFETY: test-only; serialised by ENV_LOCK.
                unsafe {
                    std::env::set_var("HTTPS_PROXY", "http://changed:9090");
                    std::env::remove_var("NO_PROXY");
                }

                // Cached config still has the original values
                assert_eq!(config.https_proxy_url.as_deref(), Some("http://proxy:8080"));
                assert_eq!(config.no_proxy.len(), 1);
                assert!(config.no_proxy[0].matches("api.internal.corp"));
            },
        );
    }

    // -- NoProxy::from_string() returns Option --

    #[test]
    fn no_proxy_from_string_option() {
        // (input, expected_is_some)
        let cases: &[(&str, bool)] =
            &[("localhost,.example.com", true), ("", false), ("   ", false)];

        for &(input, expected_some) in cases {
            assert_eq!(
                NoProxy::from_string(input).is_some(),
                expected_some,
                "NoProxy::from_string({input:?})"
            );
        }
    }

    // -- NoProxy::default() --

    #[test]
    fn no_proxy_default_is_empty() {
        let np = NoProxy::default();
        assert!(np.patterns.is_empty());
    }

    // -- Proxy::basic_auth() --

    #[test]
    fn proxy_basic_auth_stores_credentials() {
        let proxy = Proxy::all("http://proxy:8080").unwrap();
        let proxy = proxy.basic_auth("user", "pass");
        assert_eq!(proxy.url, "http://proxy:8080");
        assert_eq!(proxy.creds, Some(("user".to_owned(), "pass".to_owned())));
    }

    #[test]
    fn proxy_basic_auth_creds_flow_through_resolve() {
        let proxy = Proxy::all("http://proxy:8080")
            .unwrap()
            .basic_auth("alice", "s3cret");
        let mut config = ProxyConfig::none();
        proxy.apply_to(&mut config);
        // Credentials should be stored on the config
        assert_eq!(config.http_proxy_creds, Some(("alice".to_owned(), "s3cret".to_owned())));
        assert_eq!(config.https_proxy_creds, Some(("alice".to_owned(), "s3cret".to_owned())));
        // And flow through resolve() into the ProxyAction
        let action = config.resolve("example.com", true);
        assert_eq!(
            action,
            ProxyAction::Named(
                "http://proxy:8080".into(),
                Some(("alice".to_owned(), "s3cret".to_owned()))
            )
        );
    }

    // -- Proxy::no_proxy() --

    #[test]
    #[cfg(feature = "noop-compat")]
    fn proxy_no_proxy_table() {
        let cases: &[(Option<NoProxy>, &str)] =
            &[(NoProxy::from_string("localhost"), "Some"), (None, "None")];

        for (np, label) in cases {
            let proxy = Proxy::all("http://proxy:8080").unwrap();
            let proxy = proxy.no_proxy(np.clone());
            assert_eq!(proxy.url, "http://proxy:8080", "{label}");
        }
    }

    // -- Proxy URL validation (data-driven) --

    /// (input, expected_ok)
    const PROXY_VALIDATION_CASES: &[(&str, bool)] = &[
        ("", false),
        ("proxy:8080", false),        // no scheme
        ("ftp://proxy:8080", false),  // bad scheme
        ("http://", false),           // no host
        ("http://proxy:8080", true),  // http OK
        ("https://proxy:8080", true), // https OK
    ];

    #[test]
    fn proxy_all_validation() {
        for &(input, expected_ok) in PROXY_VALIDATION_CASES {
            assert_eq!(Proxy::all(input).is_ok(), expected_ok, "Proxy::all({input:?})");
        }
    }

    #[test]
    fn proxy_constructor_rejects_bad_input() {
        type TestCase<'a> = (&'a str, fn(&str) -> Result<Proxy, crate::Error>, &'a str);
        let cases: &[TestCase] = &[
            ("all(socks5)", |u| Proxy::all(u), "socks5://proxy:1080"),
            ("all(socks4)", |u| Proxy::all(u), "socks4://proxy:1080"),
            ("http(bad)", |u| Proxy::http(u), "not-a-url"),
            ("https(bad)", |u| Proxy::https(u), "not-a-url"),
        ];

        for &(label, ctor, url) in cases {
            assert!(ctor(url).is_err(), "{label} should fail");
        }
    }

    // -- Proxy::http / Proxy::https apply_to (data-driven) --

    #[test]
    fn proxy_apply_to_table() {
        // (scheme, url, expected_http_url, expected_https_url, label)
        type TestCase<'a> = (&'a str, &'a str, Option<&'a str>, Option<&'a str>, &'a str);
        let cases: &[TestCase] = &[
            ("http", "http://http-only:8080", Some("http://http-only:8080"), None, "http only"),
            ("https", "http://https-only:8080", None, Some("http://https-only:8080"), "https only"),
        ];

        let creds = Some(("u".to_owned(), "p".to_owned()));
        for &(scheme, url, exp_http, exp_https, label) in cases {
            let proxy = match scheme {
                "http" => Proxy::http(url),
                "https" => Proxy::https(url),
                _ => unreachable!(),
            }
            .unwrap()
            .basic_auth("u", "p");

            let mut cfg = ProxyConfig::none();
            proxy.apply_to(&mut cfg);

            assert_eq!(cfg.http_proxy_url.as_deref(), exp_http, "{label}: http_proxy_url");
            assert_eq!(cfg.https_proxy_url.as_deref(), exp_https, "{label}: https_proxy_url");
            // Creds follow the proxy URL: set only for the matching scheme.
            let exp_http_creds = if exp_http.is_some() {
                creds.clone()
            } else {
                None
            };
            let exp_https_creds = if exp_https.is_some() {
                creds.clone()
            } else {
                None
            };
            assert_eq!(cfg.http_proxy_creds, exp_http_creds, "{label}: http creds");
            assert_eq!(cfg.https_proxy_creds, exp_https_creds, "{label}: https creds");
        }
    }

    // -- NoProxy::from_env (data-driven) --

    #[test]
    fn no_proxy_from_env_table() {
        // (env_value, expected_is_some, expected_pattern_count, label)
        let cases: &[(Option<&str>, bool, usize, &str)] = &[
            (Some("localhost,.internal.corp"), true, 2, "set with patterns"),
            (None, false, 0, "unset"),
        ];

        for &(env_val, expected_some, expected_count, label) in cases {
            with_env_vars(&[("NO_PROXY", env_val)], || {
                let np = NoProxy::from_env();
                assert_eq!(np.is_some(), expected_some, "{label}");
                if let Some(np) = np {
                    assert_eq!(np.patterns.len(), expected_count, "{label}: count");
                    assert!(np.patterns[0].matches("localhost"), "{label}: first");
                    assert!(np.patterns[1].matches("api.internal.corp"), "{label}: second");
                }
            });
        }
    }

    // -- NoProxy::apply_to --

    #[test]
    fn no_proxy_apply_to_sets_patterns() {
        let np = NoProxy::from_string("localhost,.example.com").unwrap();
        let mut cfg = ProxyConfig::none();
        np.apply_to(&mut cfg);
        assert_eq!(cfg.no_proxy.len(), 2);
    }

    // -- ProxyConfig::none_from_env --

    #[test]
    fn proxy_config_none_from_env_is_empty() {
        let cfg = ProxyConfig::none_from_env();
        assert!(cfg.http_proxy_url.is_none());
        assert!(cfg.https_proxy_url.is_none());
        assert!(cfg.no_proxy.is_empty());
        assert!(cfg.http_proxy_creds.is_none());
        assert!(cfg.https_proxy_creds.is_none());
    }
}
