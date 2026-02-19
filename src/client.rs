//! HTTP client and builder.
//!
//! [`Client`] is the main entry point. Create one via [`Client::builder()`],
//! configure timeouts and options, then call [`.build()`](ClientBuilder::build).
//! `Client` is cheap to clone (`Arc` internally).

use crate::error::Error;
use crate::proxy::ProxyConfig;
use crate::request::RequestBuilder;
use crate::url::IntoUrl;
use crate::winhttp::{self, SessionConfig, WinHttpSession};
use http::{HeaderMap, HeaderValue};
use std::sync::Arc;
use std::time::Duration;

/// An async HTTP client backed by WinHTTP.
///
/// `Client` is cheap to [`Clone`] -- clones share the underlying WinHTTP
/// session handle and connection pool.
///
/// # Example
///
/// ```rust,ignore
/// let client = Client::builder()
///     .timeout(Duration::from_secs(30))
///     .connect_timeout(Duration::from_secs(10))
///     .connection_verbose(true)
///     .build()?;
///
/// let resp = client.get("https://example.com").send().await?;
/// ```
#[derive(Clone)]
pub struct Client {
    pub(crate) inner: Arc<ClientInner>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").finish()
    }
}

/// Shared state behind `Arc` in [`Client`].
pub(crate) struct ClientInner {
    /// The WinHTTP session handle (connection pool, callback, options).
    pub session: WinHttpSession,
    /// Total request timeout (including body streaming).
    pub total_timeout: Option<Duration>,
    /// Cached proxy configuration from environment variables.
    pub proxy_config: ProxyConfig,
    /// Default headers applied to every request.
    pub default_headers: HeaderMap,
    /// Whether to ignore certificate errors.
    pub accept_invalid_certs: bool,
}

/// Builder for configuring and constructing a [`Client`].
///
/// Obtain via [`Client::builder()`].
#[derive(Debug)]
pub struct ClientBuilder {
    user_agent: String,
    timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    send_timeout: Option<Duration>,
    read_timeout: Option<Duration>,
    verbose: bool,
    max_connections_per_host: Option<u32>,
    proxy_config: Option<ProxyConfig>,
    default_headers: HeaderMap,
    redirect_policy: Option<crate::redirect::Policy>,
    danger_accept_invalid_certs: bool,
    http1_only: bool,
    error: Option<Error>,
}

impl Client {
    /// Create a new `Client` with default settings.
    ///
    /// # Panics
    ///
    /// Panics if the WinHTTP session cannot be opened. This matches
    /// [`reqwest::Client::new()`](https://docs.rs/reqwest/latest/reqwest/struct.Client.html#method.new),
    /// which also panics on TLS backend failure.
    /// Prefer [`Client::builder().build()`](ClientBuilder::build) for
    /// fallible construction.
    #[cfg(feature = "panicking-compat")]
    pub fn new() -> Self {
        Client::builder()
            .build()
            .expect("Client::new() failed to build")
    }

    /// Create a new [`ClientBuilder`].
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Send a GET request to the given URL.
    pub fn get<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        RequestBuilder::new(self.clone(), "GET", url)
    }

    /// Send a POST request to the given URL.
    pub fn post<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        RequestBuilder::new(self.clone(), "POST", url)
    }

    /// Send a PUT request to the given URL.
    pub fn put<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        RequestBuilder::new(self.clone(), "PUT", url)
    }

    /// Send a PATCH request to the given URL.
    pub fn patch<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        RequestBuilder::new(self.clone(), "PATCH", url)
    }

    /// Send a DELETE request to the given URL.
    pub fn delete<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        RequestBuilder::new(self.clone(), "DELETE", url)
    }

    /// Send a HEAD request to the given URL.
    pub fn head<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        RequestBuilder::new(self.clone(), "HEAD", url)
    }

    /// Start building a request with the given HTTP method and URL.
    pub fn request<U: IntoUrl>(&self, method: http::Method, url: U) -> RequestBuilder {
        RequestBuilder::new(self.clone(), method.as_str(), url)
    }

    /// Execute a pre-built [`Request`](crate::request::Request).
    ///
    /// This is the lower-level counterpart of
    /// [`RequestBuilder::send()`](crate::RequestBuilder::send).
    /// Build a request with [`RequestBuilder::build()`](crate::RequestBuilder::build),
    /// inspect or modify it, then execute it here.
    pub async fn execute(
        &self,
        request: crate::request::Request,
    ) -> Result<crate::Response, Error> {
        let inner = &self.inner;

        // Convert HeaderMap to Vec<(String, String)> for WinHTTP.
        // HTTP header values are octets (RFC 9110 §5.5).  WinHTTP accepts
        // UTF-16 strings, so we widen each byte to its Unicode code point
        // via Latin-1 identity mapping for a lossless round-trip.
        let headers: Vec<(String, String)> = request
            .headers()
            .iter()
            .map(|(name, value)| {
                (name.as_str().to_owned(), crate::util::widen_latin1(value.as_bytes()))
            })
            .collect();

        // Per-request timeout overrides client-level timeout
        let effective_timeout = request.timeout().copied().or(inner.total_timeout);
        let deadline = effective_timeout.map(|d| std::time::Instant::now() + d);

        let url = request.url().clone();
        let method_str = request.method().as_str().to_owned();

        trace!(
            method = method_str,
            url = %url,
            timeout_ms = effective_timeout.map(|d| d.as_millis() as u64),
            "Client::execute",
        );

        // Execute request -- body is passed through to the WinHTTP layer
        // which handles in-memory bytes and streaming bodies differently.
        let body = request.into_body();
        let send_future = async {
            winhttp::execute_request(
                &inner.session,
                &url,
                &method_str,
                &headers,
                body,
                &inner.proxy_config,
                inner.accept_invalid_certs,
            )
            .await
        };

        // Race against total timeout if configured
        let raw = if let Some(timeout) = effective_timeout {
            let delay = futures_timer::Delay::new(timeout);
            let send_future = std::pin::pin!(send_future);
            let delay = std::pin::pin!(delay);

            match futures_util::future::select(send_future, delay).await {
                futures_util::future::Either::Left((result, _)) => result?,
                futures_util::future::Either::Right(((), _)) => {
                    return Err(
                        Error::timeout("total request timeout elapsed").with_url(url.clone())
                    );
                }
            }
        } else {
            send_future.await?
        };

        Ok(crate::Response::from_raw(raw, deadline, self.clone()))
    }
}

#[cfg(feature = "panicking-compat")]
impl Default for Client {
    /// Creates a `Client` with default settings.
    ///
    /// # Panics
    ///
    /// Panics if the WinHTTP session cannot be opened.
    fn default() -> Self {
        Client::builder()
            .build()
            .expect("Client::default() failed to build")
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientBuilder {
    /// Create a new `ClientBuilder` with default settings.
    pub fn new() -> Self {
        Self {
            user_agent: String::new(),
            timeout: None,
            connect_timeout: None,
            send_timeout: None,
            read_timeout: None,
            verbose: false,
            max_connections_per_host: None,
            proxy_config: None,
            default_headers: HeaderMap::new(),
            redirect_policy: None,
            danger_accept_invalid_certs: false,
            http1_only: false,
            error: None,
        }
    }

    /// Set the total request timeout.
    ///
    /// This covers the entire request lifecycle -- connection, sending,
    /// and receiving the response (including streaming body reads).
    /// Implemented via `futures_util::future::select` + `futures_timer::Delay`.
    ///
    /// Default: **no timeout** (the request can run indefinitely).
    /// WinHTTP enforces a 60-second connect timeout by default;
    /// see [`connect_timeout()`](Self::connect_timeout).
    /// Send/receive stall timeouts default to infinite (matching
    /// reqwest); see [`send_timeout()`](Self::send_timeout) and
    /// [`read_timeout()`](Self::read_timeout).
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the connection timeout.
    ///
    /// This limits only the TCP connect phase. Maps to WinHTTP's
    /// `nConnectTimeout` parameter in `WinHttpSetTimeouts`.
    ///
    /// Default: **60 seconds**.  For end-to-end control use
    /// [`timeout()`](Self::timeout) instead.
    #[must_use]
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Set the per-operation send (write) stall timeout.
    ///
    /// # wrest extension -- not present in reqwest
    ///
    /// reqwest exposes only [`timeout()`](Self::timeout) (total deadline)
    /// and [`connect_timeout()`](Self::connect_timeout).  This method
    /// controls the WinHTTP-level *idle stall* timeout for send
    /// operations: if zero bytes are transmitted for this duration,
    /// WinHTTP aborts the request immediately rather than waiting for
    /// the full total timeout to expire.  Maps to WinHTTP's
    /// `nSendTimeout` parameter in `WinHttpSetTimeouts`.
    ///
    /// Default: **no timeout** (infinite), matching hyper/tokio behaviour.
    /// For end-to-end control use [`timeout()`](Self::timeout) instead.
    #[must_use]
    pub fn send_timeout(mut self, timeout: Duration) -> Self {
        self.send_timeout = Some(timeout);
        self
    }

    /// Set the per-operation read stall timeout.
    ///
    /// # wrest extension -- not present in reqwest
    ///
    /// reqwest exposes only [`timeout()`](Self::timeout) (total deadline)
    /// and [`connect_timeout()`](Self::connect_timeout).  This method
    /// controls the WinHTTP-level *idle stall* timeout for receive
    /// operations: if zero bytes arrive for this duration, WinHTTP
    /// aborts the request immediately rather than waiting for the full
    /// total timeout to expire.  Maps to WinHTTP's `nReceiveTimeout`
    /// parameter in `WinHttpSetTimeouts`.
    ///
    /// Default: **no timeout** (infinite), matching hyper/tokio behaviour.
    /// For end-to-end control use [`timeout()`](Self::timeout) instead.
    #[must_use]
    pub fn read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = Some(timeout);
        self
    }

    /// Enable verbose connection logging via `tracing`.
    ///
    /// When enabled, WinHTTP callback events (resolving name, connecting,
    /// sending request, redirects, etc.) are logged at `TRACE` level.
    #[must_use]
    pub fn connection_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Set the User-Agent header string.
    ///
    /// Accepts any type convertible to an HTTP header value, matching
    /// the `reqwest::ClientBuilder::user_agent` signature.
    ///
    /// By default no User-Agent header is sent (matching reqwest).
    #[must_use]
    pub fn user_agent<V>(mut self, value: V) -> Self
    where
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        match HeaderValue::try_from(value) {
            Ok(v) => match v.to_str() {
                Ok(s) => self.user_agent = s.to_owned(),
                Err(e) => {
                    self.error = Some(Error::builder("invalid user-agent value").with_source(e));
                }
            },
            Err(e) => {
                let e: http::Error = e.into();
                self.error = Some(Error::builder("invalid user-agent").with_source(e));
            }
        }
        self
    }

    /// Set the maximum number of connections per server.
    ///
    /// Maps to `WINHTTP_OPTION_MAX_CONNS_PER_SERVER`. Default is INFINITE
    /// (WinHTTP default). Set to a lower value to limit concurrency to a
    /// specific server.
    #[must_use]
    pub fn max_connections_per_host(mut self, max: u32) -> Self {
        self.max_connections_per_host = Some(max);
        self
    }

    /// Set default headers that will be included in every request.
    ///
    /// Headers set on individual requests will override these defaults
    /// if they share the same header name.
    #[must_use]
    pub fn default_headers(mut self, headers: HeaderMap) -> Self {
        self.default_headers = headers;
        self
    }

    // -----------------------------------------------------------------
    // No-op reqwest compatibility stubs
    //
    // These methods accept and ignore their arguments so that code
    // written against reqwest compiles without changes.  Gated behind
    // the `noop-compat` Cargo feature.
    // -----------------------------------------------------------------

    /// Set a timeout for idle connections in the pool.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP manages its own connection pool internally and does not
    /// expose idle-timeout configuration.  Requires the `noop-compat`
    /// feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn pool_idle_timeout<T: Into<Option<Duration>>>(self, _val: T) -> Self {
        self
    }

    /// Set the maximum idle connections per host.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP manages its own connection pool internally.  Requires
    /// the `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn pool_max_idle_per_host(self, _val: usize) -> Self {
        self
    }

    /// Enable `TCP_NODELAY` on the connection.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP manages TCP socket options internally and does not
    /// expose `TCP_NODELAY`.  Requires the `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn tcp_nodelay(self, _val: bool) -> Self {
        self
    }

    /// Set TCP keepalive.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP manages TCP socket options internally and does not
    /// expose keepalive settings.  Requires the `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn tcp_keepalive<T: Into<Option<Duration>>>(self, _val: T) -> Self {
        self
    }

    /// Enable gzip content-encoding for responses.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP handles content-encoding decompression automatically
    /// and does not expose per-algorithm toggles.  Requires both the
    /// `gzip` and `noop-compat` features.
    #[cfg(all(feature = "noop-compat", feature = "gzip"))]
    #[must_use]
    pub fn gzip(self, _val: bool) -> Self {
        self
    }

    /// Enable brotli content-encoding for responses.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP only decompresses gzip and deflate responses natively.
    /// Calling `brotli(true)` is accepted for API compatibility but
    /// **will not** cause brotli-encoded responses to be decompressed.
    /// Requires both the `brotli` and `noop-compat` features.
    #[cfg(all(feature = "noop-compat", feature = "brotli"))]
    #[must_use]
    pub fn brotli(self, _val: bool) -> Self {
        self
    }

    /// Enable deflate content-encoding for responses.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP handles content-encoding decompression automatically
    /// and does not expose per-algorithm toggles.  Requires both the
    /// `deflate` and `noop-compat` features.
    #[cfg(all(feature = "noop-compat", feature = "deflate"))]
    #[must_use]
    pub fn deflate(self, _val: bool) -> Self {
        self
    }

    /// Enable zstd content-encoding for responses.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP only decompresses gzip and deflate responses natively.
    /// Calling `zstd(true)` is accepted for API compatibility but
    /// **will not** cause zstd-encoded responses to be decompressed.
    /// Requires both the `zstd` and `noop-compat` features.
    #[cfg(all(feature = "noop-compat", feature = "zstd"))]
    #[must_use]
    pub fn zstd(self, _val: bool) -> Self {
        self
    }

    /// Enable HTTP/2 with prior knowledge.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP manages protocol negotiation internally via ALPN.
    /// See [`http1_only()`](Self::http1_only) to restrict to HTTP/1.x.
    /// Requires the `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn http2_prior_knowledge(self) -> Self {
        self
    }

    /// Set the TCP keepalive probe interval.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP manages TCP socket options internally.  Requires the
    /// `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn tcp_keepalive_interval<T: Into<Option<Duration>>>(self, _val: T) -> Self {
        self
    }

    /// Set the TCP keepalive probe retry count.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP manages TCP socket options internally.  Requires the
    /// `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn tcp_keepalive_retries<T: Into<Option<u32>>>(self, _val: T) -> Self {
        self
    }

    /// Allow HTTP/0.9 responses.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP does not support HTTP/0.9.  Requires the `noop-compat`
    /// feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn http09_responses(self) -> Self {
        self
    }

    /// Send headers as title case instead of lowercase.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP manages header formatting internally.  Requires the
    /// `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn http1_title_case_headers(self) -> Self {
        self
    }

    /// Accept obsolete multiline headers in HTTP/1 responses.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP manages header parsing internally.  Requires the
    /// `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn http1_allow_obsolete_multiline_headers_in_responses(self, _val: bool) -> Self {
        self
    }

    /// Ignore invalid header lines in HTTP/1 responses.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP manages header parsing internally.  Requires the
    /// `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn http1_ignore_invalid_headers_in_responses(self, _val: bool) -> Self {
        self
    }

    /// Allow spaces after header names in HTTP/1 responses.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP manages header parsing internally.  Requires the
    /// `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn http1_allow_spaces_after_header_name_in_responses(self, _val: bool) -> Self {
        self
    }

    /// Set the HTTP/2 initial stream window size.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP manages HTTP/2 flow control internally.  Requires the
    /// `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn http2_initial_stream_window_size(self, _sz: impl Into<Option<u32>>) -> Self {
        self
    }

    /// Set the HTTP/2 initial connection window size.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP manages HTTP/2 flow control internally.  Requires the
    /// `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn http2_initial_connection_window_size(self, _sz: impl Into<Option<u32>>) -> Self {
        self
    }

    /// Enable HTTP/2 adaptive flow control.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP manages HTTP/2 flow control internally.  Requires the
    /// `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn http2_adaptive_window(self, _enabled: bool) -> Self {
        self
    }

    /// Set the maximum HTTP/2 frame size.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP manages HTTP/2 framing internally.  Requires the
    /// `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn http2_max_frame_size(self, _sz: impl Into<Option<u32>>) -> Self {
        self
    }

    /// Set the maximum HTTP/2 header list size.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP manages HTTP/2 headers internally.  Requires the
    /// `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn http2_max_header_list_size(self, _max: u32) -> Self {
        self
    }

    /// Set the HTTP/2 keep-alive ping interval.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP manages HTTP/2 connection health internally.  Requires
    /// the `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn http2_keep_alive_interval(self, _interval: impl Into<Option<Duration>>) -> Self {
        self
    }

    /// Set the HTTP/2 keep-alive ping timeout.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP manages HTTP/2 connection health internally.  Requires
    /// the `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn http2_keep_alive_timeout(self, _timeout: Duration) -> Self {
        self
    }

    /// Enable HTTP/2 keep-alive while idle.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP manages HTTP/2 connection health internally.  Requires
    /// the `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn http2_keep_alive_while_idle(self, _enabled: bool) -> Self {
        self
    }

    /// Control TLS Server Name Indication.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// WinHTTP always enables SNI via SChannel; this hint is ignored.
    /// Requires the `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn tls_sni(self, _tls_sni: bool) -> Self {
        self
    }

    /// Force using the native TLS backend.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// wrest always uses the native TLS backend (SChannel via WinHTTP).
    /// Requires the `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn use_native_tls(self) -> Self {
        self
    }

    /// Force using the native TLS backend.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// wrest always uses the native TLS backend (SChannel via WinHTTP).
    /// Requires the `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn tls_backend_native(self) -> Self {
        self
    }

    /// Disable the hickory-dns async resolver.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// wrest does not bundle any DNS resolver; WinHTTP manages DNS
    /// internally.  Requires the `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn no_hickory_dns(self) -> Self {
        self
    }

    /// Disable the trust-dns async resolver.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// Deprecated alias for [`no_hickory_dns()`](Self::no_hickory_dns).
    /// wrest does not bundle any DNS resolver.  Requires the
    /// `noop-compat` feature.
    #[cfg(feature = "noop-compat")]
    #[must_use]
    pub fn no_trust_dns(self) -> Self {
        self
    }

    /// Set the redirect policy for the client.
    ///
    /// Controls how many redirects are followed automatically.
    /// Default: follow up to 10 redirects (matching reqwest).
    ///
    /// Use [`redirect::Policy::none()`](crate::redirect::Policy::none) to
    /// disable automatic redirects entirely.
    ///
    /// # Deviation from reqwest
    ///
    /// Only [`Policy::limited()`](crate::redirect::Policy::limited) and
    /// [`Policy::none()`](crate::redirect::Policy::none) are supported.
    /// reqwest's `Policy::custom()` callback is not available because
    /// redirect handling is performed by WinHTTP internally.
    #[must_use]
    pub fn redirect(mut self, policy: crate::redirect::Policy) -> Self {
        self.redirect_policy = Some(policy);
        self
    }

    /// Add a proxy to the client.
    ///
    /// Overrides the corresponding scheme(s) from environment variables.
    /// Can be called multiple times for different schemes.
    ///
    /// # Deviation from reqwest
    ///
    /// SOCKS proxies (`socks4://`, `socks5://`) are rejected because
    /// WinHTTP only supports HTTP CONNECT proxies. reqwest supports
    /// SOCKS via the `socks` feature.
    #[must_use]
    pub fn proxy(mut self, proxy: crate::proxy::Proxy) -> Self {
        let config = self.proxy_config.get_or_insert_with(ProxyConfig::from_env);
        proxy.apply_to(config);
        self
    }

    /// Disable proxy auto-detection.
    ///
    /// Prevents the client from using any automatically detected system
    /// proxies. Proxies explicitly added via [`proxy()`](Self::proxy)
    /// are still used.
    ///
    /// Matches [`reqwest::ClientBuilder::no_proxy()`](https://docs.rs/reqwest/latest/reqwest/struct.ClientBuilder.html#method.no_proxy).
    #[must_use]
    pub fn no_proxy(mut self) -> Self {
        // Initialize a proxy config with NO env-var defaults.
        // Explicit .proxy() calls will still merge into this config.
        self.proxy_config = Some(ProxyConfig::none_from_env());
        self
    }

    /// Accept invalid TLS certificates.
    ///
    /// # Warning
    ///
    /// This is **dangerous** and should only be used for testing or
    /// in controlled environments. It disables all certificate validation.
    #[must_use]
    pub fn danger_accept_invalid_certs(mut self, accept: bool) -> Self {
        self.danger_accept_invalid_certs = accept;
        self
    }

    /// Restrict the client to HTTP/1.x only.
    ///
    /// When set, the WinHTTP session will not enable HTTP/2 protocol
    /// negotiation.
    #[must_use]
    pub fn http1_only(mut self) -> Self {
        self.http1_only = true;
        self
    }

    /// Build the [`Client`].
    ///
    /// This opens a WinHTTP session, installs the async callback, and
    /// reads proxy configuration from environment variables.
    pub fn build(self) -> Result<Client, Error> {
        if let Some(err) = self.error {
            return Err(err);
        }

        let proxy_config = self.proxy_config.unwrap_or_else(ProxyConfig::from_env);

        // Determine session-level proxy action.
        // If env vars specify a proxy, use NAMED_PROXY at session level.
        // Otherwise use AUTOMATIC_PROXY. Per-request NO_PROXY overrides happen later.
        let session_proxy =
            if proxy_config.https_proxy_url.is_some() || proxy_config.http_proxy_url.is_some() {
                // Use HTTPS proxy as the session default (most requests are HTTPS).
                // Per-request resolution will pick the right one.
                let url = proxy_config
                    .https_proxy_url
                    .as_ref()
                    .or(proxy_config.http_proxy_url.as_ref())
                    .cloned()
                    .unwrap_or_default();
                crate::proxy::ProxyAction::Named(url, None)
            } else {
                crate::proxy::ProxyAction::Automatic
            };

        // Saturate to i32::MAX rather than silently truncating.
        // WinHttpSetTimeouts takes i32 milliseconds (~24.8 days); any
        // Duration longer than that is effectively infinite.
        let to_ms = |d: std::time::Duration| -> u32 {
            u32::try_from(d.as_millis())
                .unwrap_or(i32::MAX as u32)
                .min(i32::MAX as u32)
        };
        let connect_timeout_ms = self.connect_timeout.map_or(60_000, to_ms); // 60s default

        // send/receive stall timeouts -- default 0 (infinite, no stall
        // detection) to match hyper/tokio behaviour where reqwest has no
        // per-operation idle timeout.  Callers can opt in to stall
        // detection via the send_timeout() / read_timeout() extensions.
        // Total end-to-end timeout is enforced separately via
        // futures_timer::Delay.
        let send_timeout_ms = self.send_timeout.map_or(0, to_ms);
        let read_timeout_ms = self.read_timeout.map_or(0, to_ms);

        let config = SessionConfig {
            user_agent: self.user_agent,
            connect_timeout_ms,
            send_timeout_ms,
            read_timeout_ms,
            verbose: self.verbose,
            max_connections_per_host: self.max_connections_per_host,
            proxy: session_proxy,
            redirect_policy: self.redirect_policy,
            http1_only: self.http1_only,
        };

        let session = WinHttpSession::open(&config)?;

        debug!(
            connect_timeout_ms,
            send_timeout_ms,
            read_timeout_ms,
            total_timeout_ms = self.timeout.map(|d| d.as_millis() as u64),
            proxy = ?config.proxy,
            accept_invalid_certs = self.danger_accept_invalid_certs,
            "client built",
        );

        Ok(Client {
            inner: Arc::new(ClientInner {
                session,
                total_timeout: self.timeout,
                proxy_config,
                default_headers: self.default_headers,
                accept_invalid_certs: self.danger_accept_invalid_certs,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_is_clone() {
        fn assert_clone<T: Clone>() {}
        assert_clone::<Client>();
    }

    #[test]
    fn builder_defaults() {
        let builder = ClientBuilder::new();
        assert!(builder.timeout.is_none());
        assert!(builder.connect_timeout.is_none());
        assert!(!builder.verbose);
        assert!(builder.max_connections_per_host.is_none());
        assert!(
            builder.user_agent.is_empty(),
            "default user-agent should be empty (matching reqwest)"
        );
    }

    #[test]
    fn builder_fluent_api() {
        let builder = ClientBuilder::new()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .connection_verbose(true)
            .user_agent("test-agent/1.0")
            .max_connections_per_host(6);

        assert_eq!(builder.timeout, Some(Duration::from_secs(30)));
        assert_eq!(builder.connect_timeout, Some(Duration::from_secs(10)));
        assert!(builder.verbose);
        assert_eq!(builder.user_agent, "test-agent/1.0");
        assert_eq!(builder.max_connections_per_host, Some(6));
    }

    #[test]
    fn client_build_succeeds() {
        // This actually opens a WinHTTP session
        let client = Client::builder().build();
        assert!(client.is_ok());

        // Durations larger than i32::MAX ms (~24.8 days) saturate
        // rather than wrapping (covers `unwrap_or` in `to_ms`).
        let huge = Duration::from_millis(u64::from(i32::MAX as u32) + 1);
        assert!(Client::builder().connect_timeout(huge).build().is_ok());

        // Redirect policies: exercises the WinHTTP session option arms.
        use crate::redirect::Policy;
        assert!(Client::builder().redirect(Policy::none()).build().is_ok());
        assert!(
            Client::builder()
                .redirect(Policy::limited(5))
                .build()
                .is_ok()
        );
    }

    #[test]
    fn client_clone_shares_session() {
        let client = Client::builder().build().unwrap();
        let clone = client.clone();
        assert!(Arc::ptr_eq(&client.inner, &clone.inner));
    }

    #[test]
    #[cfg(feature = "panicking-compat")]
    fn client_default() {
        let client = Client::default();
        // Verify it produced a working client (session opened)
        assert!(Arc::strong_count(&client.inner) >= 1);
    }

    #[test]
    fn client_builder_default() {
        let builder = ClientBuilder::default();
        assert!(
            builder.user_agent.is_empty(),
            "default user-agent should be empty (matching reqwest)"
        );
    }

    #[test]
    fn client_builder_new_is_pub() {
        // Proves ClientBuilder::new() is publicly accessible.
        let builder = ClientBuilder::new();
        assert!(builder.timeout.is_none());
    }

    #[test]
    fn client_http_methods() {
        let client = Client::builder().build().unwrap();
        let methods = [
            ("PUT", client.put("https://example.com")),
            ("PATCH", client.patch("https://example.com")),
            ("DELETE", client.delete("https://example.com")),
            ("HEAD", client.head("https://example.com")),
        ];
        for (expected, rb) in &methods {
            let debug = format!("{rb:?}");
            assert!(debug.contains(expected), "{expected} not found in debug");
        }
    }

    #[test]
    fn client_request_generic() {
        let client = Client::builder().build().unwrap();
        let rb = client.request(http::Method::OPTIONS, "https://example.com");
        let debug = format!("{rb:?}");
        assert!(debug.contains("OPTIONS"));
    }

    #[test]
    fn builder_default_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-custom", HeaderValue::from_static("test-value"));
        let builder = ClientBuilder::new().default_headers(headers);
        // Verify stored in builder
        assert_eq!(
            builder
                .default_headers
                .get("x-custom")
                .unwrap()
                .to_str()
                .unwrap(),
            "test-value"
        );
    }

    #[test]
    fn builder_default_headers_propagated() {
        let mut headers = HeaderMap::new();
        headers.insert("x-custom", HeaderValue::from_static("test-value"));
        let client = Client::builder().default_headers(headers).build().unwrap();
        // Verify propagated to ClientInner
        assert_eq!(
            client
                .inner
                .default_headers
                .get("x-custom")
                .unwrap()
                .to_str()
                .unwrap(),
            "test-value"
        );
    }

    /// All noop-compat builder stubs compile, return Self, and don't panic.
    ///
    /// Decompression toggles (`gzip`, `brotli`, `deflate`, `zstd`) are in
    /// [`compression_builder_stubs`] -- they are gated by their own features.
    #[test]
    #[cfg(feature = "noop-compat")]
    fn noop_compat_builder_stubs() {
        // Each stub must accept its argument and return ClientBuilder.
        let builder = ClientBuilder::new()
            // Connection pool
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_idle_timeout(None) // also accepts Option<Duration>
            .pool_max_idle_per_host(10)
            // TCP options
            .tcp_nodelay(true)
            .tcp_keepalive(Duration::from_secs(60))
            .tcp_keepalive(None)
            .tcp_keepalive_interval(Duration::from_secs(15))
            .tcp_keepalive_interval(None)
            .tcp_keepalive_retries(3u32)
            .tcp_keepalive_retries(None)
            // HTTP/1 tuning
            .http09_responses()
            .http1_title_case_headers()
            .http1_allow_obsolete_multiline_headers_in_responses(true)
            .http1_ignore_invalid_headers_in_responses(true)
            .http1_allow_spaces_after_header_name_in_responses(true)
            // HTTP/2 tuning
            .http2_prior_knowledge()
            .http2_initial_stream_window_size(65_535u32)
            .http2_initial_stream_window_size(None)
            .http2_initial_connection_window_size(65_535u32)
            .http2_initial_connection_window_size(None)
            .http2_adaptive_window(true)
            .http2_max_frame_size(16_384u32)
            .http2_max_frame_size(None)
            .http2_max_header_list_size(16_384)
            .http2_keep_alive_interval(Duration::from_secs(30))
            .http2_keep_alive_interval(None)
            .http2_keep_alive_timeout(Duration::from_secs(20))
            .http2_keep_alive_while_idle(true)
            // TLS
            .tls_sni(true)
            .use_native_tls()
            .tls_backend_native()
            // DNS
            .no_hickory_dns()
            .no_trust_dns();

        // Verify the builder is still usable after all stubs.
        let client = builder.build();
        assert!(client.is_ok(), "builder should still produce a valid client");
    }

    /// Decompression builder stubs compile, return Self, and don't panic.
    ///
    /// Each method is gated by both `noop-compat` and its own cargo
    /// feature (`gzip`, `brotli`, `deflate`, `zstd`).
    #[test]
    #[cfg(all(
        feature = "noop-compat",
        feature = "gzip",
        feature = "brotli",
        feature = "deflate",
        feature = "zstd"
    ))]
    fn compression_builder_stubs() {
        let client = ClientBuilder::new()
            .gzip(true)
            .brotli(true)
            .deflate(true)
            .zstd(true)
            .build();
        assert!(client.is_ok(), "builder should still produce a valid client");
    }

    // -- Builder field storage (data-driven) --

    #[test]
    fn builder_field_storage_table() {
        // (label, setup, check)
        type TestCase<'a> =
            (&'a str, fn(ClientBuilder) -> ClientBuilder, fn(&ClientBuilder) -> bool);
        let cases: &[TestCase] = &[
            (
                "send_timeout",
                |b| b.send_timeout(Duration::from_secs(5)),
                |b| b.send_timeout == Some(Duration::from_secs(5)),
            ),
            (
                "read_timeout",
                |b| b.read_timeout(Duration::from_secs(7)),
                |b| b.read_timeout == Some(Duration::from_secs(7)),
            ),
            (
                "redirect_policy",
                |b| b.redirect(crate::redirect::Policy::none()),
                |b| b.redirect_policy.is_some(),
            ),
            (
                "danger_accept_invalid_certs",
                |b| b.danger_accept_invalid_certs(true),
                |b| b.danger_accept_invalid_certs,
            ),
            ("http1_only", |b| b.http1_only(), |b| b.http1_only),
            ("no_proxy", |b| b.no_proxy(), |b| b.proxy_config.is_some()),
            // Duration::MAX should saturate to i32::MAX, not panic
            (
                "connect_timeout_max",
                |b| b.connect_timeout(Duration::MAX),
                |b| b.connect_timeout == Some(Duration::MAX),
            ),
        ];

        for &(label, setup, check) in cases {
            let b = setup(ClientBuilder::new());
            assert!(check(&b), "builder.{label}() was not stored");
        }
    }

    #[test]
    fn builder_user_agent_table() {
        // (label, value_bytes, expect_ok)
        //
        // Three user_agent() code paths:
        //   1. Valid visible-ASCII string → stored in builder
        //   2. Non-ASCII bytes (0x01) → HeaderValue::try_from fails → deferred error
        //   3. Opaque bytes (0x80..) → HeaderValue OK, to_str() fails → deferred error
        let cases: &[(&str, &[u8], bool)] = &[
            ("valid", b"valid-agent", true),
            ("try_from fails", b"bad\x01agent", false),
            ("to_str fails", &[0x80, 0xFF], false),
        ];

        for &(label, value, expect_ok) in cases {
            let hv = http::HeaderValue::from_bytes(value);
            let b = match hv {
                Ok(v) => ClientBuilder::new().user_agent(v),
                Err(_) => {
                    ClientBuilder::new().user_agent(String::from_utf8_lossy(value).into_owned())
                }
            };
            if expect_ok {
                assert!(b.error.is_none(), "{label}: should store without error");
                assert!(b.build().is_ok(), "{label}: should build");
            } else {
                assert!(b.error.is_some(), "{label}: should store error");
                assert!(b.build().unwrap_err().is_builder(), "{label}: should be builder error");
            }
        }
    }

    #[test]
    fn builder_accept_invalid_certs_propagated() {
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        assert!(client.inner.accept_invalid_certs);
    }
}
