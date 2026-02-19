//! WinHTTP-specific callback wiring and handle wrappers.
//!
//! This module applies the generic bridge from [`callback`](crate::callback) to
//! WinHTTP. It is entirely `pub(crate)` -- the public API is in [`client`],
//! [`request`], and [`response`].

use crate::abi;
use crate::callback::{
    CompletionSignal, SignalCancelled, await_win32, borrow_context_ptr, leak_context_ptr,
    reclaim_context_ptr,
};
use crate::error::Error;
use crate::proxy::{ProxyAction, ProxyConfig};
use crate::url::Url;
use crate::util::lock_or_clear;
use bytes::BytesMut;
use http::{StatusCode, Version};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use windows_sys::Win32::Networking::WinHttp::*;

// ---------------------------------------------------------------------------
// Result extension -- attach request URL to errors
// ---------------------------------------------------------------------------

/// Convenience extension to attach a request URL to any error in a `Result`.
///
/// The `.map_err(|e| e.with_url(url.clone()))` pattern appears throughout this
/// module because every WinHTTP call site needs to enrich errors with the
/// request URL for diagnostics.  This trait reduces that to `.url_context(url)`.
trait ResultUrlExt<T> {
    fn url_context(self, url: &Url) -> Result<T, Error>;
}

impl<T> ResultUrlExt<T> for Result<T, Error> {
    fn url_context(self, url: &Url) -> Result<T, Error> {
        self.map_err(|e| e.with_url(url.clone()))
    }
}

// ---------------------------------------------------------------------------
// Handle wrappers
// ---------------------------------------------------------------------------

/// A raw pointer stored as `usize` to satisfy `Send + Sync` bounds.
///
/// Used to pass WinHTTP handles into closures that are captured across
/// await points without poisoning the future's `Send` bound. Raw pointers
/// (`*mut c_void`) are `!Send + !Sync`, but `usize` is `Send + Sync`.
///
/// # Safety
/// The caller must ensure the pointed-to resource is thread-safe (true for
/// all WinHTTP handles -- WinHTTP is fully thread-safe by design).
#[derive(Clone, Copy)]
struct SendPtr(usize);

impl SendPtr {
    /// Convert back to a raw mutable pointer.
    fn as_mut_ptr(self) -> *mut core::ffi::c_void {
        self.0 as *mut core::ffi::c_void
    }
}

/// RAII wrapper for a raw WinHTTP handle (`*mut c_void`).
///
/// Calls `WinHttpCloseHandle` on drop. After the close, WinHTTP may still
/// deliver callbacks (the last one is `HANDLE_CLOSING`).
pub(crate) struct WinHttpHandle(pub *mut core::ffi::c_void);

impl WinHttpHandle {
    /// Get a `Send`-safe copy of the raw pointer (as `usize`).
    ///
    /// This allows passing the handle value into closures captured across
    /// `.await` points without making the future `!Send`.
    fn as_send(&self) -> SendPtr {
        SendPtr(self.0 as usize)
    }
}

impl Drop for WinHttpHandle {
    fn drop(&mut self) {
        abi::close_winhttp_handle(self.0);
    }
}

// SAFETY: WinHTTP handles are thread-safe. All WinHTTP functions accept handles
// from any thread, and the callback fires on WinHTTP's own thread pool.
unsafe impl Send for WinHttpHandle {}
unsafe impl Sync for WinHttpHandle {}

// ---------------------------------------------------------------------------
// CallbackEvent -- what the callback delivers through CompletionSignal
// ---------------------------------------------------------------------------

/// Events the WinHTTP callback delivers through [`CompletionSignal`].
#[derive(Debug)]
pub(crate) enum CallbackEvent {
    /// `SENDREQUEST_COMPLETE` or `HEADERS_AVAILABLE` -- operation succeeded.
    Complete,
    /// `READ_COMPLETE` -- `n` bytes were read into the buffer.
    ReadComplete(u32),
    /// `WRITE_COMPLETE` -- `n` bytes were written to the request body.
    WriteComplete(u32),
    /// `REQUEST_ERROR` -- operation failed.  The payload is a **Win32
    /// error code** (`u32`) from `WINHTTP_ASYNC_RESULT.dwError` -- one of
    /// the `ERROR_WINHTTP_*` constants, *not* an HRESULT.
    ///
    /// [`error_from_winhttp_code`] converts it to an HRESULT before
    /// constructing the [`Error`].
    Error(u32),
}

impl CallbackEvent {
    /// Build an error for a callback event that was not expected in this
    /// context (e.g. `ReadComplete` when we expected `Complete`).
    fn unexpected(self, url: &Url) -> Error {
        Error::request(format!("unexpected callback event: {self:?}")).with_url(url.clone())
    }

    /// Convert a `Complete` event to `Ok(())`, or an `Error` event to `Err`.
    pub fn into_result(self, state: &RequestState, url: &Url) -> Result<(), Error> {
        match self {
            CallbackEvent::Complete => Ok(()),
            CallbackEvent::Error(code) => Err(callback_error_to_error(code, state, url)),
            other => Err(other.unexpected(url)),
        }
    }

    /// Extract the byte count from a `ReadComplete` event.
    pub fn into_read_complete(self, url: &Url) -> Result<u32, Error> {
        match self {
            CallbackEvent::ReadComplete(n) => Ok(n),
            CallbackEvent::Error(code) => Err(error_from_winhttp_code(code).with_url(url.clone())),
            other => Err(other.unexpected(url)),
        }
    }

    /// Extract the byte count from a `WriteComplete` event.
    pub fn into_write_complete(self, url: &Url) -> Result<u32, Error> {
        match self {
            CallbackEvent::WriteComplete(n) => Ok(n),
            CallbackEvent::Error(code) => Err(error_from_winhttp_code(code).with_url(url.clone())),
            other => Err(other.unexpected(url)),
        }
    }
}

// ---------------------------------------------------------------------------
// RequestState -- per-request shared state
// ---------------------------------------------------------------------------

/// Shared state for one in-flight HTTP request.
///
/// Passed as `dwContext` to WinHTTP via [`leak_context_ptr`].
pub(crate) struct RequestState {
    /// The completion bridge -- callback signals, future awaits.
    pub signal: CompletionSignal<CallbackEvent>,
    /// Verbose logging flag (from `ClientBuilder::connection_verbose`).
    #[cfg_attr(not(feature = "tracing"), expect(dead_code))]
    pub verbose: bool,
    /// TLS failure detail flags captured from `SECURE_FAILURE` callback.
    pub tls_failure_flags: AtomicU32,
    /// Buffer for the current in-flight `WinHttpReadData`.
    /// Stored here (not on the future stack) so it survives future-drop.
    pub read_buffer: Mutex<Option<BytesMut>>,
    /// Request body for `WinHttpSendRequest` / `WinHttpWriteData`.
    ///
    /// Stored here (not on the future stack) so it survives future-drop
    /// during cancellation.  The WinHTTP docs require the `lpOptional`
    /// buffer passed to `WinHttpSendRequest` to "remain available until
    /// the request handle is closed or the call to WinHttpReceiveResponse
    /// has completed."  If the future is dropped mid-send (e.g. timeout),
    /// `WinHttpCloseHandle` fires but the `OPERATION_CANCELLED` callback
    /// may arrive later -- and WinHTTP could still reference the buffer.
    /// Storing it in the `Arc<RequestState>` (which outlives `HANDLE_CLOSING`)
    /// guarantees the buffer remains valid.
    pub send_body: Mutex<Option<Vec<u8>>>,
}

impl RequestState {
    /// Create a new `RequestState`.
    pub fn new(verbose: bool) -> Self {
        Self {
            signal: CompletionSignal::new(),
            verbose,
            tls_failure_flags: AtomicU32::new(0),
            read_buffer: Mutex::new(None),
            send_body: Mutex::new(None),
        }
    }
}

// SAFETY: `RequestState` is shared across the async future and the WinHTTP
// callback thread. All fields are protected by `Mutex`, `AtomicU32`, or are
// immutable.
unsafe impl Send for RequestState {}
unsafe impl Sync for RequestState {}

// ---------------------------------------------------------------------------
// The WinHTTP callback
// ---------------------------------------------------------------------------

/// WinHTTP status callback function.
///
/// This is registered via `WinHttpSetStatusCallback` on the session handle and
/// inherited by all child handles. It uses `borrow_context_ptr` to access the
/// per-request `RequestState` and signals the `CompletionSignal`.
///
/// # Safety
///
/// Called by WinHTTP on its internal thread pool. `dw_context` must be a value
/// returned by `leak_context_ptr::<RequestState>`.
pub(crate) unsafe extern "system" fn winhttp_callback(
    _hinternet: *mut core::ffi::c_void,
    dw_context: usize,
    dw_status: u32,
    lpv_info: *mut std::ffi::c_void,
    dw_info_length: u32,
) {
    if dw_context == 0 {
        return;
    }

    let state: &RequestState = unsafe { borrow_context_ptr(dw_context) };

    match dw_status {
        WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE => {
            state.signal.signal(CallbackEvent::Complete);
        }

        WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE => {
            state.signal.signal(CallbackEvent::Complete);
        }

        WINHTTP_CALLBACK_STATUS_READ_COMPLETE => {
            state
                .signal
                .signal(CallbackEvent::ReadComplete(dw_info_length));
        }

        WINHTTP_CALLBACK_STATUS_WRITE_COMPLETE => {
            let bytes = if !lpv_info.is_null() && dw_info_length >= 4 {
                unsafe { *(lpv_info as *const u32) }
            } else {
                0
            };
            state.signal.signal(CallbackEvent::WriteComplete(bytes));
        }

        WINHTTP_CALLBACK_STATUS_REQUEST_ERROR => {
            let result = unsafe { &*(lpv_info as *const WINHTTP_ASYNC_RESULT) };
            state.signal.signal(CallbackEvent::Error(result.dwError));
        }

        WINHTTP_CALLBACK_STATUS_SECURE_FAILURE => {
            let flags = unsafe { *(lpv_info as *const u32) };
            // Release: pairs with the Acquire load in callback_error_to_error
            // so the executor thread observes the stored flags.  (On x86 this
            // compiles identically to Relaxed -- the stronger ordering is for
            // correctness on weakly-ordered architectures and clarity.)
            state.tls_failure_flags.store(flags, Ordering::Release);
            // Don't signal -- the subsequent REQUEST_ERROR will carry the error.
        }

        WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING => unsafe {
            reclaim_context_ptr::<RequestState>(dw_context);
        },

        // Verbose logging for connection-level events
        #[cfg(feature = "tracing")]
        status => {
            if state.verbose {
                log_verbose_status(status, lpv_info, dw_info_length);
            }
        }
        #[cfg(not(feature = "tracing"))]
        _ => {}
    }
}

/// Log verbose connection events via `tracing`.
///
/// Extracts structured data from the WinHTTP callback `lpvStatusInformation`:
/// - `RESOLVING_NAME` / `NAME_RESOLVED`: hostname as PCWSTR
/// - `CONNECTING_TO_SERVER` / `CONNECTED_TO_SERVER`: IP address as PCWSTR
/// - `REQUEST_SENT`: byte count as `u32` (pointed to by `info`)
/// - `REDIRECT`: redirect URL as PCWSTR
/// - `SENDING_REQUEST` / `RECEIVING_RESPONSE` / `RESPONSE_RECEIVED`: no data
#[cfg(feature = "tracing")]
fn log_verbose_status(status: u32, info: *mut std::ffi::c_void, info_len: u32) {
    match status {
        WINHTTP_CALLBACK_STATUS_RESOLVING_NAME => {
            let name = unsafe { crate::util::wide_to_string_lossy(info, info_len) };
            trace!(name = %name, "WinHTTP: resolving name");
        }
        WINHTTP_CALLBACK_STATUS_NAME_RESOLVED => {
            let name = unsafe { crate::util::wide_to_string_lossy(info, info_len) };
            trace!(name = %name, "WinHTTP: name resolved");
        }
        WINHTTP_CALLBACK_STATUS_CONNECTING_TO_SERVER => {
            let ip = unsafe { crate::util::wide_to_string_lossy(info, info_len) };
            trace!(ip = %ip, "WinHTTP: connecting to server");
        }
        WINHTTP_CALLBACK_STATUS_CONNECTED_TO_SERVER => {
            let ip = unsafe { crate::util::wide_to_string_lossy(info, info_len) };
            trace!(ip = %ip, "WinHTTP: connected to server");
        }
        WINHTTP_CALLBACK_STATUS_SENDING_REQUEST => {
            trace!("WinHTTP: sending request");
        }
        WINHTTP_CALLBACK_STATUS_REQUEST_SENT => {
            let bytes = if !info.is_null() && info_len >= 4 {
                unsafe { *(info as *const u32) }
            } else {
                0
            };
            trace!(bytes = bytes, "WinHTTP: request sent");
        }
        WINHTTP_CALLBACK_STATUS_RECEIVING_RESPONSE => {
            trace!("WinHTTP: receiving response");
        }
        WINHTTP_CALLBACK_STATUS_RESPONSE_RECEIVED => {
            let bytes = if !info.is_null() && info_len >= 4 {
                unsafe { *(info as *const u32) }
            } else {
                0
            };
            trace!(bytes = bytes, "WinHTTP: response received");
        }
        WINHTTP_CALLBACK_STATUS_REDIRECT => {
            let url = unsafe { crate::util::wide_to_string_lossy(info, info_len) };
            trace!(url = %url, "WinHTTP: redirect");
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Session creation
// ---------------------------------------------------------------------------

/// Configuration for creating a WinHTTP session.
pub(crate) struct SessionConfig {
    pub user_agent: String,
    pub connect_timeout_ms: u32,
    pub send_timeout_ms: u32,
    pub read_timeout_ms: u32,
    pub verbose: bool,
    pub max_connections_per_host: Option<u32>,
    pub proxy: ProxyAction,
    pub redirect_policy: Option<crate::redirect::Policy>,
    pub http1_only: bool,
}

/// An open WinHTTP session with the callback installed.
pub(crate) struct WinHttpSession {
    pub handle: WinHttpHandle,
    pub verbose: bool,
}

impl WinHttpSession {
    /// Open a new WinHTTP session with the given configuration.
    pub fn open(config: &SessionConfig) -> Result<Self, Error> {
        // Determine the access type and proxy string.
        // Since Windows 8.1: WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY uses
        // system and per-user proxy settings (including IE/WinINET config).
        // No fallback -- this is the only code path for `ProxyAction::Automatic`.
        let (access_type, proxy_str) = match &config.proxy {
            ProxyAction::Direct => (WINHTTP_ACCESS_TYPE_NO_PROXY, None),
            ProxyAction::Named(url, _) => (WINHTTP_ACCESS_TYPE_NAMED_PROXY, Some(url.as_str())),
            ProxyAction::Automatic => (WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, None),
        };

        let h_session = abi::winhttp_open_session(
            &config.user_agent,
            access_type,
            proxy_str,
            WINHTTP_FLAG_ASYNC,
        )?;

        let session = WinHttpHandle(h_session);

        // Install the status callback on the session (inherited by all children).
        // If this fails, every async operation would hang -- must propagate.
        abi::winhttp_set_status_callback(
            session.0,
            Some(winhttp_callback),
            WINHTTP_CALLBACK_FLAG_ALL_NOTIFICATIONS,
        )?;

        // Set timeouts. nResolveTimeout = 0 means OS default.
        abi::winhttp_set_timeouts(
            session.0,
            0, // resolve: OS default
            config.connect_timeout_ms as i32,
            config.send_timeout_ms as i32,
            config.read_timeout_ms as i32,
        )?;

        // Enable HTTP/2 (unless http1_only is set).
        // - HTTP/2: Windows 10 1607+ / Server 2016+ (August 2016)
        // - HTTP/3: Windows 11 21H1+ / Server 2022+ (May 2021)
        //
        // HTTP/3 is intentionally NOT enabled by default to avoid timeout regressions.
        // HTTP/3 uses QUIC (UDP port 443). On networks where UDP is blocked by firewalls,
        // QUIC handshakes timeout (10+ seconds) before falling back to HTTP/2, causing
        // severe performance degradation. This matches reqwest's approach where HTTP/3
        // requires explicit opt-in via the `http3` feature flag.
        //
        // Fallback: unsupported flags are silently ignored; falls back to HTTP/1.1.
        // WinHTTP negotiates the highest mutually supported version with the server.
        if !config.http1_only {
            let _ = abi::winhttp_set_option_u32(
                session.0,
                WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL,
                WINHTTP_PROTOCOL_FLAG_HTTP2,
            );
        }

        // Since Windows 8.1: enable automatic decompression (gzip + deflate).
        // Fallback: responses arrive uncompressed, which is functional
        // but slower.
        let _ = abi::winhttp_set_option_u32(
            session.0,
            WINHTTP_OPTION_DECOMPRESSION,
            WINHTTP_DECOMPRESSION_FLAG_GZIP | WINHTTP_DECOMPRESSION_FLAG_DEFLATE,
        );

        // Enable assured non-blocking callbacks.  Without this, WinHTTP may
        // block inside a callback waiting for another callback to complete,
        // deadlocking the async model.  Must propagate.
        abi::winhttp_set_option_u32(session.0, WINHTTP_OPTION_ASSURED_NON_BLOCKING_CALLBACKS, 1)?;

        // Set max connections per host (only if explicitly configured).
        // The caller asked for this -- silent failure would be misleading.
        if let Some(max_conns) = config.max_connections_per_host {
            abi::winhttp_set_option_u32(session.0, WINHTTP_OPTION_MAX_CONNS_PER_SERVER, max_conns)?;
        }

        // Apply redirect policy
        match &config.redirect_policy {
            Some(policy) => match &policy.inner {
                crate::redirect::PolicyInner::None => {
                    abi::winhttp_set_option_u32(
                        session.0,
                        WINHTTP_OPTION_REDIRECT_POLICY,
                        WINHTTP_OPTION_REDIRECT_POLICY_NEVER,
                    )?;
                }
                crate::redirect::PolicyInner::Limited(max) => {
                    abi::winhttp_set_option_u32(
                        session.0,
                        WINHTTP_OPTION_MAX_HTTP_AUTOMATIC_REDIRECTS,
                        *max,
                    )?;
                }
            },
            None => {
                // Default: follow up to 10 redirects
                abi::winhttp_set_option_u32(
                    session.0,
                    WINHTTP_OPTION_MAX_HTTP_AUTOMATIC_REDIRECTS,
                    10,
                )?;
            }
        }

        Ok(Self {
            handle: session,
            verbose: config.verbose,
        })
    }
}

// ---------------------------------------------------------------------------
// Execute request
// ---------------------------------------------------------------------------

/// The raw response data after headers are received.
pub(crate) struct RawResponse {
    /// The request handle (caller takes ownership for streaming body reads).
    pub request_handle: WinHttpHandle,
    /// Shared state for the request (holds the signal + read buffer).
    pub state: Arc<RequestState>,
    /// HTTP status code.
    pub status: StatusCode,
    /// HTTP version.
    pub version: Version,
    /// The final URL after any redirects (queried via WINHTTP_OPTION_URL).
    pub url: Url,
    /// Response headers.
    pub headers: http::HeaderMap,
}

/// Execute an HTTP request and return the raw response (headers received).
///
/// This opens a connection, sends the request, and waits for headers.
/// The caller then uses [`read_chunk`] to stream the body.
pub(crate) async fn execute_request(
    session: &WinHttpSession,
    url: &Url,
    method: &str,
    headers: &[(String, String)],
    body: Option<crate::Body>,
    proxy_config: &ProxyConfig,
    accept_invalid_certs: bool,
) -> Result<RawResponse, Error> {
    use crate::body::BodyInner;

    // Check per-request NO_PROXY override
    let per_request_proxy = proxy_config.resolve(&url.host, url.is_https);

    trace!(
        url = %url,
        proxy = ?per_request_proxy,
        "proxy resolved for request",
    );

    // Create the per-request state
    let state = Arc::new(RequestState::new(session.verbose));

    // Decompose the body into its inner representation so we can
    // distinguish in-memory bytes from streaming bodies.
    let body_inner = body.map(|b| b.into_inner());

    // For in-memory bodies, store them in the Arc<RequestState> so the
    // buffer outlives the future (cancellation safety -- see §4.3 / §4.4).
    // For streaming bodies the chunks are stored one-at-a-time during the
    // write loop below.
    let (body_ptr, body_len, has_bytes_body, mut stream) = match body_inner {
        Some(BodyInner::Bytes(v)) => {
            if v.is_empty() {
                let mut guard = lock_or_clear(&state.send_body);
                *guard = Some(v);
                (0usize, 0u64, false, None)
            } else {
                let mut guard = lock_or_clear(&state.send_body);
                let stored = guard.insert(v);
                let ptr = stored.as_ptr() as usize;
                let len = stored.len() as u64;
                (ptr, len, true, None)
            }
        }
        Some(BodyInner::Stream(s)) => (0usize, 0u64, false, Some(s)),
        None => (0usize, 0u64, false, None),
    };

    // WinHttpConnect -- open a connection to the server
    let h_connect = abi::winhttp_connect(session.handle.0, &url.host, url.port).url_context(url)?;
    let _connect_handle = WinHttpHandle(h_connect);

    // WinHttpOpenRequest
    let h_request = abi::winhttp_open_request(h_connect, method, &url.path_and_query, url.is_https)
        .url_context(url)?;
    // Drop the raw connect handle pointer so it does not live across await points.
    let _ = h_connect;

    let request_handle = WinHttpHandle(h_request);
    // Drop the raw request handle pointer so it does not live across await points
    let _ = h_request;

    // Leak context pointer for the callback
    let ctx = leak_context_ptr(&state);
    if let Err(e) =
        abi::winhttp_set_option_usize(request_handle.0, WINHTTP_OPTION_CONTEXT_VALUE, ctx)
    {
        // Reclaim the leaked Arc before propagating.  The HANDLE_CLOSING
        // callback cannot do this because the context was never associated
        // with the handle, so `dw_context` will be 0.
        //
        // SAFETY: `ctx` was returned by `leak_context_ptr` immediately above
        // and no callback has been delivered for it (the context was never set).
        unsafe {
            reclaim_context_ptr::<RequestState>(ctx);
        }
        return Err(e.with_url(url.clone()));
    }

    // Apply per-request proxy override.
    // The session was opened with a single proxy URL, but the resolved
    // action may differ per request (HTTP_PROXY != HTTPS_PROXY, or
    // NO_PROXY match -> direct).
    match &per_request_proxy {
        ProxyAction::Direct => {
            abi::winhttp_set_proxy_direct(request_handle.0).url_context(url)?;
        }
        ProxyAction::Named(proxy_url, proxy_creds) => {
            // Override the session-level proxy for this specific request.
            abi::winhttp_set_proxy_named(request_handle.0, proxy_url).url_context(url)?;

            // Set proxy Basic-auth credentials if provided.
            if let Some((username, password)) = proxy_creds {
                abi::winhttp_set_proxy_credentials(request_handle.0, username, password);
            }
        }
        ProxyAction::Automatic => {
            // Session default is already automatic; nothing to override.
        }
    }

    // Disable certificate validation if requested
    if accept_invalid_certs && url.is_https {
        let security_flags: u32 = SECURITY_FLAG_IGNORE_UNKNOWN_CA
            | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
            | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
            | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        abi::winhttp_set_option_u32(
            request_handle.0,
            WINHTTP_OPTION_SECURITY_FLAGS,
            security_flags,
        )
        .url_context(url)?;
    }

    // Add custom headers
    for (name, value) in headers {
        let header_line = format!("{name}: {value}\r\n");
        abi::winhttp_add_request_header(request_handle.0, &header_line).url_context(url)?;
    }

    // Send request.  Three body paths:
    //
    // 1. In-memory bytes that fit in a DWORD (<= 4 GiB): inlined directly
    //    in WinHttpSendRequest -- one syscall, no WriteComplete overhead.
    // 2. In-memory bytes > 4 GiB: headers-only WinHttpSendRequest, then
    //    WinHttpWriteData in DWORD-sized chunks.
    // 3. Streaming body (BoxStream): chunked transfer encoding via
    //    WinHttpWriteData with application-provided chunk framing.

    /// Body-size threshold above which the large-body path is used.
    ///
    /// Production: `u32::MAX` (4 GiB).  WinHTTP's `WinHttpSendRequest`
    /// takes a `DWORD` total-length; bodies larger than this must add
    /// a `Content-Length` header manually and stream the body via
    /// `WinHttpWriteData` in `DWORD`-sized chunks.
    ///
    /// Tests: lowered to 4 MiB so unit tests can exercise the
    /// large-body code path without allocating gigabytes of memory.
    #[cfg(not(test))]
    const LARGE_BODY_THRESHOLD: u64 = u32::MAX as u64;
    #[cfg(test)]
    const LARGE_BODY_THRESHOLD: u64 = 4 * 1024 * 1024;

    /// Maximum bytes per `WinHttpWriteData` call in the large-body path.
    ///
    /// Production: `u32::MAX` -- the largest value a DWORD can hold.
    ///
    /// Tests: lowered to 2 MiB so a 5 MiB body produces 3 loop
    /// iterations, exercising the multi-write loop without allocating
    /// gigabytes of memory.
    #[cfg(not(test))]
    const LARGE_BODY_CHUNK_MAX: usize = u32::MAX as usize;
    #[cfg(test)]
    const LARGE_BODY_CHUNK_MAX: usize = 2 * 1024 * 1024;

    if let Some(ref mut stream) = stream {
        // -- Path 3: streaming body (chunked transfer encoding) ------
        trace!("body path: streaming (chunked transfer encoding)");
        //
        // WinHTTP does NOT produce RFC 7230 chunked framing -- the
        // application must emit the hex-size prefix / CRLF delimiters
        // itself.  WinHTTP simply passes the bytes through and sets
        // `Transfer-Encoding: chunked` on the wire when it sees
        // `dwTotalLength = WINHTTP_IGNORE_REQUEST_TOTAL_LENGTH` (0).
        //
        // Each chunk is encoded as:
        //     {hex_size}\r\n{data}\r\n
        // and the stream is terminated with:
        //     0\r\n\r\n

        // Tell WinHTTP the body length is unknown.
        abi::winhttp_add_request_header(request_handle.0, "Transfer-Encoding: chunked\r\n")
            .url_context(url)?;

        let h_send = request_handle.as_send();
        await_win32(&state.signal, move || {
            abi::winhttp_send_request(
                h_send.as_mut_ptr(),
                std::ptr::null(),
                0,
                WINHTTP_IGNORE_REQUEST_TOTAL_LENGTH,
            )
            .url_context(url)
        })
        .await?
        .into_result(&state, url)?;

        // Write chunks from the stream as they arrive.
        use futures_util::StreamExt;
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.map_err(|e| {
                // Classified as Request (not Body) to match reqwest: this is a
                // send-phase failure, not a response-body-read failure.
                Error::request(format!("stream body error: {e}")).with_url(url.clone())
            })?;

            if chunk.is_empty() {
                continue;
            }

            // Build the RFC 7230 chunked-encoded frame:
            //   {hex_size}\r\n{data}\r\n
            let header = format!("{:x}\r\n", chunk.len());
            let mut frame = Vec::with_capacity(header.len() + chunk.len() + 2);
            frame.extend_from_slice(header.as_bytes());
            frame.extend_from_slice(&chunk);
            frame.extend_from_slice(b"\r\n");

            // Store the encoded frame in state.send_body for
            // cancellation safety -- WinHTTP may still reference the
            // buffer if the future is dropped mid-write.
            let (frame_ptr, frame_len) = {
                let mut guard = lock_or_clear(&state.send_body);
                let stored = guard.insert(frame);
                (stored.as_ptr() as usize, stored.len() as u32)
            };

            write_data(&state.signal, &request_handle, frame_ptr, frame_len, url).await?;
        }

        // Terminate the chunked transfer: "0\r\n\r\n"
        {
            let terminator = b"0\r\n\r\n".to_vec();
            let (term_ptr, term_len) = {
                let mut guard = lock_or_clear(&state.send_body);
                let stored = guard.insert(terminator);
                (stored.as_ptr() as usize, stored.len() as u32)
            };

            write_data(&state.signal, &request_handle, term_ptr, term_len, url).await?;
        }
    } else if body_len <= LARGE_BODY_THRESHOLD {
        // Fast path: body fits in a single DWORD.  WinHTTP adds
        // Content-Length automatically and sends everything in one call.
        trace!(body_len, "body path: inline");
        let inline_len = body_len as u32;
        let h_send = request_handle.as_send();

        // `body_ptr` is already a usize (pointer into state.send_body,
        // which outlives HANDLE_CLOSING).
        let body_ptr_usize = body_ptr;

        await_win32(&state.signal, move || {
            let optional = if inline_len > 0 {
                body_ptr_usize as *const std::ffi::c_void
            } else {
                std::ptr::null()
            };
            abi::winhttp_send_request(h_send.as_mut_ptr(), optional, inline_len, inline_len)
                .url_context(url)
        })
        .await?
        .into_result(&state, url)?;
    } else {
        // Large-body path: send headers first, then stream the body in
        // chunks of up to DWORD::MAX bytes via WinHttpWriteData.
        trace!(body_len, "body path: large (multi-write)");

        // Tell WinHTTP the full content length via a Content-Length
        // header.  WinHttpSendRequest's dwTotalLength is a DWORD and
        // cannot represent bodies > 4 GiB, so the documented approach
        // (since Vista / Server 2008) is:
        //
        //   1. Add `Content-Length: <n>` as a request header.
        //   2. Pass WINHTTP_IGNORE_REQUEST_TOTAL_LENGTH as dwTotalLength.
        //   3. Write body data via WinHttpWriteData.
        //
        // See "Support for Greater Than 4-GB Upload" in the
        // WinHttpSendRequest documentation.
        abi::winhttp_add_request_header(
            request_handle.0,
            &format!("Content-Length: {body_len}\r\n"),
        )
        .url_context(url)?;

        // Send headers only -- no inline body data.
        // Content length was set via the option above.
        let h_send = request_handle.as_send();
        await_win32(&state.signal, move || {
            abi::winhttp_send_request(
                h_send.as_mut_ptr(),
                std::ptr::null(),
                0,
                WINHTTP_IGNORE_REQUEST_TOTAL_LENGTH,
            )
            .url_context(url)
        })
        .await?
        .into_result(&state, url)?;

        // Write body data in chunks via WinHttpWriteData.
        // Each call can write up to LARGE_BODY_CHUNK_MAX bytes
        // (DWORD::MAX in production, lowered under #[cfg(test)]).
        // `body_ptr` is a usize pointer into state.send_body (safe across
        // cancellation -- the Arc keeps it alive until HANDLE_CLOSING).
        if has_bytes_body {
            let total_len = body_len as usize;
            let chunk_max = LARGE_BODY_CHUNK_MAX;
            let mut offset: usize = 0;

            while offset < total_len {
                let remaining = total_len - offset;
                let chunk_size = remaining.min(chunk_max);
                let chunk_len = chunk_size as u32;

                // `body_ptr` is the base pointer (usize) into state.send_body.
                let body_offset = offset;
                write_data(&state.signal, &request_handle, body_ptr + body_offset, chunk_len, url)
                    .await?;

                offset += chunk_size;
            }
        }
    }

    // Receive response headers
    let h_recv = request_handle.as_send();
    await_win32(&state.signal, move || {
        abi::winhttp_receive_response(h_recv.as_mut_ptr()).url_context(url)
    })
    .await?
    .into_result(&state, url)?;

    // WinHttpReceiveResponse has completed -- the send body is no longer
    // referenced by WinHTTP.  Drop it eagerly to free memory before the
    // (potentially large) response body is streamed.
    //
    // Safe to recover from poison: `send_body` is an `Option<Vec<u8>>`
    // slot -- just `.take()`, no multi-field invariant.
    let _ = lock_or_clear(&state.send_body).take();

    // Query status code
    let status = query_status_code(request_handle.0, url)?;

    // Query HTTP version
    let version = query_version(request_handle.0);

    // Query response headers
    let headers = query_headers(request_handle.0, url)?;

    // Query the final URL after any redirects.  WinHTTP handles redirects
    // internally, so WINHTTP_OPTION_URL returns the URL of the last request
    // in the chain (matching reqwest's `Response::url()` behavior).
    let final_url = abi::winhttp_query_option_url(request_handle.0, WINHTTP_OPTION_URL)
        .and_then(|s| Url::parse(&s).ok())
        .unwrap_or_else(|| url.clone());

    trace!(
        status = status.as_u16(),
        version = ?version,
        final_url = %final_url,
        header_count = headers.len(),
        "headers received",
    );

    // Transfer ownership of the request handle into the response.
    // The connect handle (_connect_handle) is dropped here -- WinHTTP docs
    // confirm the request handle remains valid after the connect handle closes.
    Ok(RawResponse {
        request_handle,
        state,
        status,
        version,
        url: final_url,
        headers,
    })
}

/// Write a data buffer via `WinHttpWriteData` and await the `WriteComplete` callback.
///
/// `data_ptr` is a `usize` pointer into a buffer that outlives the async
/// operation (typically stored in `state.send_body` for cancellation safety).
async fn write_data(
    signal: &CompletionSignal<CallbackEvent>,
    handle: &WinHttpHandle,
    data_ptr: usize,
    data_len: u32,
    url: &Url,
) -> Result<u32, Error> {
    let h = handle.as_send();
    await_win32(signal, move || {
        let ptr = data_ptr as *const std::ffi::c_void;
        abi::winhttp_write_data(h.as_mut_ptr(), ptr, data_len).url_context(url)
    })
    .await?
    .into_write_complete(url)
}

/// Read a chunk of the response body.
///
/// Returns `Ok(None)` at EOF. The returned `bytes::Bytes` is zero-copy -- WinHTTP
/// writes directly into a `BytesMut` which is then frozen.
pub(crate) async fn read_chunk(
    state: &Arc<RequestState>,
    handle: &WinHttpHandle,
    url: &Url,
) -> Result<Option<bytes::Bytes>, Error> {
    // Allocate a fixed 8 KiB buffer.  WinHttpReadData behaves like recv():
    // it returns as soon as *any* data arrives (the buffer size is a maximum,
    // not a target) and signals EOF via ReadComplete(0).  A single ReadData
    // call replaces the old QueryDataAvailable + ReadData pair, halving the
    // number of async round-trips per chunk.
    const READ_BUF_SIZE: usize = 8192;
    let buf = BytesMut::with_capacity(READ_BUF_SIZE);

    // Store the buffer in the state so it outlives the async callback (cancellation safety).
    //
    // Safe to recover from poison: `read_buffer` is an `Option<BytesMut>`
    // slot -- only assignment / `.take()`, no multi-field invariant.
    *lock_or_clear(&state.read_buffer) = Some(buf);

    // Read data -- buf_ptr is computed inside the closure to avoid holding
    //    a raw pointer across the await point (which would make the future !Send).
    let h_read = handle.as_send();
    let read = await_win32(&state.signal, move || {
        let (buf_ptr, buf_capacity) = {
            // Safe to recover from poison: `read_buffer` is an
            // `Option<BytesMut>` slot -- no multi-field invariant.
            let mut guard = lock_or_clear(&state.read_buffer);
            // Destructure: buffer was stored immediately before this
            // closure runs. If missing, surface as Err, not a panic.
            let Some(buf_ref) = guard.as_mut() else {
                return Err(Error::request("read buffer missing (invariant violated)")
                    .with_url(url.clone()));
            };
            let spare = buf_ref.spare_capacity_mut();
            (spare.as_ptr() as *mut std::ffi::c_void, spare.len() as u32)
        };
        abi::winhttp_read_data(h_read.as_mut_ptr(), buf_ptr, buf_capacity).url_context(url)
    })
    .await?
    .into_read_complete(url)?;

    if read == 0 {
        // EOF -- release the buffer and signal end-of-body.
        lock_or_clear(&state.read_buffer).take();
        return Ok(None);
    }

    // Take the buffer back, advance length, freeze.
    //
    // Safe to recover from poison: `read_buffer` is an `Option<BytesMut>`
    // slot -- just `.take()`, no multi-field invariant.
    let Some(mut buf) = lock_or_clear(&state.read_buffer).take() else {
        return Err(Error::request("read buffer missing after read (invariant violated)")
            .with_url(url.clone()));
    };
    debug_assert!(
        (read as usize) <= buf.capacity(),
        "WinHTTP reported {read} bytes read but buffer capacity is {}",
        buf.capacity(),
    );
    // SAFETY: `buf` was allocated with `BytesMut::with_capacity(to_read)`
    // and passed to `WinHttpReadData` which wrote exactly `read` bytes
    // into it.  The `debug_assert!` above confirms `read <= capacity`.
    unsafe {
        buf.set_len(read as usize);
    }
    Ok(Some(buf.freeze()))
}

// ---------------------------------------------------------------------------
// Query helpers
// ---------------------------------------------------------------------------

/// Query all response headers and parse into an `http::HeaderMap`.
///
/// Uses `WINHTTP_QUERY_RAW_HEADERS_CRLF` to retrieve the full header block
/// as a single wide string, then parses each `Name: Value` line.
fn query_headers(h_request: *mut core::ffi::c_void, url: &Url) -> Result<http::HeaderMap, Error> {
    let raw = abi::winhttp_query_raw_headers(h_request).url_context(url)?;
    Ok(parse_raw_headers(&raw))
}

/// Parse a raw CRLF-delimited header block into an `http::HeaderMap`.
///
/// Parses each `Name: Value` line, skipping the status line and empty lines.
fn parse_raw_headers(raw: &str) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();

    for line in raw.lines() {
        // Skip the status line (e.g., "HTTP/1.1 200 OK") and empty lines.
        if line.is_empty() || line.starts_with("HTTP/") {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            if let (Ok(n), Ok(v)) = (
                http::header::HeaderName::from_bytes(name.as_bytes()),
                http::header::HeaderValue::from_bytes(value.as_bytes()),
            ) {
                headers.append(n, v);
            }
        }
    }

    headers
}

/// Query the HTTP status code from the response.
fn query_status_code(h_request: *mut core::ffi::c_void, url: &Url) -> Result<StatusCode, Error> {
    let status_code = abi::winhttp_query_header_u32(
        h_request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
    )
    .url_context(url)?;

    StatusCode::from_u16(status_code as u16).map_err(|_| {
        Error::request(format!("invalid status code: {status_code}")).with_url(url.clone())
    })
}

/// Query the HTTP version from the response.
///
/// Tries `WINHTTP_OPTION_HTTP_PROTOCOL_USED` first (for HTTP/2 detection),
/// falls back to the version header string.
fn query_version(h_request: *mut core::ffi::c_void) -> Version {
    let protocol_flags =
        abi::winhttp_query_option_u32(h_request, WINHTTP_OPTION_HTTP_PROTOCOL_USED);
    let version_str = abi::winhttp_query_header_string(h_request, WINHTTP_QUERY_VERSION);
    resolve_version(protocol_flags, version_str.as_deref())
}

/// Determine the HTTP version from optional protocol flags and a version
/// header string.
///
/// Protocol flags take precedence when available; otherwise falls back to
/// the version header string.  Defaults to HTTP/1.1 if neither source
/// provides a recognised version.
fn resolve_version(protocol_flags: Option<u32>, version_str: Option<&str>) -> Version {
    // Since Windows 10 1607: query the negotiated HTTP protocol.
    // Fallback: the option returns None and we fall through to the
    // version header string, which reports HTTP/1.0 or HTTP/1.1 but
    // cannot distinguish HTTP/2 or HTTP/3.
    if let Some(flags) = protocol_flags {
        // Since Windows 10 21H1: HTTP/3 flag is reported when the
        // server negotiated HTTP/3.  On older builds this bit is never
        // set, so we simply fall through to the HTTP/2 check.
        if flags & WINHTTP_PROTOCOL_FLAG_HTTP3 != 0 {
            return Version::HTTP_3;
        }
        if flags & WINHTTP_PROTOCOL_FLAG_HTTP2 != 0 {
            return Version::HTTP_2;
        }
    }

    // Fall back to the version header string.
    if let Some(s) = version_str {
        match s {
            "HTTP/1.0" => return Version::HTTP_10,
            "HTTP/1.1" => return Version::HTTP_11,
            _ => {}
        }
    }

    Version::HTTP_11 // default
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

/// Create an [`Error`] from a raw WinHTTP error code (`u32`).
///
/// Converts the code to an HRESULT and delegates to [`Error::from_hresult`]
/// so that error-kind classification happens in one place.
fn error_from_winhttp_code(code: u32) -> Error {
    Error::from_hresult(abi::hresult_from_win32(code))
}

/// Create an Error from a WinHTTP callback error, enriching with TLS details.
fn callback_error_to_error(code: u32, state: &RequestState, url: &Url) -> Error {
    let mut err = error_from_winhttp_code(code);
    err.url = Some(Box::new(url.clone()));

    // Enrich TLS errors with captured failure flags
    if code == ERROR_WINHTTP_SECURE_FAILURE {
        // Acquire: pairs with the Release store in the SECURE_FAILURE callback.
        let tls_flags = state.tls_failure_flags.load(Ordering::Acquire);
        let detail = describe_tls_failure(tls_flags);
        err.message = format!("TLS error: {detail}");
    }

    err
}

/// Convert TLS failure flags to a human-readable description.
fn describe_tls_failure(flags: u32) -> String {
    let mut parts = Vec::new();
    if flags & WINHTTP_CALLBACK_STATUS_FLAG_CERT_REV_FAILED != 0 {
        parts.push("revocation check failed");
    }
    if flags & WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CERT != 0 {
        parts.push("invalid certificate");
    }
    if flags & WINHTTP_CALLBACK_STATUS_FLAG_CERT_REVOKED != 0 {
        parts.push("certificate revoked");
    }
    if flags & WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA != 0 {
        parts.push("invalid CA");
    }
    if flags & WINHTTP_CALLBACK_STATUS_FLAG_CERT_CN_INVALID != 0 {
        parts.push("certificate CN mismatch");
    }
    if flags & WINHTTP_CALLBACK_STATUS_FLAG_CERT_DATE_INVALID != 0 {
        parts.push("certificate expired or not yet valid");
    }
    if flags & WINHTTP_CALLBACK_STATUS_FLAG_SECURITY_CHANNEL_ERROR != 0 {
        parts.push("security channel error");
    }
    if parts.is_empty() {
        "unknown TLS failure".to_owned()
    } else {
        parts.join(", ")
    }
}

impl From<SignalCancelled> for Error {
    fn from(_: SignalCancelled) -> Self {
        Error::request("operation cancelled (signal dropped)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Large-body multi-write path --
    //
    // Under `#[cfg(test)]` (which applies here, inside the crate):
    //   - `LARGE_BODY_THRESHOLD` is lowered to 4 MiB, so a 5 MiB body
    //     enters the large-body path.
    //   - `LARGE_BODY_CHUNK_MAX` is lowered to 2 MiB, so the 5 MiB
    //     body produces 3 `WinHttpWriteData` calls (2 + 2 + 1 MiB),
    //     exercising the multi-write loop.
    //
    // Integration tests can never reach this path because `#[cfg(test)]`
    // does not apply to the library when linked by `tests/*.rs`.

    #[tokio::test]
    async fn large_body_multi_write_path() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/large-ut"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .expect(1)
            .mount(&server)
            .await;

        let config = SessionConfig {
            user_agent: String::new(),
            connect_timeout_ms: 10_000,
            send_timeout_ms: 0,
            read_timeout_ms: 0,
            verbose: false,
            max_connections_per_host: None,
            proxy: ProxyAction::Automatic,
            redirect_policy: None,
            http1_only: false,
        };

        let session = WinHttpSession::open(&config).expect("session should open");
        let url: Url = format!("{}/large-ut", server.uri()).parse().unwrap();
        let proxy_config = ProxyConfig::none();

        // 5 MiB body — exceeds the 4 MiB #[cfg(test)] threshold.
        let body = crate::Body::from(vec![b'X'; 5 * 1024 * 1024]);

        let raw = execute_request(&session, &url, "POST", &[], Some(body), &proxy_config, false)
            .await
            .expect("large body request should succeed");

        assert_eq!(raw.status, 200);
    }

    // -- describe_tls_failure (data-driven) --

    // -- Session-level config variants (proxy / redirect policy) --

    #[tokio::test]
    async fn session_config_variants() {
        // Data-driven test covering session-level proxy and redirect policy
        // branches in `WinHttpSession::open`:
        //   - ProxyAction::Direct
        //   - PolicyInner::None
        //   - PolicyInner::Limited
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // (label, proxy, redirect_policy, mock_path, redirect_to, expected_status)
        struct Case {
            label: &'static str,
            proxy: ProxyAction,
            redirect_policy: Option<crate::redirect::Policy>,
            src_path: &'static str,
            redirect_to: Option<&'static str>,
            dst_path: Option<&'static str>,
            expected_status: u16,
        }

        let cases = [
            Case {
                label: "ProxyAction::Direct",
                proxy: ProxyAction::Direct,
                redirect_policy: None,
                src_path: "/direct-test",
                redirect_to: None,
                dst_path: None,
                expected_status: 200,
            },
            Case {
                label: "Policy::none() → 302 returned as-is",
                proxy: ProxyAction::Automatic,
                redirect_policy: Some(crate::redirect::Policy::none()),
                src_path: "/rp-src",
                redirect_to: Some("/rp-dst"),
                dst_path: None, // not mounted — redirect should NOT be followed
                expected_status: 302,
            },
            Case {
                label: "Policy::limited(5) → redirect followed",
                proxy: ProxyAction::Automatic,
                redirect_policy: Some(crate::redirect::Policy::limited(5)),
                src_path: "/lim-src",
                redirect_to: Some("/lim-dst"),
                dst_path: Some("/lim-dst"),
                expected_status: 200,
            },
        ];

        for case in &cases {
            let server = MockServer::start().await;

            // Mount source mock (either 200 or redirect)
            if let Some(redir) = case.redirect_to {
                Mock::given(method("GET"))
                    .and(path(case.src_path))
                    .respond_with(
                        ResponseTemplate::new(302)
                            .insert_header("location", format!("{}{redir}", server.uri())),
                    )
                    .expect(1)
                    .mount(&server)
                    .await;
            } else {
                Mock::given(method("GET"))
                    .and(path(case.src_path))
                    .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
                    .expect(1)
                    .mount(&server)
                    .await;
            }

            // Mount destination mock if redirect should be followed
            if let Some(dst) = case.dst_path {
                Mock::given(method("GET"))
                    .and(path(dst))
                    .respond_with(ResponseTemplate::new(200).set_body_string("arrived"))
                    .expect(1)
                    .mount(&server)
                    .await;
            }

            let config = SessionConfig {
                user_agent: String::new(),
                connect_timeout_ms: 10_000,
                send_timeout_ms: 0,
                read_timeout_ms: 0,
                verbose: false,
                max_connections_per_host: None,
                proxy: case.proxy.clone(),
                redirect_policy: case.redirect_policy.clone(),
                http1_only: false,
            };

            let session = WinHttpSession::open(&config)
                .unwrap_or_else(|e| panic!("{}: session open failed: {e}", case.label));
            let url: Url = format!("{}{}", server.uri(), case.src_path)
                .parse()
                .unwrap();
            let proxy_config = ProxyConfig::none();

            let raw = execute_request(&session, &url, "GET", &[], None, &proxy_config, false)
                .await
                .unwrap_or_else(|e| panic!("{}: request failed: {e}", case.label));

            assert_eq!(raw.status, case.expected_status, "{}", case.label);
        }
    }

    // -- Per-request ProxyAction::Direct via NO_PROXY match --

    #[tokio::test]
    async fn per_request_proxy_direct_via_no_proxy() {
        // Exercises the `ProxyAction::Direct` branch inside `execute_request`
        // (the per-request proxy override). The session is opened with a Named
        // proxy, but `ProxyConfig::resolve()` returns Direct because the target
        // host matches a NO_PROXY pattern.
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/np-direct"))
            .respond_with(ResponseTemplate::new(200).set_body_string("bypassed"))
            .expect(1)
            .mount(&server)
            .await;

        // Session-level: Named proxy (pointing at the same server — doesn't
        // matter because the per-request override will bypass it).
        let config = SessionConfig {
            user_agent: String::new(),
            connect_timeout_ms: 10_000,
            send_timeout_ms: 0,
            read_timeout_ms: 0,
            verbose: false,
            max_connections_per_host: None,
            proxy: ProxyAction::Named(server.uri(), None),
            redirect_policy: None,
            http1_only: false,
        };

        let session = WinHttpSession::open(&config).expect("session should open");
        let url: Url = format!("{}/np-direct", server.uri()).parse().unwrap();

        // Build a ProxyConfig whose NO_PROXY list matches 127.0.0.1 (the
        // wiremock server address), causing resolve() → Direct.
        let mut proxy_config = ProxyConfig::none();
        crate::NoProxy::from_string("127.0.0.1")
            .unwrap()
            .apply_to(&mut proxy_config);

        let raw = execute_request(&session, &url, "GET", &[], None, &proxy_config, false)
            .await
            .expect("direct bypass request should succeed");

        assert_eq!(raw.status, 200);
    }

    #[test]
    fn describe_tls_failure_table() {
        let cases: &[(u32, &[&str])] = &[
            // -- individual flags --------------------------------
            (0, &["unknown TLS failure"]),
            (WINHTTP_CALLBACK_STATUS_FLAG_CERT_REV_FAILED, &["revocation check failed"]),
            (WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CERT, &["invalid certificate"]),
            (WINHTTP_CALLBACK_STATUS_FLAG_CERT_REVOKED, &["certificate revoked"]),
            (WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA, &["invalid CA"]),
            (WINHTTP_CALLBACK_STATUS_FLAG_CERT_CN_INVALID, &["certificate CN mismatch"]),
            (
                WINHTTP_CALLBACK_STATUS_FLAG_CERT_DATE_INVALID,
                &["certificate expired or not yet valid"],
            ),
            (WINHTTP_CALLBACK_STATUS_FLAG_SECURITY_CHANNEL_ERROR, &["security channel error"]),
            // -- combined flags -----------------------------------
            (
                WINHTTP_CALLBACK_STATUS_FLAG_CERT_REVOKED
                    | WINHTTP_CALLBACK_STATUS_FLAG_CERT_DATE_INVALID,
                &["certificate revoked", "certificate expired or not yet valid"],
            ),
            (
                WINHTTP_CALLBACK_STATUS_FLAG_CERT_REV_FAILED
                    | WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CERT
                    | WINHTTP_CALLBACK_STATUS_FLAG_CERT_REVOKED
                    | WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA
                    | WINHTTP_CALLBACK_STATUS_FLAG_CERT_CN_INVALID
                    | WINHTTP_CALLBACK_STATUS_FLAG_CERT_DATE_INVALID
                    | WINHTTP_CALLBACK_STATUS_FLAG_SECURITY_CHANNEL_ERROR,
                &[
                    "revocation check failed",
                    "invalid certificate",
                    "certificate revoked",
                    "invalid CA",
                    "certificate CN mismatch",
                    "certificate expired or not yet valid",
                    "security channel error",
                ],
            ),
        ];

        for &(flags, expected) in cases {
            let s = describe_tls_failure(flags);
            for needle in expected {
                assert!(s.contains(needle), "flags 0x{flags:X}: expected {needle:?}, got: {s}");
            }
        }
    }

    // -- CallbackEvent conversion --

    #[test]
    fn callback_event_into_result() {
        let url: Url = "https://example.com".parse().unwrap();
        let state = RequestState::new(false);

        // (event, expected_outcome)
        // Ok(()) for success, Err("kind") for which is_* should be true
        #[expect(clippy::type_complexity)]
        let cases: Vec<(CallbackEvent, Result<(), fn(&Error) -> bool>)> = vec![
            (CallbackEvent::Complete, Ok(())),
            (CallbackEvent::Error(ERROR_WINHTTP_TIMEOUT), Err(Error::is_timeout)),
            (CallbackEvent::ReadComplete(42), Err(Error::is_request)),
            (CallbackEvent::WriteComplete(0), Err(Error::is_request)),
        ];

        for (event, expected) in cases {
            let label = format!("{event:?}");
            let result = event.into_result(&state, &url);
            match expected {
                Ok(()) => assert!(result.is_ok(), "{label}: expected Ok"),
                Err(check) => {
                    let err = result.expect_err(&format!("{label}: expected Err"));
                    assert!(check(&err), "{label}: wrong error kind: {err}");
                }
            }
        }
    }

    // -- CallbackEvent::into_read_complete / into_write_complete (merged) --

    #[test]
    fn callback_event_into_read_write_complete() {
        let url: Url = "https://example.com".parse().unwrap();

        // (method_name, happy_event, happy_value, wrong_variant_event)
        #[expect(clippy::type_complexity)]
        let cases: Vec<(
            &str,
            fn(CallbackEvent, &Url) -> crate::Result<u32>,
            CallbackEvent,
            u32,
            CallbackEvent,
        )> = vec![
            (
                "into_read_complete",
                |e, u| e.into_read_complete(u),
                CallbackEvent::ReadComplete(512),
                512,
                CallbackEvent::WriteComplete(0),
            ),
            (
                "into_write_complete",
                |e, u| e.into_write_complete(u),
                CallbackEvent::WriteComplete(256),
                256,
                CallbackEvent::ReadComplete(0),
            ),
        ];

        for (label, method, happy_event, expected_val, wrong_event) in cases {
            // Happy path
            assert_eq!(method(happy_event, &url).unwrap(), expected_val, "{label}: happy");

            // Wrong variant → is_request error
            let err = method(wrong_event, &url).unwrap_err();
            assert!(err.is_request(), "{label}: wrong variant should be request error");

            // Timeout variant → is_timeout error
            let err = method(CallbackEvent::Error(ERROR_WINHTTP_TIMEOUT), &url).unwrap_err();
            assert!(err.is_timeout(), "{label}: timeout variant");
        }
    }

    // -- SignalCancelled -> Error --

    #[test]
    fn signal_cancelled_into_error() {
        let err: Error = SignalCancelled.into();
        assert!(err.is_request());
        assert!(err.to_string().contains("cancelled"));
    }

    // -- Additional error path coverage --

    // NOTE: WinHTTP error-code → ErrorKind classification is covered
    // exhaustively in error.rs::hresult_classification_table.

    #[test]
    fn callback_error_to_error_preserves_url() {
        let url: Url = "https://example.com/test".parse().unwrap();
        let state = RequestState::new(false);
        let err = callback_error_to_error(ERROR_WINHTTP_TIMEOUT, &state, &url);

        assert!(err.is_timeout());
        assert_eq!(err.url().map(|u| u.as_str()), Some("https://example.com/test"));
    }

    #[test]
    fn tls_failure_enrichment() {
        let url: Url = "https://example.com".parse().unwrap();
        let state = RequestState::new(false);

        // Simulate a TLS failure flag being set
        state
            .tls_failure_flags
            .store(WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA, std::sync::atomic::Ordering::Release);

        let err = callback_error_to_error(ERROR_WINHTTP_SECURE_FAILURE, &state, &url);
        assert!(err.is_connect());
        assert!(
            err.to_string().contains("invalid CA"),
            "TLS error should be enriched with failure details, got: {err}"
        );
    }

    // -- parse_raw_headers --

    #[test]
    #[expect(clippy::type_complexity)]
    fn parse_raw_headers_table() {
        // (raw_input, expected_headers_as (name, value) pairs, label)
        let cases: &[(&str, &[(&str, &str)], &str)] = &[
            ("", &[], "empty input"),
            ("HTTP/1.1 200 OK\r\n", &[], "status line only"),
            (
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 42\r\n",
                &[("content-type", "text/html"), ("content-length", "42")],
                "typical response",
            ),
            (
                "HTTP/1.1 200 OK\r\nLocation: https://example.com:8080/path\r\n",
                &[("location", "https://example.com:8080/path")],
                "colon in value",
            ),
            (
                "HTTP/1.1 200 OK\r\nmalformed-line-without-colon\r\nContent-Type: text/plain\r\n",
                &[("content-type", "text/plain")],
                "no-colon line skipped",
            ),
            (
                "HTTP/1.1 200 OK\r\n  X-Custom  :   value with spaces   \r\n",
                &[("x-custom", "value with spaces")],
                "whitespace trimmed",
            ),
        ];

        for &(raw, expected, label) in cases {
            let headers = parse_raw_headers(raw);
            assert_eq!(headers.len(), expected.len(), "{label}: header count");
            for &(name, value) in expected {
                assert_eq!(
                    headers
                        .get(name)
                        .unwrap_or_else(|| panic!("{label}: missing {name}")),
                    value,
                    "{label}: {name}"
                );
            }
        }
    }

    #[test]
    fn parse_raw_headers_duplicate_headers() {
        let raw = "HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n";
        let headers = parse_raw_headers(raw);
        let cookies: Vec<&str> = headers
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(cookies.len(), 2);
        assert!(cookies.contains(&"a=1"));
        assert!(cookies.contains(&"b=2"));
    }

    // -- resolve_version --

    #[test]
    fn resolve_version_table() {
        // (protocol_flags, version_str, expected_version, label)
        let cases: &[(Option<u32>, Option<&str>, Version, &str)] = &[
            (None, None, Version::HTTP_11, "no info defaults to HTTP/1.1"),
            (None, Some("HTTP/1.0"), Version::HTTP_10, "version string HTTP/1.0"),
            (None, Some("HTTP/1.1"), Version::HTTP_11, "version string HTTP/1.1"),
            (None, Some("HTTP/2.0"), Version::HTTP_11, "unrecognized version string defaults"),
            (Some(0), None, Version::HTTP_11, "flags zero defaults to HTTP/1.1"),
            (Some(0), Some("HTTP/1.0"), Version::HTTP_10, "flags zero falls through to string"),
            (Some(WINHTTP_PROTOCOL_FLAG_HTTP2), None, Version::HTTP_2, "HTTP/2 flag"),
            (
                Some(WINHTTP_PROTOCOL_FLAG_HTTP2),
                Some("HTTP/1.1"),
                Version::HTTP_2,
                "HTTP/2 flag takes precedence over string",
            ),
            (Some(WINHTTP_PROTOCOL_FLAG_HTTP3), None, Version::HTTP_3, "HTTP/3 flag"),
            (
                Some(WINHTTP_PROTOCOL_FLAG_HTTP3 | WINHTTP_PROTOCOL_FLAG_HTTP2),
                None,
                Version::HTTP_3,
                "HTTP/3 takes precedence over HTTP/2",
            ),
        ];

        for &(flags, version_str, expected, label) in cases {
            let result = resolve_version(flags, version_str);
            assert_eq!(result, expected, "resolve_version: {label}");
        }
    }
}
