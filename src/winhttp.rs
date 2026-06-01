//! WinHTTP-specific callback wiring and handle wrappers.
//!
//! This module applies the generic bridge from [`callback`](crate::callback) to
//! WinHTTP. It is entirely `pub(crate)` -- the public API is in [`client`],
//! [`request`], and [`response`].

use crate::{
    Body, abi,
    body::BodyInner,
    callback::{CallbackContext, CompletionSignal, SignalCancelled, await_win32},
    error::{ContextError, Error},
    proxy::{ProxyAction, ProxyConfig},
    redirect::{self, Policy},
    url::Url,
    util::lock_or_clear,
};
use bytes::BytesMut;
use http::{StatusCode, Version};
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicU32, Ordering},
};
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

/// Close/drain state for one request handle.
struct RequestCloseState {
    closed: bool,
    active_callbacks: usize,
}

#[cfg(debug_assertions)]
thread_local! {
    static WINHTTP_CALLBACK_STACK: std::cell::RefCell<Vec<usize>> =
    const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(debug_assertions)]
struct WinHttpCallbackStackGuard {
    request: usize,
}

#[cfg(debug_assertions)]
impl WinHttpCallbackStackGuard {
    fn enter(request: usize) -> Self {
        WINHTTP_CALLBACK_STACK.with(|stack| stack.borrow_mut().push(request));
        Self { request }
    }
}

#[cfg(debug_assertions)]
impl Drop for WinHttpCallbackStackGuard {
    fn drop(&mut self) {
        WINHTTP_CALLBACK_STACK.with(|stack| {
            let popped = stack.borrow_mut().pop();
            debug_assert_eq!(
                popped,
                Some(self.request),
                "WinHTTP callback stack tracking became unbalanced"
            );
        });
    }
}

/// RAII wrapper for a raw WinHTTP handle (`*mut c_void`).
///
/// Calls `WinHttpCloseHandle` on drop. After the close, WinHTTP may still
/// deliver callbacks (the last one is `HANDLE_CLOSING`).
pub(crate) struct WinHttpHandle(pub *mut core::ffi::c_void);

impl WinHttpHandle {
    /// Convert this generic handle into a request handle that waits for
    /// `HANDLE_CLOSING` before drop returns.
    fn into_request_handle(mut self, state: Arc<RequestState>) -> WinHttpRequestHandle {
        let handle = self.0;
        self.0 = std::ptr::null_mut();
        WinHttpRequestHandle { handle, state }
    }
}

impl Drop for WinHttpHandle {
    fn drop(&mut self) {
        let _ = abi::close_winhttp_handle(self.0);
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
    /// the `ERROR_WINHTTP_*` constants.
    Win32Error(u32),
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
            CallbackEvent::Win32Error(code) => Err(callback_error_to_error(code, state, url)),
            other => Err(other.unexpected(url)),
        }
    }

    /// Extract the byte count from a `ReadComplete` event.
    pub fn into_read_complete(self, url: &Url) -> Result<u32, Error> {
        match self {
            CallbackEvent::ReadComplete(n) => Ok(n),
            CallbackEvent::Win32Error(code) => Err(Error::from_win32(code).with_url(url.clone())),
            other => Err(other.unexpected(url)),
        }
    }

    /// Extract the byte count from a `WriteComplete` event.
    pub fn into_write_complete(self, url: &Url) -> Result<u32, Error> {
        match self {
            CallbackEvent::WriteComplete(n) => Ok(n),
            CallbackEvent::Win32Error(code) => Err(Error::from_win32(code).with_url(url.clone())),
            other => Err(other.unexpected(url)),
        }
    }
}

// ---------------------------------------------------------------------------
// RequestState -- per-request shared state
// ---------------------------------------------------------------------------

/// Shared state for one in-flight HTTP request.
///
/// Passed as `dwContext` to WinHTTP via a [`CallbackContext<RequestState>`].
pub(crate) struct RequestState {
    /// The completion bridge -- callback signals, future awaits.
    pub signal: CompletionSignal<CallbackEvent>,
    /// Verbose logging flag (from `ClientBuilder::connection_verbose`).
    #[cfg_attr(not(feature = "tracing"), expect(dead_code))]
    pub verbose: bool,
    /// TLS failure detail flags captured from `SECURE_FAILURE` callback.
    pub tls_failure_flags: AtomicU32,
    /// Close/drain state for the request handle.
    close_state: Mutex<RequestCloseState>,
    close_idle: Condvar,
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
    pub send_body: Mutex<Option<bytes::Bytes>>,
    /// Origin of the current hop. Updated by `STATUS_REDIRECT`.
    /// See `strip_sensitive_headers_on_cross_origin_redirect`.
    pub current_origin: Mutex<Origin>,
    /// Set by a callback that decided to abort the request itself
    /// (e.g. failed sensitive-header strip on a cross-origin redirect).
    /// `Drop` checks this to skip a double `WinHttpCloseHandle` and
    /// `callback_error_to_error` takes the reason instead of returning
    /// the generic `OPERATION_CANCELLED`.
    pub callback_abort: Mutex<CallbackAbort>,
}

/// Combined "did a callback abort us?" + "what reason?" so they can't
/// disagree.  `Aborted` is sticky: the variant stays `Aborted` even
/// after `take_reason` consumes the inner `Option`.
#[derive(Debug)]
pub(crate) enum CallbackAbort {
    NotAborted,
    Aborted(Option<Error>),
}

impl CallbackAbort {
    pub fn is_aborted(&self) -> bool {
        matches!(self, Self::Aborted(_))
    }

    pub fn take_reason(&mut self) -> Option<Error> {
        match self {
            Self::Aborted(slot) => slot.take(),
            Self::NotAborted => None,
        }
    }
}

impl RequestState {
    /// Create a new `RequestState` seeded with the initial request's
    /// origin so the `STATUS_REDIRECT` callback can detect cross-origin
    /// hops and strip sensitive headers.
    pub fn new(verbose: bool, origin: Origin) -> Self {
        Self {
            signal: CompletionSignal::new(),
            verbose,
            tls_failure_flags: AtomicU32::new(0),
            close_state: Mutex::new(RequestCloseState {
                closed: false,
                active_callbacks: 0,
            }),
            close_idle: Condvar::new(),
            read_buffer: Mutex::new(None),
            send_body: Mutex::new(None),
            current_origin: Mutex::new(origin),
            callback_abort: Mutex::new(CallbackAbort::NotAborted),
        }
    }

    #[cfg(test)]
    pub fn new_test() -> Self {
        Self::new(false, Origin::new("http", "test.local", 80))
    }

    fn enter_callback(&self) -> RequestCallbackGuard<'_> {
        let mut close_state = self.lock_close_state();
        // Mirror `checked_sub` in the drop path: overflow here would
        // mean an unbalanced increment, which is a real bug -- panic
        // rather than silently wrap or saturate (saturating would
        // deadlock `wait_closed_and_idle` forever).
        close_state.active_callbacks = close_state
            .active_callbacks
            .checked_add(1)
            .expect("active_callbacks overflow");
        RequestCallbackGuard { request: self }
    }

    fn mark_final_callback_seen(&self) {
        let mut close_state = self.lock_close_state();
        close_state.closed = true;
        if close_state.active_callbacks == 0 {
            self.close_idle.notify_all();
        }
    }

    /// Close the WinHTTP handle from inside a callback and stash the
    /// reason for the awaiting future.  Idempotent (first caller wins).
    /// `WinHttpCloseHandle` is documented as legal from a status
    /// callback -- see WinHTTP "Security Considerations".
    pub fn abort_from_callback(&self, handle: *mut core::ffi::c_void, reason: Error) {
        // Release the lock before the FFI close: WinHttpCloseHandle may
        // queue more callbacks that need the same lock.
        {
            let mut guard = lock_or_clear(&self.callback_abort);
            if guard.is_aborted() {
                return;
            }
            *guard = CallbackAbort::Aborted(Some(reason));
        }
        // Reason already stashed; a close failure here (null handle,
        // racing double-close) doesn't change the formal property the
        // awaiter relies on.
        let _ = abi::close_winhttp_handle(handle);
    }

    fn wait_closed_and_idle(&self) {
        let mut close_state = self.lock_close_state();
        while !close_state.closed || close_state.active_callbacks != 0 {
            close_state = match self.close_idle.wait(close_state) {
                Ok(guard) => guard,
                Err(poisoned) => {
                    warn!("WinHTTP request close-state mutex poisoned while waiting; recovering");
                    self.close_state.clear_poison();
                    poisoned.into_inner()
                }
            };
        }
    }

    fn lock_close_state(&self) -> std::sync::MutexGuard<'_, RequestCloseState> {
        match self.close_state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("WinHTTP request close-state mutex poisoned; recovering");
                self.close_state.clear_poison();
                poisoned.into_inner()
            }
        }
    }
}

struct RequestCallbackGuard<'a> {
    request: &'a RequestState,
}

impl Drop for RequestCallbackGuard<'_> {
    fn drop(&mut self) {
        let mut close_state = self.request.lock_close_state();
        let Some(remaining) = close_state.active_callbacks.checked_sub(1) else {
            warn!("WinHTTP callback activity underflow; ignoring duplicate exit");
            return;
        };
        close_state.active_callbacks = remaining;
        if close_state.closed && remaining == 0 {
            self.request.close_idle.notify_all();
        }
    }
}

/// RAII wrapper for an in-flight WinHTTP request handle.
///
/// `Drop` calls `WinHttpCloseHandle` and then blocks until both:
///
/// 1. WinHTTP has delivered `WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING` (the
///    final callback for this request); and
/// 2. no other WinHTTP callback is currently active for this request.
///
/// After `Drop` returns, no WinHTTP callback can re-enter this DLL for
/// this request -- the DLL-unload invariant the native backend depends
/// on.
pub(crate) struct WinHttpRequestHandle {
    handle: *mut core::ffi::c_void,
    state: Arc<RequestState>,
}

impl WinHttpRequestHandle {
    /// Get a `Send`-safe copy of the raw pointer (as `usize`).
    fn as_send(&self) -> SendPtr {
        SendPtr(self.handle as usize)
    }

    /// Get the raw WinHTTP request handle.
    fn raw(&self) -> *mut core::ffi::c_void {
        self.handle
    }
}

impl Drop for WinHttpRequestHandle {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        {
            let request = Arc::as_ptr(&self.state) as usize;
            WINHTTP_CALLBACK_STACK.with(|stack| {
                debug_assert!(
                    !stack.borrow().contains(&request),
                    "WinHttpRequestHandle dropped while inside its own WinHTTP callback; \
                     this suggests an executor/waker synchronously polled from wake"
                );
            });
        }

        if lock_or_clear(&self.state.callback_abort).is_aborted() {
            // Callback already closed the handle; still wait for
            // HANDLE_CLOSING before the Arc<RequestState> can drop.
            self.state.wait_closed_and_idle();
        } else if abi::close_winhttp_handle(self.handle) {
            self.state.wait_closed_and_idle();
        }
        self.handle = std::ptr::null_mut();
    }
}

// SAFETY: WinHTTP request handles are thread-safe. All WinHTTP functions
// accept handles from any thread, and the callback fires on WinHTTP's own
// thread pool.
unsafe impl Send for WinHttpRequestHandle {}
unsafe impl Sync for WinHttpRequestHandle {}

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
/// inherited by all child handles. It uses [`CallbackContext::borrow_raw`] to
/// access the per-request `RequestState` and signals the `CompletionSignal`.
///
/// # Safety
///
/// Called by WinHTTP on its internal thread pool. `dw_context` must be the
/// raw pointer from a live [`CallbackContext<RequestState>`].
pub(crate) unsafe extern "system" fn winhttp_callback(
    hinternet: *mut core::ffi::c_void,
    dw_context: usize,
    dw_status: u32,
    lpv_info: *mut std::ffi::c_void,
    dw_info_length: u32,
) {
    if dw_context == 0 {
        return;
    }
    // A panic across this `extern "system"` boundary into a WinHTTP
    // worker thread is UB; swallow it here.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: caller (WinHTTP) upholds the contract documented on
        // `winhttp_callback`.
        unsafe {
            winhttp_callback_body(hinternet, dw_context, dw_status, lpv_info, dw_info_length)
        };
    }));
}

/// Body of [`winhttp_callback`], split out so the FFI entry point stays a
/// thin `catch_unwind` wrapper.
///
/// # Safety
///
/// Same contract as [`winhttp_callback`].
unsafe fn winhttp_callback_body(
    hinternet: *mut core::ffi::c_void,
    dw_context: usize,
    dw_status: u32,
    lpv_info: *mut std::ffi::c_void,
    dw_info_length: u32,
) {
    #[cfg(debug_assertions)]
    let _callback_stack_guard = WinHttpCallbackStackGuard::enter(dw_context);

    if dw_status == WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING {
        let state: Arc<RequestState> =
            unsafe { CallbackContext::<RequestState>::clone_arc_from_raw(dw_context) };
        // Release the retained context first and skip `enter_callback`:
        // a panic in the counter increment would be swallowed by
        // `catch_unwind` and leave `wait_closed_and_idle` hanging.
        // SAFETY: HANDLE_CLOSING is the final callback for this context.
        unsafe { CallbackContext::<RequestState>::drop_raw(dw_context) };
        state.mark_final_callback_seen();
        return;
    }

    let state: &RequestState = unsafe { CallbackContext::<RequestState>::borrow_raw(dw_context) };
    let _callback_guard = state.enter_callback();

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
            // Guard against a buggy/short `lpv_info` delivery (deref of a
            // null or undersized pointer is UB). Fallback signals an
            // internal error so the awaiter doesn't hang.
            let code = if !lpv_info.is_null()
                && dw_info_length as usize >= std::mem::size_of::<WINHTTP_ASYNC_RESULT>()
            {
                // SAFETY: null-checked above; payload is at least one struct
                // worth of bytes per the length check.
                unsafe { (*(lpv_info as *const WINHTTP_ASYNC_RESULT)).dwError }
            } else {
                ERROR_WINHTTP_INTERNAL_ERROR
            };
            state.signal.signal(CallbackEvent::Win32Error(code));
        }

        WINHTTP_CALLBACK_STATUS_SECURE_FAILURE => {
            // Same null/short-buffer guard as REQUEST_ERROR.
            let flags =
                if !lpv_info.is_null() && dw_info_length as usize >= std::mem::size_of::<u32>() {
                    // SAFETY: null-checked above; size verified.
                    unsafe { *(lpv_info as *const u32) }
                } else {
                    0
                };
            // Release: pairs with the Acquire load in callback_error_to_error
            // so the executor thread observes the stored flags.  (On x86 this
            // compiles identically to Relaxed -- the stronger ordering is for
            // correctness on weakly-ordered architectures and clarity.)
            state.tls_failure_flags.store(flags, Ordering::Release);
            // Don't signal -- the subsequent REQUEST_ERROR will carry the error.
        }

        WINHTTP_CALLBACK_STATUS_REDIRECT => {
            // SAFETY: lpv_info is a null-terminated UTF-16 string; dw_info_length
            // is the byte count.
            let new_url = unsafe { crate::util::wide_to_string_lossy(lpv_info, dw_info_length) };
            // Parse first so logs/errors only ever carry the redacted Url --
            // Display strips userinfo, but the raw `new_url` may contain
            // `user:pass@host` and must not be traced or embedded as-is.
            match new_url.parse::<crate::url::Url>() {
                Ok(parsed) => {
                    #[cfg(feature = "tracing")]
                    if state.verbose {
                        trace!(url = %parsed, "WinHTTP: redirect");
                    }
                    strip_sensitive_headers_on_cross_origin_redirect(hinternet, state, &parsed);
                }
                Err(_) => {
                    // Unparsable target -> can't classify origin ->
                    // abort before WinHTTP sends sensitive headers on.
                    // The raw target can't really be redacted, since it's unparsable
                    state.abort_from_callback(
                        hinternet,
                        Error::request(format!(
                            "WinHTTP redirect target is unparsable; aborting to avoid \
                             leaking sensitive headers to an unclassifiable origin: {new_url}"
                        )),
                    );
                }
            }
        }

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
        _ => {}
    }
}

/// Header names that must be stripped from a WinHTTP request when a
/// redirect crosses origins.
///
/// Per [WinHTTP Security Considerations](https://learn.microsoft.com/windows/win32/winhttp/winhttp-security-considerations)
/// item 16, WinHTTP forwards user-defined headers across redirects
/// unchanged; the application must intercept `STATUS_REDIRECT` and
/// remove sensitive headers when the redirect target differs from the
/// original (or current) origin.
const SENSITIVE_HEADERS_ON_CROSS_ORIGIN: &[&str] = &[
    "Authorization",
    "Cookie",
    "Cookie2",
    "Proxy-Authorization",
    "Proxy-Authenticate",
    "WWW-Authenticate",
];

/// HTTP origin per RFC 6454 (`scheme` + `host` + `port`). Used to
/// decide whether a redirect crosses origins and the `Authorization` /
/// `Cookie` / ... headers must be stripped before the next hop. Scheme
/// and host are stored lower-cased so comparisons are case-insensitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Origin {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl Origin {
    /// Build an `Origin`, lower-casing scheme and host so comparisons
    /// are case-insensitive.
    pub fn new(scheme: &str, host: &str, port: u16) -> Self {
        Self {
            scheme: scheme.to_ascii_lowercase(),
            host: host.to_ascii_lowercase(),
            port,
        }
    }

    /// Build an `Origin` from a parsed wrest URL.
    pub fn from_url(url: &crate::url::Url) -> Self {
        Self::new(&url.scheme, &url.host, url.port)
    }
}

/// Strip sensitive headers when `new_url` is on a different origin
/// than the tracked origin in `state`, then update the tracked origin.
///
/// Called from `WINHTTP_CALLBACK_STATUS_REDIRECT` after the caller has
/// parsed the target into a [`crate::url::Url`].  `WinHttpAddRequestHeaders`
/// (and removal) is callable inside this callback before the redirected
/// request goes on the wire (WinHTTP Security Considerations item 16).
///
/// Fails closed: any strip failure aborts the request via
/// [`RequestState::abort_from_callback`] so WinHTTP never sends
/// `Authorization`/`Cookie`/etc. on to the new origin.
fn strip_sensitive_headers_on_cross_origin_redirect(
    request_handle: *mut core::ffi::c_void,
    state: &RequestState,
    new_url: &crate::url::Url,
) {
    strip_sensitive_headers_on_cross_origin_redirect_with(
        request_handle,
        state,
        new_url,
        crate::abi::winhttp_remove_request_header,
    );
}

/// Test seam: injectable remove-header for unit tests.
fn strip_sensitive_headers_on_cross_origin_redirect_with(
    request_handle: *mut core::ffi::c_void,
    state: &RequestState,
    new_url: &crate::url::Url,
    remove_header: impl Fn(*mut core::ffi::c_void, &str) -> Result<(), Error>,
) {
    let mut guard = lock_or_clear(&state.current_origin);
    let new_origin = Origin::from_url(new_url);
    if *guard == new_origin {
        return;
    }

    for name in SENSITIVE_HEADERS_ON_CROSS_ORIGIN {
        if let Err(e) = remove_header(request_handle, name) {
            state.abort_from_callback(
                request_handle,
                Error::request(ContextError::new(
                    format!(
                        "failed to strip {name} on cross-origin redirect to {new_url}; \
                         aborting to avoid sensitive-header leak"
                    ),
                    e,
                )),
            );
            return;
        }
    }

    *guard = new_origin;
}

// ---------------------------------------------------------------------------
// Session creation
// ---------------------------------------------------------------------------

/// Configuration for creating a WinHTTP session.
pub(crate) struct SessionConfig {
    pub user_agent: String,
    pub connect_timeout_ms: i32,
    pub send_timeout_ms: i32,
    pub read_timeout_ms: i32,
    pub verbose: bool,
    pub max_connections_per_host: Option<u32>,
    pub proxy: ProxyAction,
    pub redirect_policy: Option<Policy>,
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
            config.connect_timeout_ms,
            config.send_timeout_ms,
            config.read_timeout_ms,
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
                redirect::PolicyInner::None => {
                    abi::winhttp_set_option_u32(
                        session.0,
                        WINHTTP_OPTION_REDIRECT_POLICY,
                        WINHTTP_OPTION_REDIRECT_POLICY_NEVER,
                    )?;
                }
                redirect::PolicyInner::Limited(max) => {
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
    pub request_handle: WinHttpRequestHandle,
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
    body: Option<Body>,
    proxy_config: &ProxyConfig,
    accept_invalid_certs: bool,
) -> Result<RawResponse, Error> {
    // Check per-request NO_PROXY override
    let per_request_proxy = proxy_config.resolve(&url.host, url.is_https);

    trace!(
        url = %url,
        proxy = ?per_request_proxy,
        "proxy resolved for request",
    );

    // Create the per-request state
    let state = Arc::new(RequestState::new(session.verbose, Origin::from_url(url)));

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

    // Park a context strong ref for the WinHTTP callback. On `SetOption`
    // failure the plain `WinHttpHandle::drop` closes without draining --
    // safe, since the null-`dw_context` guard short-circuits HANDLE_CLOSING.
    let ctx = CallbackContext::<RequestState>::new(&state);
    abi::winhttp_set_option_usize(request_handle.0, WINHTTP_OPTION_CONTEXT_VALUE, ctx.as_raw())
        .map_err(|e| e.with_url(url.clone()))?;
    let _ = ctx.into_raw();

    // Context installed: upgrade to the draining wrapper so any later
    // setup failure (proxy, cert, ...) drops through `wait_closed_and_idle`.
    let request_handle = request_handle.into_request_handle(Arc::clone(&state));

    // Apply per-request proxy override.
    // The session was opened with a single proxy URL, but the resolved
    // action may differ per request (HTTP_PROXY != HTTPS_PROXY, or
    // NO_PROXY match -> direct).
    match &per_request_proxy {
        ProxyAction::Direct => {
            abi::winhttp_set_proxy_direct(request_handle.raw()).url_context(url)?;
        }
        ProxyAction::Named(proxy_url, proxy_creds) => {
            // Override the session-level proxy for this specific request.
            abi::winhttp_set_proxy_named(request_handle.raw(), proxy_url).url_context(url)?;

            // Set proxy Basic-auth credentials if provided.
            if let Some((username, password)) = proxy_creds {
                abi::winhttp_set_proxy_credentials(
                    request_handle.raw(),
                    username,
                    password.expose(),
                )
                .url_context(url)?;
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
            request_handle.raw(),
            WINHTTP_OPTION_SECURITY_FLAGS,
            security_flags,
        )
        .url_context(url)?;
    }

    // Add custom headers
    for (name, value) in headers {
        let header_line = format!("{name}: {value}\r\n");
        abi::winhttp_add_request_header(request_handle.raw(), &header_line).url_context(url)?;
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
        abi::winhttp_add_request_header(request_handle.raw(), "Transfer-Encoding: chunked\r\n")
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
                Error::request(ContextError::new("stream body error", e)).with_url(url.clone())
            })?;

            if chunk.is_empty() {
                continue;
            }

            // Build the RFC 7230 chunked-encoded frame:
            //   {hex_size}\r\n{data}\r\n
            let header = format!("{:x}\r\n", chunk.len());
            let frame: Vec<u8> = [header.as_bytes(), &chunk, b"\r\n"].concat();

            // Store the encoded frame in state.send_body for
            // cancellation safety -- WinHTTP may still reference the
            // buffer if the future is dropped mid-write.
            let (frame_ptr, frame_len) = {
                let mut guard = lock_or_clear(&state.send_body);
                let stored = guard.insert(frame.into());
                (stored.as_ptr() as usize, stored.len())
            };

            write_data(&state.signal, &request_handle, frame_ptr, frame_len, url).await?;
        }

        // Terminate the chunked transfer: "0\r\n\r\n"
        {
            let terminator = b"0\r\n\r\n".to_vec();
            let (term_ptr, term_len) = {
                let mut guard = lock_or_clear(&state.send_body);
                let stored = guard.insert(terminator.into());
                (stored.as_ptr() as usize, stored.len())
            };

            write_data(&state.signal, &request_handle, term_ptr, term_len, url).await?;
        }
    } else if body_len <= LARGE_BODY_THRESHOLD {
        // Fast path: body fits in a single DWORD.  WinHTTP adds
        // Content-Length automatically and sends everything in one call.
        trace!(body_len, "body path: inline");
        #[expect(
            clippy::cast_possible_truncation,
            reason = "`body_len <= LARGE_BODY_THRESHOLD` (== u32::MAX in production) is checked above"
        )]
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
            request_handle.raw(),
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
            let total_len = usize::try_from(body_len)
                .map_err(|_| Error::body("body too large for this platform's address space"))?;
            let chunk_max = LARGE_BODY_CHUNK_MAX;
            let mut offset: usize = 0;

            #[expect(
                clippy::arithmetic_side_effects,
                reason = "offset < total_len each iteration; offset += chunk_size <= total_len; body_ptr+body_offset is within the allocated Vec"
            )]
            while offset < total_len {
                let remaining = total_len - offset;
                let chunk_size = remaining.min(chunk_max);

                // `body_ptr` is the base pointer (usize) into state.send_body.
                let body_offset = offset;
                write_data(&state.signal, &request_handle, body_ptr + body_offset, chunk_size, url)
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
    let status = query_status_code(request_handle.raw(), url)?;

    // Query HTTP version
    let version = query_version(request_handle.raw());

    // Query response headers
    let headers = query_headers(request_handle.raw(), url)?;

    // Query the final URL after any redirects.  WinHTTP handles redirects
    // internally, so WINHTTP_OPTION_URL returns the URL of the last request
    // in the chain (matching reqwest's `Response::url()` behavior).
    let final_url = abi::winhttp_query_option_url(request_handle.raw(), WINHTTP_OPTION_URL)
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
/// `data_len` is `usize`; values exceeding `u32::MAX` produce `Error::body`
/// (WinHTTP's `dwNumberOfBytesToWrite` is a `DWORD`).
async fn write_data(
    signal: &CompletionSignal<CallbackEvent>,
    handle: &WinHttpRequestHandle,
    data_ptr: usize,
    data_len: usize,
    url: &Url,
) -> Result<u32, Error> {
    let data_len_u32 =
        u32::try_from(data_len).map_err(|_| Error::body("WinHTTP write buffer exceeds 4 GiB"))?;
    let h = handle.as_send();
    await_win32(signal, move || {
        let ptr = data_ptr as *const std::ffi::c_void;
        abi::winhttp_write_data(h.as_mut_ptr(), ptr, data_len_u32).url_context(url)
    })
    .await?
    .into_write_complete(url)
}

/// Read a chunk of the response body.
///
/// Returns `Ok(None)` at EOF. The returned `bytes::Bytes` is zero-copy -- WinHTTP
/// writes directly into a `BytesMut` which is then frozen.
pub(crate) async fn read_chunk(
    handle: &WinHttpRequestHandle,
    url: &Url,
) -> Result<Option<bytes::Bytes>, Error> {
    let state = &handle.state;

    // Allocate a fixed 8 KiB buffer.  WinHttpReadData behaves like recv():
    // it returns as soon as *any* data arrives (the buffer size is a maximum,
    // not a target) and signals EOF via ReadComplete(0).  A single ReadData
    // call replaces the old QueryDataAvailable + ReadData pair, halving the
    // number of async round-trips per chunk.
    const READ_BUF_SIZE: usize = 8192;
    let buf = BytesMut::with_capacity(READ_BUF_SIZE);

    // Read data -- the buffer is moved into the closure and stored in
    // shared state for cancellation safety.  `Option::insert` returns
    // `&mut BytesMut`, so the pointer is derived within the same lock
    // scope that placed the buffer -- no Option check needed.
    //
    // The raw pointer is computed inside the closure to avoid holding it
    // across the await point (which would make the future !Send).
    let h_read = handle.as_send();
    let read = await_win32(&state.signal, move || {
        let (buf_ptr, buf_capacity) = {
            // Safe to recover from poison: `read_buffer` is an
            // `Option<BytesMut>` slot -- no multi-field invariant.
            let mut guard = lock_or_clear(&state.read_buffer);
            let buf_ref = guard.insert(buf);
            let spare = buf_ref.spare_capacity_mut();
            (spare.as_ptr() as *mut std::ffi::c_void, spare.len())
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
    let mut guard = lock_or_clear(&state.read_buffer);
    let Some(mut buf) = guard.take() else {
        return Err(Error::request("read buffer missing after read (invariant violated)")
            .with_url(url.clone()));
    };
    if (read as usize) > buf.capacity() {
        Err(Error::request(format!(
            "WinHTTP reported {read} bytes read but buffer capacity is {} (invariant violated)",
            buf.capacity(),
        ))
        .with_url(url.clone()))
    } else {
        // SAFETY: `buf` was allocated with `BytesMut::with_capacity(to_read)`
        // and passed to `WinHttpReadData` which wrote exactly `read` bytes.
        unsafe {
            buf.set_len(read as usize);
        }
        Ok(Some(buf.freeze()))
    }
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
    parse_winhttp_status_code(status_code, url)
}

/// Validate a raw WinHTTP status-code value and convert to `StatusCode`.
///
/// Rejects values outside `u16` before narrowing: a plain `as u16` cast
/// would silently truncate (e.g. `0x100C8` would masquerade as 200).
fn parse_winhttp_status_code(status_code: u32, url: &Url) -> Result<StatusCode, Error> {
    let narrow = u16::try_from(status_code).map_err(|_| {
        Error::request(format!("invalid status code: {status_code}")).with_url(url.clone())
    })?;

    StatusCode::from_u16(narrow).map_err(|e| {
        Error::request(ContextError::new(format!("invalid status code: {status_code}"), e))
            .with_url(url.clone())
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
/// provides a recognized version.
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

/// Create an Error from a WinHTTP callback error, enriching with TLS details.
fn callback_error_to_error(code: u32, state: &RequestState, url: &Url) -> Error {
    // Callback-initiated abort: surface its reason instead of the
    // generic OPERATION_CANCELLED that WinHttpCloseHandle raises.
    if let Some(reason) = lock_or_clear(&state.callback_abort).take_reason() {
        return reason.with_url(url.clone());
    }

    let mut err = Error::from_win32(code);
    err.inner.url = Some(Box::new(url.clone()));

    // Enrich TLS errors with captured failure flags
    if code == ERROR_WINHTTP_SECURE_FAILURE {
        // Acquire: pairs with the Release store in the SECURE_FAILURE callback.
        let tls_flags = state.tls_failure_flags.load(Ordering::Acquire);
        let detail = describe_tls_failure(tls_flags);
        if let Some(source) = err.inner.source.take() {
            err.inner.source =
                Some(Box::new(ContextError::new(format!("TLS error: {detail}"), source)));
        }
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
    fn from(sc: SignalCancelled) -> Self {
        Error::request(sc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::Poll;
    use std::time::Duration;

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

        // 5 MiB body -- exceeds the 4 MiB #[cfg(test)] threshold.
        let body = Body::from(vec![b'X'; 5 * 1024 * 1024]);

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
            redirect_policy: Option<Policy>,
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
                label: "Policy::none() -> 302 returned as-is",
                proxy: ProxyAction::Automatic,
                redirect_policy: Some(Policy::none()),
                src_path: "/rp-src",
                redirect_to: Some("/rp-dst"),
                dst_path: None, // not mounted -- redirect should NOT be followed
                expected_status: 302,
            },
            Case {
                label: "Policy::limited(5) -> redirect followed",
                proxy: ProxyAction::Automatic,
                redirect_policy: Some(Policy::limited(5)),
                src_path: "/lim-src",
                redirect_to: Some("/lim-dst"),
                dst_path: Some("/lim-dst"),
                expected_status: 200,
            },
        ];

        for case in cases {
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
                proxy: case.proxy,
                redirect_policy: case.redirect_policy,
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

        // Session-level: Named proxy (pointing at the same server -- doesn't
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
        // wiremock server address), causing resolve() -> Direct.
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
        let state = RequestState::new_test();

        // (event, expected_outcome)
        // Ok(()) for success, Err("kind") for which is_* should be true
        type TestCase = (CallbackEvent, Result<(), fn(&Error) -> bool>);
        let cases: Vec<TestCase> = vec![
            (CallbackEvent::Complete, Ok(())),
            (CallbackEvent::Win32Error(ERROR_WINHTTP_TIMEOUT), Err(Error::is_timeout)),
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
        type TestCase<'a> = (
            &'a str,
            fn(CallbackEvent, &Url) -> crate::Result<u32>,
            CallbackEvent,
            u32,
            CallbackEvent,
        );
        let cases: Vec<TestCase<'_>> = vec![
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

            // Wrong variant -> is_request error
            let err = method(wrong_event, &url).unwrap_err();
            assert!(err.is_request(), "{label}: wrong variant should be request error");

            // Timeout variant -> is_timeout error
            let err = method(CallbackEvent::Win32Error(ERROR_WINHTTP_TIMEOUT), &url).unwrap_err();
            assert!(err.is_timeout(), "{label}: timeout variant");
        }
    }

    // -- SignalCancelled -> Error --

    #[test]
    fn signal_cancelled_into_error() {
        let err: Error = SignalCancelled.into();
        assert!(err.is_request());
        // Display shows kind prefix; "cancelled" detail is in the source chain.
        assert_eq!(err.to_string(), "error sending request");
        let source = std::error::Error::source(&err).expect("should have source");
        assert!(source.to_string().contains("cancelled"));
    }

    /// Reject WinHTTP status codes that don't fit in `u16` before the cast,
    /// so a corrupt value like `0x100C8` cannot truncate to 200 and
    /// masquerade as success. Also exercises the `from_u16` rejection path.
    #[test]
    fn parse_winhttp_status_code_table() {
        let url: Url = "https://example.com".parse().unwrap();

        // `Ok(n)` requires `parse_winhttp_status_code(raw)` to yield
        // `StatusCode(n)`. `Err` requires rejection with `raw` present
        // somewhere in the error chain (so callers can diagnose).
        let cases: &[(u32, Result<u16, ()>)] = &[
            // -- accepts every valid HTTP status code -------------------
            (100, Ok(100)),
            (200, Ok(200)),
            (404, Ok(404)),
            (599, Ok(599)),
            // -- rejects values that don't fit in u16 -------------------
            // 0x100C8 narrowed via `as u16` is 200; must NOT silently
            // masquerade as success.
            (0x100C8, Err(())),
            (u32::MAX, Err(())),
            // -- fits in u16 but outside the HTTP three-digit range
            // (caught by `StatusCode::from_u16`) ----
            (0, Err(())),
            (99, Err(())),
            (1000, Err(())),
            (u32::from(u16::MAX), Err(())),
        ];

        // The inner error message lives in `Error::source()`, not the
        // top-level `Display`.
        fn source_chain(err: &Error) -> String {
            let mut s = String::new();
            let mut cur: Option<&dyn std::error::Error> = std::error::Error::source(err);
            while let Some(e) = cur {
                s.push_str(&format!("{e}\n"));
                cur = e.source();
            }
            s
        }

        for &(raw, ref expect) in cases {
            match (parse_winhttp_status_code(raw, &url), expect) {
                (Ok(got), Ok(want)) => {
                    assert_eq!(got.as_u16(), *want, "raw {raw}: expected {want}");
                }
                (Err(err), Err(())) => {
                    let chain = source_chain(&err);
                    assert!(
                        chain.contains(&raw.to_string()),
                        "raw {raw}: error chain must mention the value, got: {chain}"
                    );
                }
                (Ok(got), Err(())) => {
                    panic!("raw {raw}: expected rejection, got Ok({})", got.as_u16())
                }
                (Err(err), Ok(want)) => {
                    panic!("raw {raw}: expected Ok({want}), got Err({err})")
                }
            }
        }
    }

    #[test]
    fn tls_failure_enrichment() {
        let url: Url = "https://example.com".parse().unwrap();
        let state = RequestState::new_test();

        // Simulate a TLS failure flag being set
        state
            .tls_failure_flags
            .store(WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA, std::sync::atomic::Ordering::Release);

        let err = callback_error_to_error(ERROR_WINHTTP_SECURE_FAILURE, &state, &url);
        assert!(err.is_connect());
        // Display shows kind prefix; TLS detail is in the Debug output.
        assert_eq!(err.to_string(), "error trying to connect for url (https://example.com/)");
        let debug = format!("{err:?}");
        assert!(
            debug.contains("invalid CA"),
            "TLS error should be enriched with failure details in debug, got: {debug}"
        );
    }

    // -- parse_raw_headers --

    #[test]
    fn parse_raw_headers_table() {
        // (raw_input, expected_headers_as (name, value) pairs, label)
        type TestCase<'a> = (&'a str, &'a [(&'a str, &'a str)], &'a str);
        let cases: &[TestCase] = &[
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

    /// `mark_final_callback_seen` must call `notify_all` even when no
    /// callback was ever active -- the quiescent close path that fires
    /// when `HANDLE_CLOSING` arrives with no other callbacks in flight.
    #[test]
    fn mark_final_callback_seen_quiescent_notifies() {
        let state = RequestState::new_test();
        state.mark_final_callback_seen();
        assert!(state.lock_close_state().closed);
    }

    // ---------------------------------------------------------------------
    // winhttp_callback dispatch (data-driven)
    // ---------------------------------------------------------------------
    //
    // Drives `winhttp_callback` directly to cover every signaling status
    // arm plus the null/length guards on `lpv_info` (WRITE_COMPLETE,
    // REQUEST_ERROR, and SECURE_FAILURE).

    enum LpvInfo {
        Null,
        AsyncResult(WINHTTP_ASYNC_RESULT),
        U32(u32),
    }

    impl LpvInfo {
        /// Raw pointer borrowing from `self`; caller must keep `self` alive.
        fn as_ptr(&self) -> *mut std::ffi::c_void {
            match self {
                LpvInfo::Null => std::ptr::null_mut(),
                LpvInfo::AsyncResult(r) => {
                    (r as *const WINHTTP_ASYNC_RESULT) as *mut std::ffi::c_void
                }
                LpvInfo::U32(v) => (v as *const u32) as *mut std::ffi::c_void,
            }
        }
    }

    /// Expected `CompletionSignal` state after the callback runs.
    enum DispatchOutcome {
        Signaled(fn(&CallbackEvent) -> bool),
        Pending,
    }

    /// Drive `winhttp_callback` and return (poll, closed, active, tls_flags).
    fn drive_callback(
        status: u32,
        lpv_info: &LpvInfo,
        info_len: u32,
    ) -> (Poll<Result<CallbackEvent, SignalCancelled>>, bool, usize, u32) {
        use std::task::{Context, Waker};

        let state = Arc::new(RequestState::new_test());
        let listener = state.signal.listen();
        let ctx = CallbackContext::new(&state);

        // SAFETY: `ctx` keeps the Arc alive across the call; non-HANDLE_CLOSING
        // statuses use `borrow_raw` and never call `drop_raw`.
        unsafe {
            winhttp_callback(
                std::ptr::null_mut(),
                ctx.as_raw(),
                status,
                lpv_info.as_ptr(),
                info_len,
            );
        }

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut listener = std::pin::pin!(listener);
        let poll = listener.as_mut().poll(&mut cx);

        let close = state.lock_close_state();
        let closed = close.closed;
        let active = close.active_callbacks;
        drop(close);

        let tls_flags = state.tls_failure_flags.load(Ordering::Acquire);
        (poll, closed, active, tls_flags)
    }

    #[test]
    fn winhttp_callback_dispatch_table() {
        struct Case {
            label: &'static str,
            status: u32,
            info_len: u32,
            lpv_info: LpvInfo,
            expected: DispatchOutcome,
            expected_tls_flags: u32,
        }

        let async_result_size = crate::abi::dword_size_of::<WINHTTP_ASYNC_RESULT>();

        let cases = [
            Case {
                label: "SENDREQUEST_COMPLETE -> Complete",
                status: WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE,
                info_len: 0,
                lpv_info: LpvInfo::Null,
                expected: DispatchOutcome::Signaled(|e| matches!(e, CallbackEvent::Complete)),
                expected_tls_flags: 0,
            },
            Case {
                label: "HEADERS_AVAILABLE -> Complete",
                status: WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE,
                info_len: 0,
                lpv_info: LpvInfo::Null,
                expected: DispatchOutcome::Signaled(|e| matches!(e, CallbackEvent::Complete)),
                expected_tls_flags: 0,
            },
            Case {
                label: "READ_COMPLETE(42) -> ReadComplete(42)",
                status: WINHTTP_CALLBACK_STATUS_READ_COMPLETE,
                info_len: 42,
                lpv_info: LpvInfo::Null,
                expected: DispatchOutcome::Signaled(|e| {
                    matches!(e, CallbackEvent::ReadComplete(42))
                }),
                expected_tls_flags: 0,
            },
            Case {
                label: "WRITE_COMPLETE with u32(256) and info_len=4 -> WriteComplete(256)",
                status: WINHTTP_CALLBACK_STATUS_WRITE_COMPLETE,
                info_len: 4,
                lpv_info: LpvInfo::U32(256),
                expected: DispatchOutcome::Signaled(|e| {
                    matches!(e, CallbackEvent::WriteComplete(256))
                }),
                expected_tls_flags: 0,
            },
            // WRITE_COMPLETE has a null-guard that short-circuits the deref.
            Case {
                label: "WRITE_COMPLETE with NULL lpv_info -> WriteComplete(0) [null-guarded]",
                status: WINHTTP_CALLBACK_STATUS_WRITE_COMPLETE,
                info_len: 0,
                lpv_info: LpvInfo::Null,
                expected: DispatchOutcome::Signaled(|e| {
                    matches!(e, CallbackEvent::WriteComplete(0))
                }),
                expected_tls_flags: 0,
            },
            // `dw_info_length >= 4` short-circuits even with a non-null pointer.
            Case {
                label: "WRITE_COMPLETE with info_len=2 -> WriteComplete(0) [length-guarded]",
                status: WINHTTP_CALLBACK_STATUS_WRITE_COMPLETE,
                info_len: 2,
                lpv_info: LpvInfo::U32(99),
                expected: DispatchOutcome::Signaled(|e| {
                    matches!(e, CallbackEvent::WriteComplete(0))
                }),
                expected_tls_flags: 0,
            },
            // Cancellation arrives as REQUEST_ERROR(ERROR_WINHTTP_OPERATION_CANCELLED);
            // the modeled arm must signal so the awaiter isn't left hanging.
            Case {
                label: "REQUEST_ERROR(TIMEOUT) -> Win32Error(TIMEOUT)",
                status: WINHTTP_CALLBACK_STATUS_REQUEST_ERROR,
                info_len: async_result_size,
                lpv_info: LpvInfo::AsyncResult(WINHTTP_ASYNC_RESULT {
                    dwResult: 0,
                    dwError: ERROR_WINHTTP_TIMEOUT,
                }),
                expected: DispatchOutcome::Signaled(|e| {
                    matches!(e, CallbackEvent::Win32Error(ERROR_WINHTTP_TIMEOUT))
                }),
                expected_tls_flags: 0,
            },
            Case {
                label: "REQUEST_ERROR(OPERATION_CANCELLED) -> Win32Error(CANCELLED)",
                status: WINHTTP_CALLBACK_STATUS_REQUEST_ERROR,
                info_len: async_result_size,
                lpv_info: LpvInfo::AsyncResult(WINHTTP_ASYNC_RESULT {
                    dwResult: 0,
                    dwError: ERROR_WINHTTP_OPERATION_CANCELLED,
                }),
                expected: DispatchOutcome::Signaled(|e| {
                    matches!(e, CallbackEvent::Win32Error(ERROR_WINHTTP_OPERATION_CANCELLED))
                }),
                expected_tls_flags: 0,
            },
            Case {
                label: "REQUEST_ERROR(SECURE_FAILURE) -> Win32Error(SECURE_FAILURE)",
                status: WINHTTP_CALLBACK_STATUS_REQUEST_ERROR,
                info_len: async_result_size,
                lpv_info: LpvInfo::AsyncResult(WINHTTP_ASYNC_RESULT {
                    dwResult: 0,
                    dwError: ERROR_WINHTTP_SECURE_FAILURE,
                }),
                expected: DispatchOutcome::Signaled(|e| {
                    matches!(e, CallbackEvent::Win32Error(ERROR_WINHTTP_SECURE_FAILURE))
                }),
                expected_tls_flags: 0,
            },
            // Null-guard: with no AsyncResult payload, the arm must
            // fall back to INTERNAL_ERROR rather than deref NULL.
            Case {
                label: "REQUEST_ERROR with NULL lpv_info -> Win32Error(INTERNAL_ERROR) [null-guarded]",
                status: WINHTTP_CALLBACK_STATUS_REQUEST_ERROR,
                info_len: 0,
                lpv_info: LpvInfo::Null,
                expected: DispatchOutcome::Signaled(|e| {
                    matches!(e, CallbackEvent::Win32Error(ERROR_WINHTTP_INTERNAL_ERROR))
                }),
                expected_tls_flags: 0,
            },
            // SECURE_FAILURE stores flags; the subsequent REQUEST_ERROR signals.
            Case {
                label: "SECURE_FAILURE(INVALID_CA) -> flags stored, no signal",
                status: WINHTTP_CALLBACK_STATUS_SECURE_FAILURE,
                info_len: 4,
                lpv_info: LpvInfo::U32(WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA),
                expected: DispatchOutcome::Pending,
                expected_tls_flags: WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA,
            },
            Case {
                label: "SECURE_FAILURE(CERT_CN_INVALID|CERT_DATE_INVALID) -> combined flags",
                status: WINHTTP_CALLBACK_STATUS_SECURE_FAILURE,
                info_len: 4,
                lpv_info: LpvInfo::U32(
                    WINHTTP_CALLBACK_STATUS_FLAG_CERT_CN_INVALID
                        | WINHTTP_CALLBACK_STATUS_FLAG_CERT_DATE_INVALID,
                ),
                expected: DispatchOutcome::Pending,
                expected_tls_flags: WINHTTP_CALLBACK_STATUS_FLAG_CERT_CN_INVALID
                    | WINHTTP_CALLBACK_STATUS_FLAG_CERT_DATE_INVALID,
            },
            // Null-guard: REQUEST_ERROR follow-up carries the error;
            // here the arm must just leave flags at 0 without UB.
            Case {
                label: "SECURE_FAILURE with NULL lpv_info -> no signal, flags stay 0 [null-guarded]",
                status: WINHTTP_CALLBACK_STATUS_SECURE_FAILURE,
                info_len: 0,
                lpv_info: LpvInfo::Null,
                expected: DispatchOutcome::Pending,
                expected_tls_flags: 0,
            },
            // Verbose-only statuses must not signal.
            Case {
                label: "CONNECTING_TO_SERVER (verbose-only) -> no signal",
                status: WINHTTP_CALLBACK_STATUS_CONNECTING_TO_SERVER,
                info_len: 0,
                lpv_info: LpvInfo::Null,
                expected: DispatchOutcome::Pending,
                expected_tls_flags: 0,
            },
            Case {
                label: "RESOLVING_NAME (verbose-only) -> no signal",
                status: WINHTTP_CALLBACK_STATUS_RESOLVING_NAME,
                info_len: 0,
                lpv_info: LpvInfo::Null,
                expected: DispatchOutcome::Pending,
                expected_tls_flags: 0,
            },
            // Unmodeled statuses don't signal -- documents the current gap.
            Case {
                label: "Unknown status (0xDEADBEEF) -> no signal [documents the gap]",
                status: 0xDEAD_BEEF,
                info_len: 0,
                lpv_info: LpvInfo::Null,
                expected: DispatchOutcome::Pending,
                expected_tls_flags: 0,
            },
        ];

        for case in &cases {
            let (poll, closed, active, tls_flags) =
                drive_callback(case.status, &case.lpv_info, case.info_len);

            match (&case.expected, poll) {
                (DispatchOutcome::Signaled(matcher), Poll::Ready(Ok(event))) => {
                    assert!(matcher(&event), "{}: wrong event signaled: {event:?}", case.label);
                }
                (DispatchOutcome::Signaled(_), other) => {
                    panic!("{}: expected Ready(Ok(_)) signal, got {other:?}", case.label);
                }
                (DispatchOutcome::Pending, Poll::Pending) => {}
                (DispatchOutcome::Pending, other) => {
                    panic!("{}: expected Pending (no signal), got {other:?}", case.label);
                }
            }

            assert_eq!(active, 0, "{}: active_callbacks must balance to 0", case.label);
            assert!(!closed, "{}: closed must remain false (no HANDLE_CLOSING)", case.label);
            assert_eq!(tls_flags, case.expected_tls_flags, "{}: tls_failure_flags", case.label);
        }
    }

    /// `dw_context == 0` must early-return without dereferencing anything.
    #[test]
    fn winhttp_callback_null_context_is_noop() {
        // Vary status to confirm the early-return runs before per-status logic.
        let statuses = [
            WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE,
            WINHTTP_CALLBACK_STATUS_REQUEST_ERROR,
            WINHTTP_CALLBACK_STATUS_SECURE_FAILURE,
            WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING,
            0xDEAD_BEEF,
        ];

        for &status in &statuses {
            // SAFETY: dw_context=0 is the skip sentinel; callback returns immediately.
            unsafe {
                winhttp_callback(std::ptr::null_mut(), 0, status, std::ptr::null_mut(), 0);
            }
        }
    }

    /// HANDLE_CLOSING must mark closed, drop the retained Arc, and notify
    /// any `wait_closed_and_idle` waiter.
    #[test]
    fn winhttp_callback_handle_closing_releases_retained_arc() {
        let state = Arc::new(RequestState::new_test());
        let ctx = CallbackContext::new(&state);

        // Hand the retained ref to the simulated callback; strong=2 now.
        let raw = ctx.into_raw();
        assert_eq!(Arc::strong_count(&state), 2, "ref count after CallbackContext::into_raw");

        // SAFETY: `raw` is live; HANDLE_CLOSING owns the sole `drop_raw` call.
        unsafe {
            winhttp_callback(
                std::ptr::null_mut(),
                raw,
                WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING,
                std::ptr::null_mut(),
                0,
            );
        }

        // Retained ref + HANDLE_CLOSING-arm clone have both been dropped.
        assert_eq!(Arc::strong_count(&state), 1, "ref count after HANDLE_CLOSING");

        let close = state.lock_close_state();
        assert!(close.closed, "HANDLE_CLOSING must set closed=true");
        assert_eq!(close.active_callbacks, 0, "active_callbacks must balance to 0");
    }

    // ---------------------------------------------------------------------
    // wait_closed_and_idle: poison + transition tests
    // ---------------------------------------------------------------------

    /// Run `wait_closed_and_idle` on a worker; panic on timeout so a deadlock
    /// surfaces as a failure instead of hanging the suite.
    fn run_wait_with_timeout(state: &Arc<RequestState>, timeout: Duration, label: &str) {
        use std::sync::mpsc;
        use std::thread;

        let (tx, rx) = mpsc::sync_channel::<()>(1);
        let waiter = Arc::clone(state);
        let _handle = thread::spawn(move || {
            waiter.wait_closed_and_idle();
            let _ = tx.send(());
        });

        match rx.recv_timeout(timeout) {
            Ok(()) => {}
            Err(_) => panic!("{label}: wait_closed_and_idle did not return within {timeout:?}"),
        }
    }

    /// Poison `close_state` by panicking while holding the lock.
    fn poison_close_state(state: &Arc<RequestState>) {
        let s = Arc::clone(state);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard = s.close_state.lock().expect("first lock should succeed");
            panic!("simulated callback panic");
        }));
        assert!(state.close_state.is_poisoned(), "mutex should be poisoned");
    }

    /// Poison-recovery: must not deadlock when the underlying state is
    /// already terminal.
    #[test]
    fn wait_closed_and_idle_poison_recovery_table() {
        struct Case {
            label: &'static str,
            prepare: fn(&RequestState),
            poison: bool,
        }

        let cases = [
            Case {
                label: "already closed and idle, healthy mutex",
                prepare: |s| {
                    let mut g = s.lock_close_state();
                    g.closed = true;
                    g.active_callbacks = 0;
                },
                poison: false,
            },
            Case {
                label: "already closed and idle, poisoned mutex",
                prepare: |s| {
                    let mut g = s.lock_close_state();
                    g.closed = true;
                    g.active_callbacks = 0;
                },
                poison: true,
            },
            Case {
                label: "mark_final_callback_seen + poisoned mutex",
                prepare: |s| s.mark_final_callback_seen(),
                poison: true,
            },
        ];

        for case in &cases {
            let state = Arc::new(RequestState::new_test());
            (case.prepare)(&state);
            if case.poison {
                poison_close_state(&state);
            }
            run_wait_with_timeout(&state, Duration::from_secs(5), case.label);
        }
    }

    /// Wakes when another thread transitions active -> closed+idle.
    #[test]
    fn wait_closed_and_idle_wakes_on_async_transition() {
        use std::sync::mpsc;
        use std::thread;

        let state = Arc::new(RequestState::new_test());
        // Simulate an in-flight callback (active=1) before any waiter starts.
        {
            let mut g = state.lock_close_state();
            g.active_callbacks = 1;
        }

        let (tx, rx) = mpsc::sync_channel::<()>(1);
        let waiter = Arc::clone(&state);
        let _handle = thread::spawn(move || {
            waiter.wait_closed_and_idle();
            let _ = tx.send(());
        });

        // Give the waiter time to enter the condvar wait.
        thread::sleep(Duration::from_millis(50));

        // Simulate the callback finishing then HANDLE_CLOSING firing.
        {
            let mut g = state.lock_close_state();
            g.active_callbacks = 0;
        }
        state.mark_final_callback_seen();

        rx.recv_timeout(Duration::from_secs(5))
            .expect("wait_closed_and_idle should return after closed=true && active=0");
    }

    // ---- cross-origin redirect header stripping ----

    /// `Origin::from_url` normalization: case-insensitive scheme/host
    /// and default-port equivalence (parse failures are handled in
    /// `winhttp_callback_status_redirect_dispatch`).
    #[test]
    fn origin_from_url_normalization_cases() {
        struct Case {
            label: &'static str,
            a: &'static str,
            b: &'static str,
            equal: bool,
        }

        let cases = [
            Case {
                label: "host case-insensitive",
                a: "https://ExAmPlE.CoM/x",
                b: "https://example.com/y",
                equal: true,
            },
            Case {
                label: "implicit :443 == explicit :443 on https",
                a: "https://example.com/",
                b: "https://example.com:443/",
                equal: true,
            },
            Case {
                label: "cross-host",
                a: "https://api.example.com/",
                b: "https://attacker.example.org/",
                equal: false,
            },
            Case {
                label: "cross-scheme on default port (https -> http)",
                a: "https://example.com/",
                b: "http://example.com/",
                equal: false,
            },
            Case {
                label: "cross-port",
                a: "https://example.com/",
                b: "https://example.com:8443/",
                equal: false,
            },
        ];

        for case in &cases {
            let parse = |s: &str| -> crate::url::Url {
                s.parse()
                    .unwrap_or_else(|e| panic!("{}: parse {s}: {e}", case.label))
            };
            let oa = Origin::from_url(&parse(case.a));
            let ob = Origin::from_url(&parse(case.b));
            if case.equal {
                assert_eq!(oa, ob, "{}: origins must compare equal", case.label);
            } else {
                assert_ne!(oa, ob, "{}: origins must compare distinct", case.label);
            }
        }
    }

    /// Tracked origin advances only on cross-origin hops; remove-header
    /// stub always succeeds.
    #[test]
    fn cross_origin_redirect_updates_tracked_origin() {
        struct Hop {
            label: &'static str,
            redirect_to: &'static str,
            expect_origin: (&'static str, &'static str, u16),
        }

        let hops = [
            Hop {
                label: "same-origin path change leaves origin unchanged",
                redirect_to: "https://api.example.com/v2/users",
                expect_origin: ("https", "api.example.com", 443),
            },
            Hop {
                label: "cross-host updates tracked origin to attacker",
                redirect_to: "https://attacker.example.org/steal",
                expect_origin: ("https", "attacker.example.org", 443),
            },
            Hop {
                label: "further same-origin hop on new origin leaves it unchanged",
                redirect_to: "https://attacker.example.org/another",
                expect_origin: ("https", "attacker.example.org", 443),
            },
        ];

        let state = RequestState::new(false, Origin::new("https", "api.example.com", 443));

        for hop in &hops {
            let parsed: crate::url::Url = hop
                .redirect_to
                .parse()
                .unwrap_or_else(|e| panic!("test URL parse failed for {}: {e}", hop.redirect_to));
            strip_sensitive_headers_on_cross_origin_redirect_with(
                std::ptr::null_mut(),
                &state,
                &parsed,
                |_handle, _name| Ok(()),
            );
            let want = Origin::new(hop.expect_origin.0, hop.expect_origin.1, hop.expect_origin.2);
            assert_eq!(*state.current_origin.lock().unwrap(), want, "{}", hop.label,);
            assert!(
                !lock_or_clear(&state.callback_abort).is_aborted(),
                "{}: must not abort on the success path",
                hop.label,
            );
        }
    }

    /// Strip failure on a cross-origin hop must abort -- otherwise
    /// WinHTTP would forward surviving sensitive headers.  Driven over
    /// first/middle/last header in `SENSITIVE_HEADERS_ON_CROSS_ORIGIN`
    /// so all loop-exit points are pinned.
    #[test]
    fn cross_origin_redirect_aborts_on_strip_failure() {
        struct Case {
            label: &'static str,
            fail_on: &'static str,
        }

        let cases = [
            Case {
                label: "first header fails",
                fail_on: "Authorization",
            },
            Case {
                label: "middle header fails",
                fail_on: "Cookie2",
            },
            Case {
                label: "last header fails",
                fail_on: "WWW-Authenticate",
            },
        ];

        for case in &cases {
            let state = RequestState::new(false, Origin::new("https", "api.example.com", 443));
            let initial = state.current_origin.lock().unwrap().clone();
            let target: crate::url::Url = "https://attacker.example.org/steal".parse().unwrap();
            let fail_on = case.fail_on;

            strip_sensitive_headers_on_cross_origin_redirect_with(
                std::ptr::null_mut(),
                &state,
                &target,
                |_handle, name| {
                    if name == fail_on {
                        Err(Error::request("simulated WinHTTP strip failure"))
                    } else {
                        Ok(())
                    }
                },
            );

            let mut abort = lock_or_clear(&state.callback_abort);
            assert!(abort.is_aborted(), "{}: strip failure must abort", case.label);
            assert_eq!(
                *state.current_origin.lock().unwrap(),
                initial,
                "{}: origin must not advance when strip fails",
                case.label,
            );
            let reason = abort.take_reason().expect("abort reason must be stashed");
            assert!(reason.is_request(), "{}: reason should be request-phase", case.label);
            let msg = error_chain_text(&reason);
            let needle = format!("failed to strip {fail_on}");
            assert!(
                msg.contains(&needle) && msg.contains("attacker.example.org"),
                "{}: reason should mention {needle:?} + target; got: {msg}",
                case.label,
            );
        }
    }

    /// `abort_from_callback` is idempotent: first caller's reason wins
    /// regardless of how many later callers pile on.
    #[test]
    fn abort_from_callback_is_idempotent() {
        struct Case {
            label: &'static str,
            reasons: &'static [&'static str],
        }

        let cases = [
            Case {
                label: "single caller",
                reasons: &["only"],
            },
            Case {
                label: "two callers",
                reasons: &["first", "second"],
            },
            Case {
                label: "three callers",
                reasons: &["first", "second", "third"],
            },
        ];

        for case in &cases {
            let state = RequestState::new_test();
            for r in case.reasons {
                state.abort_from_callback(std::ptr::null_mut(), Error::request(*r));
            }

            let mut abort = lock_or_clear(&state.callback_abort);
            assert!(abort.is_aborted(), "{}: must be aborted", case.label);
            let reason = abort
                .take_reason()
                .unwrap_or_else(|| panic!("{}: a reason must be stashed", case.label));
            let msg = error_chain_text(&reason);
            let want = case.reasons[0];
            assert!(
                msg.contains(want),
                "{}: first caller's reason {want:?} must win; got: {msg}",
                case.label,
            );
        }
    }

    /// Join an `Error` with its `source()` chain -- `Display` only
    /// prints the top-level kind label.
    fn error_chain_text(err: &Error) -> String {
        use std::error::Error as _;
        let mut out = err.to_string();
        let mut cur: Option<&(dyn std::error::Error + 'static)> = err.source();
        while let Some(e) = cur {
            out.push_str(" :: ");
            out.push_str(&e.to_string());
            cur = e.source();
        }
        out
    }

    /// `STATUS_REDIRECT` through the full `winhttp_callback` entry
    /// point.  Covers the two outcomes that don't need a real FFI call:
    /// same-origin (no strip, no abort) and unparsable (abort).  The
    /// cross-origin success path is in
    /// `cross_origin_redirect_updates_tracked_origin` -- can't run here
    /// because the real `WinHttpAddRequestHeaders` would fail on a null
    /// handle and trip the abort path itself.
    #[test]
    fn winhttp_callback_status_redirect_dispatch() {
        struct Case {
            label: &'static str,
            initial: (&'static str, &'static str, u16),
            // Null-terminated -- WinHTTP delivers a null-terminated wide string.
            redirect_to: &'static str,
            expect_aborted: bool,
            expect_origin: (&'static str, &'static str, u16),
        }

        let cases = [
            Case {
                label: "same-origin redirect: no abort, tracker unchanged",
                initial: ("https", "api.example.com", 443),
                redirect_to: "https://api.example.com/v2/users\0",
                expect_aborted: false,
                expect_origin: ("https", "api.example.com", 443),
            },
            Case {
                label: "unparsable redirect: abort, tracker unchanged",
                initial: ("https", "api.example.com", 443),
                redirect_to: "not a url\0",
                expect_aborted: true,
                expect_origin: ("https", "api.example.com", 443),
            },
        ];

        for case in &cases {
            let state = Arc::new(RequestState::new(
                false,
                Origin::new(case.initial.0, case.initial.1, case.initial.2),
            ));
            let ctx = CallbackContext::new(&state);

            // `dwStatusInformationLength` is the BYTE length of the wide string.
            let wide: Vec<u16> = case.redirect_to.encode_utf16().collect();
            let byte_len = u32::try_from(wide.len() * 2).expect("byte len fits in u32");

            // SAFETY: `ctx` keeps the Arc alive across the call.
            // STATUS_REDIRECT is not HANDLE_CLOSING so the callback uses
            // `borrow_raw` and never `drop_raw`.
            unsafe {
                winhttp_callback(
                    std::ptr::null_mut(),
                    ctx.as_raw(),
                    WINHTTP_CALLBACK_STATUS_REDIRECT,
                    wide.as_ptr() as *mut std::ffi::c_void,
                    byte_len,
                );
            }

            let want =
                Origin::new(case.expect_origin.0, case.expect_origin.1, case.expect_origin.2);
            assert_eq!(
                *state.current_origin.lock().unwrap(),
                want,
                "{}: tracked origin",
                case.label,
            );
            let mut abort = lock_or_clear(&state.callback_abort);
            assert_eq!(
                abort.is_aborted(),
                case.expect_aborted,
                "{}: callback_abort.is_aborted()",
                case.label,
            );
            if case.expect_aborted {
                // Only path that stashes a reason via STATUS_REDIRECT;
                // assert the reason text here (the strip-layer test
                // can't reach the unparsable case anymore).
                let reason = abort
                    .take_reason()
                    .expect("expected an abort reason for the unparsable case");
                let msg = error_chain_text(&reason);
                assert!(
                    msg.contains("unparsable"),
                    "{}: abort reason should mention 'unparsable'; got: {msg}",
                    case.label,
                );
            }
            drop(abort);
            let close = state.lock_close_state();
            assert_eq!(close.active_callbacks, 0, "{}: active_callbacks must balance", case.label,);
            // Null handle -> close_winhttp_handle is a no-op, so
            // `closed` stays false even on the abort path.
            assert!(!close.closed, "{}: STATUS_REDIRECT must not mark closed", case.label,);
        }
    }

    /// All three `callback_error_to_error` branches (no-abort,
    /// abort-with-reason, abort-with-consumed-reason) must attach the
    /// URL and pick the right error source.
    #[test]
    fn callback_error_to_error_routing_cases() {
        let url: Url = "https://example.com/test".parse().unwrap();

        struct Case<'a> {
            label: &'static str,
            seed: fn() -> CallbackAbort,
            code: u32,
            check: &'a dyn Fn(&Error),
        }

        let cases: &[Case<'_>] = &[
            Case {
                label: "no abort: returns WinHTTP-coded timeout error",
                seed: || CallbackAbort::NotAborted,
                code: ERROR_WINHTTP_TIMEOUT,
                check: &|err| assert!(err.is_timeout(), "expected timeout kind"),
            },
            Case {
                label: "aborted with reason: surfaces stashed reason, not generic OPERATION_CANCELLED",
                seed: || {
                    CallbackAbort::Aborted(Some(Error::request("custom-strip-failure-marker")))
                },
                code: ERROR_WINHTTP_OPERATION_CANCELLED,
                check: &|err| {
                    let chain = error_chain_text(err);
                    assert!(
                        chain.contains("custom-strip-failure-marker"),
                        "expected marker in chain; got: {chain}",
                    );
                    assert!(
                        !chain.contains("12017"),
                        "must NOT fall through to WinHTTP-coded error; got: {chain}",
                    );
                },
            },
            Case {
                label: "aborted but reason already taken: falls through to WinHTTP-coded error",
                seed: || CallbackAbort::Aborted(None),
                code: ERROR_WINHTTP_OPERATION_CANCELLED,
                check: &|err| {
                    assert!(err.is_request(), "expected request kind");
                    let chain = error_chain_text(err);
                    assert!(
                        chain.contains("12017"),
                        "expected OPERATION_CANCELLED code (12017) in chain; got: {chain}",
                    );
                },
            },
        ];

        for case in cases {
            let state = RequestState::new_test();
            *lock_or_clear(&state.callback_abort) = (case.seed)();

            let err = callback_error_to_error(case.code, &state, &url);

            assert_eq!(
                err.url().map(|u| u.as_str()),
                Some("https://example.com/test"),
                "{}: URL must be preserved",
                case.label,
            );
            (case.check)(&err);
        }
    }

    /// `WinHttpRequestHandle::Drop` must return on every routing
    /// branch; a wrong branch deadlocks on `wait_closed_and_idle`.
    /// Drives the two null-handle branches (branch 2 needs a real
    /// WinHTTP handle, exercised by integration tests). Each case
    /// runs Drop on a worker thread with a 5s timeout.
    #[test]
    fn winhttp_request_handle_drop_routing_cases() {
        use std::sync::mpsc;

        struct Case {
            label: &'static str,
            seed_abort: bool,
            seed_closed: bool,
        }

        let cases = &[
            Case {
                label: "aborted: skip second close, wait returns because HANDLE_CLOSING pre-seeded",
                seed_abort: true,
                seed_closed: true,
            },
            Case {
                label: "not aborted, null handle: close returns false, Drop returns without wait",
                seed_abort: false,
                seed_closed: false,
            },
        ];

        for case in cases {
            let state = Arc::new(RequestState::new_test());
            if case.seed_abort {
                state.abort_from_callback(
                    std::ptr::null_mut(),
                    Error::request("simulated callback abort"),
                );
            }
            if case.seed_closed {
                state.mark_final_callback_seen();
            }

            let handle = WinHttpRequestHandle {
                handle: std::ptr::null_mut(),
                state: Arc::clone(&state),
            };

            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                drop(handle);
                let _ = tx.send(());
            });
            rx.recv_timeout(Duration::from_secs(5)).unwrap_or_else(|_| {
                panic!(
                    "{}: Drop did not return within 5s -- likely a wrong routing branch \
                     leading to a deadlock on wait_closed_and_idle",
                    case.label,
                );
            });
        }
    }
}
