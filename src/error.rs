//! Error type for wrest.
//!
//! Provides [`Error`] with query methods compatible with `reqwest::Error`:
//! [`is_builder()`](Error::is_builder), [`is_connect()`](Error::is_connect),
//! [`is_timeout()`](Error::is_timeout), [`is_request()`](Error::is_request),
//! [`is_body()`](Error::is_body), [`is_status()`](Error::is_status),
//! [`status()`](Error::status), and [`url()`](Error::url).

use crate::url::Url;
use http::StatusCode;
use std::{borrow::Cow, fmt, io};
use windows_sys::Win32::Networking::WinHttp::*;

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The error type for wrest operations.
///
/// Errors carry a `kind` classification that powers the
/// `is_builder()` / `is_connect()` / `is_timeout()` / `is_request()` /
/// `is_body()` / `is_status()` query methods, matching the `reqwest::Error`
/// API.
///
/// When a request URL is available, it is included in the `Display` output
/// for diagnostics and telemetry.
pub struct Error {
    pub(crate) inner: Box<InnerError>,
}

pub(crate) struct InnerError {
    pub(crate) kind: ErrorKind,
    pub(crate) source: Option<BoxError>,
    pub(crate) status: Option<StatusCode>,
    pub(crate) url: Option<Box<Url>>,
}

/// Classification of an [`Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorKind {
    /// Client construction error (e.g. invalid builder config).
    Builder,
    /// Connection error (`ERROR_WINHTTP_CANNOT_CONNECT`,
    /// `ERROR_WINHTTP_NAME_NOT_RESOLVED`, `ERROR_WINHTTP_SECURE_FAILURE`).
    Connect,
    /// Timeout error (`ERROR_WINHTTP_TIMEOUT`).
    Timeout,
    /// HTTP status error (from [`Response::error_for_status`](crate::Response::error_for_status)).
    Status,
    /// Other request-phase errors.
    Request,
    /// Error reading the response body.
    Body,
    /// Redirect error (`ERROR_WINHTTP_REDIRECT_FAILED`).
    Redirect,
    /// Response body decoding error (JSON deserialization, charset conversion).
    Decode,
    /// Upgrade error.
    ///
    /// Not constructed by the native WinHTTP backend (protocol upgrades
    /// are handled transparently), but kept for API compatibility with
    /// reqwest.
    #[cfg_attr(not(test), expect(dead_code))]
    Upgrade,
}

impl Error {
    /// Returns `true` if this is a builder error.
    pub fn is_builder(&self) -> bool {
        matches!(self.inner.kind, ErrorKind::Builder)
    }

    /// Returns `true` if this is a connection error.
    ///
    /// Connection errors include DNS resolution failures, TCP connection
    /// refused, and TLS handshake failures -- matching `reqwest::Error::is_connect()`.
    pub fn is_connect(&self) -> bool {
        matches!(self.inner.kind, ErrorKind::Connect)
    }

    /// Returns `true` if this is a timeout error.
    pub fn is_timeout(&self) -> bool {
        matches!(self.inner.kind, ErrorKind::Timeout)
    }

    /// Returns `true` if this error was produced by
    /// [`Response::error_for_status`](crate::Response::error_for_status).
    pub fn is_status(&self) -> bool {
        matches!(self.inner.kind, ErrorKind::Status)
    }

    /// Returns `true` if this is a request-phase error.
    pub fn is_request(&self) -> bool {
        matches!(self.inner.kind, ErrorKind::Request)
    }

    /// Returns `true` if this is a body-reading error.
    pub fn is_body(&self) -> bool {
        matches!(self.inner.kind, ErrorKind::Body)
    }

    /// Returns `true` if this is a redirect error.
    ///
    /// This is set when WinHTTP reports `ERROR_WINHTTP_REDIRECT_FAILED`,
    /// e.g. because the redirect limit was exceeded.
    pub fn is_redirect(&self) -> bool {
        matches!(self.inner.kind, ErrorKind::Redirect)
    }

    /// Returns `true` if this is a response body decoding error.
    ///
    /// This includes JSON deserialization failures (from
    /// `Response::json()`) and charset
    /// conversion errors (from [`Response::text()`](crate::Response::text)).
    pub fn is_decode(&self) -> bool {
        matches!(self.inner.kind, ErrorKind::Decode)
    }

    /// Returns `true` if this is an upgrade error.
    ///
    /// # No-op -- reqwest compatibility
    ///
    /// wrest does not support WebSocket or HTTP upgrade connections,
    /// so this always returns `false`.  Requires the `noop-compat`
    /// feature.
    #[cfg(feature = "noop-compat")]
    pub fn is_upgrade(&self) -> bool {
        matches!(self.inner.kind, ErrorKind::Upgrade)
    }

    /// Returns `true` if the underlying I/O error is a connection reset.
    ///
    /// This is the WinHTTP equivalent of an HTTP/2 GOAWAY or
    /// REFUSED_STREAM — the server closed the connection without
    /// processing the request.  Used by the retry module to identify
    /// safely-retryable failures.
    ///
    /// See also `io_error_from_winhttp()` for precise WinHTTP error code mappings to `io::ErrorKind`.
    pub(crate) fn is_connection_reset(&self) -> bool {
        use std::error::Error as _;
        let mut cur: Option<&(dyn std::error::Error + 'static)> = self.source();
        while let Some(e) = cur {
            if let Some(io_err) = e.downcast_ref::<std::io::Error>()
                && io_err.kind() == std::io::ErrorKind::ConnectionReset
            {
                return true;
            }
            cur = e.source();
        }
        false
    }

    /// Returns the HTTP status code, if this error was produced by
    /// [`Response::error_for_status`](crate::Response::error_for_status).
    pub fn status(&self) -> Option<StatusCode> {
        self.inner.status
    }

    /// Returns the request URL associated with this error, if available.
    pub fn url(&self) -> Option<&Url> {
        self.inner.url.as_deref()
    }

    /// Returns a mutable reference to the request URL associated with
    /// this error, if available.
    pub fn url_mut(&mut self) -> Option<&mut Url> {
        self.inner.url.as_deref_mut()
    }

    /// Strips the URL from this error, returning the error without a URL.
    #[must_use]
    pub fn without_url(mut self) -> Self {
        self.inner.url = None;
        self
    }

    /// Attach a request URL to this error (builder pattern).
    #[must_use]
    pub fn with_url(mut self, url: Url) -> Self {
        self.inner.url = Some(Box::new(url));
        self
    }

    // -- Internal constructors --

    /// Shared constructor for simple error kinds (no source, no status, no URL).
    fn with_kind(kind: ErrorKind, source: impl Into<BoxError>) -> Self {
        Self {
            inner: Box::new(InnerError {
                kind,
                source: Some(source.into()),
                status: None,
                url: None,
            }),
        }
    }

    /// Create a builder-phase error.
    pub(crate) fn builder(source: impl Into<BoxError>) -> Self {
        Self::with_kind(ErrorKind::Builder, source)
    }

    /// Create a status error for a failed HTTP status code.
    pub(crate) fn status_error(code: StatusCode, url: Url) -> Self {
        Self {
            inner: Box::new(InnerError {
                kind: ErrorKind::Status,
                source: None,
                status: Some(code),
                url: Some(Box::new(url)),
            }),
        }
    }

    /// Create an error from a Win32 / WinHTTP error code (`u32`).
    ///
    /// The code is classified into an [`ErrorKind`] and stored as an
    /// [`io::Error`] in the source chain with a mapped
    /// [`io::ErrorKind`] where possible (e.g. `ConnectionRefused`,
    /// `TimedOut`).
    pub(crate) fn from_win32(code: u32) -> Self {
        let kind = error_kind_from_win32(code);
        Self {
            inner: Box::new(InnerError {
                kind,
                source: Some(Box::new(io_error_from_winhttp(code))),
                status: None,
                url: None,
            }),
        }
    }

    /// Create a timeout error.
    pub(crate) fn timeout(source: impl Into<BoxError>) -> Self {
        Self::with_kind(ErrorKind::Timeout, source)
    }

    /// Create a body-reading error.
    pub(crate) fn body(source: impl Into<BoxError>) -> Self {
        Self::with_kind(ErrorKind::Body, source)
    }

    /// Create a decode error (JSON deserialization, charset conversion).
    pub(crate) fn decode(source: impl Into<BoxError>) -> Self {
        Self::with_kind(ErrorKind::Decode, source)
    }

    /// Create a request-phase error.
    pub(crate) fn request(source: impl Into<BoxError>) -> Self {
        Self::with_kind(ErrorKind::Request, source)
    }
}

impl fmt::Display for Error {
    /// Matches reqwest's `Display`: a kind-based prefix, then
    /// ` for url (...)` when the URL is known.  The source error
    /// detail is available via [`std::error::Error::source`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.inner.kind {
            ErrorKind::Builder => f.write_str("builder error")?,
            ErrorKind::Request => f.write_str("error sending request")?,
            ErrorKind::Body => f.write_str("request or response body error")?,
            ErrorKind::Decode => f.write_str("error decoding response body")?,
            ErrorKind::Redirect => f.write_str("error following redirect")?,
            ErrorKind::Connect => f.write_str("error trying to connect")?,
            ErrorKind::Timeout => f.write_str("operation timed out")?,
            ErrorKind::Status => {
                // Matches reqwest: "HTTP status client error (404 Not Found)"
                if let Some(code) = self.inner.status {
                    let prefix = if code.is_client_error() {
                        "HTTP status client error"
                    } else {
                        "HTTP status server error"
                    };
                    let reason = code.canonical_reason().unwrap_or("<unknown status code>");
                    write!(f, "{prefix} ({} {reason})", code.as_str())?;
                } else {
                    f.write_str("HTTP status error")?;
                }
            }
            ErrorKind::Upgrade => f.write_str("error upgrading connection")?,
        }
        if let Some(url) = &self.inner.url {
            write!(f, " for url ({url})")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Error")
            .field("kind", &self.inner.kind)
            .field("url", &self.inner.url)
            .field("status", &self.inner.status)
            .field("source", &self.inner.source)
            .finish()
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner
            .source
            .as_ref()
            .map(|e| &**e as &(dyn std::error::Error + 'static))
    }
}

/// Classify a Win32 / WinHTTP error code into an [`ErrorKind`].
///
/// This is the **single** place in the crate that classifies WinHTTP
/// failures into [`ErrorKind`] variants.
fn error_kind_from_win32(code: u32) -> ErrorKind {
    match code {
        ERROR_WINHTTP_CANNOT_CONNECT => ErrorKind::Connect,
        ERROR_WINHTTP_NAME_NOT_RESOLVED => ErrorKind::Connect,
        ERROR_WINHTTP_CONNECTION_ERROR => ErrorKind::Connect,
        ERROR_WINHTTP_SECURE_FAILURE => ErrorKind::Connect,
        ERROR_WINHTTP_TIMEOUT => ErrorKind::Timeout,
        ERROR_WINHTTP_REDIRECT_FAILED => ErrorKind::Redirect,
        _ => ErrorKind::Request,
    }
}

/// Create an [`io::Error`] from a WinHTTP error code with a mapped
/// [`io::ErrorKind`] where a natural mapping exists.
///
/// Uses [`io::Error::from_raw_os_error`] as the inner error so that
/// Windows' `FormatMessage` provides the human-readable description.
/// For codes with a well-known mapping (e.g. `CANNOT_CONNECT` -->
/// `ConnectionRefused`) the outer error carries the translated kind;
/// for all others the raw OS error is returned directly.
fn io_error_from_winhttp(code: u32) -> io::Error {
    let mapped_kind = match code {
        ERROR_WINHTTP_CANNOT_CONNECT => Some(io::ErrorKind::ConnectionRefused),
        ERROR_WINHTTP_CONNECTION_ERROR => Some(io::ErrorKind::ConnectionReset),
        ERROR_WINHTTP_TIMEOUT => Some(io::ErrorKind::TimedOut),
        _ => None,
    };
    match mapped_kind {
        Some(kind) => io::Error::new(kind, io::Error::from_raw_os_error(code as i32)),
        None => io::Error::from_raw_os_error(code as i32),
    }
}

// Ensure Error is Send + Sync (required for async use and reqwest compat).
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Error>();
};

/// Source error that pairs a context message with an underlying cause.
///
/// `Display` shows the context string; `source()` chains to the
/// wrapped error.  Used anywhere wrest adds diagnostic context beyond
/// what the underlying error's own `Display` provides.
#[derive(Debug)]
pub(crate) struct ContextError {
    context: Cow<'static, str>,
    source: BoxError,
}

impl ContextError {
    pub(crate) fn new(context: impl Into<Cow<'static, str>>, source: impl Into<BoxError>) -> Self {
        Self {
            context: context.into(),
            source: source.into(),
        }
    }
}

impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.context)
    }
}

impl std::error::Error for ContextError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::url::IntoUrlSealed;
    use std::error::Error as StdError;

    #[test]
    fn error_display_format() {
        // Display uses kind-based prefixes matching reqwest::Error.
        // Status errors format from the status code directly.
        let cases: Vec<(&str, Error, &str)> = vec![
            (
                "connect_with_url",
                Error {
                    inner: Box::new(InnerError {
                        kind: ErrorKind::Connect,
                        source: None,
                        status: None,
                        url: Some(Box::new("https://example.com".into_url().unwrap())),
                    }),
                },
                "error trying to connect for url (https://example.com/)",
            ),
            (
                "timeout_no_url",
                Error {
                    inner: Box::new(InnerError {
                        kind: ErrorKind::Timeout,
                        source: None,
                        status: None,
                        url: None,
                    }),
                },
                "operation timed out",
            ),
            ("request", Error::request("something went wrong"), "error sending request"),
            ("body", Error::body("read failed"), "request or response body error"),
            ("builder", Error::builder("bad config"), "builder error"),
            ("decode", Error::decode("invalid json"), "error decoding response body"),
            (
                "upgrade",
                Error {
                    inner: Box::new(InnerError {
                        kind: ErrorKind::Upgrade,
                        source: None,
                        status: None,
                        url: None,
                    }),
                },
                "error upgrading connection",
            ),
            (
                "status_client",
                Error::status_error(
                    StatusCode::IM_A_TEAPOT,
                    "https://example.com/brew".into_url().unwrap(),
                ),
                "HTTP status client error (418 I'm a teapot) for url (https://example.com/brew)",
            ),
            (
                "status_server",
                Error::status_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "https://example.com/fail".into_url().unwrap(),
                ),
                "HTTP status server error (500 Internal Server Error) for url (https://example.com/fail)",
            ),
            (
                "status_no_code",
                Error {
                    inner: Box::new(InnerError {
                        kind: ErrorKind::Status,
                        source: None,
                        status: None,
                        url: None,
                    }),
                },
                "HTTP status error",
            ),
        ];

        for (label, err, expected) in &cases {
            assert_eq!(err.to_string(), *expected, "error display: {label}");
        }
    }

    /// Each `ErrorKind` has exactly one `is_*` query method that returns
    /// `true`; all other `is_*` methods return `false`.
    #[test]
    fn error_kind_exclusivity_table() {
        // (error, check, label) -- one entry per ErrorKind.
        // The table itself doubles as the cross-check matrix: for each
        // error we call every other entry's function pointer and verify
        // only the designated one fires.
        type TestCase<'a> = (Error, fn(&Error) -> bool, &'a str);
        let cases: Vec<TestCase> = vec![
            (Error::builder("b"), Error::is_builder, "builder"),
            (Error::request("r"), Error::is_request, "request"),
            (Error::timeout("t"), Error::is_timeout, "timeout"),
            (Error::body("d"), Error::is_body, "body"),
            (Error::decode("d"), Error::is_decode, "decode"),
            (
                Error {
                    inner: Box::new(InnerError {
                        kind: ErrorKind::Connect,
                        source: None,
                        status: None,
                        url: None,
                    }),
                },
                Error::is_connect,
                "connect",
            ),
            (
                Error {
                    inner: Box::new(InnerError {
                        kind: ErrorKind::Status,
                        source: None,
                        status: Some(StatusCode::IM_A_TEAPOT),
                        url: Some(Box::new("https://example.com/brew".into_url().unwrap())),
                    }),
                },
                Error::is_status,
                "status",
            ),
            (
                Error {
                    inner: Box::new(InnerError {
                        kind: ErrorKind::Redirect,
                        source: None,
                        status: None,
                        url: None,
                    }),
                },
                Error::is_redirect,
                "redirect",
            ),
        ];

        #[cfg(feature = "noop-compat")]
        let cases = {
            let mut v = cases;
            v.push((
                Error {
                    inner: Box::new(InnerError {
                        kind: ErrorKind::Upgrade,
                        source: None,
                        status: None,
                        url: None,
                    }),
                },
                Error::is_upgrade as fn(&Error) -> bool,
                "upgrade",
            ));
            v
        };

        for (err, check, label) in &cases {
            assert!(check(err), "{label}: own is_*() should be true");

            // Cross-check: every *other* entry's function pointer must
            // return false for this error.
            for (_, other_check, other_label) in &cases {
                if *other_label != *label {
                    assert!(!other_check(err), "{label}: is_{other_label}() should be false");
                }
            }
        }

        // Verify status() and url() accessors on the Status entry.
        let status_err = &cases.iter().find(|(_, _, l)| *l == "status").unwrap().0;
        assert_eq!(status_err.status(), Some(StatusCode::IM_A_TEAPOT));
        assert_eq!(status_err.url().map(|u| u.as_str()), Some("https://example.com/brew"));

        // Non-status errors return None for both.
        let builder_err = &cases[0].0;
        assert!(builder_err.status().is_none());
        assert!(builder_err.url().is_none());
    }

    #[test]
    fn error_type_properties() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Error>();

        assert_eq!(std::mem::size_of::<Error>(), std::mem::size_of::<usize>());
    }

    #[test]
    fn error_with_url_builder() {
        let url = "https://example.com/api".into_url().unwrap();
        let err = Error::request("something failed").with_url(url);
        assert_eq!(err.url().map(|u| u.as_str()), Some("https://example.com/api"));
        // Display uses kind-based prefix; detail is in the source chain.
        assert_eq!(err.to_string(), "error sending request for url (https://example.com/api)");
        // Source chain contains the detail string.
        assert!(
            std::error::Error::source(&err)
                .map(|s| s.to_string().contains("something failed"))
                .unwrap()
        );
    }

    #[test]
    fn error_debug_display_source() {
        let err = Error::builder("bad config");
        let debug = format!("{err:?}");
        assert!(debug.contains("Builder"));
        // Detail string is in the source chain, visible in Debug.
        assert!(debug.contains("bad config"));

        let inner = std::io::Error::other("root cause");
        let ctx = ContextError::new("context message", inner);
        assert_eq!(ctx.to_string(), "context message");
        let source = StdError::source(&ctx).expect("should have source");
        assert!(source.to_string().contains("root cause"));
    }

    #[test]
    #[cfg(feature = "noop-compat")]
    fn noop_compat_is_methods_false_for_real_kinds() {
        let errors =
            [Error::builder("b"), Error::request("r"), Error::timeout("t"), Error::body("d")];
        for err in &errors {
            assert!(!err.is_redirect(), "is_redirect should be false for {err}");
            assert!(!err.is_decode(), "is_decode should be false for {err}");
            assert!(!err.is_upgrade(), "is_upgrade should be false for {err}");
        }
    }

    // -- url_mut, without_url, with_url --
    // NOTE: decode error classification is covered exhaustively by
    // `error_kind_exclusivity_table` above (the "decode" row).

    #[test]
    fn decode_error_message() {
        let err = Error::decode("JSON deserialization failed");
        // Display shows kind prefix; detail is in the source chain.
        assert_eq!(err.to_string(), "error decoding response body");
        let source = StdError::source(&err).expect("should have source");
        assert_eq!(source.to_string(), "JSON deserialization failed");
    }

    #[test]
    fn error_url_mut() {
        let url = "https://example.com".into_url().unwrap();
        let mut err = Error::request("fail").with_url(url);
        assert!(err.url_mut().is_some());
        assert_eq!(err.url_mut().unwrap().as_str(), "https://example.com/");
    }

    #[test]
    fn error_url_mut_none() {
        let mut err = Error::request("fail");
        assert!(err.url_mut().is_none());
    }

    #[test]
    fn error_without_url() {
        let url = "https://example.com".into_url().unwrap();
        let err = Error::request("fail").with_url(url);
        assert!(err.url().is_some());
        let err = err.without_url();
        assert!(err.url().is_none());
        // Display uses kind prefix; URL is stripped.
        assert_eq!(err.to_string(), "error sending request");
        // Detail preserved in source chain.
        let source = StdError::source(&err).expect("should have source");
        assert_eq!(source.to_string(), "fail");
    }

    // NOTE: `with_url` public API is already exercised by `error_with_url_builder`
    // and by `error_without_url` above.

    // -- Win32 code classification via from_win32 --

    /// Comprehensive test for `from_win32`: error-kind classification,
    /// Display/Debug formatting, source-chain `io::Error`, and
    /// `io::ErrorKind` mapping -- all in one table.
    #[test]
    fn from_win32_table() {
        // (code, kind check, expected io::ErrorKind or None, label)
        type TestCase<'a> = (u32, fn(&Error) -> bool, Option<io::ErrorKind>, &'a str);
        let cases: &[TestCase] = &[
            (
                ERROR_WINHTTP_CANNOT_CONNECT,
                Error::is_connect,
                Some(io::ErrorKind::ConnectionRefused),
                "connect",
            ),
            (ERROR_WINHTTP_NAME_NOT_RESOLVED, Error::is_connect, None, "connect (dns)"),
            (
                ERROR_WINHTTP_CONNECTION_ERROR,
                Error::is_connect,
                Some(io::ErrorKind::ConnectionReset),
                "connect (conn)",
            ),
            (ERROR_WINHTTP_SECURE_FAILURE, Error::is_connect, None, "connect (tls)"),
            (ERROR_WINHTTP_TIMEOUT, Error::is_timeout, Some(io::ErrorKind::TimedOut), "timeout"),
            (ERROR_WINHTTP_REDIRECT_FAILED, Error::is_redirect, None, "redirect"),
            // Unknown code falls through to Request.
            (0xFFFF, Error::is_request, None, "unknown"),
        ];

        for &(code, check, expected_io_kind, label) in cases {
            let err = Error::from_win32(code);

            // ErrorKind classification
            assert!(check(&err), "{label}: expected is_*() to be true");

            // Display: kind-based prefix (no raw code)
            let display = err.to_string();
            assert!(
                !display.contains(&code.to_string()),
                "{label}: Display should not contain raw code"
            );

            // Source chain: always an io::Error
            let source =
                StdError::source(&err).unwrap_or_else(|| panic!("{label}: should have source"));
            let io_err = source
                .downcast_ref::<io::Error>()
                .unwrap_or_else(|| panic!("{label}: source should be io::Error"));

            // io::ErrorKind mapping (when one exists)
            if let Some(kind) = expected_io_kind {
                assert_eq!(io_err.kind(), kind, "{label}: wrong io::ErrorKind");
            }
        }
    }

    /// Constructor sources are accessible through the standard
    /// `Error::source()` chain and can be downcast to the original type.
    #[test]
    fn source_downcast() {
        // String source is present.
        let err = Error::body("read failed");
        assert!(StdError::source(&err).is_some());

        // Typed source is downcastable.
        let inner = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe");
        let err = Error::body(inner);

        let source = StdError::source(&err).expect("should have source");
        let io_err = source
            .downcast_ref::<std::io::Error>()
            .expect("downcast to io::Error");
        assert_eq!(io_err.kind(), std::io::ErrorKind::BrokenPipe);
    }
}
