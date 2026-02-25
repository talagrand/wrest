//! Error type for wrest.
//!
//! Provides [`Error`] with query methods compatible with `reqwest::Error`:
//! [`is_builder()`](Error::is_builder), [`is_connect()`](Error::is_connect),
//! [`is_timeout()`](Error::is_timeout), [`is_request()`](Error::is_request),
//! [`is_body()`](Error::is_body), [`is_status()`](Error::is_status),
//! [`status()`](Error::status), and [`url()`](Error::url).

use crate::url::Url;
use http::StatusCode;
use std::fmt;
use std::io;
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
    pub(crate) kind: ErrorKind,
    pub(crate) message: String,
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
        matches!(self.kind, ErrorKind::Builder)
    }

    /// Returns `true` if this is a connection error.
    ///
    /// Connection errors include DNS resolution failures, TCP connection
    /// refused, and TLS handshake failures -- matching `reqwest::Error::is_connect()`.
    pub fn is_connect(&self) -> bool {
        matches!(self.kind, ErrorKind::Connect)
    }

    /// Returns `true` if this is a timeout error.
    pub fn is_timeout(&self) -> bool {
        matches!(self.kind, ErrorKind::Timeout)
    }

    /// Returns `true` if this error was produced by
    /// [`Response::error_for_status`](crate::Response::error_for_status).
    pub fn is_status(&self) -> bool {
        matches!(self.kind, ErrorKind::Status)
    }

    /// Returns `true` if this is a request-phase error.
    pub fn is_request(&self) -> bool {
        matches!(self.kind, ErrorKind::Request)
    }

    /// Returns `true` if this is a body-reading error.
    pub fn is_body(&self) -> bool {
        matches!(self.kind, ErrorKind::Body)
    }

    /// Returns `true` if this is a redirect error.
    ///
    /// This is set when WinHTTP reports `ERROR_WINHTTP_REDIRECT_FAILED`,
    /// e.g. because the redirect limit was exceeded.
    pub fn is_redirect(&self) -> bool {
        matches!(self.kind, ErrorKind::Redirect)
    }

    /// Returns `true` if this is a response body decoding error.
    ///
    /// This includes JSON deserialization failures (from
    /// `Response::json()`) and charset
    /// conversion errors (from [`Response::text()`](crate::Response::text)).
    pub fn is_decode(&self) -> bool {
        matches!(self.kind, ErrorKind::Decode)
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
        matches!(self.kind, ErrorKind::Upgrade)
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
        self.status
    }

    /// Returns the request URL associated with this error, if available.
    pub fn url(&self) -> Option<&Url> {
        self.url.as_deref()
    }

    /// Returns a mutable reference to the request URL associated with
    /// this error, if available.
    pub fn url_mut(&mut self) -> Option<&mut Url> {
        self.url.as_deref_mut()
    }

    /// Strips the URL from this error, returning the error without a URL.
    #[must_use]
    pub fn without_url(mut self) -> Self {
        self.url = None;
        self
    }

    /// Attach a request URL to this error (builder pattern).
    #[must_use]
    pub fn with_url(mut self, url: Url) -> Self {
        self.url = Some(Box::new(url));
        self
    }

    /// Attach a source error (builder pattern).
    ///
    /// Stores the underlying cause so that
    /// [`std::error::Error::source`] returns it, making error chains
    /// inspectable by `anyhow`, `eyre`, and manual walks.
    #[must_use]
    pub(crate) fn with_source(mut self, source: impl Into<BoxError>) -> Self {
        self.source = Some(source.into());
        self
    }

    // -- Internal constructors --

    /// Shared constructor for simple error kinds (no source, no status, no URL).
    fn with_kind(kind: ErrorKind, msg: impl Into<String>) -> Self {
        Self {
            kind,
            message: msg.into(),
            source: None,
            status: None,
            url: None,
        }
    }

    /// Create a builder-phase error.
    pub(crate) fn builder(msg: impl Into<String>) -> Self {
        Self::with_kind(ErrorKind::Builder, msg)
    }

    /// Create a status error for a failed HTTP status code.
    pub(crate) fn status_error(code: StatusCode, url: crate::Url) -> Self {
        let prefix = if code.is_client_error() {
            "HTTP status client error"
        } else {
            "HTTP status server error"
        };
        let reason = code.canonical_reason().unwrap_or("<unknown status code>");
        Self {
            kind: ErrorKind::Status,
            message: format!("{prefix} ({} {reason})", code.as_str()),
            source: None,
            status: Some(code),
            url: Some(Box::new(url)),
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
        let message = format!("WinHTTP error {code}");
        Self {
            kind,
            message,
            source: Some(Box::new(io_error_from_winhttp(code))),
            status: None,
            url: None,
        }
    }

    /// Create a timeout error.
    pub(crate) fn timeout(msg: impl Into<String>) -> Self {
        Self::with_kind(ErrorKind::Timeout, msg)
    }

    /// Create a body-reading error.
    pub(crate) fn body(msg: impl Into<String>) -> Self {
        Self::with_kind(ErrorKind::Body, msg)
    }

    /// Create a decode error (JSON deserialization, charset conversion).
    pub(crate) fn decode(msg: impl Into<String>) -> Self {
        Self::with_kind(ErrorKind::Decode, msg)
    }

    /// Create a request-phase error.
    pub(crate) fn request(msg: impl Into<String>) -> Self {
        Self::with_kind(ErrorKind::Request, msg)
    }
}

impl fmt::Display for Error {
    /// Matches reqwest's `Display`: a kind-based prefix, then
    /// ` for url (...)` when the URL is known.  The source error
    /// detail is available via [`std::error::Error::source`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ErrorKind::Builder => f.write_str("builder error")?,
            ErrorKind::Request => f.write_str("error sending request")?,
            ErrorKind::Body => f.write_str("request or response body error")?,
            ErrorKind::Decode => f.write_str("error decoding response body")?,
            ErrorKind::Redirect => f.write_str("error following redirect")?,
            ErrorKind::Connect => f.write_str("error trying to connect")?,
            ErrorKind::Timeout => f.write_str("operation timed out")?,
            ErrorKind::Status => {
                // Matches reqwest: "HTTP status client error (404 Not Found)"
                write!(f, "{}", self.message)?;
            }
            ErrorKind::Upgrade => f.write_str("error upgrading connection")?,
        }
        if let Some(url) = &self.url {
            write!(f, " for url ({url})")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Error")
            .field("kind", &self.kind)
            .field("message", &self.message)
            .field("url", &self.url)
            .field("status", &self.status)
            .field("source", &self.source)
            .finish()
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::url::IntoUrlSealed;
    use std::error::Error as StdError;

    #[test]
    fn error_display_format() {
        // Display uses kind-based prefixes matching reqwest::Error.
        // The `message` field is only used for Status errors where it
        // carries the "HTTP status {client,server} error (CODE REASON)" text.
        let cases: Vec<(&str, Error, &str)> = vec![
            (
                "connect_with_url",
                Error {
                    kind: ErrorKind::Connect,
                    message: "connection refused".into(),
                    source: None,
                    status: None,
                    url: Some(Box::new("https://example.com".into_url().unwrap())),
                },
                "error trying to connect for url (https://example.com/)",
            ),
            (
                "timeout_no_url",
                Error {
                    kind: ErrorKind::Timeout,
                    message: "operation timed out".into(),
                    source: None,
                    status: None,
                    url: None,
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
                    kind: ErrorKind::Upgrade,
                    message: String::new(),
                    source: None,
                    status: None,
                    url: None,
                },
                "error upgrading connection",
            ),
            (
                "status_client",
                Error {
                    kind: ErrorKind::Status,
                    message: "HTTP status client error (404 Not Found)".into(),
                    source: None,
                    status: Some(StatusCode::NOT_FOUND),
                    url: Some(Box::new("https://example.com/missing".into_url().unwrap())),
                },
                "HTTP status client error (404 Not Found) for url (https://example.com/missing)",
            ),
            (
                "status_server",
                Error {
                    kind: ErrorKind::Status,
                    message: "HTTP status server error (500 Internal Server Error)".into(),
                    source: None,
                    status: Some(StatusCode::INTERNAL_SERVER_ERROR),
                    url: Some(Box::new("https://example.com/fail".into_url().unwrap())),
                },
                "HTTP status server error (500 Internal Server Error) for url (https://example.com/fail)",
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
                    kind: ErrorKind::Connect,
                    message: "c".into(),
                    source: None,
                    status: None,
                    url: None,
                },
                Error::is_connect,
                "connect",
            ),
            (
                Error {
                    kind: ErrorKind::Status,
                    message: "s".into(),
                    source: None,
                    status: Some(StatusCode::NOT_FOUND),
                    url: Some(Box::new("https://example.com/missing".into_url().unwrap())),
                },
                Error::is_status,
                "status",
            ),
            (
                Error {
                    kind: ErrorKind::Redirect,
                    message: "r".into(),
                    source: None,
                    status: None,
                    url: None,
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
                    kind: ErrorKind::Upgrade,
                    message: "u".into(),
                    source: None,
                    status: None,
                    url: None,
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
        assert_eq!(status_err.status(), Some(StatusCode::NOT_FOUND));
        assert_eq!(status_err.url().map(|u| u.as_str()), Some("https://example.com/missing"));

        // Non-status errors return None for both.
        let builder_err = &cases[0].0;
        assert!(builder_err.status().is_none());
        assert!(builder_err.url().is_none());
    }

    #[test]
    fn error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Error>();
    }

    #[test]
    fn error_with_url_builder() {
        let url = "https://example.com/api".into_url().unwrap();
        let err = Error::request("something failed").with_url(url);
        assert_eq!(err.url().map(|u| u.as_str()), Some("https://example.com/api"));
        // Display uses kind-based prefix; detail is in the Debug/message field.
        assert_eq!(err.to_string(), "error sending request for url (https://example.com/api)");
        assert!(format!("{err:?}").contains("something failed"));
    }

    #[test]
    fn error_debug_format() {
        let err = Error::builder("bad config");
        let debug = format!("{err:?}");
        assert!(debug.contains("Builder"));
        assert!(debug.contains("bad config"));
    }

    #[test]
    fn error_std_error_source() {
        let inner = std::io::Error::other("inner");
        let err = Error::body("read failed").with_source(inner);
        assert!(StdError::source(&err).is_some());
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
        // Display shows kind prefix; detail is in Debug.
        assert_eq!(err.to_string(), "error decoding response body");
        assert!(format!("{err:?}").contains("JSON deserialization failed"));
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
        // Message preserved in Debug.
        assert!(format!("{err:?}").contains("fail"));
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

            // Debug: includes "WinHTTP error <code>" for diagnostics
            let debug = format!("{err:?}");
            assert!(
                debug.contains(&format!("WinHTTP error {code}")),
                "{label}: Debug should contain code: {debug}"
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

    /// Source errors stored via `with_source()` are accessible through
    /// the standard `Error::source()` chain and can be downcast.
    #[test]
    fn with_source_downcast() {
        let inner = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe");
        let err = Error::body("read failed").with_source(inner);

        let source = StdError::source(&err).expect("should have source");
        let io_err = source
            .downcast_ref::<std::io::Error>()
            .expect("downcast to io::Error");
        assert_eq!(io_err.kind(), std::io::ErrorKind::BrokenPipe);
    }
}
