//! Error type for wrest.
//!
//! Provides [`Error`] with query methods compatible with `reqwest::Error`:
//! [`is_builder()`](Error::is_builder), [`is_connect()`](Error::is_connect),
//! [`is_timeout()`](Error::is_timeout), [`is_request()`](Error::is_request),
//! [`is_body()`](Error::is_body), [`is_status()`](Error::is_status),
//! [`status()`](Error::status), and [`url()`](Error::url).

use crate::abi::hresult_from_win32;
use crate::url::Url;
use http::StatusCode;
use std::fmt;
use windows_sys::Win32::Networking::WinHttp::*;

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
    pub(crate) source: Option<Box<dyn std::error::Error + Send + Sync>>,
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
    #[expect(dead_code, reason = "API compat: WinHTTP handles protocol upgrades")]
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

    /// Create an error from an HRESULT code.
    ///
    /// The HRESULT is classified into an [`ErrorKind`] and formatted into
    /// the error message.  Callers typically produce the HRESULT via
    /// [`hresult_from_win32`](crate::abi::hresult_from_win32).
    pub(crate) fn from_hresult(hresult: i32) -> Self {
        let kind = error_kind_from_hresult(hresult);
        let message = format!("WinHTTP error (HRESULT 0x{hresult:08X})");
        Self {
            kind,
            message,
            source: None,
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
    /// ` for url (...)` when the URL is known.  The detail message
    /// is available via the `Debug` representation.
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

/// Map an HRESULT to an [`ErrorKind`].
///
/// The HRESULT is produced by [`hresult_from_win32`](crate::abi::hresult_from_win32)
/// from a raw Win32 / WinHTTP error code. This is the **single** place in
/// the crate that classifies WinHTTP failures into [`ErrorKind`] variants.
fn error_kind_from_hresult(hresult: i32) -> ErrorKind {
    // WinHTTP error codes are u32 constants. Convert to HRESULT for comparison.
    match hresult {
        c if c == hresult_from_win32(ERROR_WINHTTP_CANNOT_CONNECT) => ErrorKind::Connect,
        c if c == hresult_from_win32(ERROR_WINHTTP_NAME_NOT_RESOLVED) => ErrorKind::Connect,
        c if c == hresult_from_win32(ERROR_WINHTTP_CONNECTION_ERROR) => ErrorKind::Connect,
        c if c == hresult_from_win32(ERROR_WINHTTP_SECURE_FAILURE) => ErrorKind::Connect,
        c if c == hresult_from_win32(ERROR_WINHTTP_TIMEOUT) => ErrorKind::Timeout,
        c if c == hresult_from_win32(ERROR_WINHTTP_REDIRECT_FAILED) => ErrorKind::Redirect,
        _ => ErrorKind::Request,
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

    #[test]
    fn error_query_methods() {
        let connect_err = Error::builder("test");
        assert!(!connect_err.is_connect());
        assert!(!connect_err.is_timeout());
        assert!(!connect_err.is_status());
        assert!(connect_err.status().is_none());
        assert!(connect_err.url().is_none());

        let url = "https://example.com/missing".into_url().unwrap();
        let status_err = Error {
            kind: ErrorKind::Status,
            message: "404".into(),
            source: None,
            status: Some(StatusCode::NOT_FOUND),
            url: Some(Box::new(url)),
        };
        assert!(status_err.is_status());
        assert_eq!(status_err.status(), Some(StatusCode::NOT_FOUND));
        assert_eq!(status_err.url().map(|u| u.as_str()), Some("https://example.com/missing"));
    }

    /// Each `ErrorKind` has exactly one `is_*` query method that returns
    /// `true`; all other `is_*` methods return `false`.
    #[test]
    fn error_kind_exclusivity_table() {
        // (error, label, check) -- one entry per ErrorKind.
        // The table itself doubles as the cross-check matrix: for each
        // error we call every other entry's function pointer and verify
        // only the designated one fires.
        #[expect(clippy::type_complexity)]
        let cases: &[(Error, &str, fn(&Error) -> bool)] = &[
            (Error::builder("b"), "builder", Error::is_builder),
            (Error::request("r"), "request", Error::is_request),
            (Error::timeout("t"), "timeout", Error::is_timeout),
            (Error::body("d"), "body", Error::is_body),
            (Error::decode("d"), "decode", Error::is_decode),
            (
                Error {
                    kind: ErrorKind::Connect,
                    message: "c".into(),
                    source: None,
                    status: None,
                    url: None,
                },
                "connect",
                Error::is_connect,
            ),
            (
                Error {
                    kind: ErrorKind::Status,
                    message: "s".into(),
                    source: None,
                    status: Some(StatusCode::IM_A_TEAPOT),
                    url: None,
                },
                "status",
                Error::is_status,
            ),
            (
                Error {
                    kind: ErrorKind::Redirect,
                    message: "r".into(),
                    source: None,
                    status: None,
                    url: None,
                },
                "redirect",
                Error::is_redirect,
            ),
        ];

        for (err, label, check) in cases {
            assert!(check(err), "{label}: own is_*() should be true");

            // Cross-check: every *other* entry's function pointer must
            // return false for this error.
            for (_, other_label, other_check) in cases {
                if *other_label != *label {
                    assert!(!other_check(err), "{label}: is_{other_label}() should be false");
                }
            }
        }
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
        let err = Error {
            kind: ErrorKind::Body,
            message: "read failed".into(),
            source: Some(Box::new(inner)),
            status: None,
            url: None,
        };
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

    // -- HRESULT classification via from_hresult --

    /// Each WinHTTP error code produces the expected ErrorKind.
    #[test]
    fn hresult_classification_table() {
        use crate::abi::hresult_from_win32;

        #[expect(clippy::type_complexity)]
        let cases: &[(u32, &str, fn(&Error) -> bool)] = &[
            (ERROR_WINHTTP_CANNOT_CONNECT, "connect", Error::is_connect),
            (ERROR_WINHTTP_NAME_NOT_RESOLVED, "connect (dns)", Error::is_connect),
            (ERROR_WINHTTP_CONNECTION_ERROR, "connect (conn)", Error::is_connect),
            (ERROR_WINHTTP_SECURE_FAILURE, "connect (tls)", Error::is_connect),
            (ERROR_WINHTTP_TIMEOUT, "timeout", Error::is_timeout),
            (ERROR_WINHTTP_REDIRECT_FAILED, "redirect", Error::is_redirect),
        ];

        for &(code, label, check) in cases {
            let err = Error::from_hresult(hresult_from_win32(code));
            assert!(check(&err), "{label}: expected is_*() to be true");
        }
    }

    /// An unknown HRESULT falls through to ErrorKind::Request.
    #[test]
    fn hresult_unknown_maps_to_request() {
        // Use an arbitrary HRESULT that is not a known WinHTTP code.
        let err = Error::from_hresult(0x8007_FFFF_u32 as i32);
        assert!(err.is_request(), "unknown HRESULT should map to request");
        assert!(!err.is_connect());
        assert!(!err.is_timeout());
    }

    /// from_hresult stores the HRESULT hex value in the message field
    /// (visible via Debug), while Display shows the kind-based prefix.
    #[test]
    fn from_hresult_message_format() {
        use crate::abi::hresult_from_win32;
        let hr = hresult_from_win32(ERROR_WINHTTP_TIMEOUT);
        let err = Error::from_hresult(hr);
        // Display: kind-based prefix
        assert_eq!(err.to_string(), "operation timed out");
        // Debug: includes the HRESULT detail for diagnostics
        let debug = format!("{err:?}");
        assert!(debug.contains("HRESULT"), "debug should contain HRESULT: {debug}");
        assert!(debug.contains(&format!("{hr:08X}")), "debug should contain hex value: {debug}");
    }

    // NOTE: REDIRECT_FAILED → is_redirect() is already covered by the
    // "redirect" row in `hresult_classification_table` above.
}
