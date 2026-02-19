#![doc = include_str!("../README.md")]
#![doc(html_logo_url = "https://raw.githubusercontent.com/talagrand/wrest/main/docs/wrest.png")]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
// The native backend exposes `pub` types that impl non-pub traits (e.g.
// `proxy::ProxyAction`).  This lint does not apply when reqwest provides
// the public surface.
#![cfg_attr(native_winhttp, allow(private_interfaces))]

// ============================================================
// Native WinHTTP backend (Windows, unless `always-reqwest`)
//
// These modules contain the WinHTTP FFI implementation.  On non-Windows
// platforms (or when `always-reqwest` is enabled) none of this code is
// compiled -- reqwest provides every public type instead.
// ============================================================

#[cfg(native_winhttp)]
#[macro_use]
mod tracing;

#[cfg(native_winhttp)]
pub(crate) mod abi;
#[cfg(native_winhttp)]
mod body;
#[cfg(native_winhttp)]
pub(crate) mod callback;
#[cfg(native_winhttp)]
mod client;
#[cfg(native_winhttp)]
mod encoding;
#[cfg(native_winhttp)]
mod error;
/// Proxy configuration types.
#[cfg(native_winhttp)]
pub mod proxy;
/// Redirect policy configuration.
#[cfg(native_winhttp)]
pub mod redirect;
#[cfg(native_winhttp)]
mod request;
#[cfg(native_winhttp)]
mod response;
#[cfg(native_winhttp)]
pub(crate) mod url;
#[cfg(native_winhttp)]
pub(crate) mod util;
#[cfg(native_winhttp)]
pub(crate) mod winhttp;

#[cfg(native_winhttp)]
pub use body::Body;
#[cfg(native_winhttp)]
pub use client::{Client, ClientBuilder};
#[cfg(native_winhttp)]
pub use error::Error;
#[cfg(native_winhttp)]
pub use proxy::{NoProxy, Proxy};
#[cfg(native_winhttp)]
pub use request::{Request, RequestBuilder};
#[cfg(native_winhttp)]
pub use response::Response;
#[cfg(native_winhttp)]
pub use url::{IntoUrl, ParseError, Url};

/// Shortcut method to quickly make a `GET` request.
///
/// Creates a one-shot [`Client`] internally, sends the request, and
/// returns the [`Response`]. This is an `async fn` matching
/// [`reqwest::get`](https://docs.rs/reqwest/latest/reqwest/fn.get.html).
///
/// # Errors
///
/// Returns an error if the client cannot be built or the request fails.
///
/// See also [`Client::get`].
#[cfg(native_winhttp)]
pub async fn get<U: IntoUrl>(url: U) -> crate::Result<Response> {
    Client::builder().build()?.get(url).send().await
}

// ============================================================
// reqwest backend (non-Windows, or `always-reqwest` on Windows)
//
// When the native backend is inactive, every public type is a
// straight re-export from reqwest.  No wrapper types, no shims.
// ============================================================

#[cfg(not(native_winhttp))]
pub use reqwest::{
    Body, Client, ClientBuilder, Error, IntoUrl, NoProxy, Proxy, Request, RequestBuilder, Response,
    Url, get, redirect,
};

/// Proxy configuration types.
#[cfg(not(native_winhttp))]
pub mod proxy {
    pub use reqwest::{NoProxy, Proxy};
}

// ============================================================
// Common re-exports (identical types regardless of backend)
// ============================================================

pub use http::Method;
pub use http::StatusCode;
pub use http::Version;
/// Re-export the `http::header` module for header name constants.
pub use http::header;
pub use http::header::HeaderMap;

pub use bytes::Bytes;
pub use futures_core::Stream;

/// A `Result` alias where the `Err` case is [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_code_re_export() {
        // Verify wrest::StatusCode works as expected
        let ok = StatusCode::OK;
        assert_eq!(ok.as_u16(), 200);
        assert_eq!(ok.as_str(), "200");
        assert_eq!(ok, StatusCode::OK);
        assert_eq!(format!("{ok}"), "200 OK");
        assert!(!ok.is_client_error());
        assert!(!ok.is_server_error());

        let not_found = StatusCode::NOT_FOUND;
        assert!(not_found.is_client_error());
        assert!(!not_found.is_server_error());

        let internal = StatusCode::INTERNAL_SERVER_ERROR;
        assert!(!internal.is_client_error());
        assert!(internal.is_server_error());
    }

    #[test]
    fn version_re_export() {
        // Verify wrest::Version works as expected
        let v11 = Version::HTTP_11;
        let v2 = Version::HTTP_2;
        // These are distinct values
        assert_ne!(v11, v2);
    }

    /// Pin the `Debug` format of `Version` so that log output is stable.
    /// Prevents a future `http` crate version from changing the human-readable
    /// representation that appears in logs and diagnostics.
    #[test]
    fn version_debug_format_pinned() {
        assert_eq!(format!("{:?}", Version::HTTP_11), "HTTP/1.1");
        assert_eq!(format!("{:?}", Version::HTTP_2), "HTTP/2.0");
    }

    #[test]
    fn result_type_alias() {
        // Verify the Result type alias resolves correctly.
        fn returns_result() -> Result<i32> {
            Ok(42)
        }
        assert_eq!(returns_result().unwrap(), 42);
    }

    #[test]
    fn method_re_export() {
        // Verify wrest::Method is available.
        assert_eq!(Method::GET.as_str(), "GET");
        assert_eq!(Method::POST.as_str(), "POST");
        assert_eq!(Method::PUT.as_str(), "PUT");
        assert_eq!(Method::DELETE.as_str(), "DELETE");
        assert_eq!(Method::PATCH.as_str(), "PATCH");
        assert_eq!(Method::HEAD.as_str(), "HEAD");
        assert_eq!(Method::OPTIONS.as_str(), "OPTIONS");
    }

    #[test]
    fn header_module_re_export() {
        // Verify wrest::header module gives access to header name constants.
        assert_eq!(header::CONTENT_TYPE.as_str(), "content-type");
        assert_eq!(header::AUTHORIZATION.as_str(), "authorization");
        assert_eq!(header::USER_AGENT.as_str(), "user-agent");
    }

    #[test]
    fn get_free_function_is_async() {
        // Verify the free function returns a Future (it matches reqwest::get).
        // We cannot actually send without a server, but we can confirm it
        // compiles as an async fn returning Result<Response>.
        fn assert_future<T: std::future::Future>(_f: T) {}
        assert_future(get("https://example.com/test"));
    }

    /// Consolidated smoke test for Debug / Display impls across all public types.
    ///
    /// Each type that implements `Debug` or `Display` gets a format!() call
    /// here so new impls can't regress to uncovered.  Detailed format-pinning
    /// tests (e.g. `error_display_format`, `body_debug_bytes`) live alongside
    /// the types they test; this test only ensures the code *executes*.
    #[test]
    fn fmt_traits_smoke() {
        // -- Client (Debug) --
        let client = Client::builder().build().unwrap();
        let s = format!("{client:?}");
        assert!(s.contains("Client"), "Client debug: {s}");

        // -- Request (Debug) --
        let req = client.get("https://example.com/fmt").build().unwrap();
        let s = format!("{req:?}");
        assert!(s.contains("Request"), "Request debug: {s}");
        assert!(s.contains("GET"), "Request debug should show method: {s}");

        // -- RequestBuilder (Debug) -- valid URL --
        let rb = client.post("https://example.com/rb");
        let s = format!("{rb:?}");
        assert!(s.contains("RequestBuilder"), "RequestBuilder debug: {s}");

        // -- Body (Debug, bytes variant) --
        let body = Body::from("hello");
        let s = format!("{body:?}");
        assert!(s.starts_with("Body"), "Body debug: {s}");

        // -- Body (Debug, stream variant) --
        #[cfg(any(native_winhttp, feature = "stream"))]
        {
            let stream =
                futures_util::stream::iter(vec![Ok::<_, std::io::Error>(bytes::Bytes::from("x"))]);
            let body = Body::wrap_stream(stream);
            let s = format!("{body:?}");
            assert!(s.starts_with("Body"), "Body stream debug: {s}");
        }

        // -- Url (Display + Debug) --
        let url: Url = "https://example.com".parse().unwrap();
        let s = format!("{url}");
        assert!(s.contains("example.com"), "Url display: {s}");
        let s = format!("{url:?}");
        assert!(s.starts_with("Url { "), "Url debug should be struct format: {s}");
        assert!(s.contains("scheme"), "Url debug should contain scheme: {s}");

        // -- Version (Debug) --
        let s = format!("{:?}", Version::HTTP_11);
        assert!(s.contains("HTTP"), "Version debug: {s}");

        // -- redirect::Policy (Debug) --
        let p = redirect::Policy::none();
        let s = format!("{p:?}");
        assert!(s.contains("None"), "Policy debug: {s}");

        // -- StatusCode (Display) --
        let s = format!("{}", StatusCode::OK);
        assert!(s.contains("200"), "StatusCode display: {s}");
    }

    /// Smoke test for Debug / Display on native-only internal types
    /// (`SignalCancelled`, `Error::builder()`) that don't exist when
    /// the reqwest backend is active.
    #[test]
    #[cfg(native_winhttp)]
    fn fmt_traits_smoke_native_only() {
        use crate::callback::SignalCancelled;

        // -- SignalCancelled (Display + Debug) --
        let sc = SignalCancelled;
        let s = format!("{sc}");
        assert!(s.contains("cancelled"), "SignalCancelled display: {s}");
        let s = format!("{sc:?}");
        assert!(s.contains("SignalCancelled"), "SignalCancelled debug: {s}");

        // -- Error (Display + Debug) --
        // Error::builder() is a wrest-internal constructor, not available
        // on the reqwest backend where Error = reqwest::Error.
        let err = Error::builder("test");
        let s = format!("{err}");
        assert!(!s.is_empty(), "Error display: {s}");
        let s = format!("{err:?}");
        assert!(s.contains("Builder"), "Error debug: {s}");
    }
}
