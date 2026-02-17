#![doc = include_str!("../README.md")]
#![doc(html_logo_url = "https://raw.githubusercontent.com/talagrand/wrest/main/docs/wrest.png")]
#![cfg(windows)]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(private_interfaces)]

// Tracing shims -- must be first so the macros are visible to all modules.
#[macro_use]
mod tracing;

pub(crate) mod abi;
mod body;
pub(crate) mod callback;
mod client;
mod encoding;
mod error;
/// Proxy configuration types.
pub mod proxy;
/// Redirect policy configuration.
pub mod redirect;
mod request;
mod response;
pub(crate) mod url;
pub(crate) mod util;
pub(crate) mod winhttp;

// -- Public re-exports --

pub use body::Body;
pub use client::{Client, ClientBuilder};
pub use error::Error;
pub use proxy::{NoProxy, Proxy};
pub use request::{Request, RequestBuilder};
pub use response::Response;
pub use url::{IntoUrl, Url};

// Re-export ecosystem standard types.
pub use bytes::Bytes;
pub use futures_core::Stream;
pub use http::Method;
pub use http::StatusCode;
pub use http::Version;
pub use http::header::HeaderMap;

/// Re-export the `http::header` module for header name constants.
pub use http::header;

/// A `Result` alias where the `Err` case is [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

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
pub async fn get<U: IntoUrl>(url: U) -> crate::Result<Response> {
    Client::builder().build()?.get(url).send().await
}

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

    /// Consolidated smoke test for Debug / Display impls across all types.
    ///
    /// Each type that implements `Debug` or `Display` gets a format!() call
    /// here so new impls can't regress to uncovered.  Detailed format-pinning
    /// tests (e.g. `error_display_format`, `body_debug_bytes`) live alongside
    /// the types they test; this test only ensures the code *executes*.
    #[test]
    fn fmt_traits_smoke() {
        use crate::callback::SignalCancelled;

        // -- Client (Debug) --
        let client = Client::builder().build().unwrap();
        let s = format!("{client:?}");
        assert!(s.contains("Client"), "Client debug: {s}");

        // -- Request (Debug) --
        let req = client.get("https://example.com/fmt").build().unwrap();
        let s = format!("{req:?}");
        assert!(s.contains("Request"), "Request debug: {s}");
        assert!(s.contains("GET"), "Request debug should show method: {s}");

        // -- RequestBuilder (Debug) — valid URL --
        let rb = client.post("https://example.com/rb");
        let s = format!("{rb:?}");
        assert!(s.contains("RequestBuilder"), "RequestBuilder debug: {s}");

        // -- SignalCancelled (Display + Debug) --
        let sc = SignalCancelled;
        let s = format!("{sc}");
        assert!(s.contains("cancelled"), "SignalCancelled display: {s}");
        let s = format!("{sc:?}");
        assert!(s.contains("SignalCancelled"), "SignalCancelled debug: {s}");

        // -- Body (Debug, bytes variant) --
        let body = Body::from("hello");
        let s = format!("{body:?}");
        assert!(s.contains("Body"), "Body debug: {s}");

        // -- Body (Debug, stream variant) --
        let stream =
            futures_util::stream::iter(vec![Ok::<_, std::io::Error>(bytes::Bytes::from("x"))]);
        let body = Body::wrap_stream(stream);
        let s = format!("{body:?}");
        assert!(s.contains("stream"), "Body stream debug: {s}");

        // -- Error (Display + Debug) --
        let err = Error::builder("test");
        let s = format!("{err}");
        assert!(!s.is_empty(), "Error display: {s}");
        let s = format!("{err:?}");
        assert!(s.contains("Builder"), "Error debug: {s}");

        // -- Url (Display + Debug) --
        let url = "https://example.com".into_url().unwrap();
        let s = format!("{url}");
        assert!(s.contains("example.com"), "Url display: {s}");
        let s = format!("{url:?}");
        assert!(s.contains("Url("), "Url debug: {s}");

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
}
