//! WinHTTP session, request, query, and I/O wrappers.

use super::{check_win32_bool, last_win32_error, to_wide};

/// Raw handle type used by WinHTTP (`*mut c_void`).
pub(crate) type RawWinHttpHandle = *mut core::ffi::c_void;

/// Map a WinHTTP handle-returning call to `Result`.
fn check_winhttp_handle(handle: RawWinHttpHandle) -> Result<RawWinHttpHandle, Error> {
    if !handle.is_null() {
        Ok(handle)
    } else {
        Err(last_win32_error())
    }
}
use crate::Error;
use crate::util::wide_to_string;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Networking::WinHttp::*;

// ---------------------------------------------------------------------------
// WinHTTP session
// ---------------------------------------------------------------------------

/// `WinHttpOpen` -- create a new WinHTTP session handle.
pub(crate) fn winhttp_open_session(
    user_agent: &str,
    access_type: u32,
    proxy: Option<&str>,
    flags: u32,
) -> Result<RawWinHttpHandle, Error> {
    let ua = to_wide(user_agent);
    let proxy_wide = proxy.map(to_wide);
    let proxy_ptr = proxy_wide.as_ref().map_or(std::ptr::null(), |w| w.as_ptr());
    let h = unsafe { WinHttpOpen(ua.as_ptr(), access_type, proxy_ptr, std::ptr::null(), flags) };
    check_winhttp_handle(h)
}

/// `WinHttpCloseHandle`.
pub(crate) fn close_winhttp_handle(handle: RawWinHttpHandle) {
    // Guard: most WinHTTP functions, including `WinHttpCloseHandle`,
    // trigger a STATUS_ACCESS_VIOLATION when passed a null handle
    // instead of returning an error code.  Always check before calling.
    if !handle.is_null() {
        unsafe {
            WinHttpCloseHandle(handle);
        }
    }
}

/// `WinHttpSetStatusCallback` -- install a status callback on a handle.
///
/// Returns `Err` if WinHTTP returns `WINHTTP_INVALID_STATUS_CALLBACK`
/// (the sentinel function pointer with all bits set).
pub(crate) fn winhttp_set_status_callback(
    handle: RawWinHttpHandle,
    callback: WINHTTP_STATUS_CALLBACK,
    notification_flags: u32,
) -> Result<(), Error> {
    unsafe {
        let prev = WinHttpSetStatusCallback(handle, callback, notification_flags, 0);
        // WINHTTP_INVALID_STATUS_CALLBACK is ((WINHTTP_STATUS_CALLBACK)(-1)) in C.
        // windows-sys represents WINHTTP_STATUS_CALLBACK as Option<fn>,
        // so the sentinel is Some(fn-with-all-bits-set).
        let is_invalid = match prev {
            Some(f) => (f as usize) == usize::MAX,
            None => false,
        };
        if is_invalid {
            Err(super::last_win32_error())
        } else {
            Ok(())
        }
    }
}

/// `WinHttpSetTimeouts`.
pub(crate) fn winhttp_set_timeouts(
    handle: RawWinHttpHandle,
    resolve_ms: i32,
    connect_ms: i32,
    send_ms: i32,
    receive_ms: i32,
) -> Result<(), Error> {
    unsafe {
        check_win32_bool(WinHttpSetTimeouts(handle, resolve_ms, connect_ms, send_ms, receive_ms))
    }
}

// ---------------------------------------------------------------------------
// WinHttpSetOption -- typed helpers
// ---------------------------------------------------------------------------

/// `WinHttpSetOption` with a `u32` value.
pub(crate) fn winhttp_set_option_u32(
    handle: RawWinHttpHandle,
    option: u32,
    value: u32,
) -> Result<(), Error> {
    unsafe {
        check_win32_bool(WinHttpSetOption(
            handle,
            option,
            &value as *const u32 as *const core::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
        ))
    }
}

/// `WinHttpSetOption` with a `usize` value (used for `CONTEXT_VALUE`).
pub(crate) fn winhttp_set_option_usize(
    handle: RawWinHttpHandle,
    option: u32,
    value: usize,
) -> Result<(), Error> {
    unsafe {
        check_win32_bool(WinHttpSetOption(
            handle,
            option,
            &value as *const usize as *const core::ffi::c_void,
            std::mem::size_of::<usize>() as u32,
        ))
    }
}

/// `WinHttpSetOption(WINHTTP_OPTION_PROXY)` -- override to direct (no proxy).
pub(crate) fn winhttp_set_proxy_direct(handle: RawWinHttpHandle) -> Result<(), Error> {
    let info = WINHTTP_PROXY_INFO {
        dwAccessType: WINHTTP_ACCESS_TYPE_NO_PROXY,
        lpszProxy: std::ptr::null_mut(),
        lpszProxyBypass: std::ptr::null_mut(),
    };
    unsafe {
        check_win32_bool(WinHttpSetOption(
            handle,
            WINHTTP_OPTION_PROXY,
            &info as *const WINHTTP_PROXY_INFO as *const core::ffi::c_void,
            std::mem::size_of::<WINHTTP_PROXY_INFO>() as u32,
        ))
    }
}

/// `WinHttpSetOption(WINHTTP_OPTION_PROXY)` -- override to a named proxy.
///
/// Encodes the proxy URL to a null-terminated wide string internally so
/// the raw pointer in `WINHTTP_PROXY_INFO` cannot outlive its backing
/// buffer.
pub(crate) fn winhttp_set_proxy_named(
    handle: RawWinHttpHandle,
    proxy_url: &str,
) -> Result<(), Error> {
    let proxy_wide = to_wide(proxy_url);
    let info = WINHTTP_PROXY_INFO {
        dwAccessType: WINHTTP_ACCESS_TYPE_NAMED_PROXY,
        lpszProxy: proxy_wide.as_ptr() as *mut _,
        lpszProxyBypass: std::ptr::null_mut(),
    };
    unsafe {
        check_win32_bool(WinHttpSetOption(
            handle,
            WINHTTP_OPTION_PROXY,
            &info as *const WINHTTP_PROXY_INFO as *const core::ffi::c_void,
            std::mem::size_of::<WINHTTP_PROXY_INFO>() as u32,
        ))
    }
}

// ---------------------------------------------------------------------------
// WinHttpQueryOption / WinHttpQueryHeaders
// ---------------------------------------------------------------------------

/// `WinHttpQueryOption` reading a `u32` value.
///
/// Returns `None` if the option is not supported or the call fails.
pub(crate) fn winhttp_query_option_u32(handle: RawWinHttpHandle, option: u32) -> Option<u32> {
    let mut value: u32 = 0;
    let mut size = std::mem::size_of::<u32>() as u32;
    let ok =
        unsafe { WinHttpQueryOption(handle, option, &mut value as *mut u32 as *mut _, &mut size) };
    if ok != 0 { Some(value) } else { None }
}

/// `WinHttpQueryOption` reading a wide-string value (e.g. `WINHTTP_OPTION_URL`).
///
/// Uses the two-call pattern: first call queries the required buffer size,
/// second call fills the buffer.  Returns `None` if the option is not
/// supported or the call fails.
pub(crate) fn winhttp_query_option_url(handle: RawWinHttpHandle, option: u32) -> Option<String> {
    let mut size: u32 = 0;

    // First call: query required buffer size (in bytes).
    let ok = unsafe { WinHttpQueryOption(handle, option, std::ptr::null_mut(), &mut size) };
    if ok != 0 || size == 0 {
        // Succeeded with a null buffer or zero size -- unexpected for a URL.
        return None;
    }

    // Any error other than ERROR_INSUFFICIENT_BUFFER is a real failure.
    let err = unsafe { GetLastError() };
    if err != windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER {
        return None;
    }

    let len = size as usize / 2;
    let mut buf = vec![0u16; len];
    let ok = unsafe { WinHttpQueryOption(handle, option, buf.as_mut_ptr() as *mut _, &mut size) };
    if ok == 0 {
        return None;
    }

    let actual_len = size as usize / 2;
    buf.truncate(actual_len);
    // Trim trailing null if present.
    if buf.last() == Some(&0) {
        buf.pop();
    }
    Some(String::from_utf16_lossy(&buf))
}

/// `WinHttpQueryHeaders` reading a numeric value (e.g. status code).
pub(crate) fn winhttp_query_header_u32(
    handle: RawWinHttpHandle,
    info_level: u32,
) -> Result<u32, Error> {
    let mut value: u32 = 0;
    let mut size = std::mem::size_of::<u32>() as u32;
    let mut index: u32 = 0;
    unsafe {
        check_win32_bool(WinHttpQueryHeaders(
            handle,
            info_level,
            std::ptr::null(),
            &mut value as *mut u32 as *mut _,
            &mut size,
            &mut index,
        ))?;
    }
    Ok(value)
}

/// `WinHttpQueryHeaders` reading the raw header block as a `String`.
///
/// Uses the two-call pattern (query size, then fill buffer).
pub(crate) fn winhttp_query_raw_headers(handle: RawWinHttpHandle) -> Result<String, Error> {
    let mut size: u32 = 0;
    let mut index: u32 = 0;

    // First call -- query required buffer size.  Expected to fail with
    // ERROR_INSUFFICIENT_BUFFER and populate `size`.
    let ok = unsafe {
        WinHttpQueryHeaders(
            handle,
            WINHTTP_QUERY_RAW_HEADERS_CRLF,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut size,
            &mut index,
        )
    };

    if ok != 0 {
        // Succeeded with a null buffer -- means there are no headers.
        return Ok(String::new());
    }

    // Any error other than ERROR_INSUFFICIENT_BUFFER is unexpected.
    let err = unsafe { GetLastError() };
    if err != windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER {
        return Err(Error::from_win32(err));
    }

    if size == 0 {
        return Ok(String::new());
    }

    let len = size as usize / 2;
    let mut buf = vec![0u16; len];
    index = 0;

    unsafe {
        check_win32_bool(WinHttpQueryHeaders(
            handle,
            WINHTTP_QUERY_RAW_HEADERS_CRLF,
            std::ptr::null(),
            buf.as_mut_ptr() as *mut _,
            &mut size,
            &mut index,
        ))?;
    }

    // Trim to the actual length returned (may be shorter than the buffer).
    let actual_len = size as usize / 2;
    buf.truncate(actual_len);

    // Lossy conversion is appropriate here: HTTP headers are ASCII per
    // RFC 9110 §5.5, and WinHTTP produces well-formed UTF-16 for them.
    // An unpaired surrogate would require a WinHTTP bug or memory
    // corruption -- U+FFFD replacement is harmless compared to failing
    // the entire response.
    Ok(String::from_utf16_lossy(&buf))
}

/// `WinHttpQueryHeaders` reading a short wide-string value into a
/// fixed-size stack buffer, returned as an `Option<String>`.
pub(crate) fn winhttp_query_header_string(
    handle: RawWinHttpHandle,
    info_level: u32,
) -> Option<String> {
    let mut buf = [0u16; 16];
    let mut size = (buf.len() * 2) as u32;
    let mut index: u32 = 0;
    let ok = unsafe {
        WinHttpQueryHeaders(
            handle,
            info_level,
            std::ptr::null(),
            buf.as_mut_ptr() as *mut _,
            &mut size,
            &mut index,
        )
    };
    if ok != 0 {
        let len = size as usize / 2;
        // Lossy: HTTP headers are ASCII (RFC 9110 §5.5); see
        // `query_raw_headers` for rationale.
        buf.get(..len).map(String::from_utf16_lossy)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Connection / request
// ---------------------------------------------------------------------------

/// `WinHttpConnect` -- open a connection to a server.
pub(crate) fn winhttp_connect(
    session: RawWinHttpHandle,
    host: &str,
    port: u16,
) -> Result<RawWinHttpHandle, Error> {
    let host_wide = to_wide(host);
    let h = unsafe { WinHttpConnect(session, host_wide.as_ptr(), port, 0) };
    check_winhttp_handle(h)
}

/// `WinHttpOpenRequest`.
pub(crate) fn winhttp_open_request(
    connect: RawWinHttpHandle,
    method: &str,
    path: &str,
    secure: bool,
) -> Result<RawWinHttpHandle, Error> {
    let method_wide = to_wide(method);
    let path_wide = to_wide(path);
    let flags = if secure { WINHTTP_FLAG_SECURE } else { 0 };
    let h = unsafe {
        WinHttpOpenRequest(
            connect,
            method_wide.as_ptr(),
            path_wide.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            flags,
        )
    };
    check_winhttp_handle(h)
}

/// `WinHttpAddRequestHeaders` -- append a single header line.
pub(crate) fn winhttp_add_request_header(
    handle: RawWinHttpHandle,
    header_line: &str,
) -> Result<(), Error> {
    let wide: Vec<u16> = header_line.encode_utf16().collect();
    unsafe {
        check_win32_bool(WinHttpAddRequestHeaders(
            handle,
            wide.as_ptr(),
            wide.len() as u32,
            WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE,
        ))
    }
}

/// `WinHttpSetCredentials` -- set proxy Basic-auth credentials.
pub(crate) fn winhttp_set_proxy_credentials(
    handle: RawWinHttpHandle,
    username: &str,
    password: &str,
) {
    let user = to_wide(username);
    let pass = to_wide(password);
    unsafe {
        WinHttpSetCredentials(
            handle,
            WINHTTP_AUTH_TARGET_PROXY,
            WINHTTP_AUTH_SCHEME_BASIC,
            user.as_ptr(),
            pass.as_ptr(),
            std::ptr::null_mut(),
        );
    }
}

// ---------------------------------------------------------------------------
// Async I/O -- send / receive / read / write
// ---------------------------------------------------------------------------

/// `WinHttpSendRequest`.
///
/// `body_ptr` and `body_len` specify optional inline body data.
/// Both are 0 / null when there is no inline body.
pub(crate) fn winhttp_send_request(
    handle: RawWinHttpHandle,
    body_ptr: *const std::ffi::c_void,
    body_len: u32,
    total_content_len: u32,
) -> Result<(), Error> {
    unsafe {
        check_win32_bool(WinHttpSendRequest(
            handle,
            std::ptr::null(),
            0,
            body_ptr,
            body_len,
            total_content_len,
            0,
        ))
    }
}

/// `WinHttpReceiveResponse`.
pub(crate) fn winhttp_receive_response(handle: RawWinHttpHandle) -> Result<(), Error> {
    unsafe { check_win32_bool(WinHttpReceiveResponse(handle, std::ptr::null_mut())) }
}

/// `WinHttpReadData`.
pub(crate) fn winhttp_read_data(
    handle: RawWinHttpHandle,
    buf: *mut std::ffi::c_void,
    buf_len: u32,
) -> Result<(), Error> {
    unsafe { check_win32_bool(WinHttpReadData(handle, buf, buf_len, std::ptr::null_mut())) }
}

/// `WinHttpWriteData`.
pub(crate) fn winhttp_write_data(
    handle: RawWinHttpHandle,
    buf: *const std::ffi::c_void,
    len: u32,
) -> Result<(), Error> {
    unsafe { check_win32_bool(WinHttpWriteData(handle, buf, len, std::ptr::null_mut())) }
}

// ---------------------------------------------------------------------------
// URL parsing
// ---------------------------------------------------------------------------

/// Result of [`winhttp_crack_url`].
#[derive(Debug)]
pub(crate) struct CrackedUrl {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub extra: String,
}

/// `WinHttpCrackUrl` -- parse a URL into its components.
///
/// Accepts the URL *without* a fragment (caller should strip `#...` first).
pub(crate) fn winhttp_crack_url(url: &str) -> Result<CrackedUrl, Error> {
    // Guard: `WinHttpCrackUrl` with `dwUrlLength = 0` triggers a
    // STATUS_ACCESS_VIOLATION inside winhttp.dll rather than returning
    // an error code.  Catch this before calling into the OS.
    if url.is_empty() {
        return Err(Error::builder("invalid URL: (empty)".to_owned()));
    }
    let wide: Vec<u16> = url.encode_utf16().collect();

    let mut scheme_buf = vec![0u16; 16];
    let mut host_buf = vec![0u16; 2048];
    let mut path_buf = vec![0u16; 8192];
    let mut extra_buf = vec![0u16; 8192];

    let mut components = URL_COMPONENTS {
        dwStructSize: std::mem::size_of::<URL_COMPONENTS>() as u32,
        lpszScheme: scheme_buf.as_mut_ptr(),
        dwSchemeLength: scheme_buf.len() as u32,
        lpszHostName: host_buf.as_mut_ptr(),
        dwHostNameLength: host_buf.len() as u32,
        lpszUrlPath: path_buf.as_mut_ptr(),
        dwUrlPathLength: path_buf.len() as u32,
        lpszExtraInfo: extra_buf.as_mut_ptr(),
        dwExtraInfoLength: extra_buf.len() as u32,
        nScheme: 0,
        nPort: 0,
        lpszUserName: std::ptr::null_mut(),
        dwUserNameLength: 0,
        lpszPassword: std::ptr::null_mut(),
        dwPasswordLength: 0,
    };

    unsafe {
        check_win32_bool(WinHttpCrackUrl(
            wide.as_ptr(),
            wide.len() as u32,
            ICU_ESCAPE,
            &mut components,
        ))
        .map_err(|e| Error::builder(format!("invalid URL: {url}")).with_source(e))?;
    }

    Ok(CrackedUrl {
        scheme: wide_to_string(scheme_buf.as_ptr(), components.dwSchemeLength)?,
        host: wide_to_string(host_buf.as_ptr(), components.dwHostNameLength)?,
        port: components.nPort,
        path: wide_to_string(path_buf.as_ptr(), components.dwUrlPathLength)?,
        extra: wide_to_string(extra_buf.as_ptr(), components.dwExtraInfoLength)?,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn winhttp_crack_url_table() {
        let cases: &[(&str, &str, &str, u16, &str, &str, &str)] = &[
            (
                "https://example.com/path?q=1",
                "https",
                "example.com",
                443,
                "/path",
                "?q=1",
                "simple HTTPS",
            ),
            (
                "http://localhost:8080/api/v1",
                "http",
                "localhost",
                8080,
                "/api/v1",
                "",
                "HTTP with port",
            ),
            // WinHTTP returns an empty path when no path component is present.
            (
                "https://example.com",
                "https",
                "example.com",
                443,
                "",
                "",
                "root without trailing slash",
            ),
            ("http://example.com:80/", "http", "example.com", 80, "/", "", "explicit port 80"),
        ];

        for &(url, scheme, host, port, path, extra, label) in cases {
            let result = winhttp_crack_url(url)
                .unwrap_or_else(|e| panic!("winhttp_crack_url({label}): {e}"));
            assert_eq!(result.scheme, scheme, "{label}: scheme");
            assert_eq!(result.host, host, "{label}: host");
            assert_eq!(result.port, port, "{label}: port");
            assert_eq!(result.path, path, "{label}: path");
            assert_eq!(result.extra, extra, "{label}: extra");
        }
    }

    #[test]
    fn winhttp_crack_url_long_query_string() {
        let long_query = "a=".to_owned() + &"x".repeat(4000);
        let url = format!("https://example.com/search?{long_query}");
        let result = winhttp_crack_url(&url).unwrap();
        assert_eq!(result.path, "/search");
        assert!(result.extra.len() > 4000);
    }

    #[test]
    fn winhttp_crack_url_errors_table() {
        let cases: &[(&str, &str, &str)] =
            &[("", "empty", "empty string"), ("not a url at all", "invalid URL", "garbage input")];

        for &(input, needle, label) in cases {
            let err = winhttp_crack_url(input).expect_err(&format!("{label}: should fail"));
            assert!(err.is_builder(), "{label}: expected builder error");
            // Display shows kind prefix; detail text is in Debug.
            let debug = format!("{err:?}");
            assert!(debug.contains(needle), "{label}: expected '{needle}' in debug, got: {debug}");
        }
    }
}
