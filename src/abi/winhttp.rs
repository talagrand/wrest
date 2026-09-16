//! WinHTTP session, request, query, and I/O wrappers.

use super::{check_win32_bool, last_win32_error, to_wide};
use crate::Error;
use windows_sys::Win32::{Foundation::GetLastError, Networking::WinHttp::*};

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
pub(crate) fn close_winhttp_handle(handle: RawWinHttpHandle) -> bool {
    // Guard: most WinHTTP functions, including `WinHttpCloseHandle`,
    // trigger a STATUS_ACCESS_VIOLATION when passed a null handle
    // instead of returning an error code.  Always check before calling.
    if handle.is_null() {
        return false;
    }

    unsafe { WinHttpCloseHandle(handle) != 0 }
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
            super::dword_size_of::<u32>(),
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
            super::dword_size_of::<usize>(),
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
            super::dword_size_of::<WINHTTP_PROXY_INFO>(),
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
            super::dword_size_of::<WINHTTP_PROXY_INFO>(),
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
    let mut size = super::dword_size_of::<u32>();
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
    let mut size = super::dword_size_of::<u32>();
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
    const BUF_LEN: usize = 16;
    let mut buf = [0u16; BUF_LEN];
    let mut size = super::dword_size_of::<[u16; BUF_LEN]>();
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
    let wide_len = u32::try_from(wide.len())
        .map_err(|_| Error::request(format!("header line too long ({} chars)", wide.len())))?;
    unsafe {
        check_win32_bool(WinHttpAddRequestHeaders(
            handle,
            wide.as_ptr(),
            wide_len,
            WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE,
        ))
    }
}

/// Remove a single request header by name.
///
/// Calls `WinHttpAddRequestHeaders` with `"<Name>:"` (empty value) and
/// `WINHTTP_ADDREQ_FLAG_REPLACE` only -- per MS docs, REPLACE with an
/// empty value removes the header if present. `ERROR_WINHTTP_HEADER_NOT_FOUND`
/// is treated as success (the header was already absent).
pub(crate) fn winhttp_remove_request_header(
    handle: RawWinHttpHandle,
    name: &str,
) -> Result<(), Error> {
    let header_line = format!("{name}:");
    let wide: Vec<u16> = header_line.encode_utf16().collect();
    let wide_len = u32::try_from(wide.len())
        .map_err(|_| Error::request(format!("header name too long ({} chars)", wide.len())))?;
    let ok = unsafe {
        WinHttpAddRequestHeaders(handle, wide.as_ptr(), wide_len, WINHTTP_ADDREQ_FLAG_REPLACE)
    };
    if ok != 0 {
        return Ok(());
    }
    let code = unsafe { GetLastError() };
    if code == ERROR_WINHTTP_HEADER_NOT_FOUND {
        return Ok(());
    }
    Err(Error::from_win32(code))
}

/// `WinHttpSetCredentials` -- set proxy Basic-auth credentials.
pub(crate) fn winhttp_set_proxy_credentials(
    handle: RawWinHttpHandle,
    username: &str,
    password: &str,
) -> Result<(), Error> {
    let user = to_wide(username);
    let pass = to_wide(password);
    unsafe {
        check_win32_bool(WinHttpSetCredentials(
            handle,
            WINHTTP_AUTH_TARGET_PROXY,
            WINHTTP_AUTH_SCHEME_BASIC,
            user.as_ptr(),
            pass.as_ptr(),
            std::ptr::null_mut(),
        ))
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
///
/// Takes `buf_len` as `usize` and converts at the FFI boundary; any value
/// exceeding `u32::MAX` is capped to `u32::MAX` (WinHTTP would not read
/// more than `DWORD::MAX` in a single call regardless, and read sizes are
/// in practice bounded by the caller's small `BytesMut` spare capacity).
pub(crate) fn winhttp_read_data(
    handle: RawWinHttpHandle,
    buf: *mut std::ffi::c_void,
    buf_len: usize,
) -> Result<(), Error> {
    let buf_len = u32::try_from(buf_len).unwrap_or(u32::MAX);
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
