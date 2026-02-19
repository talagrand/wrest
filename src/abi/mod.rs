//! Thin safe wrappers around Win32 / WinHTTP / ICU FFI calls.
//!
//! Every raw `windows_sys` call used by wrest lives in this module tree.
//! The rest of the crate never touches `unsafe` Win32 FFI directly -- it
//! calls these helpers instead.  Each wrapper:
//!
//! * returns `Result<T, Error>` so callers decide how to handle failures,
//! * performs any `&str` → null-terminated wide string conversions, and
//! * hides pointer arithmetic and `std::mem::size_of` boilerplate.
//!
//! The module is split into:
//!
//! * [`winhttp`] -- WinHTTP session, request, query, and I/O wrappers
//! * [`encoding`] -- `MultiByteToWideChar` (NLS) and ICU charset decoding

mod encoding;
mod winhttp;

// Re-export everything so callers use `crate::abi::winhttp_open_session` etc.
pub(crate) use encoding::*;
pub(crate) use winhttp::*;

use crate::Error;
use windows_sys::Win32::Foundation::GetLastError;

// ---------------------------------------------------------------------------
// Low-level result helpers
// ---------------------------------------------------------------------------

/// Build an [`Error`] from the calling thread's last Win32 error.
fn last_win32_error() -> Error {
    let code = unsafe { GetLastError() };
    Error::from_win32(code)
}

/// Map a Win32 `BOOL` (`i32`) return value to `Result`.
fn check_win32_bool(result: i32) -> Result<(), Error> {
    if result != 0 {
        Ok(())
    } else {
        Err(last_win32_error())
    }
}

// ---------------------------------------------------------------------------
// Wide-string helpers
// ---------------------------------------------------------------------------

/// Encode a Rust `&str` as a null-terminated UTF-16 wide string.
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_wide_table() {
        let cases: &[(&str, &[u16], &str)] = &[
            ("", &[0], "empty"),
            ("abc", &[b'a' as u16, b'b' as u16, b'c' as u16, 0], "ascii"),
            ("\u{1F600}", &[0xD83D, 0xDE00, 0], "non-BMP surrogate pair"),
        ];

        for &(input, expected, label) in cases {
            let result = to_wide(input);
            assert_eq!(result, expected, "to_wide: {label}");
        }
    }
}
