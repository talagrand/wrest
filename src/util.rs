//! Shared utility functions.
//!
//! Small helpers used across multiple modules. Nothing in this module is
//! WinHTTP-specific or Win32-specific -- these are general-purpose building
//! blocks. Win32 FFI wrappers live in [`abi`](crate::abi).

use crate::Error;

// ---------------------------------------------------------------------------
// Wide-string helpers
// ---------------------------------------------------------------------------

/// Convert a wide-string pointer + length (in `u16` elements) to a Rust
/// `String`.
///
/// Uses [`String::from_utf16`] instead of lossy conversion so that invalid
/// UTF-16 (unpaired surrogates) is surfaced as an error rather than silently
/// replaced with U+FFFD.  In practice WinHTTP only produces well-formed
/// UTF-16 for HTTP(S) URLs, so this path is defensive.
pub(crate) fn wide_to_string(ptr: *const u16, len: u32) -> Result<String, Error> {
    if len == 0 || ptr.is_null() {
        return Ok(String::new());
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
    String::from_utf16(slice)
        .map_err(|_| Error::builder("WinHTTP returned invalid UTF-16 in URL component"))
}

/// Read a null-terminated wide string from a raw pointer + byte length.
///
/// Unlike [`wide_to_string`] this accepts a byte count (not a `u16` count)
/// and uses lossy conversion -- appropriate for WinHTTP callback info buffers
/// where byte length is the convention and partial data is acceptable for
/// diagnostic logging.
///
/// # Safety
///
/// `ptr` must be a valid pointer to at least `byte_len` bytes of `u16` data,
/// or null (returns an empty string).
#[cfg_attr(all(not(feature = "tracing"), not(test)), expect(dead_code))]
pub(crate) unsafe fn wide_to_string_lossy(ptr: *mut std::ffi::c_void, byte_len: u32) -> String {
    if ptr.is_null() || byte_len == 0 {
        return String::new();
    }
    // byte_len is in bytes; each wchar is 2 bytes.
    let wchar_count = (byte_len as usize) / 2;
    let slice = unsafe { std::slice::from_raw_parts(ptr as *const u16, wchar_count) };
    // Trim trailing null if present.
    let slice = match slice.iter().position(|&c| c == 0) {
        Some(pos) => slice.get(..pos).unwrap_or(slice),
        None => slice,
    };
    String::from_utf16_lossy(slice)
}

// ---------------------------------------------------------------------------
// Environment helpers
// ---------------------------------------------------------------------------

/// Read an environment variable, returning `None` for empty or unset values.
pub(crate) fn read_env_var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

// ---------------------------------------------------------------------------
// UTF-16 helpers
// ---------------------------------------------------------------------------

/// Convert a `&[u16]` buffer to a `String`, returning a [`Error::decode`]
/// on invalid UTF-16.
///
/// `context` is included in the error message to indicate the source of the
/// data (e.g. `"UTF-16LE"`, `"ICU produced invalid UTF-16"`).
pub(crate) fn string_from_utf16(buf: &[u16], context: &str) -> Result<String, Error> {
    String::from_utf16(buf).map_err(|e| Error::decode(context).with_source(e))
}

// ---------------------------------------------------------------------------
// Mutex helpers
// ---------------------------------------------------------------------------

/// Lock a [`Mutex`], recovering from poison.
///
/// If the mutex was poisoned (a prior panic occurred while the lock was
/// held), logs a warning, clears the poison flag, and returns the guard
/// anyway.
///
/// # When this is safe
///
/// All `Mutex`es in this crate protect simple `Option<T>` slots whose only
/// operations are `.take()` / `.replace()`.  There is no multi-field
/// invariant that a panicking thread could leave half-updated, so the
/// data behind the lock is always in a valid state.
pub(crate) fn lock_or_clear<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            warn!(
                "Mutex poisoned (prior panic while lock held); \
                 recovering -- protected data is a simple Option<T> slot"
            );
            mutex.clear_poison();
            poisoned.into_inner()
        }
    }
}

// ---------------------------------------------------------------------------
// Latin-1 header-value helpers
// ---------------------------------------------------------------------------

/// Widen raw header-value bytes into a `String` using Latin-1 (ISO 8859-1)
/// identity mapping: byte N becomes U+00NN.
///
/// HTTP header values are opaque octets (RFC 9110 §5.5), but
/// `RequestBuilder` stores them as `(String, String)` pairs so they can
/// be cloned, compared, and logged without carrying raw byte buffers.
/// Latin-1 is the natural encoding for this because every byte 0x00-0xFF
/// maps one-to-one to a Unicode code point, making the round-trip through
/// [`narrow_latin1`] perfectly lossless.
pub(crate) fn widen_latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

/// Narrow a Latin-1-widened string back into raw bytes.
///
/// This is the inverse of [`widen_latin1`]: each `char` is truncated to
/// its low byte.  Every char is guaranteed to be ≤ U+00FF because
/// `widen_latin1` only produces code points in that range.
pub(crate) fn narrow_latin1(s: &str) -> Vec<u8> {
    s.chars()
        .map(|ch| {
            debug_assert!(ch as u32 <= 0xFF, "narrow_latin1 called on non-Latin-1 char");
            ch as u8
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- wide_to_string --

    #[test]
    fn wide_to_string_ok_cases() {
        // (label, data, len, expected)
        let hello: [u16; 5] = [b'H' as u16, b'e' as u16, b'l' as u16, b'l' as u16, b'o' as u16];

        let cases: &[(&str, *const u16, u32, &str)] = &[
            ("null_ptr", std::ptr::null(), 10, ""),
            ("zero_len", hello.as_ptr(), 0, ""),
            ("valid_utf16", hello.as_ptr(), 5, "Hello"),
        ];

        for &(label, ptr, len, expected) in cases {
            let result = wide_to_string(ptr, len).expect(label);
            assert_eq!(result, expected, "wide_to_string {label}");
        }
    }

    #[test]
    fn wide_to_string_unpaired_surrogate() {
        // 0xD800 is a high surrogate without a low surrogate -- invalid UTF-16.
        let data: [u16; 1] = [0xD800];
        let result = wide_to_string(data.as_ptr(), 1);
        assert!(result.is_err(), "unpaired surrogate should be an error");
    }

    // -- wide_to_string_lossy --

    #[test]
    fn wide_to_string_lossy_table() {
        // Build test data that outlives the table references.
        let ab: [u16; 2] = [b'A' as u16, b'B' as u16];
        let ok_null: [u16; 3] = [b'O' as u16, b'K' as u16, 0];

        // (label, ptr, byte_len, expected)
        // SAFETY: all pointers are valid for their byte_len.
        let cases: Vec<(&str, *mut std::ffi::c_void, u32, &str)> = vec![
            ("null_ptr", std::ptr::null_mut(), 10, ""),
            ("zero_len", ab.as_ptr() as *mut std::ffi::c_void, 0, ""),
            (
                "trims_trailing_null",
                ok_null.as_ptr() as *mut std::ffi::c_void,
                6, // 3 u16 = 6 bytes
                "OK",
            ),
            (
                "no_trailing_null",
                ab.as_ptr() as *mut std::ffi::c_void,
                4, // 2 u16 = 4 bytes
                "AB",
            ),
        ];

        for (label, ptr, byte_len, expected) in &cases {
            let result = unsafe { wide_to_string_lossy(*ptr, *byte_len) };
            assert_eq!(result, *expected, "wide_to_string_lossy {label}");
        }
    }

    // -- read_env_var --

    #[test]
    fn read_env_var_unset() {
        assert!(read_env_var("wrest_TEST_NONEXISTENT_VAR_12345").is_none());
    }

    #[test]
    fn lock_or_clear_recovers_from_poison() {
        use std::sync::{Arc, Mutex};

        let mutex = Arc::new(Mutex::new(42_i32));
        let m2 = Arc::clone(&mutex);

        // Poison the mutex by panicking while holding the lock.
        let _ = std::thread::spawn(move || {
            let _guard = m2.lock().unwrap();
            panic!("intentional panic to poison mutex");
        })
        .join();

        // The mutex is now poisoned.
        assert!(mutex.lock().is_err(), "mutex should be poisoned");

        // lock_or_clear recovers and returns a valid guard.
        let guard = lock_or_clear(&mutex);
        assert_eq!(*guard, 42);
        drop(guard);

        // After recovery, the poison flag is cleared.
        assert!(mutex.lock().is_ok(), "poison should be cleared");
    }
}
