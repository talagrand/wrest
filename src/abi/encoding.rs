//! Charset decoding FFI -- Win32 NLS (`MultiByteToWideChar`) and ICU.
//!
//! This module provides two charset decoding paths:
//!
//! * [`multi_byte_to_string`] -- thin wrapper around
//!   [`MultiByteToWideChar`](windows_sys::Win32::Globalization::MultiByteToWideChar)
//!   for the 30 WHATWG encodings whose Windows code pages exist in the
//!   NLS subsystem.
//!
//! * [`icu_decode`] -- dynamic-loading fallback through `icu.dll`
//!   (Windows 10 1903+) for three WHATWG encodings whose code pages are
//!   absent from NLS: ISO-8859-10 (CP 28600), ISO-8859-14 (CP 28604),
//!   and EUC-JP (CP 51932).
//!
//! # Why not ISO-8859-16?
//!
//! Although `icu.dll` knows the *name* ISO-8859-16 (the alias table
//! `cnvalias.icu` has six aliases), the converter *data* file
//! (`iso-8859_16-2001.ucm`) was excluded from ICU's upstream build.
//! `ucnv_open("ISO-8859-16")` resolves the name but returns
//! `U_FILE_ACCESS_ERROR` because no `.cnv` data was compiled in.
//! Microsoft also removed all data-loading APIs (`u_setDataDirectory`,
//! `udata_setCommonData`, etc.) from the DLL's export table, so the
//! converter data cannot be supplied at runtime.  ISO-8859-16 is
//! instead decoded via a compile-time Rust lookup table in
//! [`crate::encoding`].

use std::sync::OnceLock;

use crate::Error;
use windows_sys::Win32::Globalization::MultiByteToWideChar;

// ===========================================================================
// NLS: MultiByteToWideChar
// ===========================================================================

/// `MultiByteToWideChar` -- decode a byte slice in a given Windows code page
/// to a Rust `String`.
///
/// Two allocations are unavoidable: one for the intermediate UTF-16 buffer
/// (`Vec<u16>`) and one for the final UTF-8 `String`.  `from_utf16` must
/// transcode every code unit, so there is no way to hand the `Vec`'s
/// memory directly to the `String`.
pub(crate) fn multi_byte_to_string(codepage: u32, data: &[u8]) -> Result<String, Error> {
    unsafe {
        // First call: query the required buffer length (in u16 elements).
        let len = MultiByteToWideChar(
            codepage,
            0,
            data.as_ptr(),
            data.len() as i32,
            std::ptr::null_mut(),
            0,
        );
        if len <= 0 {
            return Err(Error::decode(format!(
                "MultiByteToWideChar failed for code page {codepage}"
            )));
        }

        // Allocate exactly `len` u16 elements -- no zero-init needed since
        // MultiByteToWideChar will fill them.
        let mut buf: Vec<u16> = Vec::with_capacity(len as usize);
        let written = MultiByteToWideChar(
            codepage,
            0,
            data.as_ptr(),
            data.len() as i32,
            buf.as_mut_ptr(),
            len,
        );
        if written <= 0 {
            return Err(Error::decode(format!(
                "MultiByteToWideChar failed for code page {codepage}"
            )));
        }
        buf.set_len(written as usize);

        crate::util::string_from_utf16(&buf, "UTF-16 conversion failed")
    }
}

// ===========================================================================
// ICU: dynamic ucnv_* fallback
// ===========================================================================

// ---------------------------------------------------------------------------
// ICU error-code constants
// ---------------------------------------------------------------------------

/// `U_ZERO_ERROR` -- success.  Negative values are warnings (still OK);
/// positive values are errors.
const U_ZERO_ERROR: i32 = 0;

// ---------------------------------------------------------------------------
// Function-pointer types (matching ICU4C's public C ABI)
// ---------------------------------------------------------------------------
//
// On x86_64 Windows the `extern "C"` and `extern "system"` calling
// conventions are identical (both use the Microsoft x64 ABI), so
// transmuting `FARPROC` (`extern "system"`) to these `extern "C"`
// pointers is sound.

/// `UConverter *ucnv_open(const char *converterName, UErrorCode *err);`
type UcnvOpenFn = unsafe extern "C" fn(name: *const u8, err: *mut i32) -> *mut core::ffi::c_void;

/// `int32_t ucnv_toUChars(UConverter *cnv, UChar *dest, int32_t destCapacity,
///                         const char *src, int32_t srcLength, UErrorCode *err);`
type UcnvToUCharsFn = unsafe extern "C" fn(
    cnv: *mut core::ffi::c_void,
    dest: *mut u16,
    dest_capacity: i32,
    src: *const u8,
    src_length: i32,
    err: *mut i32,
) -> i32;

/// `void ucnv_close(UConverter *converter);`
type UcnvCloseFn = unsafe extern "C" fn(cnv: *mut core::ffi::c_void);

// ---------------------------------------------------------------------------
// Lazily-loaded function table
// ---------------------------------------------------------------------------

/// Resolved function pointers into `icu.dll`.
struct IcuFunctions {
    ucnv_open: UcnvOpenFn,
    ucnv_to_u_chars: UcnvToUCharsFn,
    ucnv_close: UcnvCloseFn,
}

/// Cached ICU function table.  `None` if `icu.dll` or any required export
/// could not be resolved -- this is permanent for the process lifetime.
static ICU: OnceLock<Option<IcuFunctions>> = OnceLock::new();

// ---------------------------------------------------------------------------
// Dynamic loading
// ---------------------------------------------------------------------------

/// Attempt to load `icu.dll` and resolve the three `ucnv_*` exports.
///
/// Called exactly once via [`OnceLock`].  Returns `None` if any step fails.
fn load_icu() -> Option<IcuFunctions> {
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;

    // "icu.dll\0" as null-terminated UTF-16.
    let dll_name: [u16; 8] = [
        b'i' as u16,
        b'c' as u16,
        b'u' as u16,
        b'.' as u16,
        b'd' as u16,
        b'l' as u16,
        b'l' as u16,
        0,
    ];
    let h = unsafe { LoadLibraryW(dll_name.as_ptr()) };
    if h.is_null() {
        return None;
    }

    // Resolve each function by name.  Microsoft's `icu.dll` exports
    // unversioned symbols (e.g. `ucnv_open`, not `ucnv_open_72`),
    // and appcompat policy guarantees these names are stable.
    let open = get_proc(h, b"ucnv_open\0")?;
    let to_u_chars = get_proc(h, b"ucnv_toUChars\0")?;
    let close = get_proc(h, b"ucnv_close\0")?;

    // SAFETY: on x86_64 Windows `extern "C"` == `extern "system"` (both
    // use the Microsoft x64 calling convention).  The transmuted
    // signatures match ICU4C's stable public C API.
    Some(IcuFunctions {
        ucnv_open: unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, UcnvOpenFn>(open)
        },
        ucnv_to_u_chars: unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, UcnvToUCharsFn>(to_u_chars)
        },
        ucnv_close: unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, UcnvCloseFn>(close)
        },
    })
}

/// Look up a single NUL-terminated export name via `GetProcAddress`.
fn get_proc(
    h: *mut core::ffi::c_void,
    name: &[u8], // e.g. b"ucnv_open\0"
) -> Option<unsafe extern "system" fn() -> isize> {
    use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
    unsafe { GetProcAddress(h, name.as_ptr()) }
}

// ---------------------------------------------------------------------------
// Public ICU API
// ---------------------------------------------------------------------------

/// Returns `true` if `icu.dll` could be loaded and all required exports
/// were resolved.
#[cfg(test)]
pub(crate) fn is_icu_available() -> bool {
    ICU.get_or_init(load_icu).is_some()
}

/// Decode `data` using the named ICU converter.
///
/// # Errors
///
/// Returns `Err` if:
/// * `icu.dll` is not available (pre-1903 Windows)
/// * `ucnv_open` rejects the converter name (e.g. ISO-8859-16)
/// * The conversion itself fails
pub(crate) fn icu_decode(converter_name: &str, data: &[u8]) -> Result<String, Error> {
    if data.is_empty() {
        return Ok(String::new());
    }

    let icu = ICU.get_or_init(load_icu).as_ref().ok_or_else(|| {
        Error::decode(format!("charset \"{converter_name}\" requires icu.dll (Windows 10 1903+)"))
    })?;

    // Null-terminate the converter name for ICU's C API.
    let mut name_buf = Vec::with_capacity(converter_name.len() + 1);
    name_buf.extend_from_slice(converter_name.as_bytes());
    name_buf.push(0);

    // Open the converter.
    let mut open_err = U_ZERO_ERROR;
    let cnv = unsafe { (icu.ucnv_open)(name_buf.as_ptr(), &mut open_err) };
    if open_err > U_ZERO_ERROR || cnv.is_null() {
        return Err(Error::decode(format!(
            "ICU cannot open converter \"{converter_name}\" (error code {open_err})"
        )));
    }

    // RAII guard: ensure `ucnv_close` is called even on early return.
    struct CnvGuard {
        cnv: *mut core::ffi::c_void,
        close: UcnvCloseFn,
    }
    impl Drop for CnvGuard {
        fn drop(&mut self) {
            unsafe { (self.close)(self.cnv) };
        }
    }
    let _guard = CnvGuard {
        cnv,
        close: icu.ucnv_close,
    };

    // Output buffer.  For ISO-8859-* the output is exactly 1 UChar per
    // input byte; for EUC-JP the output is *fewer* UChars than input
    // bytes (multi-byte sequences collapse).  So `data.len()` UChars
    // is always sufficient.  Add 1 for the NUL terminator ICU writes.
    let capacity = data.len() + 1;
    let mut buf: Vec<u16> = vec![0u16; capacity];

    let mut conv_err = U_ZERO_ERROR;
    let written = unsafe {
        (icu.ucnv_to_u_chars)(
            cnv,
            buf.as_mut_ptr(),
            capacity as i32,
            data.as_ptr(),
            data.len() as i32,
            &mut conv_err,
        )
    };

    if conv_err > U_ZERO_ERROR {
        return Err(Error::decode(format!(
            "ICU conversion failed for \"{converter_name}\" (error code {conv_err})"
        )));
    }

    let len = written.max(0) as usize;
    buf.truncate(len);

    crate::util::string_from_utf16(&buf, "ICU produced invalid UTF-16")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- NLS tests --

    #[test]
    fn multi_byte_to_string_table() {
        let cases: &[(u32, &[u8], &str, &str)] = &[
            (65001, b"hello world", "hello world", "UTF-8 ASCII"),
            (1252, &[0xE9], "\u{e9}", "Windows-1252 e-acute"),
        ];

        for &(codepage, data, expected, label) in cases {
            let result = multi_byte_to_string(codepage, data)
                .unwrap_or_else(|e| panic!("multi_byte_to_string({label}): {e}"));
            assert_eq!(result, expected, "{label}");
        }
    }

    #[test]
    fn multi_byte_to_string_errors_table() {
        let cases: &[(u32, &[u8], &str)] =
            &[(99999, b"hello", "invalid code page"), (65001, b"", "empty input")];

        for &(codepage, data, label) in cases {
            assert!(multi_byte_to_string(codepage, data).is_err(), "{label}: should fail");
        }
    }

    // -- ICU tests --

    #[test]
    fn load_icu_does_not_panic() {
        // Even if icu.dll is absent, load_icu should return None, not panic.
        let _ = load_icu();
    }

    #[test]
    fn icu_decode_table() {
        if !is_icu_available() {
            eprintln!("skipping: icu.dll not available");
            return;
        }

        let cases: &[(&str, &[u8], &str, &str)] = &[
            // (converter, input bytes, expected output, label)
            ("ISO-8859-10", &[0xA1, 0xA2], "\u{0104}\u{0112}", "ISO-8859-10 Ą Ē"),
            ("ISO-8859-14", &[0xA1, 0xD0], "\u{1E02}\u{0174}", "ISO-8859-14 Ḃ Ŵ"),
            ("EUC-JP", &[0xA4, 0xA2], "\u{3042}", "EUC-JP あ"),
            (
                "EUC-JP",
                &[0xC6, 0xFC, 0xCB, 0xDC, 0xB8, 0xEC],
                "\u{65E5}\u{672C}\u{8A9E}",
                "EUC-JP 日本語",
            ),
            ("EUC-JP", &[0x41, 0xA4, 0xA2], "A\u{3042}", "EUC-JP mixed ASCII"),
        ];

        for &(converter, data, expected, label) in cases {
            let result =
                icu_decode(converter, data).unwrap_or_else(|e| panic!("icu_decode({label}): {e}"));
            assert_eq!(result, expected, "{label}");
        }
    }

    #[test]
    fn icu_decode_errors_table() {
        if !is_icu_available() {
            eprintln!("skipping: icu.dll not available");
            return;
        }

        let cases: &[(&str, &[u8], &str)] = &[
            // (converter, input, label)
            ("ISO-8859-16", &[0xA1], "ISO-8859-16 data stripped from icu.dll"),
            ("totally-bogus-encoding", &[0x41], "bogus converter name"),
        ];

        for &(converter, data, label) in cases {
            assert!(icu_decode(converter, data).is_err(), "{label}: should fail");
        }
    }

    #[test]
    fn icu_decode_empty_input() {
        // Empty data returns Ok("") without touching ICU -- works even
        // if icu.dll is absent.
        let result = icu_decode("ISO-8859-10", &[]).expect("empty");
        assert_eq!(result, "");
    }
}
