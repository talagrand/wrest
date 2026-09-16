//! Lazy access to the UTS #46 IDNA APIs exported by Windows system ICU.

use std::sync::OnceLock;
use windows_sys::{
    Win32::Globalization::{
        U_BUFFER_OVERFLOW_ERROR, U_ZERO_ERROR, UErrorCode, UIDNA, UIDNA_CHECK_BIDI,
        UIDNA_CHECK_CONTEXTJ, UIDNA_ERROR_DOMAIN_NAME_TOO_LONG, UIDNA_ERROR_HYPHEN_3_4,
        UIDNA_ERROR_LABEL_TOO_LONG, UIDNA_ERROR_LEADING_HYPHEN, UIDNA_ERROR_TRAILING_HYPHEN,
        UIDNA_NONTRANSITIONAL_TO_ASCII, UIDNAInfo,
    },
    core::{PCSTR, PSTR},
};

const UTS46_OPTIONS: u32 =
    (UIDNA_CHECK_BIDI | UIDNA_CHECK_CONTEXTJ | UIDNA_NONTRANSITIONAL_TO_ASCII).cast_unsigned();
/// Errors tolerated by Wrest's URL-host policy:
/// `CheckHyphens=false` and `VerifyDnsLength=false`.
const TOLERATED_UTS46_ERRORS: u32 = (UIDNA_ERROR_LABEL_TOO_LONG
    | UIDNA_ERROR_DOMAIN_NAME_TOO_LONG
    | UIDNA_ERROR_LEADING_HYPHEN
    | UIDNA_ERROR_TRAILING_HYPHEN
    | UIDNA_ERROR_HYPHEN_3_4)
    .cast_unsigned();

type UidnaOpenUts46Fn =
    unsafe extern "C" fn(options: u32, error_code: *mut UErrorCode) -> *mut UIDNA;
type UidnaNameToAsciiUtf8Fn = unsafe extern "C" fn(
    idna: *const UIDNA,
    name: PCSTR,
    length: i32,
    dest: PSTR,
    capacity: i32,
    info: *mut UIDNAInfo,
    error_code: *mut UErrorCode,
) -> i32;
type UidnaCloseFn = unsafe extern "C" fn(idna: *mut UIDNA);

fn uidna_info() -> UIDNAInfo {
    UIDNAInfo {
        size: i16::try_from(std::mem::size_of::<UIDNAInfo>())
            .expect("UIDNAInfo size fits in int16_t"),
        isTransitionalDifferent: 0,
        reservedB3: 0,
        errors: 0,
        reservedI2: 0,
        reservedI3: 0,
    }
}

fn has_rejected_uts46_errors(info: &UIDNAInfo) -> bool {
    info.errors & !TOLERATED_UTS46_ERRORS != 0
}

struct IcuIdnaFunctions {
    open_uts46: UidnaOpenUts46Fn,
    name_to_ascii_utf8: UidnaNameToAsciiUtf8Fn,
    close: UidnaCloseFn,
}

static ICU_IDNA: OnceLock<Option<IcuIdnaFunctions>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IcuIdnaError {
    Unavailable,
    InvalidName,
}

#[cfg(test)]
pub(crate) fn is_icu_idna_available() -> bool {
    ICU_IDNA.get_or_init(load_icu_idna).is_some()
}

fn load_icu_idna() -> Option<IcuIdnaFunctions> {
    super::load_icu_exports(|module| {
        // SAFETY: Each type alias matches its ICU C declaration.
        let (Some(open_uts46), Some(name_to_ascii_utf8), Some(close)) = (unsafe {
            (
                super::get_proc_address::<UidnaOpenUts46Fn>(module, c"uidna_openUTS46"),
                super::get_proc_address::<UidnaNameToAsciiUtf8Fn>(
                    module,
                    c"uidna_nameToASCII_UTF8",
                ),
                super::get_proc_address::<UidnaCloseFn>(module, c"uidna_close"),
            )
        }) else {
            return None;
        };

        Some(IcuIdnaFunctions {
            open_uts46,
            name_to_ascii_utf8,
            close,
        })
    })
}

pub(crate) fn idna_to_ascii(name: &str) -> Result<String, IcuIdnaError> {
    let functions = ICU_IDNA
        .get_or_init(load_icu_idna)
        .as_ref()
        .ok_or(IcuIdnaError::Unavailable)?;
    let length = i32::try_from(name.len()).map_err(|_| IcuIdnaError::InvalidName)?;

    let mut error_code = U_ZERO_ERROR;
    let idna = unsafe { (functions.open_uts46)(UTS46_OPTIONS, &mut error_code) };
    if error_code > U_ZERO_ERROR || idna.is_null() {
        return Err(IcuIdnaError::InvalidName);
    }

    let idna = scopeguard::guard(idna, |idna| unsafe {
        (functions.close)(idna);
    });

    let mut info = uidna_info();
    let required = unsafe {
        (functions.name_to_ascii_utf8)(
            *idna,
            name.as_ptr(),
            length,
            std::ptr::null_mut(),
            0,
            &mut info,
            &mut error_code,
        )
    };
    if required < 0
        || (error_code > U_ZERO_ERROR && error_code != U_BUFFER_OVERFLOW_ERROR)
        || has_rejected_uts46_errors(&info)
    {
        return Err(IcuIdnaError::InvalidName);
    }

    let capacity = usize::try_from(required).map_err(|_| IcuIdnaError::InvalidName)?;
    let mut output = vec![0u8; capacity];
    error_code = U_ZERO_ERROR;
    info = uidna_info();
    let written = unsafe {
        (functions.name_to_ascii_utf8)(
            *idna,
            name.as_ptr(),
            length,
            output.as_mut_ptr(),
            required,
            &mut info,
            &mut error_code,
        )
    };
    if error_code > U_ZERO_ERROR || has_rejected_uts46_errors(&info) || written != required {
        return Err(IcuIdnaError::InvalidName);
    }

    String::from_utf8(output).map_err(|_| IcuIdnaError::InvalidName)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uidna_info_matches_icu_abi() {
        assert_eq!(std::mem::size_of::<UIDNAInfo>(), 16);
    }

    #[test]
    fn uts46_name_to_ascii_table() {
        if ICU_IDNA.get_or_init(load_icu_idna).is_some() {
            let cases = [
                ("faß.de", Ok("xn--fa-hia.de")),
                ("café.fr", Ok("xn--caf-dma.fr")),
                ("-é.fr", Ok("xn----bga.fr")),
                ("faß.de.", Ok("xn--fa-hia.de.")),
                ("café..fr", Err(IcuIdnaError::InvalidName)),
            ];
            for (input, expected) in cases {
                let actual = idna_to_ascii(input);
                match expected {
                    Ok(expected) => assert_eq!(actual.as_deref(), Ok(expected), "{input}"),
                    Err(expected) => assert_eq!(actual.unwrap_err(), expected, "{input}"),
                }
            }
        }
    }
}
