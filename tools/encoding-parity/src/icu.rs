use crate::score::{Reference, Stats, StopCounts};
use ::windows::{
    Win32::Globalization::{
        U_FILE_ACCESS_ERROR, U_ZERO_ERROR, UCNV_TO_U_CALLBACK_STOP, UConverter,
        UConverterCallbackReason, UConverterToUnicodeArgs, UErrorCode, u_getVersion, ucnv_close,
        ucnv_countAliases, ucnv_countAvailable, ucnv_getAlias, ucnv_getAvailableName, ucnv_getName,
        ucnv_open, ucnv_setToUCallBack, ucnv_toUChars,
    },
    core::PCSTR,
};
use serde::Serialize;
use std::{
    ffi::{CString, c_void},
    ptr::{null, null_mut},
};

pub fn icu_version() -> String {
    let mut version = [0_u8; 4];
    unsafe { u_getVersion(version.as_mut_ptr()) };
    version.map(|number| number.to_string()).join(".")
}

struct Converter(*mut UConverter);

impl Drop for Converter {
    fn drop(&mut self) {
        unsafe { ucnv_close(self.0) };
    }
}

#[derive(Serialize)]
pub struct Alias {
    pub catalog: String,
    pub alias: String,
    pub resolved: String,
}

fn icu_name(raw: PCSTR) -> String {
    assert!(!raw.is_null(), "ICU returned a null converter name");
    unsafe {
        raw.to_string()
            .expect("ICU returned an invalid converter name")
    }
}

pub fn available_names() -> Vec<String> {
    let count = unsafe { ucnv_countAvailable() };
    assert!(count >= 0, "ucnv_countAvailable failed: {count}");
    (0..count)
        .map(|index| icu_name(unsafe { ucnv_getAvailableName(index) }))
        .collect()
}

pub fn registered_aliases() -> Vec<Alias> {
    let mut aliases = Vec::new();
    for catalog in available_names() {
        let name = CString::new(catalog.as_str()).expect("ICU catalog name contains NUL");
        let mut code = U_ZERO_ERROR;
        let count = unsafe { ucnv_countAliases(PCSTR(name.as_ptr().cast()), &mut code) };
        assert!(code.0 <= 0, "ucnv_countAliases failed for {catalog}: {}", code.0);
        for index in 0..count {
            code = U_ZERO_ERROR;
            let raw = unsafe { ucnv_getAlias(PCSTR(name.as_ptr().cast()), index, &mut code) };
            assert!(code.0 <= 0, "ucnv_getAlias failed for {catalog}: {}", code.0);
            let alias = icu_name(raw);
            let converter = open(&alias).expect("registered ICU alias is unavailable");
            aliases.push(Alias {
                catalog: catalog.clone(),
                alias,
                resolved: canonical(&converter),
            });
        }
    }
    aliases
}

fn open(name: &str) -> Option<Converter> {
    let name = CString::new(name).expect("ICU name contains NUL");
    let mut code = U_ZERO_ERROR;
    let handle = unsafe { ucnv_open(PCSTR(name.as_ptr().cast()), &mut code) };
    if code == U_FILE_ACCESS_ERROR {
        if !handle.is_null() {
            unsafe { ucnv_close(handle) };
        }
        return None;
    }
    assert!(!handle.is_null() && code.0 <= 0, "ucnv_open failed: {}", code.0);
    Some(Converter(handle))
}

fn canonical(converter: &Converter) -> String {
    let mut code = U_ZERO_ERROR;
    let raw = unsafe { ucnv_getName(converter.0, &mut code) };
    assert!(code.0 <= 0, "ucnv_getName failed: {}", code.0);
    icu_name(raw)
}

// The generated STOP wrapper is a Rust function, not the C callback pointer ICU expects.
unsafe extern "system" fn stop_on_error(
    context: *const c_void,
    args: *mut UConverterToUnicodeArgs,
    codeunits: PCSTR,
    length: i32,
    reason: UConverterCallbackReason,
    error: *mut UErrorCode,
) {
    unsafe { UCNV_TO_U_CALLBACK_STOP(context, args, codeunits, length, reason, error) };
}

fn decode(converter: &Converter, data: &[u8]) -> (Option<Vec<u32>>, u32) {
    let mut output = vec![0_u16; data.len() * 3 + 16];
    let mut code = U_ZERO_ERROR;
    let length = unsafe {
        ucnv_toUChars(
            converter.0,
            output.as_mut_ptr(),
            output.len() as i32,
            PCSTR(data.as_ptr()),
            data.len() as i32,
            &mut code,
        )
    };
    if code.0 > 0 {
        return (None, code.0 as u32);
    }
    assert!(length >= 0 && (length as usize) <= output.len(), "ICU output buffer overflow");
    let decoded =
        String::from_utf16(&output[..length as usize]).expect("ICU produced invalid UTF-16");
    (Some(decoded.chars().map(u32::from).collect()), 0)
}

pub fn score_icu(
    name: &str,
    rows: &[(Vec<u8>, Reference)],
    limit: usize,
) -> Option<(String, Stats)> {
    let converter = open(name)?;
    let stopped = open(name).expect("ICU STOP converter became unavailable");
    let mut code = U_ZERO_ERROR;
    unsafe {
        ucnv_setToUCallBack(stopped.0, Some(stop_on_error), null(), null_mut(), null(), &mut code)
    };
    assert!(code.0 <= 0, "ucnv_setToUCallBack failed: {}", code.0);
    let resolved = canonical(&converter);
    let mut stats = Stats::new(limit);
    stats.icu_stop_wrong = Some(StopCounts::default());
    for (data, expected) in rows {
        let (actual, error) = decode(&converter, data);
        if actual
            .as_deref()
            .is_some_and(|output| output != expected.codepoints)
        {
            let (_, stop_error) = decode(&stopped, data);
            stats.classify_icu_mismatch(stop_error != 0);
        }
        stats.add(data, expected, actual.as_deref(), error);
    }
    Some((resolved, stats))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::score::oracle;

    #[test]
    fn installed_catalog_and_stop_diagnosis() {
        let names = available_names();
        assert!(!names.is_empty());
        let aliases = registered_aliases();
        assert!(aliases.iter().any(|entry| entry.catalog != entry.resolved));

        let bytes = b"\x82\"".to_vec();
        let rows = [(bytes.clone(), oracle("shift_jis", &bytes))];
        let (_, reported) = score_icu("Shift_JIS", &rows, 0).unwrap();
        assert_eq!((reported.invalid, reported.invalid_match, reported.failed_invalid), (1, 0, 0));
        let stop = reported.icu_stop_wrong.unwrap();
        assert_eq!((stop.reported_error, stop.accepted), (1, 0));

        let bytes = b"\x81\x41".to_vec();
        let rows = [(bytes.clone(), oracle("euc-kr", &bytes))];
        let (_, accepted) = score_icu("EUC-KR", &rows, 0).unwrap();
        assert_eq!((accepted.valid, accepted.valid_match, accepted.failed_valid), (1, 0, 0));
        let stop = accepted.icu_stop_wrong.unwrap();
        assert_eq!((stop.reported_error, stop.accepted), (0, 1));
    }
}
