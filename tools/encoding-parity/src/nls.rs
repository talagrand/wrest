use crate::score::{Reference, Stats};
use ::windows::Win32::{
    Foundation::{GetLastError, SetLastError, WIN32_ERROR},
    Globalization::{MULTI_BYTE_TO_WIDE_CHAR_FLAGS, MultiByteToWideChar},
};

pub fn score_nls(codepage: u32, rows: &[(Vec<u8>, Reference)], limit: usize) -> Stats {
    let mut stats = Stats::new(limit);
    for (data, expected) in rows {
        let mut output = vec![0_u16; data.len() * 3 + 16];
        // A zero-length result is a failed conversion even when Windows leaves
        // GetLastError at zero (notably for some ISO-2022-JP inputs).
        let length = unsafe {
            SetLastError(WIN32_ERROR(0));
            MultiByteToWideChar(codepage, MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0), data, Some(&mut output))
        };
        if length == 0 {
            stats.add(data, expected, None, unsafe { GetLastError().0 });
        } else {
            assert!(
                length > 0 && (length as usize) <= output.len(),
                "Win32 output buffer overflow"
            );
            let decoded = String::from_utf16(&output[..length as usize])
                .expect("Win32 produced invalid UTF-16");
            let points = decoded.chars().map(u32::from).collect::<Vec<_>>();
            stats.add(data, expected, Some(&points), 0);
        }
    }
    stats
}
