//! WHATWG Encoding Standard charset decoding.
//!
//! All 39 encodings mandated by the [WHATWG Encoding Standard][spec] are
//! supported:
//!
//! * **5 in Rust** -- UTF-8, UTF-16LE/BE, x-user-defined, and ISO-8859-16.
//!   The `replacement` pseudo-encoding is also handled in Rust, but is not
//!   counted among the 39.
//!
//! * **3 requiring ICU** -- ISO-8859-10 (Latin-6 / Nordic), ISO-8859-14
//!   (Latin-8 / Celtic), and EUC-JP (Extended Unix Code for Japanese)
//!   are absent from the Win32 NLS subsystem (see
//!   [below](#why-three-encodings-need-icu)).  On Windows 10 1903+ they
//!   are decoded at runtime through the system-bundled `icu.dll`.  On
//!   older builds, content labelled with these charsets will produce a
//!   decode error from [`Response::text()`](crate::Response::text).
//!
//! * **15 preferring ICU, with NLS fallback** -- system ICU more closely
//!   follows WHATWG for selected single-byte and CJK encodings. A missing
//!   ICU library falls back to [`MultiByteToWideChar`]; a conversion error
//!   does not.
//!
//! * **16 via NLS** -- NLS is at least as close as the available ICU
//!   converter on the measured inputs.
//!
//! ISO-8859-16 (Latin-10) is absent from both NLS and system ICU; its Rust
//! path uses a compile-time 128-entry WHATWG table.
//!
//! # Why three encodings need ICU
//!
//! | WHATWG encoding | Windows CP | Why no NLS |
//! |-----------------|------------|------------|
//! | **ISO-8859-10** (Latin-6 / Nordic) | 28600 | No NLS file -- absent from `HKLM\...\Nls\CodePage`, not enumerated by `EnumSystemCodePages`. |
//! | **ISO-8859-14** (Latin-8 / Celtic) | 28604 | Same -- Microsoft never shipped an NLS implementation. |
//! | **EUC-JP** (Extended Unix Code for Japanese) | 51932 | Listed in the [Code Page Identifiers] table but implemented only in .NET managed code. `IsValidCodePage(51932)` returns `FALSE`. Windows ships CP 20932 (JIS X 0208-1990 + 0212-1990) at the native API level, but its repertoire differs from WHATWG's EUC-JP. |
//!
//! **ISO-8859-16** (Latin-10 / South-Eastern European, CP 28606) is also
//! absent from both NLS *and* ICU, but is decoded via a compile-time
//! pure-Rust lookup table -- no runtime dependency required.
//!
//! ## Why not language packs?
//!
//! Installing Windows language packs (Settings → Language) adds UI
//! translations, fonts, and input methods -- **not** NLS code-page conversion
//! tables.  The [`IsValidCodePage`] docs state:
//!
//! > *"Starting with Windows Vista, all code pages that can be installed are
//! > loaded by default."*
//!
//! Because these three code pages do not appear in `EnumSystemCodePages`
//! (neither `CP_INSTALLED` nor `CP_SUPPORTED`), they **cannot** be
//! installed on any Windows edition.  This is a platform-level omission, not
//! a per-machine configuration issue.
//!
//! [spec]: https://encoding.spec.whatwg.org/
//! [Code Page Identifiers]: https://learn.microsoft.com/windows/win32/intl/code-page-identifiers
//! [`IsValidCodePage`]: https://learn.microsoft.com/windows/win32/api/winnls/nf-winnls-isvalidcodepage
//! [`MultiByteToWideChar`]: https://learn.microsoft.com/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar
//!
//! Label-to-code-page mapping follows the WHATWG Encoding Standard exactly,
//! including the deliberate aliasing of `ascii` / `iso-8859-1` → windows-1252.
//!
//! Reference: <https://encoding.spec.whatwg.org/>
//! Canonical label list: <https://encoding.spec.whatwg.org/encodings.json>

use crate::{Error, abi};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Decode `data` according to the WHATWG charset `label`.
///
/// * **UTF-8** labels use `String::from_utf8` for valid input and
///   `String::from_utf8_lossy` for WHATWG-compatible U+FFFD replacement
///   of malformed bytes, without calling NLS.
/// * **UTF-16LE/BE** follow WHATWG replacement behavior for malformed
///   surrogates and incomplete bytes.
/// * Unknown labels silently fall back to UTF-8.
/// * The `replacement` encoding (used by the spec to error-out certain
///   legacy labels) returns `U+FFFD` for any input.
pub(crate) fn decode_body(data: &[u8], charset: &str) -> Result<String, Error> {
    if data.is_empty() {
        return Ok(String::new());
    }

    // A BOM overrides the declared label
    // FF FE 00 00 is UTF-32LE's BOM, which WHATWG decodes as UTF-16LE.
    let (data, label) = match data {
        [0xEF, 0xBB, 0xBF, rest @ ..] => (rest, String::from("utf-8")),
        [0xFF, 0xFE, rest @ ..] => (rest, String::from("utf-16le")),
        [0xFE, 0xFF, rest @ ..] => (rest, String::from("utf-16be")),
        _ => (data, normalize_label(charset)),
    };

    // -- UTF-8 fast path ----------------------------------------------
    if is_utf8_label(&label) {
        trace!(label = charset, "charset: UTF-8 fast path");
        return Ok(match String::from_utf8(data.to_vec()) {
            Ok(s) => s,
            Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
        });
    }

    // -- Look up WHATWG label -> Windows code page ---------------------
    let Some(codepage) = whatwg_label_to_codepage(&label) else {
        // Unknown label -> fall back to UTF-8 lossy (matches reqwest)
        warn!(label = charset, "unknown charset label, falling back to UTF-8");
        return Ok(match String::from_utf8(data.to_vec()) {
            Ok(s) => s,
            Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
        });
    };

    // -- Special decodings --------------------------------------------
    match codepage {
        CP_X_USER_DEFINED => return Ok(decode_x_user_defined(data)),
        CP_REPLACEMENT => return Ok(String::from('\u{FFFD}')),
        CP_UTF16_LE => return Ok(decode_utf16(data, u16::from_le_bytes)),
        CP_UTF16_BE => return Ok(decode_utf16(data, u16::from_be_bytes)),
        CP_ISO_8859_16 => return Ok(decode_iso_8859_16(data)),
        _ => {}
    }

    match codepage_backend(codepage) {
        Some(CodepageBackend::IcuRequired(icu_name)) => {
            trace!(label = charset, codepage, icu = icu_name, "charset: required ICU decode");
            abi::icu_decode(icu_name, data)
        }
        Some(CodepageBackend::IcuPreferred(icu_name)) => {
            trace!(label = charset, codepage, icu = icu_name, "charset: preferred ICU decode");
            decode_icu_preferred(
                codepage,
                icu_name,
                data,
                abi::icu_decode_if_available,
                abi::multi_byte_to_string,
            )
        }
        Some(CodepageBackend::Nls) => {
            trace!(label = charset, codepage, "charset: NLS codepage decode");
            abi::multi_byte_to_string(codepage, data)
        }
        None => Err(Error::decode(format!("no charset decoder for code page {codepage}"))),
    }
}

// ---------------------------------------------------------------------------
// Sentinel code-page values (not real Windows CPs)
// ---------------------------------------------------------------------------

/// x-user-defined: 0x00-0x7F as ASCII, 0x80-0xFF -> U+F780-U+F7FF.
const CP_X_USER_DEFINED: u32 = 0;
/// "replacement" encoding: always yields a single U+FFFD.
const CP_REPLACEMENT: u32 = u32::MAX;
/// UTF-16LE: handled in Rust (MultiByteToWideChar does not support CP 1200).
const CP_UTF16_LE: u32 = 1200;
/// UTF-16BE: handled in Rust (MultiByteToWideChar does not support CP 1201).
const CP_UTF16_BE: u32 = 1201;
/// ISO-8859-16: absent from both NLS and ICU; decoded via pure-Rust table.
const CP_ISO_8859_16: u32 = 28606;

#[derive(Debug, PartialEq, Eq)]
enum CodepageBackend {
    IcuRequired(&'static str),
    IcuPreferred(&'static str),
    Nls,
}

// The checked-in tools/encoding-parity/ probe compares complete decoded
// strings from NLS (MultiByteToWideChar with flags 0) and system ICU against
// the WHATWG decoder (https://encoding.spec.whatwg.org/) via encoding_rs.
// It covers single bytes, CJK pair and GB four-byte grids, state boundaries,
// malformed input, and seeded streams; see its README for corpus details.
// Select the backend with the better valid-input mappings, then compare
// invalid-input recovery. Prefer NLS when ICU offers no improvement or
// regresses valid input.
//
// Scores below count inputs whose entire output matches the WHATWG oracle,
// split by whether that input was valid. They describe the named probe
// groups on the installed NLS/ICU data, not arbitrary streams or an
// ICU-preferred route when it falls back to NLS.
fn codepage_backend(codepage: u32) -> Option<CodepageBackend> {
    Some(match codepage {
        // ISO-8859-10: no NLS page; ICU matches all 256 single bytes.
        28600 => CodepageBackend::IcuRequired("ISO-8859-10"),
        // ISO-8859-14: no NLS page; ICU matches all 256 single bytes.
        28604 => CodepageBackend::IcuRequired("ISO-8859-14"),
        // EUC-JP: no NLS page. ICU matches 7,336/7,336 valid A1..FE pairs
        // and all valid SS2/SS3 inputs, but only 4/193 invalid SS2 inputs;
        // malformed-input recovery differs from WHATWG.
        51932 => CodepageBackend::IcuRequired("EUC-JP"),

        // ISO-8859-3: both match 249/249 valid bytes; ICU matches 7/7
        // invalid bytes vs NLS 0/7.
        28593 => CodepageBackend::IcuPreferred("ISO-8859-3"),
        // ISO-8859-6: both match 211/211 valid bytes; ICU matches 45/45
        // invalid bytes vs NLS 0/45.
        28596 => CodepageBackend::IcuPreferred("ISO-8859-6"),
        // ISO-8859-7: ICU matches 253/253 valid and 3/3 invalid bytes;
        // NLS matches 248/253 valid and 0/3 invalid bytes.
        28597 => CodepageBackend::IcuPreferred("ISO-8859-7"),
        // ISO-8859-8: ICU matches 220/220 valid and 36/36 invalid bytes;
        // NLS matches 217/220 valid and 0/36 invalid bytes.
        28598 => CodepageBackend::IcuPreferred("ISO-8859-8"),
        // ISO-8859-8-I: same WHATWG index and ICU scores as ISO-8859-8;
        // NLS CP38598 also matches only 217/220 valid, 0/36 invalid.
        38598 => CodepageBackend::IcuPreferred("ISO-8859-8"),
        // macintosh: ICU matches 256/256 valid bytes vs NLS 255/256;
        // NLS maps BD to U+2126 instead of WHATWG U+03A9.
        10000 => CodepageBackend::IcuPreferred("macintosh"),
        // windows-1253: both match 253/253 valid bytes; ICU matches
        // 2/3 invalid bytes vs NLS 0/3.
        1253 => CodepageBackend::IcuPreferred("windows-1253"),
        // windows-1257: both match 254/254 valid bytes; ICU matches
        // 2/2 invalid bytes vs NLS 0/2.
        1257 => CodepageBackend::IcuPreferred("windows-1257"),
        // x-mac-cyrillic: ICU matches 256/256 valid bytes vs NLS 255/256;
        // NLS maps FF to a currency sign instead of WHATWG euro.
        10017 => CodepageBackend::IcuPreferred("x-mac-cyrillic"),
        // GBK uses the WHATWG gb18030 decoder, not ICU's "GBK" table.
        // On valid pairs ICU gb18030 matches 23,921/23,940 vs NLS
        // CP936 23,839/23,940; ICU misses 19 pairs and the valid 80/euro
        // singleton, which NLS gets right.
        936 => CodepageBackend::IcuPreferred("gb18030"),
        // gb18030: ICU matches 23,921/23,940 valid pairs vs NLS CP54936
        // 23,920/23,940. On the complete four-byte grid ICU matches
        // 1,087,996/1,087,996 valid and 499,604/499,604 invalid pointers;
        // NLS matches 1,087,995 valid and no invalid pointers. ICU still
        // misdecodes 19 assigned pairs and the valid 80/euro singleton.
        54936 => CodepageBackend::IcuPreferred("gb18030"),
        // Big5: ICU Big5-HKSCS matches 18,433/18,594 valid pairs vs
        // NLS CP950 13,502/18,594, and 416/1,188 invalid pairs vs
        // NLS 0/1,188. Neither handles the four special two-scalar
        // WHATWG mappings included in the valid-pair count.
        950 => CodepageBackend::IcuPreferred("Big5-HKSCS"),
        // EUC-KR includes UHC extensions: ICU "windows-949" matches
        // 17,048/17,048 valid pairs vs NLS CP51949 8,225/17,048 and
        // ICU "EUC-KR" 8,224/17,048. ICU windows-949 matches 2,498/6,892
        // invalid pairs vs NLS 0/6,892; recovery is still incomplete.
        51949 => CodepageBackend::IcuPreferred("windows-949"),
        // IBM866: NLS matches 256/256 valid bytes vs ICU 253/256;
        // ICU misdecodes three assigned control bytes.
        866 => CodepageBackend::Nls,
        // ISO-8859-2: NLS matches all 256 single bytes.
        28592 => CodepageBackend::Nls,
        // ISO-8859-4: NLS matches all 256 single bytes.
        28594 => CodepageBackend::Nls,
        // ISO-8859-5: NLS matches all 256 single bytes.
        28595 => CodepageBackend::Nls,
        // ISO-8859-13: NLS matches all 256 single bytes.
        28603 => CodepageBackend::Nls,
        // ISO-8859-15: NLS matches all 256 single bytes.
        28605 => CodepageBackend::Nls,
        // KOI8-R: NLS matches all 256 single bytes.
        20866 => CodepageBackend::Nls,
        // KOI8-U: NLS matches 256/256 valid bytes vs ICU 254/256.
        21866 => CodepageBackend::Nls,
        // windows-874: both ICU "ibm-1162" and NLS match 248/248 valid
        // bytes, but ICU matches 8/8 invalid vs NLS 0/8. The probe's
        // two-byte grid and seeded streams also match through ibm-1162.
        874 => CodepageBackend::IcuPreferred("ibm-1162"),
        // windows-1250: NLS matches all 256 single bytes.
        1250 => CodepageBackend::Nls,
        // windows-1251: NLS matches all 256 single bytes.
        1251 => CodepageBackend::Nls,
        // windows-1252: NLS matches all 256 single bytes. WHATWG aliases
        // latin1 and ascii labels here, not to ISO-8859-1 or 7-bit ASCII.
        1252 => CodepageBackend::Nls,
        // windows-1254: NLS matches all 256 single bytes.
        1254 => CodepageBackend::Nls,
        // windows-1255: NLS matches 246/246 valid bytes vs ICU 245/246;
        // ICU matches 10/10 invalid bytes vs NLS 0/10, but loses the
        // assigned CA -> U+05BA mapping. // spellchecker:disable-line
        1255 => CodepageBackend::Nls,
        // windows-1256: NLS matches all 256 single bytes.
        1256 => CodepageBackend::Nls,
        // windows-1258: NLS matches all 256 single bytes.
        1258 => CodepageBackend::Nls,
        // ISO-2022-JP: ICU matches 7,336/7,336 valid JIS0208-1983
        // inputs vs NLS CP50220 6,946/7,336; for the escape-prefix
        // grid ICU matches 65,261/65,533 invalid vs NLS 0/65,533.
        // ICU still accepts some malformed escapes (e.g. Q ESC ( H Z)
        // without WHATWG's replacement character.
        50220 => CodepageBackend::IcuPreferred("ISO-2022-JP"),
        // Shift_JIS: both match 9,604/9,604 valid pairs, but NLS
        // matches 192/192 valid singletons vs ICU 188/192. ICU matches
        // 1,184/1,676 invalid pairs vs NLS 0/1,676; retain the
        // correct assigned-byte mappings despite worse recovery.
        932 => CodepageBackend::Nls,
        _ => return None,
    })
}

fn decode_icu_preferred(
    codepage: u32,
    icu_name: &str,
    data: &[u8],
    try_icu: impl FnOnce(&str, &[u8]) -> Result<Option<String>, Error>,
    decode_nls: impl FnOnce(u32, &[u8]) -> Result<String, Error>,
) -> Result<String, Error> {
    match try_icu(icu_name, data)? {
        Some(decoded) => Ok(decoded),
        None => {
            warn!(codepage, icu = icu_name, "ICU unavailable; using NLS charset decoder");
            decode_nls(codepage, data)
        }
    }
}

// ---------------------------------------------------------------------------
// Label helpers
// ---------------------------------------------------------------------------

/// Normalize a charset label per the WHATWG spec: strip ASCII whitespace,
/// lowercase.
fn normalize_label(label: &str) -> String {
    label
        .trim_matches(|c: char| c.is_ascii_whitespace())
        .to_ascii_lowercase()
}

/// True for labels that the WHATWG spec maps to UTF-8.
fn is_utf8_label(label: &str) -> bool {
    matches!(
        label,
        "utf-8"
            | "utf8"
            | "unicode-1-1-utf-8"
            | "unicode11utf8"
            | "unicode20utf8"
            | "x-unicode20utf8"
    )
}

// ---------------------------------------------------------------------------
// WHATWG label -> Windows code page
// ---------------------------------------------------------------------------

/// Maps every WHATWG Encoding Standard label to a Windows code page.
///
/// Labels are expected to be already ASCII-lowercased and trimmed.
/// Returns `None` for unrecognized labels.
fn whatwg_label_to_codepage(label: &str) -> Option<u32> {
    Some(match label {
        // -- UTF-8 ----------------------------------------------------
        "unicode-1-1-utf-8" | "unicode11utf8" | "unicode20utf8" | "utf-8" | "utf8"
        | "x-unicode20utf8" => 65001,

        // -- Legacy single-byte encodings -----------------------------

        // IBM866
        "866" | "cp866" | "csibm866" | "ibm866" => 866,

        // ISO-8859-2
        "csisolatin2" | "iso-8859-2" | "iso-ir-101" | "iso8859-2" | "iso88592" | "iso_8859-2"
        | "iso_8859-2:1987" | "l2" | "latin2" => 28592,

        // ISO-8859-3
        "csisolatin3" | "iso-8859-3" | "iso-ir-109" | "iso8859-3" | "iso88593" | "iso_8859-3"
        | "iso_8859-3:1988" | "l3" | "latin3" => 28593,

        // ISO-8859-4
        "csisolatin4" | "iso-8859-4" | "iso-ir-110" | "iso8859-4" | "iso88594" | "iso_8859-4"
        | "iso_8859-4:1988" | "l4" | "latin4" => 28594,

        // ISO-8859-5
        "csisolatincyrillic" | "cyrillic" | "iso-8859-5" | "iso-ir-144" | "iso8859-5"
        | "iso88595" | "iso_8859-5" | "iso_8859-5:1988" => 28595,

        // ISO-8859-6
        "arabic" | "asmo-708" | "csiso88596e" | "csiso88596i" | "csisolatinarabic" | "ecma-114"
        | "iso-8859-6" | "iso-8859-6-e" | "iso-8859-6-i" | "iso-ir-127" | "iso8859-6"
        | "iso88596" | "iso_8859-6" | "iso_8859-6:1987" => 28596,

        // ISO-8859-7
        "csisolatingreek" | "ecma-118" | "elot_928" | "greek" | "greek8" | "iso-8859-7"
        | "iso-ir-126" | "iso8859-7" | "iso88597" | "iso_8859-7" | "iso_8859-7:1987"
        | "sun_eu_greek" => 28597,

        // ISO-8859-8
        "csiso88598e" | "csisolatinhebrew" | "hebrew" | "iso-8859-8" | "iso-8859-8-e"
        | "iso-ir-138" | "iso8859-8" | "iso88598" | "iso_8859-8" | "iso_8859-8:1988" | "visual" => {
            28598
        }

        // ISO-8859-8-I
        "csiso88598i" | "iso-8859-8-i" | "logical" => 38598,

        // ISO-8859-10
        "csisolatin6" | "iso-8859-10" | "iso-ir-157" | "iso8859-10" | "iso885910" | "l6"
        | "latin6" => 28600,

        // ISO-8859-13
        "iso-8859-13" | "iso8859-13" | "iso885913" => 28603,

        // ISO-8859-14
        "iso-8859-14" | "iso8859-14" | "iso885914" => 28604,

        // ISO-8859-15
        "csisolatin9" | "iso-8859-15" | "iso8859-15" | "iso885915" | "iso_8859-15" | "l9" => 28605,

        // ISO-8859-16
        "iso-8859-16" => 28606,

        // KOI8-R
        "cskoi8r" | "koi" | "koi8" | "koi8-r" | "koi8_r" => 20866,

        // KOI8-U
        "koi8-ru" | "koi8-u" => 21866,

        // macintosh
        "csmacintosh" | "mac" | "macintosh" | "x-mac-roman" => 10000,

        // windows-874 (also TIS-620, ISO-8859-11)
        "dos-874" | "iso-8859-11" | "iso8859-11" | "iso885911" | "tis-620" | "windows-874" => 874,

        // windows-1250
        "cp1250" | "windows-1250" | "x-cp1250" => 1250,

        // windows-1251
        "cp1251" | "windows-1251" | "x-cp1251" => 1251,

        // windows-1252 -- WHATWG maps ascii / iso-8859-1 / latin1 here
        "ansi_x3.4-1968" | "ascii" | "cp1252" | "cp819" | "csisolatin1" | "ibm819"
        | "iso-8859-1" | "iso-ir-100" | "iso8859-1" | "iso88591" | "iso_8859-1"
        | "iso_8859-1:1987" | "l1" | "latin1" | "us-ascii" | "windows-1252" | "x-cp1252" => 1252,

        // windows-1253
        "cp1253" | "windows-1253" | "x-cp1253" => 1253,

        // windows-1254 (also ISO-8859-9)
        "cp1254" | "csisolatin5" | "iso-8859-9" | "iso-ir-148" | "iso8859-9" | "iso88599"
        | "iso_8859-9" | "iso_8859-9:1989" | "l5" | "latin5" | "windows-1254" | "x-cp1254" => 1254,

        // windows-1255
        "cp1255" | "windows-1255" | "x-cp1255" => 1255,

        // windows-1256
        "cp1256" | "windows-1256" | "x-cp1256" => 1256,

        // windows-1257
        "cp1257" | "windows-1257" | "x-cp1257" => 1257,

        // windows-1258
        "cp1258" | "windows-1258" | "x-cp1258" => 1258,

        // x-mac-cyrillic
        "x-mac-cyrillic" | "x-mac-ukrainian" => 10017,

        // -- Legacy multi-byte CJK ------------------------------------

        // GBK (includes gb2312)
        "chinese" | "csgb2312" | "csiso58gb231280" | "gb2312" | "gb_2312" | "gb_2312-80"
        | "gbk" | "iso-ir-58" | "x-gbk" => 936,

        // gb18030
        "gb18030" => 54936,

        // Big5
        "big5" | "big5-hkscs" | "cn-big5" | "csbig5" | "x-x-big5" => 950,

        // EUC-JP
        "cseucpkdfmtjapanese" | "euc-jp" | "x-euc-jp" => 51932,

        // ISO-2022-JP
        "csiso2022jp" | "iso-2022-jp" => 50220,

        // Shift_JIS
        "csshiftjis" | "ms932" | "ms_kanji" | "shift-jis" | "shift_jis" | "sjis"
        | "windows-31j" | "x-sjis" => 932,

        // EUC-KR
        "cseuckr" | "csksc56011987" | "euc-kr" | "iso-ir-149" | "korean" | "ks_c_5601-1987"
        | "ks_c_5601-1989" | "ksc5601" | "ksc_5601" | "windows-949" => 51949,

        // -- UTF-16 --------------------------------------------------
        "unicodefffe" | "utf-16be" => CP_UTF16_BE,
        "csunicode" | "iso-10646-ucs-2" | "ucs-2" | "unicode" | "unicodefeff" | "utf-16"
        | "utf-16le" => CP_UTF16_LE,

        // -- x-user-defined -------------------------------------------
        "x-user-defined" => CP_X_USER_DEFINED,

        // -- replacement (WHATWG: always produces U+FFFD) -------------
        "csiso2022kr" | "hz-gb-2312" | "iso-2022-cn" | "iso-2022-cn-ext" | "iso-2022-kr"
        | "replacement" => CP_REPLACEMENT,

        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Special decoders
// ---------------------------------------------------------------------------

/// x-user-defined: 0x00-0x7F -> identity, 0x80-0xFF -> U+F780-U+F7FF.
fn decode_x_user_defined(data: &[u8]) -> String {
    data.iter()
        .map(|&b| {
            if b < 0x80 {
                b as char
            } else {
                // 0xF780..=0xF7FF are all valid USVs (Supplementary PUA);
                // `unwrap_or` is a defensive tail.
                char::from_u32(0xF700 | u32::from(b)).unwrap_or('\u{FFFD}')
            }
        })
        .collect()
}

/// WHATWG ISO-8859-16 (Latin-10) upper-half decode table.
///
/// Bytes 0x00..0x7F are ASCII (decoded as identity, not in this table).
/// Bytes 0x80..0x9F are C1 controls (identity).  The remaining 96
/// positions share most code points with ISO-8859-1 but override 40 of
/// them with Romanian, Polish, and other Central/Southeast-European
/// characters plus a handful of typographic symbols.
///
/// Source: <https://encoding.spec.whatwg.org/index-iso-8859-16.txt>
#[rustfmt::skip]
static ISO_8859_16_HIGH: [u16; 128] = [
    // 0x80..0x8F: C1 controls (identity)
    0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,
    0x0088, 0x0089, 0x008A, 0x008B, 0x008C, 0x008D, 0x008E, 0x008F,
    // 0x90..0x9F: C1 controls (identity)
    0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,
    0x0098, 0x0099, 0x009A, 0x009B, 0x009C, 0x009D, 0x009E, 0x009F,
    // 0xA0      0xA1   0xA2   0xA3   0xA4   0xA5   0xA6   0xA7
    0x00A0, 0x0104, 0x0105, 0x0141, 0x20AC, 0x201E, 0x0160, 0x00A7,
    // 0xA8      0xA9   0xAA   0xAB   0xAC   0xAD   0xAE   0xAF
    0x0161, 0x00A9, 0x0218, 0x00AB, 0x0179, 0x00AD, 0x017A, 0x017B,
    // 0xB0      0xB1   0xB2   0xB3   0xB4   0xB5   0xB6   0xB7
    0x00B0, 0x00B1, 0x010C, 0x0142, 0x017D, 0x201D, 0x00B6, 0x00B7,
    // 0xB8      0xB9   0xBA   0xBB   0xBC   0xBD   0xBE   0xBF
    0x017E, 0x010D, 0x0219, 0x00BB, 0x0152, 0x0153, 0x0178, 0x017C,
    // 0xC0      0xC1   0xC2   0xC3   0xC4   0xC5   0xC6   0xC7
    0x00C0, 0x00C1, 0x00C2, 0x0102, 0x00C4, 0x0106, 0x00C6, 0x00C7,
    // 0xC8      0xC9   0xCA   0xCB   0xCC   0xCD   0xCE   0xCF
    0x00C8, 0x00C9, 0x00CA, 0x00CB, 0x00CC, 0x00CD, 0x00CE, 0x00CF,
    // 0xD0      0xD1   0xD2   0xD3   0xD4   0xD5   0xD6   0xD7
    0x0110, 0x0143, 0x00D2, 0x00D3, 0x00D4, 0x0150, 0x00D6, 0x015A,
    // 0xD8      0xD9   0xDA   0xDB   0xDC   0xDD   0xDE   0xDF
    0x0170, 0x00D9, 0x00DA, 0x00DB, 0x00DC, 0x0118, 0x021A, 0x00DF,
    // 0xE0      0xE1   0xE2   0xE3   0xE4   0xE5   0xE6   0xE7
    0x00E0, 0x00E1, 0x00E2, 0x0103, 0x00E4, 0x0107, 0x00E6, 0x00E7,
    // 0xE8      0xE9   0xEA   0xEB   0xEC   0xED   0xEE   0xEF
    0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x00EC, 0x00ED, 0x00EE, 0x00EF,
    // 0xF0      0xF1   0xF2   0xF3   0xF4   0xF5   0xF6   0xF7
    0x0111, 0x0144, 0x00F2, 0x00F3, 0x00F4, 0x0151, 0x00F6, 0x015B,
    // 0xF8      0xF9   0xFA   0xFB   0xFC   0xFD   0xFE   0xFF
    0x0171, 0x00F9, 0x00FA, 0x00FB, 0x00FC, 0x0119, 0x021B, 0x00FF,
];

/// Decode ISO-8859-16 via compile-time lookup table (no NLS / ICU needed).
fn decode_iso_8859_16(data: &[u8]) -> String {
    data.iter()
        .map(|&b| {
            if b < 0x80 {
                b as char
            } else {
                // Every `ISO_8859_16_HIGH` entry is a valid USV;
                // `unwrap_or` is a defensive tail.
                let idx = (b & 0x7F) as usize;
                char::from_u32(u32::from(ISO_8859_16_HIGH[idx])).unwrap_or('\u{FFFD}')
            }
        })
        .collect()
}

/// Decode a UTF-16 byte stream with WHATWG-conformant replacement semantics for malformed input.
fn decode_utf16(data: &[u8], from_bytes: fn([u8; 2]) -> u16) -> String {
    let (pairs, rest) = data.as_chunks::<2>();
    let words: Vec<u16> = pairs.iter().map(|c| from_bytes(*c)).collect();
    let mut result = String::from_utf16_lossy(&words);

    // `from_utf16_lossy` handles complete code units but cannot see the odd
    // trailing byte. WHATWG counts that byte and a pending high surrogate as
    // one error, already replaced by `from_utf16_lossy`.
    if !rest.is_empty()
        && !words
            .last()
            .is_some_and(|word| (0xD800..=0xDBFF).contains(word))
    {
        result.push('\u{FFFD}');
    }
    result
}

// ---------------------------------------------------------------------------
// Content-Type charset extraction
// ---------------------------------------------------------------------------

/// Extract the `charset` parameter from a `Content-Type` header value.
///
/// ```text
/// text/html; charset=utf-8       -> Some("utf-8")
/// application/json               -> None
/// text/html; charset="UTF-8"     -> Some("utf-8")
/// ```
pub(crate) fn extract_charset_from_content_type(headers: &http::HeaderMap) -> Option<String> {
    headers
        .get(http::header::CONTENT_TYPE)?
        .to_str()
        .ok()?
        .parse::<mime::Mime>()
        .ok()?
        .get_param("charset")
        .map(|value| value.as_ref().to_owned())
        .filter(|value| !value.is_empty())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- All 39 WHATWG encodings --------------------------------------

    /// Comprehensive test covering all 39 WHATWG-mandated encodings with
    /// non-trivial, non-ASCII text specific to each encoding.
    ///
    /// Byte sequences are derived from the WHATWG Encoding Standard
    /// single-byte indexes (<https://encoding.spec.whatwg.org/#indexes>)
    /// and verified against the authoritative index text files.
    #[test]
    fn all_39_whatwg_encodings() {
        // (name, label, data, expected)
        let cases: &[(&str, &str, &[u8], &str)] = &[
            // -- Pure-Rust paths ---------------------------------
            ("UTF-8", "utf-8", &[0x63, 0x61, 0x66, 0xC3, 0xA9], "caf\u{00E9}"), // spellchecker:disable-line
            ("UTF-16BE", "utf-16be", &[0x00, 0x48, 0x00, 0x69], "Hi"),
            ("UTF-16LE", "utf-16le", &[0x48, 0x00, 0x69, 0x00], "Hi"),
            ("x-user-defined", "x-user-defined", &[0x48, 0x80, 0xFF], "H\u{F780}\u{F7FF}"),
            // -- NLS and ICU-preferred encodings -----------------
            (
                "IBM866",
                "ibm866",
                &[0x8F, 0xE0, 0xA8, 0xA2, 0xA5, 0xE2],
                "\u{041F}\u{0440}\u{0438}\u{0432}\u{0435}\u{0442}",
            ),
            ("ISO-8859-2", "iso-8859-2", &[0xA3, 0xF3, 0x64, 0xBC], "\u{0141}\u{00F3}d\u{017A}"),
            ("ISO-8859-3", "iso-8859-3", &[0xA1, 0xB1], "\u{0126}\u{0127}"),
            ("ISO-8859-4", "iso-8859-4", &[0xBD, 0xBF], "\u{014A}\u{014B}"),
            ("ISO-8859-5", "iso-8859-5", &[0xBC, 0xD8, 0xE0], "\u{041C}\u{0438}\u{0440}"),
            ("ISO-8859-6", "iso-8859-6", &[0xC7, 0xC8], "\u{0627}\u{0628}"),
            ("ISO-8859-7", "iso-8859-7", &[0xC1, 0xF9], "\u{0391}\u{03C9}"),
            ("ISO-8859-8", "iso-8859-8", &[0xE0, 0xE1], "\u{05D0}\u{05D1}"),
            ("ISO-8859-8-I", "iso-8859-8-i", &[0xF9, 0xFA], "\u{05E9}\u{05EA}"),
            ("ISO-8859-13", "iso-8859-13", &[0xD9, 0xF9], "\u{0141}\u{0142}"),
            ("ISO-8859-15", "iso-8859-15", &[0xA4, 0xBC], "\u{20AC}\u{0152}"),
            ("KOI8-R", "koi8-r", &[0xF2, 0xD5, 0xD3, 0xD8], "\u{0420}\u{0443}\u{0441}\u{044C}"),
            ("KOI8-U", "koi8-u", &[0xB4, 0xA4], "\u{0404}\u{0454}"),
            (
                "macintosh",
                "macintosh",
                &[0xC7, 0xC8, 0xD2, 0xD3],
                "\u{00AB}\u{00BB}\u{201C}\u{201D}",
            ),
            ("windows-874", "windows-874", &[0xA1, 0xA2], "\u{0E01}\u{0E02}"),
            ("windows-1250", "windows-1250", &[0x8A, 0x9A], "\u{0160}\u{0161}"),
            (
                "windows-1251",
                "windows-1251",
                &[0xCC, 0xEE, 0xF1, 0xEA, 0xE2, 0xE0],
                "\u{041C}\u{043E}\u{0441}\u{043A}\u{0432}\u{0430}",
            ),
            ("windows-1252", "windows-1252", &[0x80, 0x93, 0x94], "\u{20AC}\u{201C}\u{201D}"),
            ("windows-1253", "windows-1253", &[0xC1, 0xF9], "\u{0391}\u{03C9}"),
            ("windows-1254", "windows-1254", &[0xD0, 0xF0], "\u{011E}\u{011F}"),
            ("windows-1255", "windows-1255", &[0x80, 0xE0], "\u{20AC}\u{05D0}"),
            ("windows-1256", "windows-1256", &[0xC7, 0xC8], "\u{0627}\u{0628}"),
            ("windows-1257", "windows-1257", &[0xC0, 0xE0], "\u{0104}\u{0105}"),
            ("windows-1258", "windows-1258", &[0xD0, 0xF0], "\u{0110}\u{0111}"),
            ("x-mac-cyrillic", "x-mac-cyrillic", &[0x80, 0x81], "\u{0410}\u{0411}"),
            ("GBK", "gbk", &[0xC4, 0xE3, 0xBA, 0xC3], "\u{4F60}\u{597D}"),
            ("gb18030", "gb18030", &[0xC4, 0xE3, 0xBA, 0xC3], "\u{4F60}\u{597D}"),
            ("Big5", "big5", &[0xA4, 0xA4], "\u{4E2D}"),
            ("ISO-2022-JP", "iso-2022-jp", &[0x1B, 0x24, 0x42, 0x46, 0x7C], "\u{65E5}"),
            ("Shift_JIS", "shift_jis", &[0x82, 0xB1], "\u{3053}"),
            ("EUC-KR", "euc-kr", &[0xC7, 0xD1], "\u{D55C}"),
            // -- ICU-required encodings (require Windows 10 1903+)
            ("ISO-8859-10", "iso-8859-10", &[0xA1, 0xA2], "\u{0104}\u{0112}"),
            ("ISO-8859-14", "iso-8859-14", &[0xA1, 0xD0], "\u{1E02}\u{0174}"),
            ("EUC-JP", "euc-jp", &[0xC6, 0xFC, 0xCB, 0xDC, 0xB8, 0xEC], "\u{65E5}\u{672C}\u{8A9E}"),
            // -- Compile-time lookup table -----------------------
            ("ISO-8859-16", "iso-8859-16", &[0xAA, 0xBA], "\u{0218}\u{0219}"),
        ];

        assert_eq!(cases.len(), 39, "must cover all 39 WHATWG encodings");
        for &(name, label, data, expected) in cases {
            let result =
                decode_body(data, label).unwrap_or_else(|e| panic!("{name} ({label}): {e}"));
            assert_eq!(result, expected, "{name} ({label})");
        }
    }

    #[test]
    fn preferred_icu_falls_back_only_when_unavailable() {
        use std::cell::Cell;

        let cases: &[(u32, &str, &[u8], &str)] = &[
            (28597, "ISO-8859-7", &[0xA4], "\u{20AC}"),
            (874, "ibm-1162", &[0xDB], "\u{FFFD}"),
            (50220, "ISO-2022-JP", b"\x1B$B!A\x1B(B", "\u{FF5E}"),
        ];
        for &(codepage, name, data, expected) in cases {
            let nls_called = Cell::new(false);
            let decoded = decode_icu_preferred(
                codepage,
                name,
                data,
                |converter, input| {
                    assert_eq!((converter, input), (name, data));
                    Ok(Some(expected.to_owned()))
                },
                |_, _| {
                    nls_called.set(true);
                    Ok(String::new())
                },
            )
            .expect("ICU decode");
            assert_eq!(decoded, expected, "{name}");
            assert!(!nls_called.get(), "{name}");

            let decoded = decode_icu_preferred(
                codepage,
                name,
                data,
                |_, _| Ok(None),
                |page, input| {
                    assert_eq!((page, input), (codepage, data));
                    Ok("NLS fallback".to_owned())
                },
            )
            .expect("NLS fallback");
            assert_eq!(decoded, "NLS fallback", "{name}");

            let error = decode_icu_preferred(
                codepage,
                name,
                data,
                |_, _| Err(Error::decode("ICU conversion failed")),
                |_, _| {
                    nls_called.set(true);
                    Ok(String::new())
                },
            );
            assert!(error.is_err(), "{name}");
            assert!(!nls_called.get(), "{name}");
        }
    }

    #[test]
    fn preferred_icu_matches_selected_whatwg_mappings() {
        if !abi::is_icu_available() {
            eprintln!("skipping: icu.dll not available");
            return;
        }
        let cases: &[(&str, &[u8], &str)] = &[
            ("iso-8859-3", &[0xA5], "\u{FFFD}"),
            ("iso-8859-6", &[0xA1], "\u{FFFD}"),
            ("iso-8859-7", &[0xA4], "\u{20AC}"),
            ("iso-8859-8-i", &[0xFD], "\u{200E}"),
            ("macintosh", &[0xBD], "\u{03A9}"),
            ("windows-874", &[0x80, 0xA1, 0xDB, 0xFC], "\u{20AC}\u{0E01}\u{FFFD}\u{FFFD}"),
            ("x-mac-cyrillic", &[0xFF], "\u{20AC}"),
            ("gbk", &[0xFE, 0x60], "\u{3918}"),
            ("gb18030", &[0xFE, 0x60], "\u{3918}"),
            ("big5", &[0x87, 0x40], "\u{43F0}"),
            ("euc-kr", &[0x81, 0x41], "\u{AC02}"),
            ("iso-2022-jp", b"\x1B$B!A\x1B(B", "\u{FF5E}"),
            ("iso-2022-jp", b"\x1B$B!\x7F\x1B(B", "\u{FFFD}"),
        ];
        for &(label, data, expected) in cases {
            assert_eq!(decode_body(data, label).expect(label), expected, "{label}");
        }
    }

    // -- decode_body edge cases --------------------------------------

    #[test]
    fn decode_body_table() {
        let cases: &[(&[u8], &str, &str, &str)] = &[
            // (data, label, expected, description)

            // UTF-8 label variants
            (b"ok", "utf8", "ok", "utf8 alias"),
            (b"ok", "UTF-8", "ok", "uppercase label"),
            (b"ok", "  utf-8  ", "ok", "whitespace-trimmed label"),
            (b"ok", "unicode-1-1-utf-8", "ok", "utf-8 alias long"),
            (b"ok", "x-unicode20utf8", "ok", "utf-8 alias x-"),
            // UTF-8 BOM handling
            (&[0xEF, 0xBB, 0xBF, b'h', b'i'], "utf-8", "hi", "UTF-8 BOM stripped"),
            (&[0xEF, 0xBB, 0xBF], "utf-8", "", "UTF-8 BOM only"),
            // A BOM overrides the declared label (WHATWG decode, encoding_rs).
            (&[0xFF, 0xFE, 0x41, 0x00], "utf-8", "A", "UTF-16LE BOM beats utf-8 label"),
            (&[0xFE, 0xFF, 0x00, 0x41], "utf-8", "A", "UTF-16BE BOM beats utf-8 label"),
            (&[0xEF, 0xBB, 0xBF, b'h', b'i'], "windows-1252", "hi", "UTF-8 BOM beats 1252 label"),
            (
                &[0xEF, 0xBB, 0xBF, b'A', 0xFF, b'B'],
                "utf-16be",
                "A\u{FFFD}B",
                "UTF-8 BOM beats UTF-16BE label for malformed UTF-8",
            ),
            (&[0xFE, 0xFF, 0x00, 0x41], "utf-16le", "A", "BE BOM beats utf-16le label"),
            (&[0xFF, 0xFE, 0x41, 0x00], "totally-bogus", "A", "BOM beats unknown label"),
            // The sniffed BOM is consumed once; a literal U+FEFF after it survives.
            (
                &[0xEF, 0xBB, 0xBF, 0xEF, 0xBB, 0xBF, b'h', b'i'],
                "utf-8",
                "\u{FEFF}hi",
                "UTF-8 BOM then U+FEFF",
            ),
            (&[0xFF, 0xFE, 0xFF, 0xFE, 0x41, 0x00], "utf-16le", "\u{FEFF}A", "LE BOM then U+FEFF"),
            (&[0xFE, 0xFF, 0xFE, 0xFF, 0x00, 0x41], "utf-16be", "\u{FEFF}A", "BE BOM then U+FEFF"),
            // FF FE 00 00 is UTF-32LE's BOM; WHATWG sniffs it as UTF-16LE.
            (&[0xFF, 0xFE, 0x00, 0x00], "utf-8", "\u{0}", "UTF-32LE BOM is UTF-16LE"),
            // UTF-8 lossy fallback for invalid bytes
            (b"hi\xFFlo", "utf-8", "hi\u{FFFD}lo", "UTF-8 invalid byte → U+FFFD"),
            // Empty data always returns empty string
            (b"", "windows-1252", "", "empty data"),
            (b"", "utf-8", "", "empty UTF-8"),
            // Unknown label → UTF-8 fallback (matches reqwest)
            (b"hello", "totally-bogus", "hello", "unknown label → UTF-8"),
            // Unknown label with invalid UTF-8 → lossy fallback
            (b"hi\xFFlo", "totally-bogus", "hi\u{FFFD}lo", "unknown label → UTF-8 lossy"),
            // WHATWG aliasing: ascii / iso-8859-1 → windows-1252
            // 0x80 = € (U+20AC) in windows-1252
            (&[0x80], "ascii", "\u{20AC}", "ascii → windows-1252"),
            (&[0x80], "iso-8859-1", "\u{20AC}", "iso-8859-1 → windows-1252"),
            (&[0x80], "latin1", "\u{20AC}", "latin1 → windows-1252"),
            (&[0x80], "us-ascii", "\u{20AC}", "us-ascii → windows-1252"),
            // Case-insensitive label lookup
            (&[0x93], "WINDOWS-1252", "\u{201C}", "case: UPPER"),
            (&[0x93], "Windows-1252", "\u{201C}", "case: Mixed"),
            // replacement encoding: always yields U+FFFD
            (b"anything", "replacement", "\u{FFFD}", "replacement encoding"),
            (b"anything", "hz-gb-2312", "\u{FFFD}", "hz-gb-2312 → replacement"),
            (b"anything", "iso-2022-kr", "\u{FFFD}", "iso-2022-kr → replacement"),
            // x-user-defined: 0x80→U+F780, 0xFF→U+F7FF
            (&[0x80, 0xFF], "x-user-defined", "\u{F780}\u{F7FF}", "x-user-defined high bytes"),
            // ICU alias labels
            (&[0xA1], "latin6", "\u{0104}", "latin6 → ISO-8859-10"),
            (&[0xA4, 0xA2], "cseucpkdfmtjapanese", "\u{3042}", "cseucpkdfmtjapanese → EUC-JP"),
        ];

        for &(data, label, expected, desc) in cases {
            let result = decode_body(data, label).unwrap_or_else(|e| panic!("{desc}: {e}"));
            assert_eq!(result, expected, "{desc}");
        }
    }

    // -- UTF-16 edge cases ---------------------------------------------

    #[test]
    fn utf16_decode_table() {
        let cases: &[(&str, &[u8], &str, &str)] = &[
            // (charset, data, expected, description)

            // Basic
            ("utf-16le", &[0x41, 0x00, 0x42, 0x00], "AB", "LE basic"),
            ("utf-16be", &[0x00, 0x41, 0x00, 0x42], "AB", "BE basic"),
            (
                "utf-16le",
                &[0x41, 0x00, 0x34, 0xD8, 0x1E, 0xDD, 0x42, 0x00],
                "A\u{1D11E}B",
                "LE surrogate pair",
            ),
            (
                "utf-16be",
                &[0x00, 0x41, 0xD8, 0x34, 0xDD, 0x1E, 0x00, 0x42],
                "A\u{1D11E}B",
                "BE surrogate pair",
            ),
            // BOM stripping
            ("utf-16le", &[0xFF, 0xFE, 0x41, 0x00], "A", "LE BOM stripped"),
            ("utf-16be", &[0xFE, 0xFF, 0x00, 0x41], "A", "BE BOM stripped"),
        ];

        for &(charset, data, expected, desc) in cases {
            let result = decode_body(data, charset).unwrap_or_else(|e| panic!("{desc}: {e}"));
            assert_eq!(result, expected, "{desc}");
        }
    }

    #[test]
    fn utf16_replacement_table() {
        let cases: &[(&str, &[u8], &str, &str)] = &[
            // (charset, data, expected, description)
            ("utf-16le", &[0x00, 0xD8], "\u{FFFD}", "LE lone high surrogate"),
            ("utf-16be", &[0xD8, 0x00], "\u{FFFD}", "BE lone high surrogate"),
            (
                "utf-16le",
                &[0x41, 0x00, 0x00, 0xDC, 0x42, 0x00],
                "A\u{FFFD}B",
                "LE lone low surrogate",
            ),
            (
                "utf-16be",
                &[0x00, 0x41, 0xDC, 0x00, 0x00, 0x42],
                "A\u{FFFD}B",
                "BE lone low surrogate",
            ),
            (
                "utf-16le",
                &[0x00, 0xD8, 0x41, 0x00],
                "\u{FFFD}A",
                "LE high surrogate followed by BMP",
            ),
            (
                "utf-16be",
                &[0xD8, 0x00, 0x00, 0x41],
                "\u{FFFD}A",
                "BE high surrogate followed by BMP",
            ),
            (
                "utf-16le",
                &[0x00, 0xD8, 0x00, 0xD8, 0x41, 0x00],
                "\u{FFFD}\u{FFFD}A",
                "LE consecutive high surrogates",
            ),
            (
                "utf-16be",
                &[0xD8, 0x00, 0xD8, 0x00, 0x00, 0x41],
                "\u{FFFD}\u{FFFD}A",
                "BE consecutive high surrogates",
            ),
            ("utf-16le", &[0x41], "\u{FFFD}", "LE single byte"),
            ("utf-16be", &[0x41], "\u{FFFD}", "BE single byte"),
            ("utf-16le", &[0x41, 0x00, 0x42], "A\u{FFFD}", "LE odd trailing byte"),
            ("utf-16be", &[0x00, 0x41, 0x42], "A\u{FFFD}", "BE odd trailing byte"),
            ("utf-16le", &[0xFF, 0xFE, 0x41, 0x00, 0x42], "A\u{FFFD}", "LE BOM + odd remainder"),
            ("utf-16be", &[0xFE, 0xFF, 0x00, 0x41, 0x42], "A\u{FFFD}", "BE BOM + odd remainder"),
            (
                "utf-8",
                &[0xFF, 0xFE, 0x41, 0x00, 0x42],
                "A\u{FFFD}",
                "LE BOM beats UTF-8 with odd remainder",
            ),
            (
                "utf-16le",
                &[0xFE, 0xFF, 0x00, 0x41, 0x42],
                "A\u{FFFD}",
                "BE BOM beats LE with odd remainder",
            ),
            (
                "utf-16le",
                &[0x41, 0x00, 0x00, 0xD8, 0x42],
                "A\u{FFFD}",
                "LE high surrogate + odd byte is one error",
            ),
            (
                "utf-16be",
                &[0x00, 0x41, 0xD8, 0x00, 0x42],
                "A\u{FFFD}",
                "BE high surrogate + odd byte is one error",
            ),
            (
                "utf-8",
                &[0xFF, 0xFE, 0x41, 0x00, 0x00, 0xD8, 0x42],
                "A\u{FFFD}",
                "LE BOM + high surrogate + odd byte",
            ),
            (
                "utf-16le",
                &[0xFE, 0xFF, 0x00, 0x41, 0xD8, 0x00, 0x42],
                "A\u{FFFD}",
                "BE BOM + high surrogate + odd byte",
            ),
            (
                "utf-8",
                &[0xFF, 0xFE, 0xFF, 0xFE, 0x00, 0xD8, 0x41],
                "\u{FEFF}\u{FFFD}",
                "LE double BOM + high surrogate + odd byte",
            ),
            (
                "utf-8",
                &[0xFE, 0xFF, 0xFE, 0xFF, 0xD8, 0x00, 0x41],
                "\u{FEFF}\u{FFFD}",
                "BE double BOM + high surrogate + odd byte",
            ),
        ];

        for &(charset, data, expected, desc) in cases {
            let result = decode_body(data, charset).unwrap_or_else(|e| panic!("{desc}: {e}"));
            assert_eq!(result, expected, "{desc}");
        }
    }

    // -- ISO-8859-16 lookup table --------------------------------------

    /// Spot-check non-identity mappings against the WHATWG index:
    /// <https://encoding.spec.whatwg.org/index-iso-8859-16.txt>
    #[test]
    fn iso_8859_16_spot_checks() {
        let cases: &[(u8, char)] = &[
            (0xA1, '\u{0104}'), // Ą
            (0xA2, '\u{0105}'), // ą
            (0xA3, '\u{0141}'), // Ł
            (0xA4, '\u{20AC}'), // €
            (0xA5, '\u{201E}'), // „
            (0xA6, '\u{0160}'), // Š
            (0xA8, '\u{0161}'), // š
            (0xAC, '\u{0179}'), // Ź
            (0xAF, '\u{017B}'), // Ż
            (0xB2, '\u{010C}'), // Č
            (0xB3, '\u{0142}'), // ł
            (0xB4, '\u{017D}'), // Ž
            (0xB5, '\u{201D}'), // "
            (0xB8, '\u{017E}'), // ž
            (0xB9, '\u{010D}'), // č
            (0xBC, '\u{0152}'), // Œ
            (0xBD, '\u{0153}'), // œ
            (0xBE, '\u{0178}'), // Ÿ
            (0xBF, '\u{017C}'), // ż
            (0xC3, '\u{0102}'), // Ă
            (0xC5, '\u{0106}'), // Ć
            (0xD0, '\u{0110}'), // Đ
            (0xD1, '\u{0143}'), // Ń
            (0xD5, '\u{0150}'), // Ő
            (0xD7, '\u{015A}'), // Ś
            (0xD8, '\u{0170}'), // Ű
            (0xDD, '\u{0118}'), // Ę
            (0xE3, '\u{0103}'), // ă
            (0xE5, '\u{0107}'), // ć
            (0xF0, '\u{0111}'), // đ
            (0xF1, '\u{0144}'), // ń
            (0xF5, '\u{0151}'), // ő
            (0xF7, '\u{015B}'), // ś
            (0xF8, '\u{0171}'), // ű
            (0xFD, '\u{0119}'), // ę
            (0xFE, '\u{021B}'), // ț
        ];
        for &(byte, expected) in cases {
            let result =
                decode_body(&[byte], "iso-8859-16").unwrap_or_else(|e| panic!("0x{byte:02X}: {e}"));
            assert_eq!(result.chars().next().unwrap(), expected, "byte 0x{byte:02X}");
        }
    }

    /// Every byte 0x00..=0xFF decodes without panic and produces exactly
    /// one character.
    #[test]
    fn iso_8859_16_full_range() {
        let all_bytes: Vec<u8> = (0u8..=255).collect();
        let result = decode_body(&all_bytes, "iso-8859-16").expect("full range");
        assert_eq!(result.chars().count(), 256);
    }

    // -- Content-Type charset extraction -----------------------------

    #[test]
    fn extract_charset_table() {
        let cases: &[(&str, Option<&str>, &str)] = &[
            ("text/html; charset=utf-8", Some("utf-8"), "plain charset"),
            ("text/html; charset=\"UTF-8\"", Some("utf-8"), "quoted charset"),
            ("application/json", None, "no charset param"),
            // An empty label uses the caller-provided default encoding.
            ("text/html; charset=", None, "empty charset value"),
            // An empty quoted value makes the media type invalid.
            ("text/html; charset=\"\"", None, "empty quoted charset value"),
            // Malformed MIME is ignored as a whole.
            ("text/html; x=charset=wrong; charset=right", None, "invalid parameter value"),
            (
                "text/plain; note=\"x;charset=windows-1252\"; charset=utf-8",
                Some("utf-8"),
                "semicolon inside quoted parameter",
            ),
            // charset= as part of a longer parameter name must not match
            ("text/html; notcharset=oops", None, "charset prefix in param name"),
            // Case-insensitive parameter name
            ("text/html; Charset=Latin1", Some("latin1"), "uppercase Charset"),
            ("text/html; CHARSET=Big5", Some("big5"), "all-caps CHARSET"),
            // Malformed MIME is ignored as a whole.
            ("text/html; boundary; charset=UTF-8", None, "param without equals sign"),
        ];

        for &(content_type, expected, desc) in cases {
            let mut headers = http::HeaderMap::new();
            headers.insert(http::header::CONTENT_TYPE, content_type.parse().expect("valid"));
            assert_eq!(extract_charset_from_content_type(&headers).as_deref(), expected, "{desc}");
        }
    }

    #[test]
    fn extract_charset_no_content_type() {
        let headers = http::HeaderMap::new();
        assert_eq!(extract_charset_from_content_type(&headers), None);
    }
}
