use self::Domain::*;
use serde::Serialize;
#[cfg(test)]
use std::collections::HashSet;

// GB18030 four-byte grammar: 81..FE, 30..39, 81..FE, 30..39.
// The pointer grid also includes unassigned positions that trigger replacement.
pub const GB18030_FOUR_BYTE_POINTERS: usize = 126 * 10 * 126 * 10;
pub const DEFAULT_FOUR_BYTE_SAMPLES: usize = 18_412;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Domain {
    Single,
    Gb,
    Big5,
    EucKr,
    EucJp,
    ShiftJis,
    Iso2022Jp,
}

#[derive(Clone, Copy, Debug)]
pub struct Case {
    pub label: &'static str,
    pub codepage: Option<u32>,
    pub icu: &'static str,
    pub domain: Domain,
    pub variants: &'static [&'static str],
}

const fn case(
    label: &'static str,
    codepage: Option<u32>,
    icu: &'static str,
    domain: Domain,
    variants: &'static [&'static str],
) -> Case {
    Case {
        label,
        codepage,
        icu,
        domain,
        variants,
    }
}

// The native routes in src\encoding.rs, including their chosen ICU tables.
pub const CASES: &[Case] = &[
    case("iso-8859-10", None, "ISO-8859-10", Single, &[]),
    case("iso-8859-14", None, "ISO-8859-14", Single, &[]),
    case("euc-jp", None, "EUC-JP", EucJp, &[]),
    case("iso-8859-3", Some(28593), "ISO-8859-3", Single, &[]),
    case("iso-8859-6", Some(28596), "ISO-8859-6", Single, &[]),
    case("iso-8859-7", Some(28597), "ISO-8859-7", Single, &[]),
    case("iso-8859-8", Some(28598), "ISO-8859-8", Single, &[]),
    case("iso-8859-8-i", Some(38598), "ISO-8859-8", Single, &[]),
    case("macintosh", Some(10000), "macintosh", Single, &[]),
    case("windows-1253", Some(1253), "windows-1253", Single, &[]),
    case("windows-1257", Some(1257), "windows-1257", Single, &[]),
    case("x-mac-cyrillic", Some(10017), "x-mac-cyrillic", Single, &[]),
    case("gbk", Some(936), "gb18030", Gb, &["GBK"]),
    case("gb18030", Some(54936), "gb18030", Gb, &["GBK"]),
    case("big5", Some(950), "Big5-HKSCS", Big5, &["Big5", "ibm-950_P110-1999"]),
    case(
        "euc-kr",
        Some(51949),
        "windows-949",
        EucKr,
        &["EUC-KR", "ibm-949_P110-1999", "ibm-949_P11A-1999", "ibm-1363_P11B-1998"],
    ),
    case("ibm866", Some(866), "IBM866", Single, &[]),
    case("iso-8859-2", Some(28592), "ISO-8859-2", Single, &[]),
    case("iso-8859-4", Some(28594), "ISO-8859-4", Single, &[]),
    case("iso-8859-5", Some(28595), "ISO-8859-5", Single, &[]),
    case("iso-8859-13", Some(28603), "ISO-8859-13", Single, &[]),
    case("iso-8859-15", Some(28605), "ISO-8859-15", Single, &[]),
    case("koi8-r", Some(20866), "KOI8-R", Single, &[]),
    case("koi8-u", Some(21866), "KOI8-U", Single, &[]),
    case("windows-874", Some(874), "ibm-1162", Single, &["windows-874", "iso-8859_11-2001"]),
    case("windows-1250", Some(1250), "windows-1250", Single, &[]),
    case("windows-1251", Some(1251), "windows-1251", Single, &[]),
    case("windows-1252", Some(1252), "windows-1252", Single, &[]),
    case("windows-1254", Some(1254), "windows-1254", Single, &[]),
    case("windows-1255", Some(1255), "windows-1255", Single, &[]),
    case("windows-1256", Some(1256), "windows-1256", Single, &[]),
    case("windows-1258", Some(1258), "windows-1258", Single, &[]),
    case(
        "iso-2022-jp",
        Some(50220),
        "ISO-2022-JP",
        Iso2022Jp,
        &["ISO-2022-JP-1", "ISO-2022-JP-2", "JIS7", "JIS8"],
    ),
    case("shift_jis", Some(932), "Shift_JIS", ShiftJis, &["ibm-943"]),
];

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(tag = "kind", content = "seed", rename_all = "kebab-case")]
pub enum Coverage {
    ExhaustiveShape,
    SeededSample(u64),
    DeterministicSample,
    Curated,
}

pub struct Group {
    pub name: &'static str,
    pub inputs: Vec<Vec<u8>>,
    pub coverage: Coverage,
}

pub fn group(name: &'static str, inputs: impl IntoIterator<Item = Vec<u8>>) -> Group {
    Group {
        name,
        inputs: inputs.into_iter().collect(),
        coverage: Coverage::ExhaustiveShape,
    }
}

impl Group {
    pub(crate) fn sampled(mut self, seed: u64) -> Self {
        self.coverage = Coverage::SeededSample(seed);
        self
    }

    pub(crate) fn deterministic(mut self) -> Self {
        self.coverage = Coverage::DeterministicSample;
        self
    }

    pub fn curated(mut self) -> Self {
        self.coverage = Coverage::Curated;
        self
    }
}

/// Exclude inputs that WHATWG routes to a Unicode decoder before consulting
/// the declared legacy charset. Keep the midstream versions as byte data.
pub fn exclude_initial_boms(groups: &mut [Group]) {
    for group in groups {
        group.inputs.retain(|data| {
            !data.starts_with(b"\xef\xbb\xbf")
                && !data.starts_with(b"\xff\xfe")
                && !data.starts_with(b"\xfe\xff")
        });
    }
}

pub fn pairs(domain: Domain) -> Vec<Vec<u8>> {
    // Enumerate the WHATWG lead/trail shapes, including unassigned pairs to
    // measure recovery. Gaps in trail ranges (notably 7F) matter.
    let (leads, trails): (Vec<u8>, Vec<u8>) = match domain {
        Gb => ((0x81..=0xfe).collect(), (0x40..=0x7e).chain(0x80..=0xfe).collect()),
        Big5 => ((0x81..=0xfe).collect(), (0x40..=0x7e).chain(0xa1..=0xfe).collect()),
        EucKr => ((0x81..=0xfe).collect(), (0x41..=0xfe).collect()),
        EucJp => ((0xa1..=0xfe).collect(), (0xa1..=0xfe).collect()),
        ShiftJis => {
            ((0x81..=0x9f).chain(0xe0..=0xfc).collect(), (0x40..=0x7e).chain(0x80..=0xfc).collect())
        }
        _ => panic!("no pair grid for {domain:?}"),
    };
    leads
        .iter()
        .flat_map(|&lead| trails.iter().map(move |&trail| vec![lead, trail]))
        .collect()
}

pub fn four_byte_sample(count: usize) -> Vec<Vec<u8>> {
    assert!(count <= GB18030_FOUR_BYTE_POINTERS);
    // Evenly spaced pointer indices include both endpoints. 12,600 = 10*126*10
    // pointers per first byte; 1,260 = 126*10 per first digit.
    (0..count)
        .map(|index| {
            let pointer = if count == 1 {
                0
            } else {
                (index as u64 * (GB18030_FOUR_BYTE_POINTERS - 1) as u64 / (count - 1) as u64)
                    as usize
            };
            vec![
                0x81 + (pointer / 12600) as u8,
                0x30 + ((pointer / 1260) % 10) as u8,
                0x81 + ((pointer / 10) % 126) as u8,
                0x30 + (pointer % 10) as u8,
            ]
        })
        .collect()
}

// Published SplitMix64 increment and mixing constants. Preserve both the
// algorithm and draw order: either change alters the recorded corpus hashes.
pub(crate) struct SplitMix64(pub(crate) u64);

impl SplitMix64 {
    pub(crate) fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    pub(crate) fn index(&mut self, len: usize) -> usize {
        (self.next() % len as u64) as usize
    }
}

pub fn iso2022_expanded_groups() -> Vec<Group> {
    let mut result = Vec::new();
    // ESC $ B / ESC $ @ designate the two JIS0208 versions; ESC ( B
    // switches back to ASCII so each pair is measured in isolation.
    for (name, escape) in [("JIS0208-1983", &b"\x1b$B"[..]), ("JIS0208-1978", &b"\x1b$@"[..])] {
        result.push(group(
            name,
            (0x21..=0x7e).flat_map(|lead| {
                (0x21..=0x7e).map(move |trail| [escape, &[lead, trail], b"\x1b(B"].concat())
            }),
        ));
    }
    // Roman and Katakana are stateful modes; ESC $ ( D requests JIS0212,
    // which triggers WHATWG error recovery.
    for (name, escape) in [
        ("ASCII", &b"\x1b(B"[..]),
        ("Roman", &b"\x1b(J"[..]),
        ("Katakana", &b"\x1b(I"[..]),
        ("JIS0212-escape", &b"\x1b$(D"[..]),
    ] {
        result.push(group(name, (0..=255).map(|value| [escape, &[value], b"\x1b(B"].concat())));
    }
    result.push(group(
        "truncated-kanji",
        (0..=255).map(|lead| [b"\x1b$B".as_slice(), &[lead]].concat()),
    ));
    result.push(group(
        "kanji-trails",
        (0x21..=0x7e).flat_map(|lead| {
            (0..=255).map(move |trail| [b"\x1b$B".as_slice(), &[lead, trail], b"\x1b(B"].concat())
        }),
    ));
    result.push(group(
        "escape-prefix",
        [
            b"Q\x1b".as_slice(),
            b"Q\x1b$",
            b"Q\x1b$(",
            b"Q\x1b(",
            b"Q\x1b$X",
            b"Q\x1b(B",
            b"Q\x1b(J",
            b"Q\x1b(I",
            b"Q\x1b$B",
            b"Q\x1b$@",
            b"Q\x1b$(D",
            b"Q\x1b$B$\"",
            b"Q\x1b$B$\"\x1b(B",
        ]
        .into_iter()
        .map(<[u8]>::to_vec),
    ));
    // ESC/designation, boundary, and CR/LF bytes bias the seeded streams
    // toward mode changes and recovery across successive inputs.
    let mut rng = SplitMix64(20260930);
    let alphabet = [
        0x1b, 0x24, 0x28, 0x29, 0x40, 0x42, 0x49, 0x4a, 0x5c, 0x7e, 0x80, 0xa1, 0xfe, 0xff, 0x0a,
        0x0d,
    ];
    result.push(
        group(
            "mixed",
            (0..5000).map(|_| {
                let length = (rng.next() % 24 + 1) as usize;
                let mut bytes = vec![b'Q'];
                bytes.extend((0..length).map(|_| alphabet[rng.index(alphabet.len())]));
                bytes
            }),
        )
        .sampled(20260930),
    );
    result
}

pub fn windows874_expanded_groups() -> Vec<Group> {
    // ASCII Q exposes context-sensitive recovery; raw pairs are separate.
    let pairs = group(
        "ASCII-prefixed pairs",
        (0..=255).flat_map(|first| (0..=255).map(move |second| vec![b'Q', first, second])),
    );
    let mut rng = SplitMix64(874);
    let mixed = group(
        "ASCII-prefixed mixed",
        (0..10000).map(|_| {
            let length = (rng.next() % 63 + 1) as usize;
            let mut bytes = vec![b'Q'];
            bytes.extend((0..length).map(|_| rng.next() as u8));
            bytes
        }),
    )
    .sampled(874);
    vec![pairs, mixed]
}

fn iso2022_transition_groups() -> Vec<Group> {
    // Q ESC xx yy Z covers every two-byte continuation after an escape,
    // including invalid designations followed by ASCII to test reprocessing.
    let escapes = group(
        "escape-prefix grid",
        (0..=255)
            .flat_map(|first| (0..=255).map(move |second| vec![b'Q', 0x1b, first, second, b'Z'])),
    );
    let encoding = encoding_rs::ISO_2022_JP;
    // Build valid units that return to ASCII, then concatenate 1..=12 of
    // them to observe transitions across (rather than only within) modes.
    let mut units = vec![b"A".to_vec()];
    for escape in [&b"\x1b(B"[..], &b"\x1b(J"[..], &b"\x1b(I"[..]] {
        for byte in 0..=255 {
            let input = [escape, &[byte], b"\x1b(B"].concat();
            if !encoding.decode_without_bom_handling(&input).1 {
                units.push(input);
            }
        }
    }
    for escape in [&b"\x1b$B"[..], &b"\x1b$@"[..]] {
        for lead in 0x21..=0x7e {
            for trail in 0x21..=0x7e {
                let input = [escape, &[lead, trail], b"\x1b(B"].concat();
                if !encoding.decode_without_bom_handling(&input).1 {
                    units.push(input);
                }
            }
        }
    }
    let mut rng = SplitMix64(20260933);
    let transitions = group(
        "mode transitions",
        (0..10000).map(|_| {
            let mut input = vec![b'Q'];
            let count = rng.next() % 12 + 1;
            for _ in 0..count {
                input.extend_from_slice(&units[rng.index(units.len())]);
                if rng.next().is_multiple_of(2) {
                    input.push(b'A');
                }
            }
            input.push(b'Z');
            input
        }),
    )
    .sampled(20260933);
    vec![escapes, transitions]
}

fn cjk_expanded_groups(case: &Case) -> Vec<Group> {
    if case.domain == Iso2022Jp {
        return iso2022_transition_groups();
    }
    let encoding = encoding_rs::Encoding::for_label(case.label.as_bytes())
        .expect("built-in native case must have an encoding_rs label");
    let mut result = Vec::new();
    if case.domain == EucJp {
        // SS2 (8E) introduces half-width Katakana; SS3 (8F) introduces
        // three-byte JIS0212. "other" exercises every malformed SS3 tail.
        result.push(group("SS2 8E+byte", (0..=255).map(|byte| vec![0x8e, byte])));
        result.push(group(
            "SS3 8F+A1..FE+A1..FE",
            (0xa1..=0xfe)
                .flat_map(|second| (0xa1..=0xfe).map(move |third| vec![0x8f, second, third])),
        ));
        result.push(group(
            "SS3 other",
            (0..=255).flat_map(|second| {
                (0..=255)
                    .filter(move |&third| {
                        !(0xa1..=0xfe).contains(&second) || !(0xa1..=0xfe).contains(&third)
                    })
                    .map(move |third| vec![0x8f, second, third])
            }),
        ));
        result.push(group(
            "SS3 ASCII trails",
            (0xa1..=0xfe).flat_map(|second| {
                (0..=0x7f).map(move |third| vec![b'Q', 0x8f, second, third, b'Z'])
            }),
        ));
    }
    if case.domain == Gb {
        // Fix the first lead/digit at 81 30, then exhaust both remaining
        // bytes; includes interrupted prefixes as well as complete forms.
        result.push(group(
            "interrupted four-byte prefixes",
            (0..=255).flat_map(|third| {
                (0..=255).map(move |fourth| vec![b'Q', 0x81, 0x30, third, fourth, b'Z'])
            }),
        ));
    }
    let leads = match case.domain {
        Gb | Big5 | EucKr => (0x81..=0xfe).collect::<Vec<_>>(),
        EucJp => (0xa1..=0xfe).chain([0x8e, 0x8f]).collect(),
        ShiftJis => (0x81..=0x9f).chain(0xe0..=0xfc).collect(),
        _ => unreachable!("no CJK corpus for {}", case.label),
    };
    let ascii_trails = group(
        "ASCII-prefixed lead+ASCII",
        leads
            .into_iter()
            .flat_map(|lead| (0..=0x7f).map(move |trail| vec![b'Q', lead, trail, b'Z'])),
    );
    result.push(ascii_trails);

    let mut units: Vec<Vec<u8>> = (0..=255).map(|byte| vec![byte]).collect();
    units.extend(pairs(case.domain));
    if case.domain == EucJp {
        units.extend((0..=255).map(|byte| vec![0x8e, byte]));
        units.extend(
            (0xa1..=0xfe)
                .flat_map(|second| (0xa1..=0xfe).map(move |third| vec![0x8f, second, third])),
        );
    }
    if case.domain == Gb {
        units.extend(four_byte_sample(DEFAULT_FOUR_BYTE_SAMPLES));
    }
    units.retain(|input| !encoding.decode_without_bom_handling(input).1);
    // Distinct fixed seeds give each encoding its own stream sequence.
    // Valid units can interact at their boundaries; score the whole result.
    let seed = match case.domain {
        Gb if case.label == "gbk" => 20260935,
        Gb => 20260936,
        Big5 => 20260934,
        EucKr => 20260931,
        EucJp => 20260930,
        ShiftJis => 20260932,
        _ => unreachable!(),
    };
    let mut rng = SplitMix64(seed);
    result.push(
        group(
            "valid mixed streams",
            (0..10000).map(|_| {
                let mut input = vec![b'Q'];
                let count = rng.next() % 15 + 1;
                for _ in 0..count {
                    input.extend_from_slice(&units[rng.index(units.len())]);
                }
                input.push(b'Z');
                input
            }),
        )
        .sampled(seed),
    );
    result
}

pub fn groups(case: &Case, four_byte_count: usize, screening: bool) -> Vec<Group> {
    if case.domain == Iso2022Jp && !screening {
        let mut result = iso2022_expanded_groups();
        result.extend(cjk_expanded_groups(case));
        return result;
    }
    let mut result = vec![group("singletons", (0..=255).map(|byte| vec![byte]))];
    if case.label == "windows-874" && !screening {
        result.extend(windows874_expanded_groups());
    }
    if matches!(case.domain, Gb | Big5 | EucKr | EucJp | ShiftJis) {
        result.push(group("pairs", pairs(case.domain)));
    }
    if case.domain == Gb && four_byte_count != 0 {
        let four = group("four-byte sample", four_byte_sample(four_byte_count));
        result.push(if four_byte_count == GB18030_FOUR_BYTE_POINTERS {
            four
        } else {
            four.deterministic()
        });
    }
    if case.domain == Iso2022Jp {
        result.push(
            group(
                "escape samples",
                [
                    b"\x1b$B$\"\x1b(B".as_slice(),
                    b"\x1b$(D$\"\x1b(B",
                    b"\x1b$(",
                    b"\x1b$X",
                    b"\x1b$B$",
                ]
                .into_iter()
                .map(<[u8]>::to_vec),
            )
            .curated(),
        );
    }
    if !screening && case.domain != Single {
        result.extend(cjk_expanded_groups(case));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_routes_have_distinct_whatwg_labels() {
        assert_eq!(CASES.len(), 34);
        let mut labels = HashSet::new();
        for case in CASES {
            assert!(labels.insert(case.label));
            assert!(encoding_rs::Encoding::for_label(case.label.as_bytes()).is_some());
        }
    }

    #[test]
    fn only_leading_boms_are_removed_from_builtin_groups() {
        let mut groups = vec![group(
            "test",
            [
                b"\xef\xbb\xbf".to_vec(),
                b"\xff\xfeQ".to_vec(),
                b"\xfe\xff".to_vec(),
                b"Q\xef\xbb\xbfZ".to_vec(),
                b"Q\xff\xfeZ".to_vec(),
                b"Q\xfe\xffZ".to_vec(),
            ],
        )];
        exclude_initial_boms(&mut groups);
        assert_eq!(
            groups[0].inputs,
            [b"Q\xef\xbb\xbfZ".to_vec(), b"Q\xff\xfeZ".to_vec(), b"Q\xfe\xffZ".to_vec()]
        );
    }
}
