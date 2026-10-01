use crate::corpus::{Case, Domain, Group, SplitMix64, group, pairs};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

// NUL/ESC, ISO designators, ASCII boundaries, C1/DBCS leads, EUC SS2/SS3,
// and high trail edges: this alphabet biases mixed streams toward state changes.
const EDGE_BYTES: &[u8] = &[
    0x00, 0x1b, 0x20, 0x24, 0x28, 0x29, 0x30, 0x39, 0x40, 0x41, 0x5c, 0x7e, 0x7f, 0x80, 0x81, 0x82,
    0x8e, 0x8f, 0x9f, 0xa0, 0xa1, 0xc1, 0xe0, 0xfe, 0xff,
];

fn seed(label: &str) -> u64 {
    let digest = Sha256::digest(label.as_bytes());
    u64::from_le_bytes(
        digest[..8]
            .try_into()
            .expect("SHA-256 digest contains eight bytes"),
    )
}

fn random_streams(label: &str) -> Group {
    let seed = seed(label);
    let mut rng = SplitMix64(seed);
    // 10,000 streams, 1..=64 bytes; one quarter of draws use all byte
    // values, three quarters favor EDGE_BYTES. Q/Z test ASCII recovery
    // and expose recovery after malformed input.
    group(
        "mixed malformed/boundary streams",
        (0..10000).map(|index| {
            let count = (rng.next() % 64 + 1) as usize;
            let mut input = Vec::with_capacity(count + 2);
            if index % 2 == 0 {
                input.push(b'Q');
            }
            for _ in 0..count {
                let selector = rng.next();
                input.push(if selector.is_multiple_of(4) {
                    (rng.next() & 0xff) as u8
                } else {
                    EDGE_BYTES[rng.index(EDGE_BYTES.len())]
                });
            }
            if index % 3 == 0 {
                input.push(b'Z');
            }
            input
        }),
    )
    .sampled(seed)
}

fn single_byte_groups(label: &str) -> Vec<Group> {
    let raw = group(
        "raw byte pairs",
        (0..=255).flat_map(|first| (0..=255).map(move |second| vec![first, second])),
    );
    let framed = group(
        "ASCII-prefixed byte pairs",
        (0..=255).flat_map(|first| (0..=255).map(move |second| vec![b'Q', first, second, b'Z'])),
    );
    // Frame each single byte with ASCII to expose context-sensitive decoding.
    let framed_singletons =
        group("ASCII-framed singletons", (0..=255).map(|byte| vec![b'Q', byte, b'Z']));
    vec![raw, framed, random_streams(label), framed_singletons]
}

fn variable_units(case: &Case) -> Vec<Vec<u8>> {
    let encoding = encoding_rs::Encoding::for_label(case.label.as_bytes())
        .expect("built-in native case must have an encoding_rs label");
    let mut units = BTreeSet::new();
    for &byte in EDGE_BYTES {
        units.insert(vec![byte]);
    }
    let candidates = pairs(case.domain);
    let last = candidates
        .last()
        .expect("CJK pair grid must not be empty")
        .clone();
    let mut valid = 0;
    let mut invalid = 0;
    for input in candidates {
        let (decoded, had_errors) = encoding.decode_without_bom_handling(&input);
        let count = if had_errors { &mut invalid } else { &mut valid };
        // Seed mapped and unmapped pair cases in byte order; Big5's two-scalar
        // mappings additionally expose output-length differences.
        if *count < 4 {
            units.insert(input.clone());
            *count += 1;
        }
        if case.domain == Domain::Big5 && !had_errors && decoded.chars().count() > 1 {
            units.insert(input);
        }
    }
    units.insert(last);
    // Include complete and unfinished sequences so the next unit in an ordered
    // pair can complete a pending character or trigger error recovery.
    match case.domain {
        Domain::Gb => {
            units.extend([
                vec![0x81, 0x30],             // Lead+digit selects GB's four-byte path.
                vec![0x81, 0x30, 0x81],       // Awaiting the final digit.
                vec![0x81, 0x30, 0x81, 0x30], // First pointer, U+0080.
                vec![0x84, 0x31, 0xa4, 0x37], // Maps to U+FFFD without a decoding error.
                vec![0xfe, 0x39, 0xfe, 0x39], // Highest pointer; no Unicode mapping.
                vec![0x80],                   // Single-byte euro sign.
                vec![0xa3, 0xa0],             // WHATWG mapping for ideographic space.
            ]);
        }
        Domain::EucJp => {
            units.extend([
                vec![0x8e],             // SS2 awaits a halfwidth-katakana byte.
                vec![0x8e, 0xa1],       // First halfwidth-katakana mapping.
                vec![0x8f],             // SS3 awaits two JIS X 0212 bytes.
                vec![0x8f, 0xa1],       // SS3 awaits its second byte.
                vec![0x8f, 0xa1, 0xa1], // Low-end JIS X 0212 pair, unmapped.
                vec![0x8f, 0xfe, 0xfe], // High-end JIS X 0212 pair, unmapped.
            ]);
        }
        Domain::EucKr => {
            units.extend([
                vec![0x81, 0x41], // Extended lead with a mapped trail.
                vec![0x81, 0x5b], // Unmapped trail '[' is reconsumed as ASCII.
            ]);
        }
        Domain::ShiftJis => {
            units.extend([
                vec![0x82, 0x22], // Invalid trail '"' is reconsumed as ASCII.
                vec![0x82, 0xa0], // Mapped hiragana U+3042.
            ]);
        }
        Domain::Big5 => {
            // Four Big5 pairs decode to U+00CA/U+00EA plus U+0304/U+030C.
            units.extend([vec![0x88, 0x62], vec![0x88, 0x64], vec![0x88, 0xa3], vec![0x88, 0xa5]]);
        }
        _ => unreachable!(),
    }
    units.into_iter().collect()
}

fn variable_groups(case: &Case) -> Vec<Group> {
    // Sweep every possible trail after each lead: EOF exposes incomplete or
    // unmapped pairs, while Q...Z exposes ASCII recovery after bad trails.
    let leads: Vec<u8> = match case.domain {
        Domain::Gb | Domain::Big5 | Domain::EucKr => (0x81..=0xfe).collect(),
        Domain::EucJp => (0xa1..=0xfe).chain([0x8e, 0x8f]).collect(),
        Domain::ShiftJis => (0x81..=0x9f).chain(0xe0..=0xfc).collect(),
        _ => unreachable!(),
    };
    let raw = group(
        "all lead+byte at EOF",
        leads
            .iter()
            .flat_map(|&lead| (0..=255).map(move |trail| vec![lead, trail])),
    );
    let framed = group(
        "all lead+byte with ASCII recovery",
        leads
            .iter()
            .flat_map(|&lead| (0..=255).map(move |trail| vec![b'Q', lead, trail, b'Z'])),
    );
    let units = variable_units(case);
    // A truncated left unit can consume bytes from the right unit. Test both
    // at the start of input and between Q/Z to reveal ASCII resynchronization.
    let pairwise_start = group(
        "ordered boundary units at start/EOF",
        units.iter().flat_map(|left| {
            units
                .iter()
                .map(move |right| [left.as_slice(), right.as_slice()].concat())
        }),
    );
    let pairwise_framed = group(
        "ordered boundary units between ASCII",
        units.iter().flat_map(|left| {
            units.iter().map(move |right| {
                [b"Q".as_slice(), left.as_slice(), right.as_slice(), b"Z"].concat()
            })
        }),
    );
    let mut result = vec![raw, framed, pairwise_start, pairwise_framed, random_streams(case.label)];
    if case.domain == Domain::Gb {
        // A GB lead+digit enters the four-byte path. Vary every third byte
        // and fourth-byte values on and near the digit bounds (30..39);
        // Q/Z reveal recovery when either byte breaks that path.
        let boundaries = group(
            "GB four-byte prefix boundaries",
            [0x81, 0x84, 0x9f, 0xfe].into_iter().flat_map(|lead| {
                [0x30, 0x35, 0x39].into_iter().flat_map(move |digit| {
                    (0..=255).flat_map(move |third| {
                        [0x00, 0x2f, 0x30, 0x39, 0x3a, 0x40, 0x7f, 0x80, 0xfe, 0xff]
                            .into_iter()
                            .map(move |fourth| vec![b'Q', lead, digit, third, fourth, b'Z'])
                    })
                })
            }),
        );
        result.push(boundaries);
    }
    result
}

fn iso2022_groups(case: &Case) -> Vec<Group> {
    // ESC ( B = ASCII, ESC ( J = Roman, ESC ( I = Katakana,
    // ESC $ B / ESC $ @ = two JIS0208 designations.
    let modes: [&[u8]; 6] = [b"", b"\x1b(B", b"\x1b(J", b"\x1b(I", b"\x1b$B", b"\x1b$@"];
    // Partial designations and pending kanji leads, including ! and ~
    // (the first/last JIS0208 bytes), before the next arbitrary byte.
    let pending: [&[u8]; 9] =
        [b"", b"\x1b", b"\x1b(", b"\x1b$", b"\x1b$(", b"!", b"~", b"\x1b$B!", b"\x1b$@~"];
    let at_eof = group(
        "ISO designated mode/pending/next byte at EOF",
        modes.iter().flat_map(|mode| {
            pending.iter().flat_map(move |state| {
                (0..=255).map(move |byte| [b"Q".as_slice(), mode, state, &[byte]].concat())
            })
        }),
    );
    let with_ascii = group(
        "ISO designated mode/pending/next byte then ASCII",
        modes.iter().flat_map(|mode| {
            pending.iter().flat_map(move |state| {
                (0..=255).map(move |byte| [b"Q".as_slice(), mode, state, &[byte], b"Z"].concat())
            })
        }),
    );
    let mode_changes = group(
        "ISO ordered designation changes",
        modes.iter().flat_map(|from| {
            modes.iter().flat_map(move |to| {
                [0x00, 0x1b, 0x20, 0x21, 0x5c, 0x7e, 0x7f, 0x80, 0xff]
                    .into_iter()
                    .flat_map(move |byte| {
                        [b"".as_slice(), b"Q"].into_iter().map(move |prefix| {
                            [prefix, from, b"!A", to, &[byte], b"\x1b(BZ"].concat()
                        })
                    })
            })
        }),
    );
    // Include every byte (and EOF) after each partial escape at the
    // actual start of input so bare, truncated designations are measured.
    let initial_escapes = group(
        "ISO initial escape prefixes at EOF",
        [b"\x1b".as_slice(), b"\x1b(", b"\x1b$", b"\x1b$("]
            .into_iter()
            .flat_map(|prefix| {
                std::iter::once(prefix.to_vec())
                    .chain((0..=255).map(move |byte| [prefix, &[byte]].concat()))
            }),
    );
    vec![at_eof, with_ascii, mode_changes, random_streams(case.label), initial_escapes]
}

/// Builds stream, state-transition, and midstream-signature groups for a native route.
pub fn comprehensive_groups(case: &Case) -> Vec<Group> {
    let mut groups = match case.domain {
        Domain::Single => single_byte_groups(case.label),
        Domain::Iso2022Jp => iso2022_groups(case),
        _ => variable_groups(case),
    };
    // Q makes each BOM signature midstream input to the legacy decoder;
    // Z exposes its recovery into ASCII.
    groups.push(
        group(
            "midstream Unicode signature bytes",
            [b"\xef\xbb\xbf".as_slice(), b"\xff\xfe", b"\xfe\xff"]
                .into_iter()
                .map(|signature| [b"Q".as_slice(), signature, b"Z"].concat()),
        )
        .curated(),
    );
    groups
}
