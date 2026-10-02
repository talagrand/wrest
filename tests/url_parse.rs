//! URL parsing conformance tests against the WHATWG `urltestdata.json`
//! test suite from [web-platform-tests](https://github.com/web-platform-tests/wpt).
//!
//! Each test case is classified as either:
//! - **RFC-comparable**: well-formed RFC 3986 input whose component meaning
//!   is directly comparable with WHATWG. Zero failures expected.
//! - **Error-recovery**: invalid or edge-case input where behavior differs
//!   between strict RFC parsing and WHATWG. Divergences are tracked but not
//!   failures.
//!
//! To run:
//! ```
//! cargo test --test url_parse
//! ```

// The entire test file requires TLS.  On native WinHTTP, TLS is always
// available via Schannel.  On reqwest passthrough, a TLS feature must be
// enabled.  When neither is true the file compiles to nothing.
#![cfg(any(native_winhttp, feature = "default-tls", feature = "native-tls"))]
#![expect(clippy::tests_outside_test_module)]

use wrest::Url;

// Pin the corpus so upstream expectation changes cannot break CI without a code change.
// To refresh, bump to a newer tag from https://github.com/web-platform-tests/wpt
// (tags under `epochs/weekly/`).
const URLTESTDATA_URL: &str = concat!(
    "https://raw.githubusercontent.com/web-platform-tests/wpt/",
    "epochs/weekly/2026-09-28_05H",
    "/url/resources/urltestdata.json"
);

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum UrlTestEntry {
    Test(UrlTestCase),
    #[expect(dead_code, reason = "WPT comment text is intentionally ignored")]
    Comment(String),
}

#[derive(serde::Deserialize)]
struct UrlTestCase {
    input: String,
    #[serde(default)]
    base: Option<String>,
    #[serde(default)]
    failure: bool,
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    port: String,
    #[serde(default)]
    pathname: String,
    #[serde(default)]
    search: String,
    #[serde(default)]
    hash: String,
}

#[derive(Clone, Copy)]
#[expect(
    dead_code,
    reason = "each backend constructs only its applicable difference variants"
)]
enum KnownDifference {
    ParseFailure {
        input: &'static str,
    },
    Hostname {
        input: &'static str,
        expected: &'static str,
    },
}

impl KnownDifference {
    fn input(self) -> &'static str {
        match self {
            Self::ParseFailure { input } | Self::Hostname { input, .. } => input,
        }
    }
}

/// Fetch the WHATWG `urltestdata.json` from GitHub and run every applicable
/// test case against `wrest::Url::parse`.
#[tokio::test]
async fn whatwg_urltestdata() {
    let client = wrest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("client build should succeed");

    let resp = client
        .get(URLTESTDATA_URL)
        .send()
        .await
        .expect("failed to fetch urltestdata.json");

    assert_eq!(
        resp.status(),
        wrest::StatusCode::OK,
        "unexpected status fetching urltestdata.json: {}",
        resp.status()
    );

    let body = resp.text().await.expect("failed to read response body");
    let entries: Vec<UrlTestEntry> =
        serde_json::from_str(&body).expect("failed to parse urltestdata.json");
    let object_test_cases = entries
        .iter()
        .filter(|entry| matches!(entry, UrlTestEntry::Test(_)))
        .count();
    assert_known_differences(&entries);

    let mut tested = 0usize;
    let mut skipped = SkipCounts::default();
    let mut rfc_comparable_tested = 0usize;
    let mut rfc_comparable_failures: Vec<String> = Vec::new();
    let mut error_recovery_divergences = 0usize;

    for entry in &entries {
        let case = match entry {
            UrlTestEntry::Test(case) => case,
            UrlTestEntry::Comment(_) => continue,
        };

        // Skip relative-URL tests (base != null).
        if case.base.is_some() {
            skipped.relative_url += 1;
            continue;
        }

        let input = case.input.as_str();

        // Expected-failure tests.
        if case.failure {
            if input.starts_with("http://") || input.starts_with("https://") {
                if Url::parse(input).is_ok() {
                    error_recovery_divergences += 1;
                }
                tested += 1;
            } else {
                skipped.non_http_failure += 1;
            }
            continue;
        }

        // Only test http/https success cases.
        let protocol = case.protocol.as_str();
        if protocol != "http:" && protocol != "https:" {
            skipped.non_http_success += 1;
            continue;
        }

        let is_rfc_comparable = is_rfc_comparable_input(input);

        let parsed = match Url::parse(input) {
            Ok(u) => u,
            Err(e) => {
                if is_rfc_comparable {
                    rfc_comparable_failures
                        .push(format!("parse failed for RFC-comparable URL {input:?}: {e}"));
                } else {
                    error_recovery_divergences += 1;
                }
                if is_rfc_comparable {
                    rfc_comparable_tested += 1;
                }
                tested += 1;
                continue;
            }
        };

        let expected_path = case.pathname.as_str();
        let expected_search = case.search.as_str();
        let expected_hash = case.hash.as_str();
        let expected_hostname = case.hostname.as_str();
        let expected_port = case.port.as_str();

        let path_ok = components_equivalent(parsed.path(), expected_path);
        let hostname_ok = parsed.host_str() == Some(expected_hostname);
        let port_ok = match expected_port {
            "" => parsed.port().is_none(),
            port => port.parse::<u16>().ok() == parsed.port(),
        };
        let actual_search = match parsed.query() {
            Some(q) => format!("?{q}"),
            None => String::new(),
        };
        let search_ok = components_equivalent(&actual_search, expected_search);
        let actual_hash = match parsed.fragment() {
            Some(f) => format!("#{f}"),
            None => String::new(),
        };
        let hash_ok = components_equivalent(&actual_hash, expected_hash);

        if !hostname_ok || !port_ok || !path_ok || !search_ok || !hash_ok {
            let msg = format!(
                "{input:?}: hostname={:?}(exp {:?}), port={:?}(exp {:?}), \
                 path={:?}(exp {:?}), search={:?}(exp {:?}), hash={:?}(exp {:?})",
                parsed.host_str(),
                expected_hostname,
                parsed.port(),
                expected_port,
                parsed.path(),
                expected_path,
                actual_search,
                expected_search,
                actual_hash,
                expected_hash,
            );
            if is_rfc_comparable {
                rfc_comparable_failures.push(msg);
            } else {
                error_recovery_divergences += 1;
            }
        }

        if is_rfc_comparable {
            rfc_comparable_tested += 1;
        }
        tested += 1;
    }

    let skipped = skipped.total();
    eprintln!(
        "WHATWG urltestdata: {tested} tested, {skipped} skipped, \
         {rfc_comparable_tested} RFC-comparable, \
         {error_recovery_divergences} error-recovery divergences"
    );

    assert_eq!(
        tested + skipped,
        object_test_cases,
        "every object test case must be exercised or deliberately skipped"
    );
    assert!(tested >= 100, "too few corpus cases were exercised: {tested}");
    assert!(
        rfc_comparable_tested >= 40,
        "too few RFC-comparable corpus cases were exercised: {rfc_comparable_tested}"
    );

    // RFC-comparable URLs MUST match exactly -- zero failures.
    assert!(
        rfc_comparable_failures.is_empty(),
        "RFC-comparable URLs had {} failures:\n{}",
        rfc_comparable_failures.len(),
        rfc_comparable_failures.join("\n")
    );
}

#[derive(Default)]
struct SkipCounts {
    relative_url: usize,
    non_http_failure: usize,
    non_http_success: usize,
}

impl SkipCounts {
    fn total(&self) -> usize {
        self.relative_url
            .checked_add(self.non_http_failure)
            .and_then(|total| total.checked_add(self.non_http_success))
            .expect("skip count overflow")
    }
}

fn is_rfc_comparable_input(input: &str) -> bool {
    is_rfc_clean_input(input) && known_difference(input).is_none()
}

fn known_difference(input: &str) -> Option<KnownDifference> {
    known_differences()
        .iter()
        .copied()
        .find(|difference| difference.input() == input)
}

fn assert_known_differences(entries: &[UrlTestEntry]) {
    for difference in known_differences().iter().copied() {
        let input = difference.input();
        let case = entries
            .iter()
            .find_map(|entry| match entry {
                UrlTestEntry::Test(case) if case.input == input => Some(case),
                _ => None,
            })
            .unwrap_or_else(|| panic!("known difference is absent from the corpus: {input:?}"));
        assert!(!case.failure, "{input}: corpus now expects parse failure");

        match difference {
            KnownDifference::ParseFailure { .. } => {
                assert!(Url::parse(input).is_err(), "{input}: expected backend parse failure");
            }
            KnownDifference::Hostname { expected, .. } => {
                assert_ne!(
                    case.hostname, expected,
                    "{input}: corpus hostname now matches the backend exception"
                );
                assert_eq!(
                    Url::parse(input)
                        .expect("known hostname difference should parse")
                        .host_str(),
                    Some(expected),
                    "{input}: backend hostname difference"
                );
            }
        }
    }
}

fn known_differences() -> &'static [KnownDifference] {
    #[cfg(native_winhttp)]
    {
        // WHATWG reinterprets these RFC registered names as legacy IPv4
        // addresses. Wrest intentionally preserves the registered names.
        &[
            KnownDifference::Hostname {
                input: "http://192.0x00A80001",
                expected: "192.0x00a80001",
            },
            KnownDifference::Hostname {
                input: "https://0x.0x.0",
                expected: "0x.0x.0",
            },
            KnownDifference::Hostname {
                input: "https://0x.0x.0x.0x",
                expected: "0x.0x.0x.0x",
            },
            KnownDifference::Hostname {
                input: "https://00.00.00.00",
                expected: "00.00.00.00",
            },
            KnownDifference::Hostname {
                input: "https://0000000000000000000000000000000000000000177.0.0.1",
                expected: "0000000000000000000000000000000000000000177.0.0.1",
            },
        ]
    }

    #[cfg(not(native_winhttp))]
    {
        // Reqwest's current IDNA implementation rejects these RFC-comparable
        // WPT cases instead of preserving the A-label as the corpus expects.
        &[
            KnownDifference::ParseFailure {
                input: "http://a.b.c.xn--pokxncvks",
            },
            KnownDifference::ParseFailure {
                input: "http://10.0.0.xn--pokxncvks",
            },
            KnownDifference::ParseFailure {
                input: "http://a.b.c.XN--pokxncvks",
            },
            KnownDifference::ParseFailure {
                input: "http://a.b.c.Xn--pokxncvks",
            },
            KnownDifference::ParseFailure {
                input: "http://10.0.0.XN--pokxncvks",
            },
            KnownDifference::ParseFailure {
                input: "http://10.0.0.xN--pokxncvks",
            },
            KnownDifference::ParseFailure {
                input: "https://xn--/",
            },
        ]
    }
}

/// Returns `true` if `input` is a syntactically valid RFC URI whose
/// components can be compared directly with the WHATWG expectation.
fn is_rfc_clean_input(input: &str) -> bool {
    // Must have scheme://authority form.
    if !input.contains("://") || has_invalid_percent_encoding(input) {
        return false;
    }
    for b in input.bytes() {
        // C0 controls, DEL, non-ASCII, space, backslash
        if b <= 0x1F || b == 0x7F || b == b' ' || b == b'\\' || b > 0x7E {
            return false;
        }
        // Exclude raw characters whose treatment is component-specific:
        // strict RFC syntax rejects some, while WHATWG may percent-encode them;
        // WHATWG special-query parsing also encodes apostrophes permitted by RFC.
        if matches!(b, b'"' | b'<' | b'>' | b'`' | b'\'') {
            return false;
        }
    }
    // Dot-segments are normalized by WHATWG during parsing but only during
    // reference resolution under RFC 3986.
    if input.contains("/./")
        || input.contains("/../")
        || input.ends_with("/.")
        || input.ends_with("/..")
        || input.contains("%2e")
        || input.contains("%2E")
    {
        return false;
    }
    // The WHATWG fixture uses an empty string for both absent and explicitly
    // empty fragments, while Wrest preserves delimiter presence as Some("").
    if input.ends_with('#') {
        return false;
    }
    true
}

#[test]
fn rfc_comparable_classifier_table() {
    let cases = [
        ("https://example.com:8443/path?query#fragment", true),
        ("https://example.com/path/../next", false),
        ("https://example.com/%zz", false),
        ("https://example.com/#", false),
    ];

    for (input, expected) in cases {
        assert_eq!(is_rfc_comparable_input(input), expected, "{input}");
    }
}

#[test]
fn known_differences_are_not_rfc_comparable() {
    for difference in known_differences() {
        let input = difference.input();
        assert!(!is_rfc_comparable_input(input), "{input}");
    }
}

fn has_invalid_percent_encoding(input: &str) -> bool {
    let mut bytes = input.as_bytes().iter().copied();
    while let Some(byte) = bytes.next() {
        if byte == b'%'
            && !matches!(
                (bytes.next(), bytes.next()),
                (Some(high), Some(low)) if high.is_ascii_hexdigit() && low.is_ascii_hexdigit()
            )
        {
            return true;
        }
    }
    false
}

#[cfg(native_winhttp)]
#[test]
fn known_hostname_differences_match_backend_policy() {
    for difference in known_differences() {
        let KnownDifference::Hostname { input, expected } = *difference else {
            continue;
        };

        assert!(!is_rfc_comparable_input(input), "{input}: RFC-comparable filter");
        assert_eq!(Url::parse(input).unwrap().host_str(), Some(expected), "{input}");
    }
}

/// Compare two URL component strings, treating percent-encoded hex digits
/// case-insensitively (e.g., `%2f` == `%2F`).
fn components_equivalent(a: &str, b: &str) -> bool {
    let mut a = a.bytes();
    let mut b = b.bytes();

    loop {
        match (a.next(), b.next()) {
            (None, None) => return true,
            (Some(b'%'), Some(b'%')) => {
                let escape = (a.next(), a.next(), b.next(), b.next());
                match escape {
                    (Some(a_high), Some(a_low), Some(b_high), Some(b_low))
                        if a_high.is_ascii_hexdigit()
                            && a_low.is_ascii_hexdigit()
                            && b_high.is_ascii_hexdigit()
                            && b_low.is_ascii_hexdigit()
                            && a_high.eq_ignore_ascii_case(&b_high)
                            && a_low.eq_ignore_ascii_case(&b_low) => {}
                    _ => return false,
                }
            }
            (Some(a), Some(b)) if a == b => {}
            _ => return false,
        }
    }
}

#[test]
fn component_comparison_only_folds_percent_escape_hex() {
    let cases = [
        ("/same/path", "/same/path", true),
        ("/a%2fb", "/a%2Fb", true),
        ("/a%aFb", "/a%AFb", true),
        ("/Users/A", "/users/a", false),
        ("/left", "/right", false),
    ];

    for (left, right, expected) in cases {
        assert_eq!(components_equivalent(left, right), expected, "{left:?} vs {right:?}");
    }
}

#[test]
fn at_sign_outside_authority_table() {
    let cases = [
        (
            "https://trusted.example?next=@attacker.example/collect",
            Some("next=@attacker.example/collect"),
            None,
        ),
        ("https://trusted.example/path?@attacker.example", Some("@attacker.example"), None),
        (
            "https://trusted.example/path#@attacker.example/collect",
            None,
            Some("@attacker.example/collect"),
        ),
    ];

    for (input, query, fragment) in cases {
        let url = Url::parse(input).unwrap();
        assert_eq!(url.host_str(), Some("trusted.example"), "{input}: host");
        assert_eq!(url.query(), query, "{input}: query");
        assert_eq!(url.fragment(), fragment, "{input}: fragment");
    }
}

#[test]
fn relative_reference_userinfo_table() {
    let input = concat!("https://", "alice", ":", "secret", "@example.com/a/b");
    let base = Url::parse(input).unwrap();
    let cases = [
        ("../next", "alice", Some("secret")),
        ("?q=1", "alice", Some("secret")),
        ("#next", "alice", Some("secret")),
        ("//other.example/path", "", None),
        ("https://other.example/path", "", None),
    ];

    for (reference, username, password) in cases {
        let joined = base.join(reference).unwrap();
        assert_eq!(joined.username(), username, "{reference}: username");
        assert_eq!(joined.password(), password, "{reference}: password");
    }
}

#[test]
fn empty_delimiter_reference_table() {
    let base = Url::parse("https://example.com/a/b?old=1#old").unwrap();
    let cases = [
        ("", Some("old=1"), None, "https://example.com/a/b?old=1"),
        ("?", Some(""), None, "https://example.com/a/b?"),
        ("#", Some("old=1"), Some(""), "https://example.com/a/b?old=1#"),
        ("?#", Some(""), Some(""), "https://example.com/a/b?#"),
    ];

    for (reference, query, fragment, serialized) in cases {
        let joined = base.join(reference).unwrap();
        assert_eq!(joined.query(), query, "{reference:?}: query");
        assert_eq!(joined.fragment(), fragment, "{reference:?}: fragment");
        assert_eq!(joined.as_str(), serialized, "{reference:?}: serialization");
    }
}

#[test]
fn absolute_scheme_case_table() {
    let base = Url::parse("https://example.com/a").unwrap();
    let cases = [("HTTP://other.example/path", "http"), ("hTtPs://other.example/path", "https")];

    for (reference, scheme) in cases {
        assert_eq!(base.join(reference).unwrap().scheme(), scheme, "{reference}");
    }
}

#[cfg(native_winhttp)]
#[test]
fn native_rejects_non_http_scheme_table() {
    let base = Url::parse("https://example.com/a").unwrap();
    let cases = [
        "ftp://other.example/path",
        "ws://other.example/path",
        "wss://other.example/path",
        "file:///tmp/file",
        "custom://other.example/path",
    ];

    for reference in cases {
        assert_eq!(
            base.join(reference).unwrap_err(),
            wrest::ParseError::UnsupportedScheme,
            "{reference}"
        );
    }
}

#[cfg(native_winhttp)]
#[test]
fn native_unicode_domain_table() {
    let cases =
        [("https://faß.de/path", "xn--fa-hia.de"), ("https://café.fr/path", "xn--caf-dma.fr")];

    for (input, expected_host) in cases {
        match Url::parse(input) {
            Ok(url) => assert_eq!(url.host_str(), Some(expected_host), "{input}"),
            Err(error) => assert_eq!(error, wrest::ParseError::IdnaError, "{input}"),
        }
    }
}
