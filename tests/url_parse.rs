//! URL parsing conformance tests against the WHATWG `urltestdata.json`
//! test suite from [web-platform-tests](https://github.com/web-platform-tests/wpt).
//!
//! Each test case is classified as either:
//! - **RFC-clean**: well-formed RFC 3986 input whose component meaning is
//!   directly comparable with WHATWG. Zero failures expected.
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
// This is the last revision before WPT b63305b changed `xn--` A-label
// expectations, which affect reqwest itself.
const URLTESTDATA_URL: &str = concat!(
    "https://raw.githubusercontent.com/web-platform-tests/wpt/",
    "f28876b96acf16e0408b9cce4bd3b40a729375d4",
    "/url/resources/urltestdata.json"
);

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
    let entries: Vec<serde_json::Value> =
        serde_json::from_str(&body).expect("failed to parse urltestdata.json");

    let mut tested = 0u32;
    let mut skipped = 0u32;
    let mut rfc_clean_tested = 0u32;
    let mut rfc_clean_failures: Vec<String> = Vec::new();
    let mut error_recovery_divergences = 0u32;

    for entry in &entries {
        let Some(obj) = entry.as_object() else {
            continue; // skip comment strings
        };

        // Skip relative-URL tests (base != null).
        match obj.get("base") {
            Some(serde_json::Value::Null) => {}
            None => {}
            _ => {
                skipped += 1;
                continue;
            }
        }

        let input = obj["input"].as_str().unwrap();

        // Expected-failure tests.
        if obj.contains_key("failure") {
            if input.starts_with("http://") || input.starts_with("https://") {
                if Url::parse(input).is_ok() {
                    error_recovery_divergences += 1;
                }
                tested += 1;
            } else {
                skipped += 1;
            }
            continue;
        }

        // Only test http/https success cases.
        let protocol = obj.get("protocol").and_then(|v| v.as_str()).unwrap_or("");
        if protocol != "http:" && protocol != "https:" {
            skipped += 1;
            continue;
        }

        let is_rfc_clean = is_rfc_clean_input(input);

        let parsed = match Url::parse(input) {
            Ok(u) => u,
            Err(e) => {
                if is_rfc_clean {
                    rfc_clean_failures
                        .push(format!("parse failed for RFC-clean URL {input:?}: {e}"));
                } else {
                    error_recovery_divergences += 1;
                }
                if is_rfc_clean {
                    rfc_clean_tested += 1;
                }
                tested += 1;
                continue;
            }
        };

        let expected_path = obj["pathname"].as_str().unwrap();
        let expected_search = obj["search"].as_str().unwrap();
        let expected_hash = obj["hash"].as_str().unwrap();

        let path_ok = components_equivalent(parsed.path(), expected_path);
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

        if !path_ok || !search_ok || !hash_ok {
            let msg = format!(
                "{input:?}: path={:?}(exp {:?}), search={:?}(exp {:?}), hash={:?}(exp {:?})",
                parsed.path(),
                expected_path,
                actual_search,
                expected_search,
                actual_hash,
                expected_hash,
            );
            if is_rfc_clean {
                rfc_clean_failures.push(msg);
            } else {
                error_recovery_divergences += 1;
            }
        }

        if is_rfc_clean {
            rfc_clean_tested += 1;
        }
        tested += 1;
    }

    eprintln!(
        "WHATWG urltestdata: {tested} tested, {skipped} skipped, \
         {rfc_clean_tested} RFC-clean, \
         {error_recovery_divergences} error-recovery divergences"
    );

    assert!(tested >= 100, "too few tests ran: {tested}");
    assert!(rfc_clean_tested >= 40, "too few RFC-clean tests: {rfc_clean_tested}");

    // RFC-clean URLs MUST match exactly -- zero failures.
    assert!(
        rfc_clean_failures.is_empty(),
        "RFC-clean URLs had {} failures:\n{}",
        rfc_clean_failures.len(),
        rfc_clean_failures.join("\n")
    );
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
