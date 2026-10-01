use serde::Serialize;

#[derive(Clone, Serialize)]
pub struct Reference {
    pub codepoints: Vec<u32>,
    pub had_errors: bool,
}

#[derive(Default, Serialize)]
pub struct Stats {
    pub valid: usize,
    pub valid_match: usize,
    pub invalid: usize,
    pub invalid_match: usize,
    pub failed_valid: usize,
    pub failed_invalid: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icu_stop_wrong: Option<StopCounts>,
    pub valid_examples: Vec<String>,
    pub invalid_examples: Vec<String>,
    #[serde(skip)]
    limit: usize,
}

#[derive(Default, Serialize)]
pub struct StopCounts {
    pub reported_error: usize,
    pub accepted: usize,
}

impl Stats {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            ..Self::default()
        }
    }

    pub fn add(&mut self, data: &[u8], expected: &Reference, actual: Option<&[u32]>, error: u32) {
        assert!(actual.is_none() || error == 0, "native error with output");
        let (total, matches, failures, examples) = if expected.had_errors {
            (
                &mut self.invalid,
                &mut self.invalid_match,
                &mut self.failed_invalid,
                &mut self.invalid_examples,
            )
        } else {
            (
                &mut self.valid,
                &mut self.valid_match,
                &mut self.failed_valid,
                &mut self.valid_examples,
            )
        };
        *total += 1;
        if actual == Some(&expected.codepoints) {
            *matches += 1;
        } else {
            if actual.is_none() {
                *failures += 1;
            }
            if examples.len() < self.limit {
                let got =
                    actual.map_or_else(|| format!("native failure ({error})"), format_codepoints);
                examples.push(format!(
                    "{}: {} -> {got}",
                    hex(data),
                    format_codepoints(&expected.codepoints),
                ));
            }
        }
    }

    pub fn classify_icu_mismatch(&mut self, reported_error: bool) {
        let counts = self
            .icu_stop_wrong
            .as_mut()
            .expect("ICU STOP counts initialized");
        if reported_error {
            counts.reported_error += 1;
        } else {
            counts.accepted += 1;
        }
    }

    pub fn summary(&self) -> String {
        let mut summary = format!(
            "valid {}/{}; invalid {}/{}; native failures {}/{} (valid/invalid)",
            self.valid_match,
            self.valid,
            self.invalid_match,
            self.invalid,
            self.failed_valid,
            self.failed_invalid
        );
        if let Some(stop) = &self.icu_stop_wrong {
            summary.push_str(&format!(
                "; ICU wrong output (STOP error/accepted) {}/{}",
                stop.reported_error, stop.accepted
            ));
        }
        summary
    }
}

pub fn oracle(label: &str, data: &[u8]) -> Reference {
    let encoding = encoding_rs::Encoding::for_label(label.as_bytes())
        .expect("built-in native route must have a WHATWG encoding");
    // U+FFFD can be an assigned mapping (GB18030 84 31 A4 37), so the
    // decoder's error flag, rather than its output, determines validity.
    let (decoded, had_errors) = encoding.decode_without_bom_handling(data);
    Reference {
        codepoints: decoded.chars().map(u32::from).collect(),
        had_errors,
    }
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn format_codepoints(sequence: &[u32]) -> String {
    if sequence.is_empty() {
        "(empty)".to_owned()
    } else {
        sequence
            .iter()
            .map(|point| format!("U+{point:04X}"))
            .collect::<Vec<_>>()
            .join("+")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores_the_entire_output_in_separate_validity_buckets() {
        let mut stats = Stats::new(2);
        let valid_replacement = oracle("gb18030", b"\x84\x31\xa4\x37");
        assert_eq!(valid_replacement.codepoints, [0xfffd]);
        assert!(!valid_replacement.had_errors);
        stats.add(b"\x84\x31\xa4\x37", &valid_replacement, Some(&[0xfffd]), 0);
        stats.add(b"\x84\x31\xa4\x37", &valid_replacement, None, 1113);

        let invalid = oracle("shift_jis", b"\x82\"");
        assert_eq!(invalid.codepoints, [0xfffd, u32::from(b'"')]);
        stats.add(b"\x82\"", &invalid, Some(&[0xfffd]), 0);
        stats.add(b"\x82\"", &invalid, Some(&[0xfffd, u32::from(b'"')]), 0);
        assert_eq!((stats.valid, stats.valid_match, stats.failed_valid), (2, 1, 1));
        assert_eq!((stats.invalid, stats.invalid_match, stats.failed_invalid), (2, 1, 0));
        assert_eq!(stats.valid_examples.len(), 1);
        assert_eq!(stats.invalid_examples, ["8222: U+FFFD+U+0022 -> U+FFFD"]);
    }

    #[test]
    fn stop_classifies_only_icu_wrong_output_without_changing_scores() {
        let mut stats = Stats::new(0);
        stats.icu_stop_wrong = Some(StopCounts::default());
        let expected = oracle("shift_jis", b"\x82\"");
        stats.add(b"\x82\"", &expected, Some(&[0xfffd]), 0);
        stats.classify_icu_mismatch(true);
        stats.add(b"\x82\"", &expected, Some(&[0x003f]), 0);
        stats.classify_icu_mismatch(false);
        stats.add(b"\x82\"", &expected, Some(&expected.codepoints), 0);
        stats.add(b"\x82\"", &expected, None, 10);
        let counts = stats.icu_stop_wrong.unwrap();
        assert_eq!((stats.invalid, stats.invalid_match, stats.failed_invalid), (4, 1, 1));
        assert_eq!((counts.reported_error, counts.accepted), (1, 1));
    }
}
