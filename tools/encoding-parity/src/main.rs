#[cfg(not(windows))]
compile_error!("encoding-parity is a Windows-only diagnostic");

mod analysis;
mod corpus;
mod icu;
mod nls;
mod score;

use crate::{
    analysis::comprehensive_groups,
    corpus::{
        CASES, Case, Coverage, DEFAULT_FOUR_BYTE_SAMPLES, GB18030_FOUR_BYTE_POINTERS, Group,
        exclude_initial_boms, group, groups,
    },
    icu::{available_names, icu_version, registered_aliases, score_icu},
    nls::score_nls,
    score::{Reference, Stats, oracle},
};
use clap::{Parser, ValueEnum};
use serde::Serialize;
use sha2::{Digest, Sha256};
use windows_version::OsVersion;

#[derive(Clone, Copy, Default, ValueEnum)]
enum OutputFormat {
    #[default]
    Human,
    Json,
}

#[derive(Parser)]
#[command(about = "Compare WHATWG decoding with Windows NLS and ICU")]
struct Cli {
    /// Native-converter encoding; omit to measure all built-in routes.
    #[arg(long, value_parser = parse_encoding)]
    encoding: Option<String>,
    /// Compare another ICU converter name for the selected encoding.
    #[arg(long, requires = "encoding")]
    icu_name: Vec<String>,
    /// List installed ICU converter names and exit.
    #[arg(long, conflicts_with = "list_aliases")]
    list_icu: bool,
    /// List installed aliases, their catalog entries, and resolved converters.
    #[arg(long)]
    list_aliases: bool,
    /// Compare every installed ICU converter with one WHATWG encoding (slow).
    #[arg(long, requires = "encoding", conflicts_with = "installed_survey")]
    all_icu: bool,
    /// Screen all installed converters against bounded grids for all routes (slow).
    #[arg(
        long,
        conflicts_with_all = ["icu_name", "input_hex", "list_icu", "list_aliases"]
    )]
    installed_survey: bool,
    /// Number of evenly spaced GB four-byte pointers (0 skips them).
    #[arg(long, value_name = "N", value_parser = parse_four_byte_count)]
    four_byte_samples: Option<usize>,
    /// Number of valid and invalid mismatch examples per group and backend.
    #[arg(long, default_value_t = 3)]
    examples: usize,
    /// Replay raw bytes under one requested legacy encoding.
    #[arg(long, value_name = "HEX", value_parser = parse_hex, requires = "encoding",
          conflicts_with = "four_byte_samples")]
    input_hex: Vec<Vec<u8>>,
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    format: OutputFormat,
}

fn parse_four_byte_count(raw: &str) -> Result<usize, String> {
    let count = raw.parse::<usize>().map_err(|error| error.to_string())?;
    if count > GB18030_FOUR_BYTE_POINTERS {
        return Err(format!("must be 0..={GB18030_FOUR_BYTE_POINTERS}"));
    }
    Ok(count)
}

fn parse_encoding(raw: &str) -> Result<String, String> {
    if CASES.iter().any(|case| case.label == raw) {
        Ok(raw.to_owned())
    } else {
        Err(format!("unknown native-converter encoding {raw:?}; see src\\corpus.rs"))
    }
}

fn parse_hex(raw: &str) -> Result<Vec<u8>, String> {
    if raw.is_empty() || !raw.len().is_multiple_of(2) {
        return Err("expected a nonempty, even-length hex string".into());
    }
    raw.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|error| error.to_string())?;
            u8::from_str_radix(text, 16).map_err(|error| error.to_string())
        })
        .collect()
}

#[derive(Serialize)]
struct Measurement {
    name: String,
    resolved: Option<String>,
    stats: Option<Stats>,
}

#[derive(Serialize)]
struct Replay {
    hex: String,
    oracle: Reference,
}

#[derive(Serialize)]
struct GroupReport {
    name: &'static str,
    inputs: usize,
    coverage: Coverage,
    input_sha256: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    replay: Vec<Replay>,
    measurements: Vec<Measurement>,
}

#[derive(Serialize)]
struct CaseReport {
    encoding: &'static str,
    groups: Vec<GroupReport>,
}

#[derive(Serialize)]
struct Report {
    profile: &'static str,
    command: Vec<String>,
    four_byte_samples: usize,
    windows_build: u32,
    icu_version: String,
    cases: Vec<CaseReport>,
}

fn fingerprint(inputs: &[Vec<u8>]) -> String {
    // Length-prefix each input so [01,02] hashes differently from [01],[02].
    let mut hash = Sha256::new();
    for input in inputs {
        hash.update((input.len() as u64).to_le_bytes());
        hash.update(input);
    }
    format!("{:x}", hash.finalize())
}

fn measure(group: Group, case: &Case, cli: &Cli, candidates: &[&str]) -> GroupReport {
    let input_sha256 = fingerprint(&group.inputs);
    let rows: Vec<_> = group
        .inputs
        .into_iter()
        .map(|data| {
            let expected = oracle(case.label, &data);
            (data, expected)
        })
        .collect();
    let replay = if group.name == "replay" {
        rows.iter()
            .map(|(bytes, expected)| Replay {
                hex: bytes.iter().map(|byte| format!("{byte:02X}")).collect(),
                oracle: expected.clone(),
            })
            .collect()
    } else {
        Vec::new()
    };
    let mut measurements = Vec::new();
    if let Some(codepage) = case.codepage {
        measurements.push(Measurement {
            name: format!("Win32 CP{codepage} flags=0"),
            resolved: None,
            stats: Some(score_nls(codepage, &rows, cli.examples)),
        });
    }
    for &name in candidates {
        let measured = score_icu(name, &rows, cli.examples);
        assert!(
            name != case.icu || measured.is_some(),
            "selected ICU converter {name:?} is unavailable"
        );
        let (resolved, stats) = match measured {
            Some((resolved, stats)) => (Some(resolved), Some(stats)),
            None => (None, None),
        };
        measurements.push(Measurement {
            name: format!("ICU {name}"),
            resolved,
            stats,
        });
    }
    GroupReport {
        name: group.name,
        inputs: rows.len(),
        coverage: group.coverage,
        input_sha256,
        replay,
        measurements,
    }
}

fn run(cli: Cli) {
    let windows_build = OsVersion::current().build;
    if cli.list_icu {
        let names = available_names();
        if matches!(cli.format, OutputFormat::Json) {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "windows_build": windows_build, "icu_version": icu_version(),
                    "available_names": names
                }))
                .expect("serialize catalog")
            );
        } else {
            println!("Windows build {}; ICU {}", windows_build, icu_version());
            println!("{}", names.join("\n"));
        }
        return;
    }
    if cli.list_aliases {
        let aliases = registered_aliases();
        if matches!(cli.format, OutputFormat::Json) {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "windows_build": windows_build, "icu_version": icu_version(),
                    "aliases": aliases
                }))
                .expect("serialize aliases")
            );
        } else {
            println!("Windows build {}; ICU {}", windows_build, icu_version());
            println!("Catalog\tAlias\tResolved");
            for entry in aliases {
                println!("{}\t{}\t{}", entry.catalog, entry.alias, entry.resolved);
            }
        }
        return;
    }
    let cases: Vec<&Case> = match &cli.encoding {
        Some(label) => vec![CASES.iter().find(|case| case.label == label).unwrap()],
        None => CASES.iter().collect(),
    };
    let screening = cli.installed_survey || cli.all_icu;
    let four_byte_samples = if !cli.input_hex.is_empty() {
        0
    } else {
        cli.four_byte_samples.unwrap_or(if cli.installed_survey {
            0
        } else if cli.all_icu {
            DEFAULT_FOUR_BYTE_SAMPLES
        } else {
            GB18030_FOUR_BYTE_POINTERS
        })
    };
    let installed = if cli.all_icu || cli.installed_survey {
        available_names()
    } else {
        Vec::new()
    };
    let mut report = Report {
        profile: if !cli.input_hex.is_empty() {
            "replay"
        } else if screening {
            "installed-survey"
        } else {
            "comprehensive"
        },
        command: std::env::args().skip(1).collect(),
        four_byte_samples,
        windows_build,
        icu_version: icu_version(),
        cases: Vec::new(),
    };
    for case in cases {
        let mut candidates = vec![case.icu];
        if !screening {
            candidates.extend(case.variants);
        }
        candidates.extend(cli.icu_name.iter().map(String::as_str));
        candidates.extend(installed.iter().map(String::as_str));
        let mut unique = Vec::new();
        for name in candidates {
            if !unique.contains(&name) {
                unique.push(name);
            }
        }
        let generated = if cli.input_hex.is_empty() {
            let mut generated = groups(case, four_byte_samples, screening);
            if !screening {
                generated.extend(comprehensive_groups(case));
            }
            exclude_initial_boms(&mut generated);
            generated
        } else {
            vec![group("replay", cli.input_hex.clone()).curated()]
        };
        let groups = generated
            .into_iter()
            .map(|group| measure(group, case, &cli, &unique))
            .collect();
        report.cases.push(CaseReport {
            encoding: case.label,
            groups,
        });
    }
    if matches!(cli.format, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&report).expect("serialize report"));
    } else {
        println!(
            "Windows build {}; ICU {}; {}",
            report.windows_build, report.icu_version, report.profile
        );
        for case in &report.cases {
            println!("\n{}:", case.encoding);
            for group in &case.groups {
                println!(
                    "  {}: {} inputs ({:?}), SHA-256 {}",
                    group.name, group.inputs, group.coverage, group.input_sha256
                );
                for replay in &group.replay {
                    println!(
                        "    {}: oracle {:?}, error={}",
                        replay.hex, replay.oracle.codepoints, replay.oracle.had_errors
                    );
                }
                for measurement in &group.measurements {
                    let name = match &measurement.resolved {
                        Some(resolved) => format!("{} ({resolved})", measurement.name),
                        None => measurement.name.clone(),
                    };
                    if let Some(stats) = &measurement.stats {
                        println!("    {name}: {}", stats.summary());
                        for example in &stats.valid_examples {
                            println!("      valid: {example}");
                        }
                        for example in &stats.invalid_examples {
                            println!("      invalid: {example}");
                        }
                    } else {
                        println!("    {name}: unavailable");
                    }
                }
            }
        }
    }
}

fn main() {
    run(Cli::parse());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_preserve_input_boundaries_and_order() {
        assert_ne!(fingerprint(&[vec![1, 2]]), fingerprint(&[vec![1], vec![2]]));
        assert_ne!(fingerprint(&[vec![1], vec![2]]), fingerprint(&[vec![2], vec![1]]));
    }

    #[test]
    fn comprehensive_shapes_cover_iso_states_and_gb_pointer_bounds() {
        let case = CASES
            .iter()
            .find(|case| case.label == "iso-2022-jp")
            .unwrap();
        let iso_inputs = &comprehensive_groups(case)[0].inputs;
        assert_eq!(iso_inputs.len(), 6 * 9 * 256);
        assert!(iso_inputs.contains(&b"Q\x1b$B!\x00".to_vec()));
        assert!(iso_inputs.contains(&b"Q\x1b$@~\xff".to_vec()));

        let gb = corpus::four_byte_sample(3);
        assert_eq!(gb.len(), 3);
        assert_eq!(gb.first().unwrap().as_slice(), b"\x81\x30\x81\x30");
        assert_eq!(gb.last().unwrap().as_slice(), b"\xfe\x39\xfe\x39");
        assert!(gb.iter().all(|bytes| {
            bytes.len() == 4
                && (0x81..=0xfe).contains(&bytes[0])
                && (0x30..=0x39).contains(&bytes[1])
                && (0x81..=0xfe).contains(&bytes[2])
                && (0x30..=0x39).contains(&bytes[3])
        }));
    }

    #[test]
    fn replays_two_gb18030_inputs_through_run() {
        let cli = Cli::try_parse_from([
            "encoding-parity",
            "--encoding",
            "gb18030",
            "--input-hex",
            "8431A437",
            "--input-hex",
            "FE39FE39",
            "--format",
            "json",
        ])
        .expect("valid replay options");
        assert_eq!(cli.input_hex, [vec![0x84, 0x31, 0xA4, 0x37], vec![0xFE, 0x39, 0xFE, 0x39]]);
        run(cli);
    }
}
