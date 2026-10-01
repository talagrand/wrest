# Encoding parity probe

Probe to compare the results of Windows NLS vs ICU vs the WHATWG
encoding spec, as implemented by `encoding_rs`.
The route table in `corpus.rs` lists the 34 ICU/NLS-backed encodings
we are measuring as well as the selected ICU name.

## Quick start

```
cargo run --manifest-path tools\encoding-parity\Cargo.toml -- --encoding euc-jp
cargo run --manifest-path tools\encoding-parity\Cargo.toml -- --encoding iso-2022-jp
cargo run --manifest-path tools\encoding-parity\Cargo.toml -- --encoding gb18030 --format json --examples 0 > gb.json
```

Omit `--encoding` to test every route. Standard runs include stream and state
corpora, curated ICU variants, and **all 1,587,600 structurally valid GB
four-byte pointers** for GBK and GB18030. Use `--four-byte-samples 0` to omit
that exhaustive pointer grid while retaining the other corpus groups, or
supply another sample size. An all-route run with `--examples 0 --format json`
took about 56 seconds on one Windows machine; runtime varies by machine.
Use `--icu-name NAME --encoding LABEL` to compare another ICU converter.

To test other installed ICU converters:

```
cargo run --manifest-path tools\encoding-parity\Cargo.toml -- --list-icu
cargo run --manifest-path tools\encoding-parity\Cargo.toml -- --list-aliases
cargo run --manifest-path tools\encoding-parity\Cargo.toml -- --encoding euc-kr --all-icu --examples 0 --format json > euc-kr-catalog.json
cargo run --manifest-path tools\encoding-parity\Cargo.toml -- --installed-survey --examples 0 --format json > installed-survey.json
```

`--list-aliases` shows each catalog converter, its registered alias, and
the converter actually resolved when that alias is opened; these can differ.
`--all-icu` compares every installed name with the selected WHATWG route
using bounded screening groups and 18,412 GB four-byte samples by default.
`--installed-survey` uses the same screening groups for all routes (or just
`--encoding LABEL`), without GB four-byte samples by default. These opt-in
catalog scans do not run the full corpus per converter; they can still be slow.
Named candidates are deduplicated; missing optional converters remain
`unavailable`.

## Reading a score

`valid 63/63; invalid 4/193` means that the native decoder produced the
**entire same Unicode output** as the WHATWG oracle on 63 of 63 inputs where
the oracle reported no decoding error, and 4 of 193 inputs where it did.
These are counts of *inputs*, not Unicode characters.
An input mapping to U+FFFD can still be oracle-valid:
GB18030 `84 31 A4 37` is one such assigned mapping. For invalid inputs,
the comparison includes the position of replacement characters and ASCII
that the decoder reprocesses after a bad lead or escape.

`native failures` counts calls returning no output; those never count as
matches, even when the oracle output is empty. Examples show expected and
actual code points separately for valid and invalid mismatches. `--examples
N` limits examples *per category, converter, and group*; zero keeps only
counts. A missing optional ICU variant is marked `unavailable`, not scored
as a match.
For ICU, `ICU wrong output (STOP error/accepted)` partitions only the
**normal-conversion outputs that differ** from WHATWG: a second conversion
of those bytes with ICU's STOP callback either reports an error or accepts
them while decoding differently. Native failures are counted separately.
This is not a validity verdict, an error-position locator, or a scan of
all invalid inputs; oracle validity and exact-match totals are unchanged.

## Why these corpus shapes?

* **Isolated bytes and bounded grids:** all 256 single bytes, all allowed
  CJK lead/trail pairs, and every two-byte input for
  single-byte encodings. These expose mapping differences and undefined
  bytes. GB's four-byte grammar is `81..FE 30..39 81..FE 30..39`;
  sampling or exhausting its pointers checks long mappings and unmapped
  pointers.
* **ASCII framing and recovery:** `Q` before and `Z` after byte pairs or
  selected units reveal whether a malformed lead consumes the following
  ASCII. Standard runs also cross CJK leads with *every* possible
  next byte, and tries ordered valid, unassigned, and truncated units.
* **Stateful paths:** EUC-JP `8E` (SS2) and `8F` (SS3) select different
  character sets and can end unfinished. Big5 includes pairs mapping to
  two Unicode scalars. ISO-2022-JP uses ESC designations to switch between
  ASCII, Roman, Katakana, and JIS modes; complete JIS grids, partial
  escapes, pending leads, and mode changes probe both ordinary text and
  resynchronization. GB lead+digit prefixes enter the four-byte path;
  interrupted prefixes check its recovery.
* **Streams:** fixed-seed mixtures of valid units exercise transitions;
  fixed-seed malformed/boundary streams (including ASCII sentinels) exercise
  recovery over longer inputs. These are samples, not exhaustive streams.

Built-in groups exclude inputs starting with `EF BB BF`, `FF FE`, or
`FE FF`: a response-level BOM would select a Unicode decoder before the
declared legacy charset. The same signatures *midstream* are measured as
legacy bytes. Replay deliberately accepts any raw bytes, including leading
signatures, under the named decoder:

```
cargo run --manifest-path tools\encoding-parity\Cargo.toml -- --encoding gb18030 --input-hex 8431A437 --input-hex FE39FE39
cargo run --manifest-path tools\encoding-parity\Cargo.toml -- --encoding shift_jis --input-hex 8222 --format json
cargo run --manifest-path tools\encoding-parity\Cargo.toml -- --encoding iso-2022-jp --input-hex 511B28485A
```

The first GB input maps *validly* to U+FFFD; the last GB pointer is
unmapped. `82 22` tests whether an invalid Shift_JIS lead lets the ASCII
quote through. `51 1B 28 48 5A` tests recovery from an unknown
ISO-2022-JP escape between `Q` and `Z`.

## Reproducing and interpreting a run

Save `--format json` output with the exact command, Windows build, and ICU
version. The Cargo lockfile records the `encoding_rs` version used by the oracle.
Each group records its input count, `coverage.kind` (and `coverage.seed`
for seeded samples), and an input fingerprint.
Scores across groups may count the same input more than once. Even a perfect
score on every named finite shape does not prove parity on arbitrary streams
or represent a statistical sample of web pages.

`cargo test --manifest-path tools\encoding-parity\Cargo.toml` checks scoring,
BOM filtering, route availability, fingerprint sensitivity to input boundaries
and order, and a two-input JSON replay through `run`.
To investigate a mismatch, copy its hex bytes into `--input-hex` and compare
the oracle, NLS, and ICU outputs without regenerating a large corpus.
