# ratdmp

```text
+------------------------------------------------------------+
|  RRRR    AAA   TTTTT  DDDD   MMM MMM  PPPP                 |
|  R   R  A   A    T    D   D  M M M M  P   P                |
|  RRRR   AAAAA    T    D   D  M  M  M  PPPP                 |
|  R  R   A   A    T    D   D  M     M  P                    |
|  R   R  A   A    T    DDDD   M     M  P                    |
+------------------------------------------------------------+

             Fast, composable memory-dump extraction
```

> **A fast Rust core library plus a ready-to-use CLI for DFIR and
> malware-analysis workflows.**

[![Crates.io](https://img.shields.io/crates/v/ratdmp?logo=rust)](https://crates.io/crates/ratdmp)
[![Documentation](https://img.shields.io/docsrs/ratdmp?logo=docs.rs)](https://docs.rs/ratdmp)
[![License](https://img.shields.io/crates/l/ratdmp)](https://github.com/N0moreher0/ratdmp)

This repository contains two layers:

- **`ratdmp`** — the library crate published on
  [crates.io](https://crates.io/crates/ratdmp), containing the extraction
  engine, noise filtering, bounded parallel scanning, and serializable
  results.
- **`ratdmp-cli`** — the optional command-line frontend in [`cli/`](./cli/),
  published separately with a RATDMP banner, automatic reports, JSON/text
  output, encoding filters, credential/IP/crypto-wallet triage signals, and
  hardware-aware scanning.

Use the Rust API directly for custom applications, or install the finished
CLI when you want an immediate command-line workflow.

## Install the CLI and use it

Install once; Cargo downloads the CLI and core library, builds an optimized
`ratdmp` executable, and places it on your Cargo binary path:

```powershell
cargo install ratdmp-cli
```

Then scan immediately:

```powershell
ratdmp memory.dmp --auto-tune
ratdmp memory.dmp --entropy --format json -o triage.json
ratdmp memory.dmp --yar rules.yar --format json -o yara.json
ratdmp memory.dmp --brute-xor "1b;2b" --format json -o xor.json
```

Update an existing installation:

```powershell
cargo install ratdmp-cli --force
```

See all available options:

```powershell
ratdmp --help
```

## Why ratdmp?

Memory dumps are large, noisy, and full of useful evidence hidden among
padding bytes. `ratdmp` gives applications a predictable core:

- **Streaming by default**: scan multi-gigabyte files without loading them
  completely into RAM.
- **Dual encoding support**: detect ASCII and UTF-16LE in the same pass.
- **Conservative noise filtering**: suppress clear period-1 and period-2
  fill patterns while preserving short evidence.
- **Entropy hints**: identify fixed-size regions with high byte-distribution
  entropy as possible compressed, encrypted, or packed data; no decryption is
  attempted.
- In CLI JSON output, matching regions are emitted as `group: "Undefined"`
  records with `offset`, `length`, `entropy`, and `data_hex`.
- Text output emits the same `Undefined` records in tab-separated form.
- Entropy scanning is opt-in with `--entropy` so the default scan keeps its
  original throughput.
- **Configurable behavior**: control minimum length, result limits, and noise
  thresholds from Rust.
- **Parallel when useful**: opt into bounded region-based scanning with Rayon.
- **Composable output**: receive sorted `ExtractedString` values and decide
  how your application classifies, displays, or stores them.
- **Separate frontend**: the core stays composable while `ratdmp-cli` offers
  a complete terminal workflow for users who want one.

## Installation

```toml
[dependencies]
ratdmp = "0.9.1"
```

Or:

```bash
cargo add ratdmp
```

The crate exposes a Rust API only. Build your own CLI, service, desktop
application, forensic pipeline, or scripting integration around it.

For the ready-made frontend, inspect [`cli/src/main.rs`](./cli/src/main.rs)
or install it with `cargo install ratdmp-cli`.

## Quick start

```rust
use ratdmp::extract_strings_from_file;

fn main() -> std::io::Result<()> {
    let strings = extract_strings_from_file(
        "memory.dmp",
        4,       // minimum string length
        200_000, // maximum results
    )?;

    for result in strings {
        println!(
            "{:#010x}\t{}\t{}",
            result.offset, result.encoding, result.text
        );
    }
    Ok(())
}
```

## API surface

| API | Use case |
| --- | --- |
| `extract_strings` | Scan bytes already held in memory |
| `extract_strings_with_noise_config` | In-memory scan with custom filtering |
| `extract_strings_from_reader` | Stream from any `std::io::Read` |
| `extract_strings_from_reader_with_noise_config` | Stream with custom filtering |
| `extract_strings_from_file` | Scan a file with bounded memory |
| `extract_strings_from_file_with_noise_config` | File scan with custom filtering |
| `extract_strings_from_file_parallel` | Opt-in parallel file scan |
| `scan_yara_from_reader_streaming` | Stream bytes through compiled YARA rules |
| `scan_yara_from_file_streaming` | Compile a rule file and scan a dump |
| `NoiseConfig` | Configure or disable repeat-pattern filtering |

Every result is an `ExtractedString`:

```rust
pub struct ExtractedString {
    pub offset: u64,
    pub encoding: &'static str, // "ascii" or "utf16le"
    pub text: String,
}
```

Results are sorted by ascending offset. `ExtractedString` derives
`serde::Serialize`, so applications can emit JSON, NDJSON, database records,
or any custom protocol without pulling a serializer into this crate.

## Filtering and evidence policy

The default filter targets two high-confidence low-information shapes:

- period-1 repeats: `AAAAAAAAAAAA`
- period-2 repeats: `ABABABABABAB`

Short repeats remain available because values such as `0000` can be meaningful
evidence. Use `NoiseConfig` when your workload needs a different trade-off:

```rust
use ratdmp::{
    extract_strings_from_file_with_noise_config,
    NoiseConfig,
};

let config = NoiseConfig::from_threshold(16);
let strings = extract_strings_from_file_with_noise_config(
    "memory.dmp",
    6,
    500_000,
    config,
)?;
```

To preserve all repeat patterns:

```rust
let config = NoiseConfig::disabled();
```

The library does not classify IOC content, apply vendor-specific rules, or
decide what is malicious. That is intentional: downstream applications can
layer their own regexes, YARA rules, enrichment, confidence scoring, privacy
handling, and reporting without fighting a bundled CLI policy.

## CLI frontend in this repository

The GitHub repository includes the complete CLI source under [`cli/`](./cli/).
It is a separate package so the core library remains reusable:

```text
ratdmp/
├── src/lib.rs          # ratdmp core library
├── cli/
│   ├── Cargo.toml      # ratdmp-cli package
│   └── src/main.rs     # ratdmp executable
├── Cargo.toml          # ratdmp core package
└── README.md           # repository guide
```

The CLI adds:

- `--format text|json`
- `--encoding all|ascii|utf16`
- `--min-len` and `--max-strings`
- `--noise-threshold`
- `--threads` and `--auto-tune`
- `--format`, `--encoding`, `--min-len`, and `--max-strings` are echoed to
  `stderr` in a selected-options block before scanning.
- `--entropy` to export high-entropy memory regions
- `--yar <PATH>` to compile and match a YARA rule file during bounded
  streaming scan (matched rules are emitted as `group: "YARA"` records)
- `--brute-xor <1b;2b;3b>` to opt into bounded candidate collection and
  printable/UTF-8 scored XOR brute-forcing in the CLI only
- `--parse-pid` to map common PID markers in extracted strings
- `-o/--output`
- automatic scan reports and priority triage signals on `stderr`
- IPv4/IPv6 and common crypto-wallet address hints

Results stay clean on `stdout`, so the CLI works both interactively and in
shell pipelines. The priority signals are practical investigation hints for
common credential, token, secret, URL, network, and email patterns; they are
not a verdict that a value is valid, active, or malicious.

Entropy scanning is opt-in so the default scan keeps its original throughput.
When enabled, fixed-size high-entropy regions are exported as `Undefined`
records in both text and JSON output. Each record includes its offset, length,
measured entropy, and original bytes encoded as hexadecimal; ratdmp does not
decrypt or identify the underlying compression/encryption format.

### Optional XOR brute-force triage

`--brute-xor` is deliberately implemented in `ratdmp-cli`, not in the Core
library. It collects up to 256 non-zero byte candidates, each between 10 and
100 bytes, then tries the requested repeating-key XOR sizes:

```powershell
ratdmp memory.dmp --brute-xor "1b"
ratdmp memory.dmp --brute-xor "1b;2b" --format json -o xor.json
```

Candidates are ranked by printable ASCII/whitespace ratio, valid UTF-8, and
bonus terms such as `http`, `www`, `.exe`, `.dll`, `Virtual`, `Create`, and
`Thread`. The CLI retains the top five results per candidate after combining
the selected key sizes. One-byte XOR is cheap; two-byte XOR is substantially
more expensive, and three-byte XOR is exhaustive over 16,777,216 keys per
candidate. `--auto-tune` currently tunes string-extraction workers; it does
not parallelize the XOR brute-force loop.

### YARA streaming

The Core exposes `scan_yara_from_reader_streaming` and
`scan_yara_from_file_streaming`. The CLI's `--yar <PATH>` compiles the rule
file and scans bounded chunks with overlap, so rules crossing an I/O boundary
remain visible without loading the complete dump into memory.

## Streaming and parallel scanning

The normal file and reader APIs use bounded streaming memory. They are a good
default for very large dumps, slow disks, and memory-constrained systems.
The CLI's default single-worker mode streams each result directly to its
output instead of retaining the complete result set in memory.

For fast storage and CPU-heavy workloads, use the parallel API inside your own
controlled worker pool:

```rust
use ratdmp::{
    extract_strings_from_file_parallel,
    NoiseConfig,
};

let strings = extract_strings_from_file_parallel(
    "memory.dmp",
    4,
    500_000,
    NoiseConfig::default(),
)?;
```

The parallel API divides the input into fixed regions, preserves offsets, and
returns results in sorted order. Configure Rayon's thread pool in your
application when you need an explicit CPU/RAM policy.

## Building an application around the core

The crate deliberately leaves these product decisions to you:

- CLI arguments and terminal UI
- IOC and credential detection
- JSON, CSV, NDJSON, or database output
- progress bars and cancellation
- case management and evidence provenance
- redaction, access control, and retention
- YARA, regex, entropy, or threat-intelligence enrichment

This makes the core suitable for both the included CLI and a custom
`strings`-style utility or full forensic pipeline.

## Performance characteristics

- Single-pass ASCII/UTF-16LE extraction.
- Constant-memory streaming path with respect to file size.
- Parallel path bounded by active worker regions, not total file size.
- Result collection is capped by `max_strings`.
- No `.dmp`/MDMP structural parsing: the input is treated as raw bytes so the
  extractor remains independent of minidump format and producer.

Benchmark your target storage, CPU, and result density with your own dump
corpus. Output volume and downstream processing often dominate end-to-end
runtime after extraction.

## Minimum supported Rust version

Rust 1.70.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.
