# ratdmp

```text
                 _ __ ___   __| |_ __ ___  _ __
                | '_ ` _ \ / _` | '__/ _ \| '_ \
                | | | | | | (_| | | | (_) | |_) |
                |_| |_| |_|\__,_|_|  \___/| .__/
                                          |_|

             Fast, composable memory-dump string extraction
```

> **A focused Rust library for building your own DFIR and malware-analysis
> tooling.**

[![Crates.io](https://img.shields.io/crates/v/ratdmp?logo=rust)](https://crates.io/crates/ratdmp)
[![Documentation](https://img.shields.io/docsrs/ratdmp?logo=docs.rs)](https://docs.rs/ratdmp)
[![License](https://img.shields.io/crates/l/ratdmp)](https://github.com/N0moreher0/ratdmp)

`ratdmp` is a library-first, streaming ASCII/UTF-16LE string extractor for
raw memory dumps and other binary payloads. It provides the extraction engine,
noise filtering, bounded parallel scanning, and serializable results; your
application owns the UI, IOC rules, storage, alerting, and reporting.

## Why ratdmp?

Memory dumps are large, noisy, and full of useful evidence hidden among
padding bytes. `ratdmp` gives applications a predictable core:

- **Streaming by default**: scan multi-gigabyte files without loading them
  completely into RAM.
- **Dual encoding support**: detect ASCII and UTF-16LE in the same pass.
- **Conservative noise filtering**: suppress clear period-1 and period-2
  fill patterns while preserving short evidence.
- **Configurable behavior**: control minimum length, result limits, and noise
  thresholds from Rust.
- **Parallel when useful**: opt into bounded region-based scanning with Rayon.
- **Composable output**: receive sorted `ExtractedString` values and decide
  how your application classifies, displays, or stores them.
- **Library-only crate**: no bundled CLI, terminal policy, IOC assumptions, or
  output format imposed on downstream users.

## Installation

```toml
[dependencies]
ratdmp = "0.5"
```

Or:

```bash
cargo add ratdmp
```

The crate exposes a Rust API only. Build your own CLI, service, desktop
application, forensic pipeline, or scripting integration around it.

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

## Streaming and parallel scanning

The normal file and reader APIs use bounded streaming memory. They are a good
default for very large dumps, slow disks, and memory-constrained systems.

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

## Building an application around ratdmp

The crate deliberately leaves these product decisions to you:

- CLI arguments and terminal UI
- IOC and credential detection
- JSON, CSV, NDJSON, or database output
- progress bars and cancellation
- case management and evidence provenance
- redaction, access control, and retention
- YARA, regex, entropy, or threat-intelligence enrichment

This makes the core suitable for both a minimal `strings`-style utility and a
full forensic pipeline.

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
