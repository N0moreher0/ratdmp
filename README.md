# ratdmp

```text
                 _ __ ___   __| |_ __ ___  _ __
                | '_ ` _ \ / _` | '__/ _ \| '_ \
                | | | | | | (_| | | | (_) | |_) |
                |_| |_| |_|\__,_|_|  \___/| .__/
                                          |_|

        Fast memory-dump string triage for DFIR and malware analysis
```

> **Extract fast. Triage immediately. Keep stdout automation-friendly.**

[![Crates.io](https://img.shields.io/crates/v/ratdmp?logo=rust)](https://crates.io/crates/ratdmp)
[![Documentation](https://img.shields.io/docsrs/ratdmp?logo=docs.rs)](https://docs.rs/ratdmp)
[![License](https://img.shields.io/crates/l/ratdmp)](https://github.com/N0moreher0/ratdmp)

Fast, streaming ASCII / UTF-16LE string extractor for raw memory dump
(`.dmp`) files — with simple, conservative noise filtering for
byte-fill / heap-fill patterns and built-in IOC-oriented triage. Written for
malware analysis, DFIR, and memory-forensics workflows.

## Why

Running something like Unix `strings` on a multi-gigabyte memory dump
usually means: (1) reading the whole file into RAM, and (2) getting
flooded with junk like `AAAAAAAA...` or `ABABABAB...` from Windows
heap padding / byte-fill patterns, alongside the IOCs you actually
care about.

`ratdmp` fixes both:

- **Streaming.** Reads the file in 32MB chunks (`extract_strings_from_file`
  / `extract_strings_from_reader`), never loading the entire dump into
  memory. A `.dmp` file can be many gigabytes — this crate's peak memory
  use does not scale with file size.
- **Single-pass, dual-encoding.** ASCII and UTF-16LE runs are detected in
  the *same* scan over the buffer, not two separate passes.
- **Conservative noise filtering.** Runs that are pure period-1
  (`aaaaaaaa...`) or period-2 (`ababab...`) repeats, above a length
  threshold, are dropped as low-information byte-fill noise. Short
  repeats (like `"0000"`) are deliberately kept, since they can be real
  data (PINs, years, etc.) — the filter only removes patterns long
  enough to be confidently noise, never sacrificing recall for short
  strings.
- **Built-in triage signals.** The CLI surfaces likely credentials, tokens,
  secrets, URLs, network indicators, and email addresses in a highlighted
  priority section while preserving every extracted result in stdout.
- **Terminal-first UX.** A polished banner, scan status, grouped length
  summary, throughput, peak memory, and priority findings are printed to
  `stderr`; text and JSON results remain safe for scripts and pipelines.

## At a glance

| Capability | Details |
| --- | --- |
| Input | Raw `.dmp` files or any binary payload |
| Encodings | ASCII and UTF-16LE in one scan |
| Processing | Streaming by default; bounded parallel regions available |
| Noise filter | Conservative period-1 and period-2 fill-pattern detection |
| Triage | Credential/token/secret, URL, network, and email indicators |
| Output | Human-readable text or machine-readable JSON |
| Scale | Hardware-aware `--auto-tune` with CPU/RAM safety limits |
| Dependencies | No CLI framework or JSON runtime dependency |

## Usage

```rust
use ratdmp::extract_strings_from_file;

fn main() -> std::io::Result<()> {
    let strings = extract_strings_from_file("memory.dmp", /* min_len */ 4, /* max_strings */ 200_000)?;
    for s in &strings {
        println!("[{}] offset={} {:?}", s.encoding, s.offset, s.text);
    }
    Ok(())
}
```

Already have the bytes in memory instead of a file on disk? Use
`extract_strings(&data, min_len, max_strings)`. Reading from any
`std::io::Read` (a socket, a pipe, a decompression stream, …)? Use
`extract_strings_from_reader(reader, min_len, max_strings, estimated_len)`.

Each result is an `ExtractedString { offset: u64, encoding: &'static str, text: String }`
(`encoding` is `"ascii"` or `"utf16le"`), sorted by `offset`. The struct
derives `serde::Serialize` if you want to hand it off as JSON.

## CLI

The crate also ships a `ratdmp` binary — arg parsing and JSON output are
hand-rolled (no clap, no serde_json).

**Pre-built binaries:** grab the latest `.exe`/binary for Linux, Windows,
or macOS (x86_64 + Apple Silicon) from the [Releases
page](https://github.com/N0moreher0/ratdmp/releases) — no Rust toolchain
needed. Every release also ships a `SHA256SUMS` file to verify the download.

Or build/install from source:

```bash
cargo install ratdmp

ratdmp lsass.dmp
ratdmp lsass.dmp --min-len 6 --format json -o strings.json
ratdmp lsass.dmp --encoding utf16 --max-strings 5000
ratdmp lsass.dmp --noise-threshold 16
ratdmp lsass.dmp --threads 8
ratdmp lsass.dmp --auto-tune
ratdmp --help
```

Options: `--min-len <N>`, `--max-strings <N>`, `--format <text|json>`,
`--encoding <all|ascii|utf16>`, `-o/--output <path>` (defaults to stdout),
`--stats` (legacy no-op; the report is now automatic).
Text format is `offset\tencoding\ttext` per line; JSON format is a plain
array of `{"offset":...,"encoding":...,"text":...}`.

### Recommended workflows

```bash
# Fast interactive triage; UI and priority findings go to stderr.
ratdmp memory.dmp --auto-tune

# Clean text stream for grep, awk, or another forensic tool.
ratdmp memory.dmp --auto-tune 2>scan-report.txt | grep -Ei 'token|secret|http'

# Stable JSON artifact for automation.
ratdmp memory.dmp --format json --auto-tune -o strings.json 2>scan-report.txt

# Focus on UTF-16LE strings and retain a larger result set.
ratdmp memory.dmp --encoding utf16 --max-strings 500000 -o utf16.txt
```

### Terminal UI and automatic report

When running interactively, ratdmp shows a structured banner, scan status, and
summary panel inspired by modern open-source CLI tools. The report is always
written to `stderr`, so stdout remains clean for pipes, redirected text, and
JSON parsers:

```text
+------------------------------------------------------------+
| ratdmp v0.4.0 | memory-dump string triage                 |
+------------------------------------------------------------+
  input  sample_demo.dmp  |  5.42 KiB  |  text
  [..] scanning
  [OK] scan complete
+-------------------- summary -----------------------------+
  results      : 15
  length       : 2 short | 4 medium | 9 long
  threads      : 1
  file size    : 5.42 KiB
  elapsed      : 26.235 ms
  throughput   : 206.41 KiB/s
  peak memory  : 36.35 MiB
+------------------------------------------------------------+
  [!] priority findings (up to 12)
      credential 0x00000624 ascii   discord_token=...
      email      0x00000724 ascii   analyst@example.test
```

Results are grouped by text length (`short` 4-7, `medium` 8-31, `long` 32+).
Likely high-value strings such as credentials, tokens, secrets, URLs, network
indicators, and email addresses are listed separately and highlighted with
ANSI color when stderr is a terminal. Color is disabled automatically when
output is redirected. The UI never writes ANSI escape sequences to redirected
output and never contaminates stdout, making it suitable for shell pipelines
and automation. These are triage signals, not proof that a string is valid,
active, or malicious; validate findings in their surrounding memory context.

**`--noise-threshold <N>`** — configures the byte-fill/heap-fill noise
filter instead of the hardcoded defaults (period-1 repeats like `aaaa`
need length `N`, period-2 repeats like `abab` need `N+2`). `0` disables
the filter entirely, so nothing gets dropped. Library callers get the same
control via `NoiseConfig` and the `*_with_noise_config` functions.

**`--threads <N>`** — scans using an N-worker `rayon` work-stealing pool
instead of the default single-threaded streaming scan. `1` (default) is
the original sequential/streaming path: constant peak memory regardless of
file size, best for very large dumps or slow disks. `>1` splits the file
into 64MB regions scanned in parallel, which is faster on multi-core
machines once the CPU-bound scan itself (not disk I/O) becomes the
bottleneck — e.g. a warm page cache or fast NVMe. Library callers can use
`extract_strings_from_file_parallel` directly.

**`--auto-tune`** — selects a resource-conservative thread count from the
logical CPU count, available memory, and the number of 64 MiB regions in the
input. Small files stay on the low-memory streaming path. On larger files it
uses at most roughly 75% of logical CPUs (always leaving at least one free)
and budgets at most 25% of currently available RAM for scan workers. This
means a machine with more CPU/RAM scales to more workers, while a low-memory
machine automatically backs off. On platforms where available RAM cannot be
queried, the CPU cap remains active and the bounded worker buffers are used.
This reduces contention with other applications, but cannot guarantee zero
impact from disk I/O, thermal throttling, or the output destination. It only
tunes parallelism: string length, noise filtering, encoding, output format,
and result limits remain unchanged. An explicit `--threads N` always takes
precedence; use it only when you deliberately want to override the safety
policy.

The automatic report reads timing and memory directly from the OS (without an
extra dependency):

```
  [OK] scan complete
+-------------------- summary -----------------------------+
  results      : 262
  length       : 41 short | 136 medium | 85 long
  threads      : 8
  file size    : 64.00 MiB
  elapsed      : 200.209 ms
  throughput   : 319.68 MiB/s
  peak memory  : 34.12 MiB
+------------------------------------------------------------+
```

`peak RSS` is read from `/proc/self/status` (Linux) or
`GetProcessMemoryInfo` (Windows, via raw FFI) -- it prints `n/a` on other
platforms rather than guessing.

## Scope and boundaries

- No `.dmp`/MDMP structural parsing (no stream/module/thread table
  lookups) — it treats the file as a raw byte payload and scans the
  whole thing. This is intentional: it makes the extractor independent
  of the specific minidump format version or which tool produced it.
- The CLI provides lightweight IOC-oriented triage signals for common
  credential, token, secret, URL, network, and email patterns. It does not
  claim that a highlighted string is valid, active, or malicious.
- No aggressive entropy-based suppression or broad deduplication is applied.
  The default favors evidence preservation; use `--noise-threshold`,
  `--min-len`, `--encoding`, and `--max-strings` to tune collection for a
  specific investigation.

## Minimum supported Rust version

1.70 (uses `const fn` with loops for the printable-byte lookup table).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
