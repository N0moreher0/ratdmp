# ratdmp

Fast, streaming ASCII / UTF-16LE string extractor for raw memory dump
(`.dmp`) files — with simple, conservative noise filtering for
byte-fill / heap-fill patterns. Written for malware analysis / DFIR /
memory-forensics workflows.

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

The crate also ships a `ratdmp` binary — no extra dependencies (no clap,
no serde_json; arg parsing and JSON output are both hand-rolled to keep
the crate's "one dependency" philosophy):

```bash
cargo install ratdmp

ratdmp lsass.dmp
ratdmp lsass.dmp --min-len 6 --format json -o strings.json
ratdmp lsass.dmp --encoding utf16 --max-strings 5000
ratdmp --help
```

Options: `--min-len <N>`, `--max-strings <N>`, `--format <text|json>`,
`--encoding <all|ascii|utf16>`, `-o/--output <path>` (defaults to stdout),
`--stats` (prints a timing/throughput/peak-RSS summary to stderr, so it
never mixes into piped stdout output).
Text format is `offset\tencoding\ttext` per line; JSON format is a plain
array of `{"offset":...,"encoding":...,"text":...}`.

`--stats` output looks like this (all read straight from the OS, no extra
dependency):

```
--- stats ---
file size     : 64.00 MiB
time          : 200.209 ms
throughput    : 319.68 MiB/s
strings found : 262 (ascii: 262, utf16le: 0)
peak RSS      : 34.12 MiB
```

`peak RSS` is read from `/proc/self/status` (Linux) or
`GetProcessMemoryInfo` (Windows, via raw FFI) -- it prints `n/a` on other
platforms rather than guessing.

## What this crate does *not* do

- No `.dmp`/MDMP structural parsing (no stream/module/thread table
  lookups) — it treats the file as a raw byte payload and scans the
  whole thing. This is intentional: it makes the extractor independent
  of the specific minidump format version or which tool produced it.
- No IOC classification (URLs, IPs, wallet addresses, etc.) — this
  crate's only job is turning bytes into candidate strings. Feed its
  output into whatever classifier fits your pipeline.
- No entropy-based or statistical filtering beyond the two explicit
  repeat patterns described above — the goal is to reject only what's
  unambiguously noise, not to be a general-purpose deduplication or
  scoring engine.

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
