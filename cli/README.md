# ratdmp-cli

```text
+------------------------------------------------------------+
|  RRRR    AAA   TTTTT  DDDD   MMM MMM  PPPP                 |
|  R   R  A   A    T    D   D  M M M M  P   P                |
|  RRRR   AAAAA    T    D   D  M  M  M  PPPP                 |
|  R  R   A   A    T    D   D  M     M  P                    |
|  R   R  A   A    T    DDDD   M     M  P                    |
+------------------------------------------------------------+
```

Professional command-line frontend for the
[`ratdmp`](https://crates.io/crates/ratdmp) memory-dump extraction library.

## Install

```bash
cargo install ratdmp-cli
```

This downloads the core library, builds an optimized `ratdmp` executable, and
installs it on your Cargo binary path.

## Use

```bash
ratdmp memory.dmp
ratdmp memory.dmp --auto-tune
ratdmp memory.dmp --format json -o strings.json
ratdmp memory.dmp --encoding utf16 --min-len 6
ratdmp memory.dmp --noise-threshold 16 --threads 4
ratdmp memory.dmp --yar rules.yar --format json -o triage.json
ratdmp memory.dmp --brute-xor "1b;2b" --format json -o xor.json
```

## Features

- ASCII and UTF-16LE extraction.
- Streaming scans for large dump files.
- Configurable minimum length and result limits.
- Conservative repeat-noise filtering.
- Parallel scanning with explicit threads or `--auto-tune`.
- Text or JSON output.
- Default single-worker scans stream results directly to the output.
- `--entropy` enables high-entropy region hints in the report on `stderr`.
- `--yar <PATH>` compiles and matches a YARA/YARA-X rule file while streaming
  the dump; each matching rule is emitted as a `YARA` output record.
- `--brute-xor <1b;2b;3b>` is an opt-in CLI-only pass. It collects bounded
  non-zero byte candidates, tries the selected XOR key sizes, scores printable
  ASCII/UTF-8 output, boosts useful IOC terms, and retains the top five
  results per candidate/key size.
- JSON output also includes each matching region as a `group: "Undefined"`
  record with its bytes encoded as `data_hex`.
- Text output includes the same `Undefined` entropy records with
  `length`, `entropy`, and `data_hex` fields.
- Entropy scanning is opt-in to preserve default scan speed.
- `--parse-pid` adds a `pid` field to JSON or a `pid=...` column to text output
  when a string contains a `PID=`/`ProcessId=` marker.
- Automatic scan summary and priority triage signals on `stderr`.
- IPv4/IPv6 and common crypto-wallet address triage signals.
- Clean stdout for shell pipelines and automation.

Run `ratdmp --help` for the complete option list.
