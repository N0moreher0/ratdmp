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
```

## Features

- ASCII and UTF-16LE extraction.
- Streaming scans for large dump files.
- Configurable minimum length and result limits.
- Conservative repeat-noise filtering.
- Parallel scanning with explicit threads or `--auto-tune`.
- Text or JSON output.
- Default single-worker scans stream results directly to the output.
- Automatic high-entropy region hints are printed in the report on `stderr`.
- JSON output also includes each matching region as a `group: "Undefined"`
  record with its bytes encoded as `data_hex`.
- Automatic scan summary and priority triage signals on `stderr`.
- IPv4/IPv6 and common crypto-wallet address triage signals.
- Clean stdout for shell pipelines and automation.

Run `ratdmp --help` for the complete option list.
