# ratdmp-cli

Command-line frontend for the [`ratdmp`](https://crates.io/crates/ratdmp)
library.

## Install

```bash
cargo install ratdmp-cli
```

This downloads the core library, builds an optimized `ratdmp` executable, and
installs it on your Cargo binary path.

## Use

```bash
ratdmp memory.dmp
ratdmp memory.dmp --auto-tune --stats
ratdmp memory.dmp --format json -o strings.json
```
