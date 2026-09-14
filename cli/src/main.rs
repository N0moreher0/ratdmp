use ratdmp::{
    extract_strings_from_file_parallel, extract_strings_from_file_with_noise_config,
    ExtractedString, NoiseConfig, MAX_STRINGS, MIN_STRING_LEN,
};
use std::fs::File;
use std::io::{self, BufWriter, IsTerminal, Write};
use std::time::Instant;

#[derive(Clone, Copy, PartialEq)]
enum Format {
    Text,
    Json,
}

struct Args {
    path: String,
    min_len: usize,
    max_strings: usize,
    format: Format,
    encoding: Encoding,
    output: Option<String>,
    noise_threshold: Option<usize>,
    threads: usize,
    auto_tune: bool,
    stats: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum Encoding {
    All,
    Ascii,
    Utf16,
}

const HELP: &str = "\
+------------------------------------------------------------+
|  RRRR    AAA   TTTTT  DDDD   MMM MMM  PPPP                 |
|  R   R  A   A    T    D   D  M M M M  P   P                |
|  RRRR   AAAAA    T    D   D  M  M  M  PPPP                 |
|  R  R   A   A    T    D   D  M     M  P                    |
|  R   R  A   A    T    DDDD   M     M  P                    |
+------------------------------------------------------------+
ratdmp — fast memory-dump string extraction

USAGE:
    ratdmp <path> [OPTIONS]

OPTIONS:
    --min-len <N>        Minimum string length (default 4)
    --max-strings <N>    Maximum results (default 200000)
    --format <text|json> Output format (default text)
    --encoding <all|ascii|utf16>
                          Restrict output by encoding (default all)
    -o, --output <PATH>  Write results to a file
    --noise-threshold <N>
                          Repeat-noise threshold; 0 disables filtering
    --threads <N>        Parallel worker count
    --auto-tune          Choose a safe worker count for this machine
    --stats              Always-on report compatibility flag
    -h, --help           Show this help
";

fn parse_args() -> Result<Args, String> {
    let mut values = std::env::args().skip(1).collect::<Vec<_>>();
    if values.is_empty() || values.iter().any(|v| v == "-h" || v == "--help") {
        print!("{HELP}");
        std::process::exit(0);
    }
    let path = values.remove(0);
    let mut args = Args {
        path,
        min_len: MIN_STRING_LEN,
        max_strings: MAX_STRINGS,
        format: Format::Text,
        encoding: Encoding::All,
        output: None,
        noise_threshold: None,
        threads: 1,
        auto_tune: false,
        stats: false,
    };
    let mut i = 0;
    while i < values.len() {
        let flag = values[i].as_str();
        let next = |i: &mut usize| -> Result<String, String> {
            *i += 1;
            values
                .get(*i)
                .cloned()
                .ok_or_else(|| format!("missing value after '{flag}'"))
        };
        match flag {
            "--min-len" => {
                args.min_len = next(&mut i)?
                    .parse()
                    .map_err(|_| "invalid --min-len".to_string())?
            }
            "--max-strings" => {
                args.max_strings = next(&mut i)?
                    .parse()
                    .map_err(|_| "invalid --max-strings".to_string())?
            }
            "--format" => {
                args.format = match next(&mut i)?.as_str() {
                    "text" => Format::Text,
                    "json" => Format::Json,
                    other => return Err(format!("invalid format '{other}'")),
                };
            }
            "--encoding" => {
                args.encoding = match next(&mut i)?.as_str() {
                    "all" => Encoding::All,
                    "ascii" => Encoding::Ascii,
                    "utf16" => Encoding::Utf16,
                    other => return Err(format!("invalid encoding '{other}'")),
                };
            }
            "-o" | "--output" => args.output = Some(next(&mut i)?),
            "--noise-threshold" => {
                args.noise_threshold = Some(
                    next(&mut i)?
                        .parse()
                        .map_err(|_| "invalid --noise-threshold".to_string())?,
                )
            }
            "--threads" => {
                args.threads = next(&mut i)?
                    .parse()
                    .map_err(|_| "invalid --threads".to_string())?;
                if args.threads == 0 {
                    return Err("--threads must be at least 1".to_string());
                }
            }
            "--auto-tune" => args.auto_tune = true,
            "--stats" => args.stats = true,
            other => return Err(format!("unknown option '{other}'")),
        }
        i += 1;
    }
    Ok(args)
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn important_reason(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    if [
        "password", "passwd", "token", "secret", "apikey", "api_key", "jwt",
    ]
    .iter()
    .any(|term| lower.contains(term))
    {
        Some("credential")
    } else if lower.contains("http://") || lower.contains("https://") {
        Some("url")
    } else if lower.contains("c2") || lower.contains("gate.php") {
        Some("network")
    } else if lower.contains('@') {
        Some("email")
    } else {
        None
    }
}

fn print_banner(path: &str, size: u64, format: Format) {
    if !io::stderr().is_terminal() {
        return;
    }
    let format = match format {
        Format::Text => "text",
        Format::Json => "json",
    };
    eprintln!("\x1b[1;36m+------------------------------------------------------------+\x1b[0m");
    eprintln!(
        "\x1b[1;36m|  \x1b[1;37mRATDMP\x1b[1;36m  |  memory-dump string triage                  |\x1b[0m"
    );
    eprintln!("\x1b[1;36m+------------------------------------------------------------+\x1b[0m");
    eprintln!("  input      : {path}");
    eprintln!("  size/format: {size} bytes / {format}");
    eprintln!("  \x1b[1;34m[..] scanning\x1b[0m");
}

fn print_report(results: &[ExtractedString], size: u64, elapsed: f64, threads: usize) {
    let color = io::stderr().is_terminal();
    let mut short = 0;
    let mut medium = 0;
    let mut long = 0;
    let mut important = Vec::new();
    for result in results {
        match result.text.chars().count() {
            0..=7 => short += 1,
            8..=31 => medium += 1,
            _ => long += 1,
        }
        if important_reason(&result.text).is_some() && important.len() < 12 {
            important.push(result);
        }
    }
    if color {
        eprintln!("\x1b[1;32m  [OK] scan complete\x1b[0m");
        eprintln!("\x1b[1;36m+-------------------- summary -----------------------------+\x1b[0m");
    } else {
        eprintln!("  [OK] scan complete");
        eprintln!("+-------------------- summary -----------------------------+");
    }
    eprintln!("  results    : {}", results.len());
    eprintln!("  length     : {short} short | {medium} medium | {long} long");
    eprintln!("  threads    : {threads}");
    eprintln!("  file size  : {size} bytes");
    eprintln!("  elapsed    : {:.3} ms", elapsed * 1000.0);
    eprintln!(
        "  throughput : {:.2} MiB/s",
        size as f64 / elapsed.max(f64::MIN_POSITIVE) / 1_048_576.0
    );
    eprintln!("+------------------------------------------------------------+");
    if !important.is_empty() {
        eprintln!("  [!] priority findings (up to 12)");
        for result in important {
            let reason = important_reason(&result.text).unwrap_or("interesting");
            eprintln!(
                "      {reason:<10} {:#010x} {:<7} {}",
                result.offset, result.encoding, result.text
            );
        }
    }
}

fn write_results(
    results: &[ExtractedString],
    format: Format,
    writer: &mut dyn Write,
) -> io::Result<()> {
    match format {
        Format::Text => {
            for result in results {
                writeln!(
                    writer,
                    "{:#010x}\t{}\t{}",
                    result.offset, result.encoding, result.text
                )?;
            }
        }
        Format::Json => {
            writeln!(writer, "[")?;
            for (index, result) in results.iter().enumerate() {
                let comma = if index + 1 < results.len() { "," } else { "" };
                writeln!(
                    writer,
                    "  {{\"offset\":{},\"encoding\":{},\"text\":{}}}{comma}",
                    result.offset,
                    json_escape(result.encoding),
                    json_escape(&result.text)
                )?;
            }
            writeln!(writer, "]")?;
        }
    }
    Ok(())
}

fn main() -> Result<(), String> {
    let args = parse_args()?;
    let file_size = std::fs::metadata(&args.path)
        .map_err(|e| format!("cannot inspect '{}': {e}", args.path))?
        .len();
    print_banner(&args.path, file_size, args.format);
    let threads = if args.auto_tune {
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        if cpus <= 2 {
            1
        } else {
            std::cmp::max(1, std::cmp::min(cpus - 1, cpus * 3 / 4))
        }
    } else {
        args.threads
    };
    let noise = args
        .noise_threshold
        .map(NoiseConfig::from_threshold)
        .unwrap_or_default();
    let start = Instant::now();
    let results = if threads > 1 {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .map_err(|e| format!("cannot create worker pool: {e}"))?;
        pool.install(|| {
            extract_strings_from_file_parallel(&args.path, args.min_len, args.max_strings, noise)
        })
    } else {
        extract_strings_from_file_with_noise_config(
            &args.path,
            args.min_len,
            args.max_strings,
            noise,
        )
    }
    .map_err(|e| format!("scan failed: {e}"))?;
    let results: Vec<ExtractedString> = results
        .into_iter()
        .filter(|result| match args.encoding {
            Encoding::All => true,
            Encoding::Ascii => result.encoding == "ascii",
            Encoding::Utf16 => result.encoding == "utf16le",
        })
        .collect();

    match args.output {
        Some(path) => {
            let file = File::create(&path).map_err(|e| format!("cannot create '{path}': {e}"))?;
            write_results(&results, args.format, &mut BufWriter::new(file))
                .map_err(|e| format!("write failed: {e}"))?;
            eprintln!("wrote {} results to '{path}'", results.len());
        }
        None => {
            write_results(
                &results,
                args.format,
                &mut BufWriter::new(io::stdout().lock()),
            )
            .map_err(|e| format!("write failed: {e}"))?;
        }
    }
    let _ = args.stats;
    print_report(&results, file_size, start.elapsed().as_secs_f64(), threads);
    Ok(())
}
