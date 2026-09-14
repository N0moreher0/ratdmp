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
    output: Option<String>,
    noise_threshold: Option<usize>,
    threads: usize,
    auto_tune: bool,
    stats: bool,
}

const HELP: &str = "\
ratdmp — fast memory-dump string extraction

USAGE:
    ratdmp <path> [OPTIONS]

OPTIONS:
    --min-len <N>        Minimum string length (default 4)
    --max-strings <N>    Maximum results (default 200000)
    --format <text|json> Output format (default text)
    -o, --output <PATH>  Write results to a file
    --noise-threshold <N>
                          Repeat-noise threshold; 0 disables filtering
    --threads <N>        Parallel worker count
    --auto-tune          Choose a conservative worker count for this machine
    --stats              Print timing and memory statistics to stderr
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
                }
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
    let threads = if args.auto_tune {
        std::cmp::max(
            1,
            std::thread::available_parallelism()
                .map(|n| n.get() * 3 / 4)
                .unwrap_or(1),
        )
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
    if args.stats || io::stderr().is_terminal() {
        let elapsed = start.elapsed().as_secs_f64();
        eprintln!("--- ratdmp scan ---");
        eprintln!("results    : {}", results.len());
        eprintln!("file size  : {} bytes", file_size);
        eprintln!("threads    : {threads}");
        eprintln!("elapsed    : {:.3} ms", elapsed * 1000.0);
        eprintln!(
            "throughput : {:.2} MiB/s",
            file_size as f64 / elapsed.max(f64::MIN_POSITIVE) / 1_048_576.0
        );
    }
    Ok(())
}
