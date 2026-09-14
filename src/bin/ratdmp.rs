//! CLI for the `ratdmp` crate — extracts ASCII/UTF-16LE strings from a RAM
//! dump file (`.dmp`) or any binary file, streaming it in chunks, never
//! loading the whole file into RAM.
//!
//! No extra dependencies added (no clap) — keeps the `ratdmp` crate's
//! philosophy of exactly one dependency (`serde`, for `ExtractedString`'s
//! derive Serialize). Arg parsing is hand-rolled, and JSON output is
//! hand-written too (no `serde_json`). The optional `--stats` block (wall
//! time, throughput, peak RSS) is implemented the same way: peak memory is
//! read straight from the OS (`/proc/self/status` on Linux,
//! `GetProcessMemoryInfo` on Windows via raw FFI) instead of pulling in a
//! crate like `sysinfo` just for one number.

use ratdmp::{
    extract_strings_from_file_parallel, extract_strings_from_file_with_noise_config,
    ExtractedString, NoiseConfig, MAX_STRINGS, MIN_STRING_LEN,
};
use std::fs::File;
use std::io::{self, BufRead, BufWriter, IsTerminal, Write};
use std::process::ExitCode;
use std::time::Instant;

/// Best-effort "peak RSS" (peak resident/working set) reader. Only wired
/// up for Linux and Windows (the platforms this CLI has actually been
/// tested on) -- returns `None` everywhere else rather than guessing.
/// This is intentionally read straight from the OS via raw FFI / procfs,
/// not through a crate, to keep `ratdmp`'s "essentially zero extra
/// dependencies" philosophy even for the CLI's `--stats` output.
mod mem_stats {
    #[cfg(target_os = "linux")]
    pub fn peak_rss_bytes() -> Option<u64> {
        // VmHWM ("High Water Mark") = peak resident set size since process
        // start, in kB. Simpler and just as accurate as parsing /proc/self/statm
        // for our purposes (a one-shot CLI run, not a long-lived daemon).
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmHWM:") {
                let kb: u64 = rest.trim().trim_end_matches("kB").trim().parse().ok()?;
                return Some(kb * 1024);
            }
        }
        None
    }

    #[cfg(target_os = "windows")]
    pub fn peak_rss_bytes() -> Option<u64> {
        // Matches the Win32 PROCESS_MEMORY_COUNTERS layout exactly (all
        // fields are DWORD/SIZE_T in declaration order) -- declared by hand
        // instead of depending on the `windows`/`winapi` crate.
        #[repr(C)]
        struct ProcessMemoryCounters {
            cb: u32,
            page_fault_count: u32,
            peak_working_set_size: usize,
            working_set_size: usize,
            quota_peak_paged_pool_usage: usize,
            quota_paged_pool_usage: usize,
            quota_peak_non_paged_pool_usage: usize,
            quota_non_paged_pool_usage: usize,
            pagefile_usage: usize,
            peak_pagefile_usage: usize,
        }

        #[link(name = "kernel32")]
        extern "system" {
            fn GetCurrentProcess() -> *mut core::ffi::c_void;
        }
        #[link(name = "psapi")]
        extern "system" {
            fn GetProcessMemoryInfo(
                process: *mut core::ffi::c_void,
                counters: *mut ProcessMemoryCounters,
                cb: u32,
            ) -> i32;
        }

        unsafe {
            let mut counters: ProcessMemoryCounters = std::mem::zeroed();
            let cb = std::mem::size_of::<ProcessMemoryCounters>() as u32;
            let ok = GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, cb);
            if ok != 0 {
                Some(counters.peak_working_set_size as u64)
            } else {
                None
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    pub fn peak_rss_bytes() -> Option<u64> {
        None
    }
}

/// Human-friendly byte formatting for the `--stats` block (KiB/MiB/GiB).
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut val = bytes as f64;
    let mut unit = 0;
    while val >= 1024.0 && unit < UNITS.len() - 1 {
        val /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{val:.2} {}", UNITS[unit])
    }
}

struct Args {
    path: String,
    min_len: usize,
    max_strings: usize,
    format: Format,
    encoding: EncodingFilter,
    output: Option<String>,
    stats: bool,
    noise_threshold: Option<usize>,
    threads: usize,
    auto_tune: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum Format {
    Text,
    Json,
}

#[derive(Clone, Copy, PartialEq)]
enum EncodingFilter {
    All,
    Ascii,
    Utf16,
}

const USAGE: &str = "\
ratdmp — extracts ASCII/UTF-16LE strings from a RAM dump file (.dmp) or any binary file.

USAGE:
    ratdmp <path> [OPTIONS]

OPTIONS:
    --min-len <N>        Minimum length for a valid string (default 4)
    --max-strings <N>    Maximum number of strings to return (default 200000)
    --format <text|json> Output format (default text)
    --encoding <all|ascii|utf16>
                          Filter by encoding (default all)
    -o, --output <path>  Write to a file instead of stdout
    --stats               Print timing/throughput/peak-RSS stats to stderr
    --noise-threshold <N> Min run length for the byte-fill/heap-fill noise
                          filter (period-1 repeats use N, period-2 use N+2).
                          0 disables the filter entirely. (default: 6)
    --threads <N>         Scan using N worker threads (rayon work-stealing
                          pool) instead of the single-threaded streaming
                          scanner. 1 = sequential/streaming (default, lowest
                          peak memory, works on files of any size). >1 =
                          parallel scan, faster on multi-core machines with
                          fast storage / a warm page cache.
    --auto-tune            Choose a resource-conservative thread count from
                          CPU count, available memory, and input size. Explicit
                          --threads still takes precedence.
    -h, --help            Print this help

NOTE:
    When results are printed to stdout (no -o given) and both stdin and
    stdout are a real terminal, ratdmp asks afterwards whether to also
    save the filtered results to a file [y/N]. This prompt is skipped
    automatically when piping or redirecting output.

EXAMPLES:
    ratdmp lsass.dmp
    ratdmp lsass.dmp --min-len 6 --format json -o strings.json
    ratdmp lsass.dmp --encoding utf16 --max-strings 5000
    ratdmp lsass.dmp --stats -o strings.txt
    ratdmp lsass.dmp --noise-threshold 16
    ratdmp lsass.dmp --threads 8 --stats
    ratdmp lsass.dmp --auto-tune --stats
";

mod auto_tune {
    const REGION_BYTES: u64 = 64 * 1024 * 1024;
    const MEMORY_PER_WORKER: u64 = 128 * 1024 * 1024;

    /// Returns available memory in bytes when the operating system exposes it
    /// without requiring another dependency.
    pub fn available_memory_bytes() -> Option<u64> {
        #[cfg(target_os = "windows")]
        {
            #[repr(C)]
            struct MemoryStatus {
                length: u32,
                memory_load: u32,
                total_phys: u64,
                avail_phys: u64,
                total_page_file: u64,
                avail_page_file: u64,
                total_virtual: u64,
                avail_virtual: u64,
                avail_extended_virtual: u64,
            }
            #[link(name = "kernel32")]
            extern "system" {
                fn GlobalMemoryStatusEx(status: *mut MemoryStatus) -> i32;
            }
            unsafe {
                let mut status = MemoryStatus {
                    length: std::mem::size_of::<MemoryStatus>() as u32,
                    memory_load: 0,
                    total_phys: 0,
                    avail_phys: 0,
                    total_page_file: 0,
                    avail_page_file: 0,
                    total_virtual: 0,
                    avail_virtual: 0,
                    avail_extended_virtual: 0,
                };
                if GlobalMemoryStatusEx(&mut status) != 0 {
                    return Some(status.avail_phys);
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
            for line in meminfo.lines() {
                if let Some(value) = line.strip_prefix("MemAvailable:") {
                    let kib = value
                        .trim()
                        .strip_suffix("kB")?
                        .trim()
                        .parse::<u64>()
                        .ok()?;
                    return Some(kib * 1024);
                }
            }
        }

        None
    }

    /// Tune parallelism conservatively, leaving CPU and memory for the rest
    /// of the machine. This is a cap, not a promise about disk contention or
    /// thermal throttling.
    pub fn choose_threads(file_size: u64, requested: usize) -> usize {
        if requested != 1 {
            return requested;
        }

        let logical_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let chunks = ((file_size + REGION_BYTES - 1) / REGION_BYTES) as usize;
        if chunks <= 1 {
            return 1;
        }

        // Keep one logical CPU available, and use no more than roughly 75%
        // of the logical CPUs. Integer arithmetic rounds down conservatively.
        let cpu_limit = if logical_cpus <= 2 {
            1
        } else {
            std::cmp::min(logical_cpus - 1, (logical_cpus * 3) / 4)
        };

        // Reserve at least 75% of currently available RAM for other
        // processes. Each parallel region is 64 MiB and has scanner/result
        // overhead, so budget 128 MiB per worker.
        let memory_limit = available_memory_bytes()
            .map(|bytes| std::cmp::max(1, ((bytes / 4) / MEMORY_PER_WORKER) as usize))
            .unwrap_or(1);

        std::cmp::max(
            1,
            std::cmp::min(chunks, std::cmp::min(cpu_limit, memory_limit)),
        )
    }
}

fn parse_args() -> Result<Args, String> {
    let mut raw: Vec<String> = std::env::args().skip(1).collect();

    if raw.is_empty() || raw.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        std::process::exit(0);
    }

    let path = raw.remove(0);
    if path.starts_with('-') {
        return Err(format!(
            "missing path (the first arg must be a file path, got '{path}')"
        ));
    }

    let mut min_len = MIN_STRING_LEN;
    let mut max_strings = MAX_STRINGS;
    let mut format = Format::Text;
    let mut encoding = EncodingFilter::All;
    let mut output: Option<String> = None;
    let mut stats = false;
    let mut noise_threshold: Option<usize> = None;
    let mut threads: usize = 1;
    let mut threads_explicit = false;
    let mut auto_tune = false;

    let mut i = 0usize;
    while i < raw.len() {
        let arg = raw[i].as_str();
        macro_rules! next_val {
            () => {{
                i += 1;
                raw.get(i)
                    .ok_or_else(|| format!("missing value after '{arg}'"))?
                    .clone()
            }};
        }
        match arg {
            "--min-len" => {
                let v = next_val!();
                min_len = v
                    .parse::<usize>()
                    .map_err(|_| format!("--min-len is not a valid number: '{v}'"))?;
            }
            "--max-strings" => {
                let v = next_val!();
                max_strings = v
                    .parse::<usize>()
                    .map_err(|_| format!("--max-strings is not a valid number: '{v}'"))?;
            }
            "--format" => {
                let v = next_val!();
                format = match v.as_str() {
                    "text" => Format::Text,
                    "json" => Format::Json,
                    _ => return Err(format!("--format must be 'text' or 'json', got '{v}'")),
                };
            }
            "--encoding" => {
                let v = next_val!();
                encoding = match v.as_str() {
                    "all" => EncodingFilter::All,
                    "ascii" => EncodingFilter::Ascii,
                    "utf16" => EncodingFilter::Utf16,
                    _ => {
                        return Err(format!(
                            "--encoding must be 'all'/'ascii'/'utf16', got '{v}'"
                        ))
                    }
                };
            }
            "-o" | "--output" => {
                output = Some(next_val!());
            }
            "--stats" => {
                stats = true;
            }
            "--noise-threshold" => {
                let v = next_val!();
                let parsed = v
                    .parse::<usize>()
                    .map_err(|_| format!("--noise-threshold is not a valid number: '{v}'"))?;
                noise_threshold = Some(parsed);
            }
            "--threads" => {
                threads_explicit = true;
                let v = next_val!();
                threads = v
                    .parse::<usize>()
                    .map_err(|_| format!("--threads is not a valid number: '{v}'"))?;
                if threads == 0 {
                    return Err("--threads must be at least 1".to_string());
                }
            }
            "--auto-tune" => {
                auto_tune = true;
            }
            other => return Err(format!("unrecognized arg: '{other}' (see --help)")),
        }
        i += 1;
    }

    Ok(Args {
        path,
        min_len,
        max_strings,
        format,
        encoding,
        output,
        stats,
        noise_threshold,
        threads,
        auto_tune: auto_tune && !threads_explicit,
    })
}

fn matches_encoding(s: &ExtractedString, filter: EncodingFilter) -> bool {
    match filter {
        EncodingFilter::All => true,
        EncodingFilter::Ascii => s.encoding == "ascii",
        EncodingFilter::Utf16 => s.encoding == "utf16le",
    }
}

/// Hand-rolled JSON string escaping (RFC 8259) — good enough for CLI
/// output, no need to pull in serde_json just for this.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
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

fn write_output(strings: &[ExtractedString], format: Format, w: &mut dyn Write) -> io::Result<()> {
    match format {
        Format::Text => {
            for s in strings {
                writeln!(w, "{:#010x}\t{}\t{}", s.offset, s.encoding, s.text)?;
            }
        }
        Format::Json => {
            writeln!(w, "[")?;
            for (idx, s) in strings.iter().enumerate() {
                let comma = if idx + 1 < strings.len() { "," } else { "" };
                writeln!(
                    w,
                    "  {{\"offset\":{},\"encoding\":{},\"text\":{}}}{comma}",
                    s.offset,
                    json_escape(s.encoding),
                    json_escape(&s.text)
                )?;
            }
            writeln!(w, "]")?;
        }
    }
    Ok(())
}

/// Prompt the user on stderr and read one line of reply from stdin.
/// Returns `None` if either stream can't be read (never called unless both
/// are already confirmed to be real terminals).
fn prompt(question: &str) -> Option<String> {
    eprint!("{question} ");
    io::stderr().flush().ok()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line).ok()?;
    Some(line.trim().to_string())
}

/// After printing filtered results to stdout, ask whether the user also
/// wants them saved to a file (`y`/`N`, default no). Only called when both
/// stdin and stdout are real terminals -- a script piping `ratdmp`'s
/// output (`ratdmp x.dmp | grep ...`) never gets an unexpected prompt.
fn maybe_prompt_save(strings: &[ExtractedString], format: Format) {
    let answer = match prompt("Save filtered results to a file? [y/N]") {
        Some(a) => a.to_lowercase(),
        None => return,
    };
    if answer != "y" && answer != "yes" {
        return;
    }

    let path = match prompt("Output file path:") {
        Some(p) if !p.is_empty() => p,
        _ => {
            eprintln!("no path given, skipping save");
            return;
        }
    };

    match File::create(&path) {
        Ok(file) => {
            let mut w = BufWriter::new(file);
            match write_output(strings, format, &mut w) {
                Ok(()) => eprintln!("wrote {} strings to '{path}'", strings.len()),
                Err(e) => eprintln!("error writing output: {e}"),
            }
        }
        Err(e) => eprintln!("could not create output '{path}': {e}"),
    }
}

fn run() -> Result<(), String> {
    let args = parse_args()?;

    let file_size = std::fs::metadata(&args.path).map(|m| m.len()).unwrap_or(0);
    let start = Instant::now();

    let noise_cfg = match args.noise_threshold {
        Some(t) => NoiseConfig::from_threshold(t),
        None => NoiseConfig::default(),
    };
    let effective_threads = if args.auto_tune {
        auto_tune::choose_threads(file_size, args.threads)
    } else {
        args.threads
    };
    if args.auto_tune {
        eprintln!(
            "auto-tune: selected {} thread{} for {} input",
            effective_threads,
            if effective_threads == 1 { "" } else { "s" },
            human_bytes(file_size)
        );
    }

    let strings = if effective_threads > 1 {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(effective_threads)
            .build()
            .map_err(|e| format!("could not set up {}-thread pool: {e}", effective_threads))?;
        pool.install(|| {
            extract_strings_from_file_parallel(
                &args.path,
                args.min_len,
                args.max_strings,
                noise_cfg,
            )
        })
        .map_err(|e| format!("could not read '{}': {e}", args.path))?
    } else {
        extract_strings_from_file_with_noise_config(
            &args.path,
            args.min_len,
            args.max_strings,
            noise_cfg,
        )
        .map_err(|e| format!("could not read '{}': {e}", args.path))?
    };

    let filtered: Vec<&ExtractedString> = strings
        .iter()
        .filter(|s| matches_encoding(s, args.encoding))
        .collect();
    let ascii_count = filtered.iter().filter(|s| s.encoding == "ascii").count();
    let utf16_count = filtered.len() - ascii_count;
    // Clone into an owned Vec<ExtractedString> so write_output can be
    // reused as-is, rather than writing two versions (filter Vec<&T> vs
    // Vec<T>) -- the string count is already capped by max_strings, so
    // cloning here isn't a real performance concern.
    let owned: Vec<ExtractedString> = filtered
        .into_iter()
        .map(|s| ExtractedString {
            offset: s.offset,
            encoding: s.encoding,
            text: s.text.clone(),
        })
        .collect();

    // Elapsed time covers extraction + filtering, deliberately NOT the
    // subsequent write_output/-o write (I/O time depends on the disk/
    // terminal, not on this crate's algorithm -- mixing it in would make
    // the throughput number misleading).
    let elapsed = start.elapsed();

    match &args.output {
        Some(path) => {
            let file =
                File::create(path).map_err(|e| format!("could not create output '{path}': {e}"))?;
            let mut w = BufWriter::new(file);
            write_output(&owned, args.format, &mut w)
                .map_err(|e| format!("error writing output: {e}"))?;
            eprintln!("wrote {} strings to '{path}'", owned.len());
        }
        None => {
            {
                let stdout = io::stdout();
                let mut w = BufWriter::new(stdout.lock());
                write_output(&owned, args.format, &mut w)
                    .map_err(|e| format!("error writing stdout: {e}"))?;
            }
            // Only offer this when there's an actual human on the other end
            // of both stdin and stdout -- piping (`ratdmp x.dmp | grep ...`)
            // or redirecting output must stay non-interactive.
            if io::stdin().is_terminal() && io::stdout().is_terminal() {
                maybe_prompt_save(&owned, args.format);
            }
        }
    }

    if args.stats {
        let secs = elapsed.as_secs_f64();
        let throughput = if secs > 0.0 {
            (file_size as f64) / secs
        } else {
            f64::INFINITY
        };
        eprintln!("--- stats ---");
        eprintln!("threads       : {}", effective_threads);
        eprintln!("file size     : {}", human_bytes(file_size));
        eprintln!("time          : {:.3} ms", elapsed.as_secs_f64() * 1000.0);
        eprintln!("throughput    : {}/s", human_bytes(throughput as u64));
        eprintln!(
            "strings found : {} (ascii: {ascii_count}, utf16le: {utf16_count})",
            owned.len()
        );
        match mem_stats::peak_rss_bytes() {
            Some(bytes) => eprintln!("peak RSS      : {}", human_bytes(bytes)),
            None => eprintln!("peak RSS      : n/a (not supported on this OS)"),
        }
    }

    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ratdmp: error: {e}");
            ExitCode::FAILURE
        }
    }
}
