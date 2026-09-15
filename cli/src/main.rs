use ratdmp::{
    extract_strings_from_file_parallel, extract_strings_from_file_streaming,
    extract_strings_from_file_with_noise_config,
    scan_entropy_from_file_streaming_with_data, scan_yara_from_file_streaming, EntropyRegion,
    ExtractedString, NoiseConfig, MAX_STRINGS, MIN_STRING_LEN,
};
use std::fs::File;
use std::io::{self, BufReader, BufWriter, IsTerminal, Read, Write};
use std::time::Instant;

const ENTROPY_THRESHOLD: f64 = 7.2;
const MAX_ENTROPY_REPORTS: usize = 12;
const MAX_XOR_CANDIDATES: usize = 256;
const MAX_XOR_CANDIDATE_LEN: usize = 100;
const MIN_XOR_CANDIDATE_LEN: usize = 10;
const MAX_XOR_RESULTS_PER_CANDIDATE: usize = 5;

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
    entropy: bool,
    yar: Option<String>,
    brute_xor: Option<Vec<usize>>,
    parse_pid: bool,
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
    --entropy            Scan and export high-entropy regions
    --yar <PATH>         Compile and match a YARA/YARA-X rule file while streaming
    --brute-xor <1b;2b;3b>
                          Brute-force XOR candidates using selected key sizes
    --parse-pid          Map PID markers in extracted strings
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
        entropy: false,
        yar: None,
        brute_xor: None,
        parse_pid: false,
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
            "--entropy" => args.entropy = true,
            "--yar" => args.yar = Some(next(&mut i)?),
            "--brute-xor" => {
                let value = next(&mut i)?;
                let mut sizes = Vec::new();
                for part in value.split([';', ',']) {
                    let size = part
                        .strip_suffix('b')
                        .unwrap_or(part)
                        .parse::<usize>()
                        .map_err(|_| "invalid --brute-xor key size".to_string())?;
                    if !(1..=3).contains(&size) {
                        return Err("--brute-xor supports key sizes 1b, 2b, and 3b".to_string());
                    }
                    if !sizes.contains(&size) {
                        sizes.push(size);
                    }
                }
                if sizes.is_empty() {
                    return Err("--brute-xor requires at least one key size".to_string());
                }
                args.brute_xor = Some(sizes);
            }
            "--parse-pid" => args.parse_pid = true,
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

fn hex_encode(data: &[u8]) -> String {
    let mut encoded = String::with_capacity(data.len() * 2);
    for byte in data {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

fn write_entropy_json(
    region: EntropyRegion,
    data: &[u8],
    writer: &mut dyn Write,
    result_count: &mut usize,
) -> io::Result<()> {
    if *result_count > 0 {
        write!(writer, ",\n")?;
    }
    write!(
        writer,
        "  {{\"group\":\"Undefined\",\"offset\":{},\"length\":{},\"entropy\":{:.6},\"data_hex\":{}}}",
        region.offset,
        region.length,
        region.entropy,
        json_escape(&hex_encode(data))
    )?;
    *result_count += 1;
    Ok(())
}

fn write_entropy_text(
    region: EntropyRegion,
    data: &[u8],
    writer: &mut dyn Write,
) -> io::Result<()> {
    writeln!(
        writer,
        "{:#010x}\tUndefined\tlength={}\tentropy={:.6}\tdata_hex={}",
        region.offset,
        region.length,
        region.entropy,
        hex_encode(data)
    )
}

fn write_yara_text(
    rule: &ratdmp::YaraMatch,
    writer: &mut dyn Write,
) -> io::Result<()> {
    writeln!(
        writer,
        "{:#010x}\tYARA\t{}::{}",
        rule.offset, rule.namespace, rule.rule
    )
}

fn write_yara_json(
    rule: &ratdmp::YaraMatch,
    writer: &mut dyn Write,
    result_count: &mut usize,
) -> io::Result<()> {
    if *result_count > 0 {
        write!(writer, ",\n")?;
    }
    write!(
        writer,
        "  {{\"group\":\"YARA\",\"offset\":{},\"namespace\":{},\"rule\":{}}}",
        rule.offset,
        json_escape(&rule.namespace),
        json_escape(&rule.rule)
    )?;
    *result_count += 1;
    Ok(())
}

#[derive(Clone)]
struct XorResult {
    offset: u64,
    key: Vec<u8>,
    plaintext: Vec<u8>,
    score: f64,
}

fn xor_printable_score(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let printable = data
        .iter()
        .filter(|&&byte| (32..=126).contains(&byte) || byte == b'\t' || byte == b'\n' || byte == b'\r')
        .count();
    let text = String::from_utf8_lossy(data).to_ascii_lowercase();
    let mut score = printable as f64 / data.len() as f64;
    if std::str::from_utf8(data).is_ok() {
        score += 0.15;
    }
    for keyword in ["http", "www", ".exe", ".dll", "virtual", "create", "thread"] {
        if text.contains(keyword) {
            score += 0.25;
        }
    }
    score
}

fn xor_top_results(candidate: &[u8], offset: u64, key_size: usize) -> Vec<XorResult> {
    let key_count = 1usize << (key_size * 8);
    let mut top = Vec::with_capacity(MAX_XOR_RESULTS_PER_CANDIDATE);
    for value in 0..key_count {
        let mut key = vec![0u8; key_size];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = ((value >> (index * 8)) & 0xff) as u8;
        }
        let plaintext: Vec<u8> = candidate
            .iter()
            .enumerate()
            .map(|(index, &byte)| byte ^ key[index % key_size])
            .collect();
        let result = XorResult {
            offset,
            key,
            score: xor_printable_score(&plaintext),
            plaintext,
        };
        let position = top
            .iter()
            .position(|item: &XorResult| result.score > item.score)
            .unwrap_or(top.len());
        top.insert(position, result);
        if top.len() > MAX_XOR_RESULTS_PER_CANDIDATE {
            top.pop();
        }
    }
    top
}

fn collect_xor_candidates(path: &str) -> io::Result<Vec<(u64, Vec<u8>)>> {
    let mut reader = BufReader::with_capacity(1 << 16, File::open(path)?);
    let mut byte = [0u8; 1];
    let mut run = Vec::new();
    let mut run_offset = 0u64;
    let mut offset = 0u64;
    let mut candidates = Vec::new();
    loop {
        let read = reader.read(&mut byte)?;
        if read == 0 {
            break;
        }
        if byte[0] == 0 {
            append_xor_candidates(&mut candidates, run_offset, &run);
            run.clear();
        } else {
            if run.is_empty() {
                run_offset = offset;
            }
            run.push(byte[0]);
        }
        offset += 1;
        if candidates.len() >= MAX_XOR_CANDIDATES {
            break;
        }
    }
    if candidates.len() < MAX_XOR_CANDIDATES {
        append_xor_candidates(&mut candidates, run_offset, &run);
    }
    candidates.truncate(MAX_XOR_CANDIDATES);
    Ok(candidates)
}

fn append_xor_candidates(candidates: &mut Vec<(u64, Vec<u8>)>, offset: u64, data: &[u8]) {
    if data.len() < MIN_XOR_CANDIDATE_LEN {
        return;
    }
    for (index, chunk) in data.chunks(MAX_XOR_CANDIDATE_LEN).enumerate() {
        if chunk.len() >= MIN_XOR_CANDIDATE_LEN
            && !chunk.windows(2).all(|window| window[0] == window[1])
            && !chunk
                .windows(3)
                .all(|window| window[0] == window[2] && window[0] != window[1])
        {
            candidates.push((offset + (index * MAX_XOR_CANDIDATE_LEN) as u64, chunk.to_vec()));
            if candidates.len() >= MAX_XOR_CANDIDATES {
                return;
            }
        }
    }
}

fn write_xor_text(result: &XorResult, writer: &mut dyn Write) -> io::Result<()> {
    writeln!(
        writer,
        "{:#010x}\tXOR\tkey={}\tscore={:.3}\t{}",
        result.offset,
        hex_encode(&result.key),
        result.score,
        String::from_utf8_lossy(&result.plaintext)
    )
}

fn write_xor_json(
    result: &XorResult,
    writer: &mut dyn Write,
    result_count: &mut usize,
) -> io::Result<()> {
    if *result_count > 0 {
        write!(writer, ",\n")?;
    }
    write!(
        writer,
        "  {{\"group\":\"XOR\",\"offset\":{},\"key\":{},\"score\":{:.6},\"plaintext\":{}}}",
        result.offset,
        json_escape(&hex_encode(&result.key)),
        result.score,
        json_escape(&String::from_utf8_lossy(&result.plaintext))
    )?;
    *result_count += 1;
    Ok(())
}

fn write_string_json(
    result: &ExtractedString,
    writer: &mut dyn Write,
    result_count: &mut usize,
    parse_pid: bool,
) -> io::Result<()> {
    if *result_count > 0 {
        write!(writer, ",\n")?;
    }
    write!(
        writer,
        "  {{\"offset\":{},\"encoding\":{},\"text\":{}",
        result.offset,
        json_escape(result.encoding),
        json_escape(&result.text)
    )?;
    if parse_pid {
        match parse_pid_marker(&result.text) {
            Some(pid) => write!(writer, ",\"pid\":{pid}")?,
            None => write!(writer, ",\"pid\":null")?,
        }
    }
    write!(writer, "}}")?;
    *result_count += 1;
    Ok(())
}

fn parse_pid_marker(text: &str) -> Option<u32> {
    let tokens: Vec<&str> = text
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect();
    for (index, token) in tokens.iter().enumerate() {
        if token.eq_ignore_ascii_case("pid") || token.eq_ignore_ascii_case("processid") {
            if let Some(value) = tokens.get(index + 1) {
                if value.bytes().all(|byte| byte.is_ascii_digit()) {
                    if let Ok(pid) = value.parse::<u32>() {
                        return Some(pid);
                    }
                }
            }
        }
    }
    None
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
    } else if contains_ip_address(text) {
        Some("ip-address")
    } else if contains_crypto_address(text) {
        Some("crypto-wallet")
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

fn contains_ip_address(text: &str) -> bool {
    text.split(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != ':')
        .filter(|token| !token.is_empty())
        .any(|token| {
            token
                .split_once(':')
                .map(|(host, _port)| host.parse::<std::net::Ipv4Addr>().is_ok())
                .unwrap_or(false)
                || token.parse::<std::net::Ipv4Addr>().is_ok()
                || token.parse::<std::net::Ipv6Addr>().is_ok()
        })
}

fn contains_crypto_address(text: &str) -> bool {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .any(is_crypto_address)
}

fn is_crypto_address(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();

    // Ethereum and EVM-compatible addresses.
    if token.len() == 42
        && lower.starts_with("0x")
        && token[2..].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return true;
    }

    // Bitcoin legacy (1/3...), native SegWit (bc1...), and testnet (tb1...).
    if (token.starts_with('1') || token.starts_with('3'))
        && (26..=35).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() && !matches!(b, b'0' | b'O' | b'I' | b'l'))
    {
        return true;
    }
    if (lower.starts_with("bc1") || lower.starts_with("tb1"))
        && token.len() >= 14
        && token[3..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b.is_ascii_lowercase() && b.is_ascii_alphanumeric()))
    {
        return true;
    }

    // Monero primary addresses are 95-character Base58 strings beginning 4.
    if token.starts_with('4')
        && token.len() == 95
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() && !matches!(b, b'0' | b'O' | b'I' | b'l'))
    {
        return true;
    }

    // Solana addresses are typically 32-44 characters of Base58.
    token.len() >= 32
        && token.len() <= 44
        && token.bytes().any(|b| b.is_ascii_digit())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() && !matches!(b, b'0' | b'O' | b'I' | b'l'))
}

#[cfg(test)]
mod tests {
    use super::{contains_crypto_address, contains_ip_address, important_reason, parse_pid_marker};

    #[test]
    fn highlights_ipv4_and_ipv6() {
        assert!(contains_ip_address("connect 192.168.56.101:4444"));
        assert!(contains_ip_address("fe80::1"));
    }

    #[test]
    fn highlights_common_wallet_formats() {
        assert!(contains_crypto_address(
            "0x52908400098527886E0F7030069857D2E4169EE7"
        ));
        assert!(contains_crypto_address(
            "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
        ));
    }

    #[test]
    fn prioritizes_ip_and_wallet_signals() {
        assert_eq!(important_reason("server=10.0.0.8"), Some("ip-address"));
        assert_eq!(
            important_reason("wallet=0x52908400098527886E0F7030069857D2E4169EE7"),
            Some("crypto-wallet")
        );
    }

    #[test]
    fn parses_common_pid_markers() {
        assert_eq!(parse_pid_marker("ProcessId=4242 image.exe"), Some(4242));
        assert_eq!(parse_pid_marker("pid: 1337"), Some(1337));
        assert_eq!(parse_pid_marker("no process marker"), None);
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

fn print_report(
    result_count: usize,
    short: usize,
    medium: usize,
    long: usize,
    important: &[ExtractedString],
    entropy_regions: &[EntropyRegion],
    size: u64,
    elapsed: f64,
    threads: usize,
) {
    let color = io::stderr().is_terminal();
    if color {
        eprintln!("\x1b[1;32m  [OK] scan complete\x1b[0m");
        eprintln!("\x1b[1;36m+-------------------- summary -----------------------------+\x1b[0m");
    } else {
        eprintln!("  [OK] scan complete");
        eprintln!("+-------------------- summary -----------------------------+");
    }
    eprintln!("  results    : {result_count}");
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
                "      - {:<12} | offset {:#010x} | {:<7} | {}",
                reason,
                result.offset, result.encoding, result.text
            );
        }
    }
    if !entropy_regions.is_empty() {
        eprintln!("  [!] high-entropy regions (showing up to 12)");
        for region in entropy_regions {
            eprintln!(
                "      offset {:#010x}  {:>6} bytes  entropy {:.3}/8.000",
                region.offset, region.length, region.entropy
            );
        }
    }
}

fn record_result(
    result: ExtractedString,
    writer: &mut dyn Write,
    format: Format,
    result_count: &mut usize,
    short: &mut usize,
    medium: &mut usize,
    long: &mut usize,
    important: &mut Vec<ExtractedString>,
    parse_pid: bool,
) -> io::Result<()> {
    match format {
        Format::Text => {
            write!(
                writer,
                "{:#010x}\t{}\t{}",
                result.offset, result.encoding, result.text
            )?;
            if parse_pid {
                match parse_pid_marker(&result.text) {
                    Some(pid) => write!(writer, "\tpid={pid}")?,
                    None => write!(writer, "\tpid=-")?,
                }
            }
            writeln!(writer)?;
        }
        Format::Json => {
            write_string_json(&result, writer, result_count, parse_pid)?;
        }
    }
    *result_count += 1;
    match result.text.chars().count() {
        0..=7 => *short += 1,
        8..=31 => *medium += 1,
        _ => *long += 1,
    }
    if important.len() < 12 && important_reason(&result.text).is_some() {
        important.push(result);
    }
    Ok(())
}

fn write_results(
    results: &[ExtractedString],
    format: Format,
    writer: &mut dyn Write,
    parse_pid: bool,
) -> io::Result<()> {
    match format {
        Format::Text => {
            for result in results {
                write!(
                    writer,
                    "{:#010x}\t{}\t{}",
                    result.offset, result.encoding, result.text
                )?;
                if parse_pid {
                    match parse_pid_marker(&result.text) {
                        Some(pid) => write!(writer, "\tpid={pid}")?,
                        None => write!(writer, "\tpid=-")?,
                    }
                }
                writeln!(writer)?;
            }
        }
        Format::Json => {
            writeln!(writer, "[")?;
            let mut result_count = 0;
            for result in results {
                write_string_json(result, writer, &mut result_count, parse_pid)?;
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
    let mut entropy_regions = Vec::new();
    if args.entropy {
        scan_entropy_from_file_streaming_with_data(&args.path, ENTROPY_THRESHOLD, |region, _| {
            if entropy_regions.len() < MAX_ENTROPY_REPORTS {
                entropy_regions.push(region);
            }
        })
        .map_err(|e| format!("entropy scan failed: {e}"))?;
    }
    let mut yara_matches = Vec::new();
    if let Some(rules_path) = args.yar.as_ref() {
        scan_yara_from_file_streaming(&args.path, rules_path, |matched| {
            yara_matches.push(matched);
        })
        .map_err(|e| format!("YARA scan failed: {e}"))?;
    }
    let mut xor_results = Vec::new();
    if let Some(key_sizes) = args.brute_xor.as_ref() {
        let candidates = collect_xor_candidates(&args.path)
            .map_err(|e| format!("XOR candidate scan failed: {e}"))?;
        for (offset, candidate) in candidates {
            let mut candidate_results = Vec::new();
            for &key_size in key_sizes {
                candidate_results.extend(xor_top_results(&candidate, offset, key_size));
            }
            candidate_results.sort_by(|left, right| {
                right
                    .score
                    .partial_cmp(&left.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            candidate_results.truncate(MAX_XOR_RESULTS_PER_CANDIDATE);
            xor_results.extend(candidate_results);
        }
        xor_results.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }
    if threads == 1 {
        let mut writer: Box<dyn Write> = match args.output.as_ref() {
            Some(path) => Box::new(BufWriter::new(
                File::create(path).map_err(|e| format!("cannot create '{path}': {e}"))?,
            )),
            None => Box::new(BufWriter::new(io::stdout().lock())),
        };
        if args.format == Format::Json {
            write!(writer, "[\n").map_err(|e| format!("write failed: {e}"))?;
        }
        let mut result_count = 0;
        let mut short = 0;
        let mut medium = 0;
        let mut long = 0;
        let mut important = Vec::new();
        let mut write_error = None;
        extract_strings_from_file_streaming(
            &args.path,
            args.min_len,
            args.max_strings,
            noise,
            |result| {
                if write_error.is_some() {
                    return;
                }
                if matches!(args.encoding, Encoding::All)
                    || (args.encoding == Encoding::Ascii && result.encoding == "ascii")
                    || (args.encoding == Encoding::Utf16 && result.encoding == "utf16le")
                {
                    if let Err(error) = record_result(
                        result,
                        &mut writer,
                        args.format,
                        &mut result_count,
                        &mut short,
                        &mut medium,
                        &mut long,
                        &mut important,
                        args.parse_pid,
                    ) {
                        write_error = Some(error);
                    }
                }
            },
        )
        .map_err(|e| format!("scan failed: {e}"))?;
        if let Some(error) = write_error {
            return Err(format!("write failed: {error}"));
        }
        if args.format == Format::Json {
            let mut json_count = result_count;
            for matched in &yara_matches {
                write_yara_json(matched, &mut writer, &mut json_count)
                    .map_err(|e| format!("write failed: {e}"))?;
            }
            for result in &xor_results {
                write_xor_json(result, &mut writer, &mut json_count)
                    .map_err(|e| format!("write failed: {e}"))?;
            }
            if args.entropy {
                scan_entropy_from_file_streaming_with_data(
                    &args.path,
                    ENTROPY_THRESHOLD,
                    |region, data| {
                        if write_error.is_none() {
                            if let Err(error) =
                                write_entropy_json(region, data, &mut writer, &mut json_count)
                            {
                                write_error = Some(error);
                            }
                        }
                    },
                )
                .map_err(|e| format!("entropy scan failed: {e}"))?;
            }
            if let Some(error) = write_error {
                return Err(format!("write failed: {error}"));
            }
            write!(writer, "\n]\n").map_err(|e| format!("write failed: {e}"))?;
        } else {
            for matched in &yara_matches {
                write_yara_text(matched, &mut writer)
                    .map_err(|e| format!("write failed: {e}"))?;
            }
            for result in &xor_results {
                write_xor_text(result, &mut writer)
                    .map_err(|e| format!("write failed: {e}"))?;
            }
            if args.entropy {
            scan_entropy_from_file_streaming_with_data(
                &args.path,
                ENTROPY_THRESHOLD,
                |region, data| {
                    if write_error.is_none() {
                        if let Err(error) = write_entropy_text(region, data, &mut writer) {
                            write_error = Some(error);
                        }
                    }
                },
            )
            .map_err(|e| format!("entropy scan failed: {e}"))?;
            if let Some(error) = write_error {
                return Err(format!("write failed: {error}"));
            }
            }
        }
        writer.flush().map_err(|e| format!("write failed: {e}"))?;
        if let Some(path) = args.output {
            eprintln!("wrote {result_count} results to '{path}'");
        }
        print_report(
            result_count, short, medium, long, &important, &entropy_regions, file_size,
            start.elapsed().as_secs_f64(), threads,
        );
        return Ok(());
    }

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

    let output_path = args.output.clone();
    let mut writer: Box<dyn Write> = match output_path.as_ref() {
        Some(path) => Box::new(BufWriter::new(
            File::create(path).map_err(|e| format!("cannot create '{path}': {e}"))?,
        )),
        None => Box::new(BufWriter::new(io::stdout().lock())),
    };
    if args.format == Format::Json {
        write!(writer, "[\n").map_err(|e| format!("write failed: {e}"))?;
        let mut json_count = 0;
        for result in &results {
            write_string_json(result, &mut writer, &mut json_count, args.parse_pid)
            .map_err(|e| format!("write failed: {e}"))?;
        }
        for matched in &yara_matches {
            write_yara_json(matched, &mut writer, &mut json_count)
            .map_err(|e| format!("write failed: {e}"))?;
        }
        for result in &xor_results {
            write_xor_json(result, &mut writer, &mut json_count)
                .map_err(|e| format!("write failed: {e}"))?;
        }
        if args.entropy {
            let mut entropy_write_error = None;
            scan_entropy_from_file_streaming_with_data(
            &args.path,
            ENTROPY_THRESHOLD,
            |region, data| {
                if entropy_write_error.is_none() {
                    if let Err(error) =
                        write_entropy_json(region, data, &mut writer, &mut json_count)
                    {
                        entropy_write_error = Some(error);
                    }
                }
            },
            )
            .map_err(|e| format!("entropy scan failed: {e}"))?;
            if let Some(error) = entropy_write_error {
            return Err(format!("write failed: {error}"));
            }
        }
        writeln!(writer, "\n]").map_err(|e| format!("write failed: {e}"))?;
    } else {
        write_results(&results, args.format, &mut writer, args.parse_pid)
            .map_err(|e| format!("write failed: {e}"))?;
        for matched in &yara_matches {
            write_yara_text(matched, &mut writer)
                .map_err(|e| format!("write failed: {e}"))?;
        }
        for result in &xor_results {
            write_xor_text(result, &mut writer)
                .map_err(|e| format!("write failed: {e}"))?;
        }
        if args.entropy && args.format == Format::Text {
            let mut entropy_write_error = None;
            scan_entropy_from_file_streaming_with_data(
                &args.path,
                ENTROPY_THRESHOLD,
                |region, data| {
                    if entropy_write_error.is_none() {
                        if let Err(error) = write_entropy_text(region, data, &mut writer) {
                            entropy_write_error = Some(error);
                        }
                    }
                },
            )
            .map_err(|e| format!("entropy scan failed: {e}"))?;
            if let Some(error) = entropy_write_error {
                return Err(format!("write failed: {error}"));
            }
        }
    }
    writer.flush().map_err(|e| format!("write failed: {e}"))?;
    if let Some(path) = output_path {
        eprintln!("wrote {} results to '{path}'", results.len());
    }
    let _ = args.stats;
    let mut short = 0;
    let mut medium = 0;
    let mut long = 0;
    let mut important = Vec::new();
    for result in &results {
        match result.text.chars().count() {
            0..=7 => short += 1,
            8..=31 => medium += 1,
            _ => long += 1,
        }
        if important.len() < 12 && important_reason(&result.text).is_some() {
            important.push(result.clone());
        }
    }
    print_report(
        results.len(), short, medium, long, &important, &entropy_regions, file_size,
        start.elapsed().as_secs_f64(), threads,
    );
    Ok(())
}
