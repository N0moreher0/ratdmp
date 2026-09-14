//! `ratdmp` -- a standalone crate (open source, dual-licensed
//! MIT/Apache-2.0). Depends on `serde` (so `ExtractedString` can be
//! serialized -- the caller decides how to wrap it in JSON/its own protocol
//! if needed, this crate only returns a plain `Vec<ExtractedString>`) and
//! `rayon`, used only by the opt-in parallel scanning path
//! (`extract_strings_from_file_parallel`) -- the default sequential/
//! streaming path does not touch it.
//!
//! Pulls printable ASCII / UTF-16LE strings out of a raw `.dmp` memory-dump
//! file (or any other binary file). Pure post-processing over an
//! already-existing file on disk (no WinAPI / process-permission
//! involved) -- scans the buffer sequentially, grouping contiguous runs of
//! printable bytes (ASCII) and UTF-16LE runs (printable low byte, high byte
//! == 0x00), the same principle as the Unix `strings` command. It does NOT
//! parse the MDMP file format's internal structure -- scanning the whole
//! payload is the only approach that doesn't depend on the Windows/DbgHelp
//! version that produced the dump.
//!
//! Two things keep this fast and memory-safe on multi-gigabyte files:
//! - Chunked streaming (`CHUNK_SIZE` = 32MB per read) via `Read`, carrying
//!   exactly 1 trailing byte over to the next chunk so a UTF-16LE pair
//!   straddling an I/O boundary is always tested correctly -- the whole
//!   file (which can be several GB) is NEVER loaded into RAM at once.
//! - ASCII and UTF-16LE are detected SIMULTANEOUSLY in a single pass
//!   (`StringRunScanner::feed`) instead of two independent loops -- fewer
//!   passes over the buffer.
//!
//! SPEED OPTIMIZATIONS (results unchanged, speed only): (1) a precomputed
//! 256-entry `PRINTABLE_TABLE` lookup table built at compile time instead
//! of a range-match per byte; (2) each byte is looked up in the printable
//! table EXACTLY ONCE (the ascii branch and the utf16 branch, when that
//! byte acts as the "lo" byte, share the same lookup); (3) fast-skip jumps
//! straight over an entire run of consecutive non-printable bytes when no
//! run is currently open (skipping the lookahead/aligned computation and
//! the no-op flush() calls for each junk byte entirely) -- non-printable
//! binary regions typically make up the bulk of a real RAM dump, so this
//! is the hottest path.
//!
//! Noise filtering (higher filter accuracy than a naive `strings`-style
//! scan, same ASCII/UTF-16LE run-grouping logic): a naive scan accepts ANY
//! run meeting `min_len` as a valid "string", including a run of a single
//! repeated character (`AAAAAAAA...`) or two characters alternating
//! (`ABABABAB...`) -- an extremely common kind of noise in real RAM dumps
//! (byte-fill/heap-fill patterns on alloc/free, alignment padding, repeated
//! memset), which almost never carries useful information and needlessly
//! bloats the result. `is_low_information_repeat()` filters exactly those
//! two simple repeat shapes (period 1 and period 2, only triggered from a
//! long-enough threshold so it doesn't accidentally drop short real
//! strings like "0000"/"====" which can still be real data) -- it does NOT
//! filter more broadly (no entropy/complex statistics) to avoid false
//! negatives (missing real strings), staying true to the "only filter
//! what's certainly noise" spirit.

use serde::Serialize;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};

/// Default `min_len` when the caller doesn't pass one -- a reasonable
/// baseline for the `extract_strings*` functions below when the caller
/// wants a sensible default instead of picking their own.
pub const MIN_STRING_LEN: usize = 4;
/// Default `max_strings` (see MIN_STRING_LEN above).
pub const MAX_STRINGS: usize = 200_000;

// Default minimum length for a "single repeated character" run (period 1,
// e.g. "aaaaaa") to be treated as byte-fill/padding noise rather than real
// data. Set a bit higher than the default MIN_STRING_LEN (4) because short
// strings like "0000"/"1111" can still be real numbers (a PIN, a repeated
// year...). Overridable at runtime via `NoiseConfig` / `--noise-threshold`.
const NOISE_REPEAT1_MIN_LEN: usize = 6;

// Default minimum length for a "strictly alternating 2-character" run
// (period 2, e.g. "ababab"/"\xCD\xAB\xCD\xAB...") to be treated as noise --
// higher than the period-1 threshold because a 2-character pattern has a
// slightly higher chance of coincidentally matching a real string (e.g. a
// short letter pair repeated), so more length evidence is required to be
// confident it's a fill pattern. Overridable at runtime, see `NoiseConfig`.
const NOISE_REPEAT2_MIN_LEN: usize = 8;

/// Runtime-configurable noise-filter thresholds (see `is_low_information_repeat`).
/// Previously these were the hardcoded constants `NOISE_REPEAT1_MIN_LEN` /
/// `NOISE_REPEAT2_MIN_LEN` -- now callers (including the CLI's
/// `--noise-threshold <N>`) can tune or fully disable the filter.
#[derive(Debug, Clone, Copy)]
pub struct NoiseConfig {
    /// Minimum run length for a period-1 repeat (e.g. "aaaaaa") to count as noise.
    pub repeat1_min_len: usize,
    /// Minimum run length for a period-2 repeat (e.g. "abab") to count as noise.
    pub repeat2_min_len: usize,
}

impl Default for NoiseConfig {
    fn default() -> Self {
        Self {
            repeat1_min_len: NOISE_REPEAT1_MIN_LEN,
            repeat2_min_len: NOISE_REPEAT2_MIN_LEN,
        }
    }
}

impl NoiseConfig {
    /// Turns the noise filter off entirely (every run is kept, however repetitive).
    pub fn disabled() -> Self {
        Self {
            repeat1_min_len: usize::MAX,
            repeat2_min_len: usize::MAX,
        }
    }

    /// Builds a config from a single `--noise-threshold <N>`-style value:
    /// `N` becomes the period-1 threshold, and the period-2 threshold is
    /// `N + 2` (preserving the original gap between the two, since a
    /// 2-character pattern needs a bit more length evidence to be confident
    /// it's a fill pattern rather than a coincidental short real string).
    /// `0` disables the filter entirely.
    pub fn from_threshold(threshold: usize) -> Self {
        if threshold == 0 {
            Self::disabled()
        } else {
            Self {
                repeat1_min_len: threshold,
                repeat2_min_len: threshold + 2,
            }
        }
    }
}

// File chunk size per read -- large enough for efficient I/O,
// small enough to not accumulate too much RAM for the buffer.
const CHUNK_SIZE: usize = 32 * 1024 * 1024;

// Upper bound on the length of a currently-open "run" before it's forced
// to flush into the results -- guards against an unusually long run of
// contiguous printable bytes growing the buffer without limit. 1MB of text
// for a single "string" is already more than enough to spot an IOC.
const MAX_RUN_CHARS: usize = 1_000_000;

const AVG_BYTES_PER_STRING: u64 = 48; // pure heuristic, only used to hint the initial capacity
const MIN_CAPACITY_HINT: usize = 64;

#[derive(Debug, Clone, Serialize)]
pub struct ExtractedString {
    pub offset: u64,
    pub encoding: &'static str,
    pub text: String,
}

/// The printable-character set: printable ASCII + common whitespace,
/// minus `\v` (0x0b) and `\f` (0x0c).
///
/// OPTIMIZATION (character set unchanged): a 256-entry lookup table is
/// computed at compile time instead of matching several range branches per
/// byte -- looking up `PRINTABLE_TABLE[b as usize]` is a branchless O(1)
/// array read, much cheaper than a chain of range comparisons when running
/// over tens/hundreds of millions of bytes in a real dump file.
const fn build_printable_table() -> [bool; 256] {
    let mut table = [false; 256];
    let mut i = 0usize;
    while i < 256 {
        let b = i as u8;
        table[i] = match b {
            b'0'..=b'9' => true,
            b'A'..=b'Z' => true,
            b'a'..=b'z' => true,
            b' ' | b'\t' | b'\n' | b'\r' => true,
            // !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
            0x21..=0x2F | 0x3A..=0x40 | 0x5B..=0x60 | 0x7B..=0x7E => true,
            _ => false,
        };
        i += 1;
    }
    table
}

static PRINTABLE_TABLE: [bool; 256] = build_printable_table();

#[inline(always)]
fn is_printable(b: u8) -> bool {
    PRINTABLE_TABLE[b as usize]
}

/// Stateful scanner that groups ASCII + UTF-16LE runs SIMULTANEOUSLY in a
/// single pass over the buffer, and carries its state (a still-open run)
/// ACROSS successive calls to `feed()` on different chunks of data read
/// from the file -- so a string straddling two I/O chunk boundaries is
/// still grouped in full, never truncated or lost.
///
/// The UTF-16LE testing rule is kept EXACTLY as in the original: every byte
/// position could be the START of a new string (every offset is tried),
/// but while a run is ALREADY open, the next test only happens at the
/// correct "next low byte" position (2 bytes ahead).
struct StringRunScanner<'a> {
    min_len: usize,
    noise_cfg: NoiseConfig,
    on_found: &'a mut dyn FnMut(ExtractedString),

    ascii_start: i64,
    ascii_buf: Vec<u8>,

    u16_start: i64,
    u16_next_pos: i64,
    u16_buf: Vec<u16>,
}

impl<'a> StringRunScanner<'a> {
    fn new(
        min_len: usize,
        noise_cfg: NoiseConfig,
        on_found: &'a mut dyn FnMut(ExtractedString),
    ) -> Self {
        Self {
            min_len,
            noise_cfg,
            on_found,
            ascii_start: -1,
            ascii_buf: Vec::with_capacity(64),
            u16_start: -1,
            u16_next_pos: -1,
            u16_buf: Vec::with_capacity(64),
        }
    }

    /// Processes `process_count` bytes starting at `buffer[offset]`,
    /// corresponding to absolute offset `global_base` in the original
    /// overall data. `buffer_valid_len` is the total number of bytes
    /// ACTUALLY available in the buffer from `offset` onward (can be
    /// LARGER than process_count) -- used to safely test 1-byte lookahead
    /// (buffer[i+1]) without processing that byte right away, letting the
    /// caller "hold back" the last byte of a chunk as carry into the next
    /// `feed()` call.
    fn feed(
        &mut self,
        buffer: &[u8],
        offset: usize,
        process_count: usize,
        buffer_valid_len: usize,
        global_base: u64,
    ) {
        let mut k = 0usize;
        while k < process_count {
            // -- Fast-skip: when NO run is currently open (neither ascii
            // nor utf16), the current position can only be the START of a
            // new run, never a CONTINUATION point -- and both run kinds
            // require the current byte (ascii) / "lo" byte (utf16) to be
            // printable, so a non-printable byte can't open any run at all
            // (it could only be the "hi" byte of a utf16 pair starting at
            // the PREVIOUS position -- and that position already did its
            // own lookahead check on this byte, no need to re-check).
            // So jump straight over the whole run of consecutive
            // non-printable bytes without computing has_next/aligned or
            // calling the no-op flush() for every junk byte -- the
            // non-printable binary region is usually the bulk of a real
            // RAM dump's payload, so this is the hottest path.
            if self.ascii_start < 0 && self.u16_start < 0 {
                while k < process_count && !is_printable(buffer[offset + k]) {
                    k += 1;
                }
                if k >= process_count {
                    break;
                }
            }

            let i = offset + k;
            let g = global_base + k as u64;
            let b = buffer[i];
            let printable_b = is_printable(b); // shared by both branches below, avoids looking up the table twice for the same byte

            // -- ASCII: only needs the current byte itself, no lookahead --
            if printable_b {
                if self.ascii_start < 0 {
                    self.ascii_start = g as i64;
                }
                self.ascii_buf.push(b);
                if self.ascii_buf.len() >= MAX_RUN_CHARS {
                    self.flush_ascii();
                }
            } else {
                self.flush_ascii();
            }

            // -- UTF-16LE: needs a lookahead at buffer[i+1] --
            let has_next = (i + 1) < (offset + buffer_valid_len);
            if has_next {
                let aligned = self.u16_start < 0 || g as i64 == self.u16_next_pos;
                if aligned {
                    let hi = buffer[i + 1];
                    if hi == 0x00 && printable_b {
                        if self.u16_start < 0 {
                            self.u16_start = g as i64;
                            self.u16_buf.clear();
                        }
                        self.u16_buf.push(b as u16);
                        self.u16_next_pos = g as i64 + 2;
                        if self.u16_buf.len() >= MAX_RUN_CHARS {
                            self.flush_u16();
                        }
                    } else {
                        self.flush_u16();
                    }
                }
            }

            k += 1;
        }
    }

    /// Call ONCE after `feed()` has processed all the data (end of
    /// file/array) so the still-open run at the very end isn't lost.
    fn flush_all(&mut self) {
        self.flush_ascii();
        self.flush_u16();
    }

    fn flush_ascii(&mut self) {
        if self.ascii_start >= 0
            && self.ascii_buf.len() >= self.min_len
            && !is_low_information_repeat(&self.ascii_buf, &self.noise_cfg)
        {
            let text = String::from_utf8_lossy(&self.ascii_buf).into_owned();
            (self.on_found)(ExtractedString {
                offset: self.ascii_start as u64,
                encoding: "ascii",
                text,
            });
        }
        self.ascii_start = -1;
        self.ascii_buf.clear();
    }

    fn flush_u16(&mut self) {
        if self.u16_start >= 0 && self.u16_buf.len() >= self.min_len {
            // u16_buf always holds values in 0..=0x7F (gated by is_printable
            // before pushing) -- the `as u8` cast is safe, no bits lost.
            let as_bytes: Vec<u8> = self.u16_buf.iter().map(|&c| c as u8).collect();
            if !is_low_information_repeat(&as_bytes, &self.noise_cfg) {
                let text = String::from_utf16_lossy(&self.u16_buf);
                (self.on_found)(ExtractedString {
                    offset: self.u16_start as u64,
                    encoding: "utf16le",
                    text,
                });
            }
        }
        self.u16_start = -1;
        self.u16_next_pos = -1;
        self.u16_buf.clear();
    }
}

/// Detects two shapes of "simple repeat noise" (byte-fill/heap-fill/
/// padding) -- period 1 (a single repeated character) or period 2
/// (strictly alternating 2 characters) covering the ENTIRE run, with no
/// other characters mixed in. Only triggers past the corresponding length
/// threshold (see the constants above) so it doesn't accidentally drop
/// short real strings. Takes a `&[u8]` shared by both ASCII (`ascii_buf`)
/// and UTF-16LE lowered to its low bytes (`u16_buf` is always within
/// 0..=0x7F since it's gated by `is_printable` before being pushed into
/// the buffer, so the `as u8` cast loses no information).
fn is_low_information_repeat(buf: &[u8], cfg: &NoiseConfig) -> bool {
    let n = buf.len();
    if n == 0 {
        return false;
    }

    // Period 1: every byte is identical to the first byte.
    if n >= cfg.repeat1_min_len && buf.iter().all(|&b| b == buf[0]) {
        return true;
    }

    // Period 2: strictly alternates between 2 values (different from each
    // other -- if they were the same it would already have been caught by
    // the period-1 branch) across the whole run length.
    if n >= cfg.repeat2_min_len {
        let (p0, p1) = (buf[0], buf[1]);
        if p0 != p1
            && buf
                .iter()
                .enumerate()
                .all(|(i, &b)| b == if i % 2 == 0 { p0 } else { p1 })
        {
            return true;
        }
    }

    false
}

fn estimate_capacity(input_len: u64, max_strings: usize) -> usize {
    let guess = if input_len > 0 {
        std::cmp::max(MIN_CAPACITY_HINT as u64, input_len / AVG_BYTES_PER_STRING)
    } else {
        MIN_CAPACITY_HINT as u64
    };
    std::cmp::min(max_strings as u64, guess) as usize
}

/// Returns a list of `ExtractedString`, sorted by ascending offset, from a
/// byte slice ALREADY in RAM. `max_strings` is an upper bound to avoid
/// unbounded growth of memory / the JSON returned to the UI.
pub fn extract_strings(data: &[u8], min_len: usize, max_strings: usize) -> Vec<ExtractedString> {
    extract_strings_with_noise_config(data, min_len, max_strings, NoiseConfig::default())
}

/// Same as `extract_strings`, but with a configurable noise filter (see
/// `NoiseConfig`) instead of the hardcoded defaults.
pub fn extract_strings_with_noise_config(
    data: &[u8],
    min_len: usize,
    max_strings: usize,
    noise_cfg: NoiseConfig,
) -> Vec<ExtractedString> {
    let mut results: Vec<ExtractedString> =
        Vec::with_capacity(estimate_capacity(data.len() as u64, max_strings));
    {
        let mut on_found = |s: ExtractedString| {
            if results.len() < max_strings {
                results.push(s);
            }
        };
        let mut scanner = StringRunScanner::new(min_len, noise_cfg, &mut on_found);
        scanner.feed(data, 0, data.len(), data.len(), 0);
        scanner.flush_all();
    }
    results.sort_by_key(|s| s.offset);
    results
}

// Borrow-checker note: in `extract_strings_from_reader` below, the outer
// loop needs to check "have we hit max_strings yet" while the `on_found`
// closure holds a mutable borrow of `results` for the whole block -- using
// `results.len()` directly in the `while` condition would conflict with
// that borrow (the closure is still alive). A separate `Cell<usize>` is
// used for the counter instead: `Cell::get()` only needs `&self` (an
// immutable borrow), so it can be read alongside the closure's mutable
// borrow of `results` without upsetting the borrow checker.

/// Extracts strings directly from a `Read`, in chunks -- NEVER
/// loads more than `CHUNK_SIZE` bytes into RAM at once, suitable for
/// multi-GB dump files. Carries exactly 1 trailing byte from each chunk
/// into the next so a UTF-16LE pair straddling an I/O boundary is always
/// tested correctly.
pub fn extract_strings_from_reader<R: Read>(
    reader: R,
    min_len: usize,
    max_strings: usize,
    estimated_len: u64,
) -> std::io::Result<Vec<ExtractedString>> {
    extract_strings_from_reader_with_noise_config(
        reader,
        min_len,
        max_strings,
        estimated_len,
        NoiseConfig::default(),
    )
}

/// Same as `extract_strings_from_reader`, but with a configurable noise
/// filter (see `NoiseConfig`) instead of the hardcoded defaults.
pub fn extract_strings_from_reader_with_noise_config<R: Read>(
    mut reader: R,
    min_len: usize,
    max_strings: usize,
    estimated_len: u64,
    noise_cfg: NoiseConfig,
) -> std::io::Result<Vec<ExtractedString>> {
    let mut results: Vec<ExtractedString> =
        Vec::with_capacity(estimate_capacity(estimated_len, max_strings));
    let count = std::cell::Cell::new(0usize); // see the borrow-checker note in extract_strings()
    {
        let mut on_found = |s: ExtractedString| {
            if count.get() < max_strings {
                results.push(s);
                count.set(count.get() + 1);
            }
        };
        let mut scanner = StringRunScanner::new(min_len, noise_cfg, &mut on_found);

        let mut buffer = vec![0u8; CHUNK_SIZE];
        let mut global_base: u64 = 0;
        let mut carry_len: usize = 0; // 0 or 1 -- whether buffer[0] currently holds a carry byte from the previous chunk

        while count.get() < max_strings {
            let to_read_into = buffer.len() - carry_len;
            let mut read_total = 0usize;
            while read_total < to_read_into {
                let n =
                    reader.read(&mut buffer[carry_len + read_total..carry_len + to_read_into])?;
                if n == 0 {
                    break; // no more data (EOF)
                }
                read_total += n;
            }

            let len = carry_len + read_total;
            if len == 0 {
                break; // nothing left to process (including the carry)
            }

            let is_last_chunk = read_total < to_read_into; // read fewer bytes than requested = hit EOF

            if is_last_chunk {
                // Last chunk: process ALL `len` bytes (there's no
                // following chunk left for the last byte to carry into),
                // then flush any still-open run.
                scanner.feed(&buffer, 0, len, len, global_base);
                scanner.flush_all();
                break;
            } else {
                // There's a next chunk: process the first (len-1) bytes,
                // but allow lookahead across the full `len` bytes
                // (buffer_valid_len=len) so a UTF-16LE pair right at the
                // boundary is still tested correctly within this chunk.
                // Keep buffer[len-1] as the carry byte for the next chunk.
                scanner.feed(&buffer, 0, len - 1, len, global_base);
                buffer[0] = buffer[len - 1];
                carry_len = 1;
                global_base += (len - 1) as u64;
            }
        }
    }

    results.sort_by_key(|s| s.offset);
    Ok(results)
}

/// Streams extracted strings to `on_found` while scanning a reader.
///
/// The input is still read in fixed-size chunks, but results are delivered
/// immediately instead of being accumulated in a `Vec`. This keeps memory
/// bounded by the scan buffer and the caller's callback state.
pub fn extract_strings_from_reader_streaming<R: Read, F: FnMut(ExtractedString)>(
    mut reader: R,
    min_len: usize,
    max_strings: usize,
    noise_cfg: NoiseConfig,
    mut on_found: F,
) -> std::io::Result<usize> {
    let emitted = std::cell::Cell::new(0usize);
    let mut scanner_callback = |s: ExtractedString| {
        if emitted.get() < max_strings {
            emitted.set(emitted.get() + 1);
            on_found(s);
        }
    };
    let mut scanner = StringRunScanner::new(min_len, noise_cfg, &mut scanner_callback);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut global_base = 0u64;
    let mut carry_len = 0usize;

    while emitted.get() < max_strings {
        let to_read_into = buffer.len() - carry_len;
        let mut read_total = 0usize;
        while read_total < to_read_into {
            let n = reader.read(&mut buffer[carry_len + read_total..carry_len + to_read_into])?;
            if n == 0 {
                break;
            }
            read_total += n;
        }

        let len = carry_len + read_total;
        if len == 0 {
            break;
        }
        let is_last_chunk = read_total < to_read_into;
        if is_last_chunk {
            scanner.feed(&buffer, 0, len, len, global_base);
            scanner.flush_all();
            break;
        }

        scanner.feed(&buffer, 0, len - 1, len, global_base);
        buffer[0] = buffer[len - 1];
        carry_len = 1;
        global_base += (len - 1) as u64;
    }

    Ok(emitted.get())
}

/// File-based streaming variant of [`extract_strings_from_reader_streaming`].
pub fn extract_strings_from_file_streaming<F: FnMut(ExtractedString)>(
    dump_path: &str,
    min_len: usize,
    max_strings: usize,
    noise_cfg: NoiseConfig,
    on_found: F,
) -> std::io::Result<usize> {
    let file = File::open(dump_path)?;
    let reader = BufReader::with_capacity(1 << 16, file);
    extract_strings_from_reader_streaming(reader, min_len, max_strings, noise_cfg, on_found)
}

/// Extracts strings from a `.dmp` file, in chunks -- does NOT
/// read the whole file into RAM.
pub fn extract_strings_from_file(
    dump_path: &str,
    min_len: usize,
    max_strings: usize,
) -> std::io::Result<Vec<ExtractedString>> {
    extract_strings_from_file_with_noise_config(
        dump_path,
        min_len,
        max_strings,
        NoiseConfig::default(),
    )
}

/// Same as `extract_strings_from_file`, but with a configurable noise
/// filter (see `NoiseConfig`) instead of the hardcoded defaults.
pub fn extract_strings_from_file_with_noise_config(
    dump_path: &str,
    min_len: usize,
    max_strings: usize,
    noise_cfg: NoiseConfig,
) -> std::io::Result<Vec<ExtractedString>> {
    let file = File::open(dump_path)?;
    let estimated_len = file.metadata().map(|m| m.len()).unwrap_or(0);
    // 64KB BufReader -- a good balance between syscall overhead and memory
    // use for sequential reads; the OS read-ahead heuristics naturally
    // match this access pattern too.
    let reader = BufReader::with_capacity(1 << 16, file);
    extract_strings_from_reader_with_noise_config(
        reader,
        min_len,
        max_strings,
        estimated_len,
        noise_cfg,
    )
}

// --- Parallel scanning (rayon work-stealing) --------------------------------
//
// The single-threaded path above is I/O-bound-friendly (streams CHUNK_SIZE
// at a time, constant peak memory) but only uses one core for the actual
// scanning. On a multi-core box scanning an already-fast SSD/NVMe (or a
// dump cached by the OS page cache), the CPU-bound scan itself becomes the
// bottleneck -- this is where splitting the work across threads helps.
//
// Design: split the file into fixed-size `PARALLEL_CHUNK_SIZE` regions and
// hand each region to rayon's work-stealing pool (`par_iter`). Each worker
// re-opens the file and seeks to its region independently (cheap: just an
// fd + seek, no shared state/locking needed between threads). Each region
// is read with an extra `MAX_RUN_CHARS` bytes of "overlap" past its
// boundary -- exactly the same limit the single-threaded scanner already
// force-flushes a run at -- so a run starting near the end of a region is
// never truncated by the region split. A region only *keeps* strings whose
// start offset falls inside its own `[start, logical_end)` -- the next
// region picks up the continuation on its own, so nothing is duplicated or
// lost at the boundary. Results are concatenated and re-sorted by offset
// (each region's own results are already offset-sorted, but merge order
// across regions/threads isn't guaranteed).
const PARALLEL_CHUNK_SIZE: u64 = 64 * 1024 * 1024; // 64MB per region

/// Same as `extract_strings_from_file`, but scans the file in parallel
/// across multiple OS threads via `rayon`'s work-stealing thread pool
/// instead of a single sequential pass. Best on multi-core machines with
/// fast storage / a warm page cache, where the CPU-bound scan (not disk
/// I/O) is the bottleneck. Peak memory is bounded by
/// `num_active_threads * (PARALLEL_CHUNK_SIZE + MAX_RUN_CHARS)`, not by the
/// file size. Use `rayon::ThreadPoolBuilder::num_threads` (or the
/// `RAYON_NUM_THREADS` env var) to control the degree of parallelism; by
/// default rayon uses one thread per logical CPU.
pub fn extract_strings_from_file_parallel(
    dump_path: &str,
    min_len: usize,
    max_strings: usize,
    noise_cfg: NoiseConfig,
) -> std::io::Result<Vec<ExtractedString>> {
    use rayon::prelude::*;

    let file_len = std::fs::metadata(dump_path)?.len();
    if file_len == 0 {
        return Ok(Vec::new());
    }

    let overlap = MAX_RUN_CHARS as u64;
    let n_chunks = ((file_len + PARALLEL_CHUNK_SIZE - 1) / PARALLEL_CHUNK_SIZE) as usize;

    let chunk_results: Vec<std::io::Result<Vec<ExtractedString>>> = (0..n_chunks)
        .into_par_iter()
        .map(|idx| -> std::io::Result<Vec<ExtractedString>> {
            let start = idx as u64 * PARALLEL_CHUNK_SIZE;
            // The boundary this region "owns" -- strings starting at or
            // past this point belong to the NEXT region, not this one.
            let logical_end = std::cmp::min(start + PARALLEL_CHUNK_SIZE, file_len);
            // How far past the boundary this region actually reads, purely
            // to give a run starting right before `logical_end` room to
            // finish (or hit its own MAX_RUN_CHARS force-flush, same as
            // the sequential scanner would).
            let read_end = std::cmp::min(logical_end + overlap, file_len);
            let read_len = (read_end - start) as usize;

            let mut file = File::open(dump_path)?;
            file.seek(SeekFrom::Start(start))?;
            let mut buf = vec![0u8; read_len];
            file.read_exact(&mut buf)?;

            let mut local: Vec<ExtractedString> = Vec::new();
            {
                let mut on_found = |s: ExtractedString| {
                    if s.offset < logical_end {
                        local.push(s);
                    }
                };
                let mut scanner = StringRunScanner::new(min_len, noise_cfg, &mut on_found);
                scanner.feed(&buf, 0, buf.len(), buf.len(), start);
                scanner.flush_all();
            }
            Ok(local)
        })
        .collect();

    let mut results = Vec::new();
    for r in chunk_results {
        results.extend(r?);
    }
    results.sort_by_key(|s| s.offset);
    if results.len() > max_strings {
        results.truncate(max_strings);
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_and_utf16_basic() {
        let mut data = Vec::new();
        data.extend_from_slice(b"\x00\x01hello world\x00");
        // "hi" UTF-16LE
        data.extend_from_slice(&[b'h', 0x00, b'i', 0x00, 0x00, 0x00]);
        let out = extract_strings(&data, 4, 200_000);
        assert!(out
            .iter()
            .any(|s| s.encoding == "ascii" && s.text == "hello world"));
    }

    #[test]
    fn min_len_filters_short_runs() {
        let data = b"ab\x00cdef\x00".to_vec();
        let out = extract_strings(&data, 4, 200_000);
        assert!(!out.iter().any(|s| s.text == "ab"));
        assert!(out.iter().any(|s| s.text == "cdef"));
    }

    #[test]
    fn chunk_boundary_carries_utf16_pair() {
        // Simulate a small CHUNK_SIZE by feeding manually across 2
        // consecutive feed() calls, carrying exactly 1 trailing byte --
        // this mirrors exactly what extract_strings_from_reader does at a
        // real chunk boundary.
        let full = {
            let mut v = Vec::new();
            v.extend_from_slice(&[b'a', 0x00, b'b', 0x00, b'c', 0x00, b'd', 0x00]);
            v
        };
        let mut results = Vec::new();
        {
            let mut on_found = |s: ExtractedString| results.push(s);
            let mut scanner = StringRunScanner::new(4, NoiseConfig::default(), &mut on_found);
            // Chunk 1: bytes 0..=5 (feed 5, valid_len 6) -- carry byte 6 (index 5)
            scanner.feed(&full[0..6], 0, 5, 6, 0);
            // Chunk 2 starts with the carry (full[5]) then the rest full[6..]
            let mut block2 = vec![full[5]];
            block2.extend_from_slice(&full[6..]);
            scanner.feed(&block2, 0, block2.len(), block2.len(), 5);
            scanner.flush_all();
        }
        assert!(results
            .iter()
            .any(|s| s.encoding == "utf16le" && s.text == "abcd"));
    }

    #[test]
    fn round_trip_via_reader_matches_in_memory() {
        let mut data = Vec::new();
        for i in 0..5000u32 {
            data.extend_from_slice(format!("token_{i:04}_", i = i).as_bytes());
        }
        let expected = extract_strings(&data, 4, 200_000);
        let via_reader =
            extract_strings_from_reader(std::io::Cursor::new(&data), 4, 200_000, data.len() as u64)
                .unwrap();
        assert_eq!(expected.len(), via_reader.len());
        assert_eq!(expected[0].text, via_reader[0].text);
    }

    #[test]
    fn noise_period1_ascii_is_filtered() {
        // "aaaaaaaa" (8 characters, >= NOISE_REPEAT1_MIN_LEN) is a
        // textbook byte-fill run -- must be filtered out of the results.
        let data = b"\x00aaaaaaaa\x00".to_vec();
        let out = extract_strings(&data, 4, 200_000);
        assert!(!out.iter().any(|s| s.text == "aaaaaaaa"));
    }

    #[test]
    fn noise_period2_ascii_is_filtered() {
        // "ABABABAB" (8 characters, exactly the NOISE_REPEAT2_MIN_LEN
        // threshold) -- alternating 2-character repeat, must be filtered.
        let data = b"\x00ABABABAB\x00".to_vec();
        let out = extract_strings(&data, 4, 200_000);
        assert!(!out.iter().any(|s| s.text == "ABABABAB"));
    }

    #[test]
    fn short_repeat_below_threshold_is_kept() {
        // "0000" (4 characters, below NOISE_REPEAT1_MIN_LEN=6) can still
        // be a real number (a PIN/year) -- must NOT be filtered out.
        let data = b"\x000000\x00".to_vec();
        let out = extract_strings(&data, 4, 200_000);
        assert!(out.iter().any(|s| s.text == "0000"));
    }

    #[test]
    fn custom_noise_threshold_from_cli_style_value() {
        // With threshold=16, an 8-char repeat like "aaaaaaaa" is now BELOW
        // the (raised) noise threshold, so it must be kept.
        let cfg = NoiseConfig::from_threshold(16);
        let data = b"\x00aaaaaaaa\x00".to_vec();
        let out = extract_strings_with_noise_config(&data, 4, 200_000, cfg);
        assert!(out.iter().any(|s| s.text == "aaaaaaaa"));
    }

    #[test]
    fn noise_threshold_zero_disables_filter_entirely() {
        let cfg = NoiseConfig::from_threshold(0);
        let data = b"\x00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x00".to_vec();
        let out = extract_strings_with_noise_config(&data, 4, 200_000, cfg);
        assert!(out.iter().any(|s| s.text.starts_with("aaaa")));
    }

    #[test]
    fn parallel_matches_sequential_on_multi_region_data() {
        // Build data spanning several PARALLEL_CHUNK_SIZE-sized regions so
        // the parallel path actually exercises >1 chunk / boundary
        // handling, and check it agrees with the sequential scanner.
        let mut data = Vec::new();
        for i in 0..3000u32 {
            data.extend_from_slice(format!("marker_{i:05}_value_", i = i).as_bytes());
        }
        let tmp = std::env::temp_dir().join(format!("ratdmp_test_{}.bin", std::process::id()));
        std::fs::write(&tmp, &data).unwrap();

        let sequential = extract_strings(&data, 4, 200_000);
        let parallel = extract_strings_from_file_parallel(
            tmp.to_str().unwrap(),
            4,
            200_000,
            NoiseConfig::default(),
        )
        .unwrap();

        std::fs::remove_file(&tmp).ok();

        assert_eq!(sequential.len(), parallel.len());
        for (a, b) in sequential.iter().zip(parallel.iter()) {
            assert_eq!(a.offset, b.offset);
            assert_eq!(a.text, b.text);
        }
    }

    #[test]
    fn real_looking_string_not_filtered() {
        let data = b"\x00password123\x00".to_vec();
        let out = extract_strings(&data, 4, 200_000);
        assert!(out.iter().any(|s| s.text == "password123"));
    }

    #[test]
    fn noise_period1_utf16_is_filtered() {
        // "aaaaaaaa" as UTF-16LE (8 characters) -- the same filtering
        // logic must apply to the utf16le branch, not just ascii.
        let mut data = vec![0x00, 0x00];
        for _ in 0..8 {
            data.push(b'a');
            data.push(0x00);
        }
        data.extend_from_slice(&[0x00, 0x00]);
        let out = extract_strings(&data, 4, 200_000);
        assert!(!out
            .iter()
            .any(|s| s.encoding == "utf16le" && s.text == "aaaaaaaa"));
    }
}
