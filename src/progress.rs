//! Live search progress: a spinner, a flickering "currently tried" address,
//! and running attempt/rate stats, redrawn on a single terminal line.

use std::io::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Exposes the most recent candidate address tried by each worker, for
/// display purposes only. Each worker owns one slot, so reads and writes
/// never contend.
pub struct LiveFeed {
    slots: Vec<Mutex<[u8; 40]>>,
    filled: Vec<AtomicBool>,
}

impl LiveFeed {
    pub fn new(threads: usize) -> Self {
        Self {
            slots: (0..threads).map(|_| Mutex::new([0u8; 40])).collect(),
            filled: (0..threads).map(|_| AtomicBool::new(false)).collect(),
        }
    }

    pub fn set(&self, worker: usize, addr_hex: &[u8; 40]) {
        *self.slots[worker].lock().unwrap() = *addr_hex;
        self.filled[worker].store(true, Ordering::Relaxed);
    }

    /// Returns the last candidate address seen by one of the workers, chosen
    /// round-robin by call count, or None if nothing has been tried yet.
    fn sample(&self, call: usize) -> Option<[u8; 40]> {
        if self.slots.is_empty() {
            return None;
        }
        let i = call % self.slots.len();
        if self.filled[i].load(Ordering::Relaxed) {
            Some(*self.slots[i].lock().unwrap())
        } else {
            None
        }
    }
}

const SPINNER_FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// Redraws a single status line ~10x/sec until `running` is cleared. Once
/// the hash rate has a first real reading, also prints a one-time
/// estimated-time-to-match range (not a countdown) derived from the search
/// space size and that rate; `combined` is the total vanity byte length (0
/// to skip the estimate, e.g. a random account with no prefix/suffix).
pub fn report_progress(
    attempts: &AtomicU64,
    feed: &LiveFeed,
    running: &AtomicBool,
    combined: usize,
) {
    let start = Instant::now();
    let mut rate_window_start = start;
    let mut rate_window_attempts = 0u64;
    let mut rate = 0f64;
    let mut estimate_printed = combined == 0;

    let mut frame = 0usize;
    let mut stderr = std::io::stderr();
    while running.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(100));

        let total = attempts.load(Ordering::Relaxed);
        let now = Instant::now();
        let elapsed_since_last = now.duration_since(rate_window_start);
        if elapsed_since_last >= Duration::from_secs(1) {
            rate = (total - rate_window_attempts) as f64 / elapsed_since_last.as_secs_f64();
            rate_window_attempts = total;
            rate_window_start = now;

            if !estimate_printed && rate > 0.0 {
                let _ = writeln!(stderr, "\r\x1b[K{}", estimate_time_to_match(combined, rate));
                estimate_printed = true;
            }
        }

        let addr = feed.sample(frame);
        let addr_str = match &addr {
            Some(a) => std::str::from_utf8(a).unwrap_or("?").to_string(),
            None => "·".repeat(40),
        };
        let spin = SPINNER_FRAMES[frame % SPINNER_FRAMES.len()];
        let elapsed = format_duration(now.duration_since(start));

        let _ = write!(
            stderr,
            "\r\x1b[K{spin} 0x{addr_str}   {} tried   {}/s   {elapsed}",
            commify(total),
            commify(rate as u64),
        );
        let _ = stderr.flush();

        frame += 1;
    }
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else {
        format!("{}m{}s", secs / 60, secs % 60)
    }
}

/// Computes a one-standard-deviation range for how long finding a match
/// should take, given the search space size (16^combined candidates, each
/// an independent 1-in-N chance) and the current hash rate. Match count
/// follows a geometric distribution, whose standard deviation is very close
/// to its own mean whenever the match probability is small (as it always is
/// here) -- so this range is naturally wide, and its low end is naturally
/// close to "could happen immediately". That's an inherent property of
/// these odds, not an approximation error.
fn estimate_time_to_match(combined: usize, rate: f64) -> String {
    let p = 1.0 / 16f64.powi(combined as i32);
    let mean = 1.0 / p;
    let stddev = ((1.0 - p) / (p * p)).sqrt();

    let low_attempts = (mean - stddev).max(0.0);
    let high_attempts = mean + stddev;

    let (range_str, mean_str) =
        format_duration_triple(low_attempts / rate, mean / rate, high_attempts / rate);
    format!("Est. time to match (1\u{03c3} range): {range_str} (mean: {mean_str})")
}

/// Formats three second counts (a low/high range plus the mean) sharing a
/// single human-scaled unit chosen from the largest (high) value, e.g.
/// ("6.2-12.4h", "9.3h").
fn format_duration_triple(
    low_seconds: f64,
    mean_seconds: f64,
    high_seconds: f64,
) -> (String, String) {
    const UNITS: [(f64, &str); 5] = [
        (1.0, "s"),
        (60.0, "m"),
        (3600.0, "h"),
        (86400.0, "d"),
        (86400.0 * 365.25, "y"),
    ];

    let mut unit = UNITS[0];
    for u in UNITS {
        if high_seconds >= u.0 {
            unit = u;
        }
    }

    let range_str = format!(
        "{}-{}{}",
        format_num(low_seconds / unit.0),
        format_num(high_seconds / unit.0),
        unit.1
    );
    let mean_str = format!("{}{}", format_num(mean_seconds / unit.0), unit.1);
    (range_str, mean_str)
}

fn format_num(v: f64) -> String {
    if v >= 10.0 {
        format!("{v:.0}")
    } else {
        let s = format!("{v:.1}");
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    }
}

/// Inserts thousands separators, e.g. 1234567 -> "1,234,567".
pub fn commify(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let lead = bytes.len() % 3;
    let lead = if lead == 0 { 3 } else { lead };

    let mut out = String::with_capacity(s.len() + s.len() / 3);
    out.push_str(&s[..lead.min(bytes.len())]);
    let mut i = lead;
    while i < bytes.len() {
        out.push(',');
        out.push_str(&s[i..i + 3]);
        i += 3;
    }
    out
}
