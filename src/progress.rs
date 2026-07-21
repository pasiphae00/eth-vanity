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

/// Redraws a single status line ~10x/sec until `running` is cleared.
pub fn report_progress(attempts: &AtomicU64, feed: &LiveFeed, running: &AtomicBool) {
    let start = Instant::now();
    let mut rate_window_start = start;
    let mut rate_window_attempts = 0u64;
    let mut rate = 0f64;

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
            "\r{spin} 0x{addr_str}   {} tried   {}/s   {elapsed}   ",
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
