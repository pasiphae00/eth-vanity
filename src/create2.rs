//! CREATE2 vanity contract address mining.
//!
//! Pure hashing per EIP-1014: keccak256(0xff ++ deployer ++ salt ++
//! keccak256(initCode))[12..]. No elliptic-curve math is involved, so
//! there's no batching trick needed for speed the way wallet search needs
//! one — this is about as fast as the hash function itself allows.

use keccak_asm::{Digest, Keccak256};
use rand::TryRng;
use rand::rngs::SysRng;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::matching::MatchCriteria;
use crate::progress::LiveFeed;

/// How many consecutive salts get hashed before checking for cancellation
/// and reporting progress/attempts. There's no expensive per-candidate step
/// to amortize here (unlike wallet search's EC math) — this purely bounds
/// how often we touch shared/atomic state.
const BATCH: usize = 8192;

pub struct Create2Result {
    pub salt: [u8; 32],
    pub address: [u8; 20],
}

#[inline]
fn create2_address(
    hasher: &mut Keccak256,
    deployer: &[u8; 20],
    salt: &[u8; 32],
    init_code_hash: &[u8; 32],
) -> [u8; 20] {
    hasher.update([0xff]);
    hasher.update(deployer);
    hasher.update(salt);
    hasher.update(init_code_hash);
    let hash = hasher.finalize_reset();

    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    addr
}

fn search_worker(
    deployer: &[u8; 20],
    init_code_hash: &[u8; 32],
    criteria: &MatchCriteria,
    attempts: &AtomicU64,
    running: &AtomicBool,
    feed: Option<&LiveFeed>,
    worker: usize,
) -> Option<Create2Result> {
    let mut salt = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut salt[..24])
        .expect("OS RNG failed");

    let mut hasher = Keccak256::new();
    let mut addr_hex = [0u8; 40];
    let mut counter: u64 = 0;

    loop {
        if !running.load(Ordering::Relaxed) {
            return None;
        }

        for b in 0..BATCH {
            salt[24..32].copy_from_slice(&counter.to_be_bytes());
            counter += 1;

            let addr = create2_address(&mut hasher, deployer, &salt, init_code_hash);
            hex::encode_to_slice(addr, &mut addr_hex).unwrap();

            if let Some(feed) = feed
                && b == BATCH - 1
            {
                feed.set(worker, &addr_hex);
            }

            if !criteria.matches(&addr_hex) {
                continue;
            }

            attempts.fetch_add((b + 1) as u64, Ordering::Relaxed);
            return Some(Create2Result {
                salt,
                address: addr,
            });
        }

        attempts.fetch_add(BATCH as u64, Ordering::Relaxed);
    }
}

pub fn search(
    deployer: &[u8; 20],
    init_code_hash: &[u8; 32],
    criteria: &MatchCriteria,
    threads: usize,
    attempts: &AtomicU64,
    feed: Option<&LiveFeed>,
    running: &AtomicBool,
) -> Option<Create2Result> {
    std::thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::channel();

        for worker in 0..threads {
            let tx = tx.clone();
            scope.spawn(move || {
                if let Some(result) = search_worker(
                    deployer,
                    init_code_hash,
                    criteria,
                    attempts,
                    running,
                    feed,
                    worker,
                ) {
                    running.store(false, Ordering::Relaxed);
                    let _ = tx.send(result);
                }
            });
        }
        drop(tx);

        rx.recv().ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    fn hex20(s: &str) -> [u8; 20] {
        let mut a = [0u8; 20];
        a.copy_from_slice(&hex::decode(s).unwrap());
        a
    }
    fn hex32(s: &str) -> [u8; 32] {
        let mut a = [0u8; 32];
        a.copy_from_slice(&hex::decode(s).unwrap());
        a
    }

    /// This exact deployer/init-code-hash/salt/address combination was
    /// independently verified against go-ethereum's own
    /// crypto.CreateAddress2 while building the Go implementation this
    /// project is benchmarked against, so it's a trustworthy fixed vector
    /// for the EIP-1014 formula here.
    #[test]
    fn create2_address_matches_known_vector() {
        let deployer = hex20("5B0E9E4889aD487B4F4Ebe84D9c85834B09bacF6");
        let init_code_hash =
            hex32("725967456576a059bfb03e05bb4b594f603ce2617eaa298d674781e715397861");
        let salt = hex32("7c2d0040162b6b0855c62e454f3e106d48f3af297f28041300000000000009b6");
        let want = hex20("0000951d00B0a839005aC2dD42e5acC2669c2A00");

        let mut hasher = Keccak256::new();
        let got = create2_address(&mut hasher, &deployer, &salt, &init_code_hash);
        assert_eq!(got, want);
    }

    #[test]
    fn search_end_to_end_finds_matching_address() {
        let deployer = hex20("5B0E9E4889aD487B4F4Ebe84D9c85834B09bacF6");
        let init_code_hash =
            hex32("725967456576a059bfb03e05bb4b594f603ce2617eaa298d674781e715397861");

        let criteria = MatchCriteria {
            prefix: b"00".to_vec(),
            suffix: vec![],
        };
        let attempts = AtomicU64::new(0);
        let running = AtomicBool::new(true);

        let result = search(
            &deployer,
            &init_code_hash,
            &criteria,
            4,
            &attempts,
            None,
            &running,
        )
        .expect("search should find a match");

        let mut addr_hex = [0u8; 40];
        hex::encode_to_slice(result.address, &mut addr_hex).unwrap();
        assert!(criteria.matches(&addr_hex));

        let mut hasher = Keccak256::new();
        let recomputed = create2_address(&mut hasher, &deployer, &result.salt, &init_code_hash);
        assert_eq!(
            recomputed, result.address,
            "recomputing from the returned salt must reproduce the returned address"
        );
    }
}
