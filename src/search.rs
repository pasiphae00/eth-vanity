//! Wallet keypair search.
//!
//! Like the Go implementation this compares against, each worker walks a
//! chain of consecutive private keys starting at a random k0:
//! k0*G, (k0+1)*G, (k0+2)*G, ... Each step is a cheap elliptic-curve point
//! addition (+= G) rather than a full scalar multiplication. Results are
//! buffered in batches and converted to affine coordinates (needed to hash
//! X||Y into an address) together, via k256's built-in batch-normalize
//! (Montgomery's trick: one modular inversion amortized across the whole
//! batch instead of paid per candidate).
//!
//! Consecutive points differ from independent random points only by a
//! fixed, known offset from G; since Keccak256 output is unrelated to any
//! algebraic structure in its input, the resulting addresses are
//! indistinguishable from independently sampled ones for search purposes.
//! This is the same technique used by other vanity-address generators
//! (e.g. profanity).

use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::{BatchNormalize, Field};
use k256::{ProjectivePoint, Scalar};
use keccak_asm::{Digest, Keccak256};
use rand::rngs::SysRng;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::matching::MatchCriteria;
use crate::progress::LiveFeed;

/// How many consecutive candidate points get accumulated before paying for
/// a single batched modular inversion to convert all of them to affine
/// coordinates at once.
const BATCH_SIZE: usize = 1024;

pub struct SearchResult {
    pub private_key: [u8; 32],
    pub address: [u8; 20],
}

fn random_scalar() -> Scalar {
    // ff::Field::try_random performs rejection sampling internally, matching
    // the rigor of standard ECDSA key generation. SysRng is fallible (it's
    // backed by the OS entropy source), which failing is astronomically
    // unlikely and not meaningfully recoverable, hence the expect.
    Scalar::try_random(&mut SysRng).expect("OS RNG failed")
}

/// Computes the address for an affine point: keccak256(X || Y)[12..].
#[inline]
fn address_from_affine(hasher: &mut Keccak256, pt: &k256::AffinePoint) -> [u8; 20] {
    hasher.update(pt.x());
    hasher.update(pt.y());
    let hash = hasher.finalize_reset();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    addr
}

pub fn search_worker(
    criteria: &MatchCriteria,
    attempts: &AtomicU64,
    running: &AtomicBool,
    feed: Option<&LiveFeed>,
    worker: usize,
) -> Option<SearchResult> {
    let k0 = random_scalar();
    let mut cur = ProjectivePoint::mul_by_generator_vartime(&k0);

    let mut batch = vec![ProjectivePoint::IDENTITY; BATCH_SIZE];
    let mut hasher = Keccak256::new();
    let mut addr_hex = [0u8; 40];

    // total_offset is the number of point additions applied to cur since it
    // started at k0*G; it persists across batches (unlike a per-batch
    // counter) because it's what lets us recover the actual private key
    // scalar (k0 + total_offset) for whichever candidate matches, no matter
    // which batch it turns up in.
    let mut total_offset: u64 = 0;

    loop {
        if !running.load(Ordering::Relaxed) {
            return None;
        }

        for slot in batch.iter_mut() {
            cur += ProjectivePoint::GENERATOR;
            *slot = cur;
        }

        let affine = ProjectivePoint::batch_normalize_vartime(batch.as_slice());

        for (i, pt) in affine.iter().enumerate() {
            let addr = address_from_affine(&mut hasher, pt);
            hex::encode_to_slice(addr, &mut addr_hex).unwrap();

            total_offset += 1;
            if let Some(feed) = feed
                && i == BATCH_SIZE - 1
            {
                feed.set(worker, &addr_hex);
            }

            if !criteria.matches(&addr_hex) {
                continue;
            }

            attempts.fetch_add((i + 1) as u64, Ordering::Relaxed);

            let offset = Scalar::from(total_offset);
            let match_scalar = k0 + offset;

            let mut private_key = [0u8; 32];
            private_key.copy_from_slice(&match_scalar.to_bytes());

            return Some(SearchResult {
                private_key,
                address: addr,
            });
        }

        attempts.fetch_add(BATCH_SIZE as u64, Ordering::Relaxed);
    }
}

/// Spawns `threads` OS threads that each walk an independent chain of
/// candidate keys (see `search_worker`) until one matches criteria or
/// `running` is cleared (e.g. by a Ctrl+C handler). Returns None if the
/// search was interrupted before any match was found.
pub fn search(
    criteria: &MatchCriteria,
    threads: usize,
    attempts: &AtomicU64,
    feed: Option<&LiveFeed>,
    running: &AtomicBool,
) -> Option<SearchResult> {
    std::thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::channel();

        for worker in 0..threads {
            let tx = tx.clone();
            scope.spawn(move || {
                if let Some(result) = search_worker(criteria, attempts, running, feed, worker) {
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
    use k256::elliptic_curve::PrimeField;
    use std::sync::atomic::AtomicBool;

    /// Computes the address for scalar k independently of the
    /// batched-increment machinery above, via a direct fixed-base scalar
    /// multiplication. This is the trusted reference every other test here
    /// is checked against.
    fn reference_address(scalar: Scalar) -> [u8; 20] {
        let point = ProjectivePoint::mul_by_generator_vartime(&scalar);
        let affine = point.to_affine();
        let mut hasher = Keccak256::new();
        address_from_affine(&mut hasher, &affine)
    }

    /// Walks several small batches (crossing multiple batch boundaries) of
    /// the same accumulate -> batch_normalize -> hash pipeline
    /// `search_worker` uses, and checks every single candidate address
    /// against `reference_address` for that exact scalar (k0 + offset).
    /// This is the test that would catch an off-by-one at a batch boundary,
    /// which is exactly the kind of bug that would silently produce a
    /// wallet whose saved private key doesn't match the address it was
    /// found under.
    #[test]
    fn batched_addresses_match_reference_across_batch_boundaries() {
        const TEST_BATCH: usize = 8;
        const NUM_BATCHES: usize = 5;

        let k0 = random_scalar();
        let mut cur = ProjectivePoint::mul_by_generator_vartime(&k0);
        let mut hasher = Keccak256::new();
        let mut total_offset: u64 = 0;

        for _ in 0..NUM_BATCHES {
            let mut batch = vec![ProjectivePoint::IDENTITY; TEST_BATCH];
            for slot in batch.iter_mut() {
                cur += ProjectivePoint::GENERATOR;
                *slot = cur;
            }
            let affine = ProjectivePoint::batch_normalize_vartime(batch.as_slice());

            for pt in affine.iter() {
                let got = address_from_affine(&mut hasher, pt);
                total_offset += 1;

                let want = reference_address(k0 + Scalar::from(total_offset));
                assert_eq!(got, want, "mismatch at total_offset={total_offset}");
            }
        }
    }

    /// Runs the real `search` entry point with a short prefix and checks
    /// that the returned private key actually reproduces the returned
    /// address -- the invariant that matters most, since if this is ever
    /// wrong the tool saves a keystore for the wrong key.
    #[test]
    fn search_end_to_end_private_key_matches_address() {
        for _ in 0..10 {
            let criteria = MatchCriteria {
                prefix: b"a".to_vec(),
                suffix: vec![],
            };
            let attempts = AtomicU64::new(0);
            let running = AtomicBool::new(true);

            let result = search(&criteria, 4, &attempts, None, &running)
                .expect("search should find a match");

            let mut addr_hex = [0u8; 40];
            hex::encode_to_slice(result.address, &mut addr_hex).unwrap();
            assert!(
                criteria.matches(&addr_hex),
                "address {addr_hex:?} doesn't satisfy criteria"
            );

            let scalar_bytes: [u8; 32] = result.private_key;
            let scalar = Scalar::from_repr(scalar_bytes.into()).expect("valid scalar");
            let derived = reference_address(scalar);
            assert_eq!(
                derived, result.address,
                "private key does not reproduce the found address"
            );
        }
    }

    #[test]
    fn point_addition_matches_reference_for_small_offsets() {
        for offset in 0u64..20 {
            let k0 = random_scalar();
            let mut cur = ProjectivePoint::mul_by_generator_vartime(&k0);
            for _ in 0..offset {
                cur += ProjectivePoint::GENERATOR;
            }
            let mut hasher = Keccak256::new();
            let got = address_from_affine(&mut hasher, &cur.to_affine());
            let want = reference_address(k0 + Scalar::from(offset));
            assert_eq!(got, want, "offset={offset}");
        }
    }
}
