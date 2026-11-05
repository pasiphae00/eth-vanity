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
use k256::elliptic_curve::{BatchNormalize, Field, PrimeField};
use k256::{ProjectivePoint, Scalar};
use keccak_asm::{Digest, Keccak256};
use rand::TryRng;
use rand::rngs::SysRng;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use zeroize::{Zeroize, Zeroizing};

use crate::entropy::EXTERNAL_ENTROPY_BYTES;
use crate::matching::MatchCriteria;
use crate::progress::LiveFeed;

/// How many consecutive candidate points get accumulated before paying for
/// a single batched modular inversion to convert all of them to affine
/// coordinates at once.
const BATCH_SIZE: usize = 1024;

pub struct SearchResult {
    /// Boxed so the key stays at one heap address, wiped on drop. Moving an
    /// inline array through the result channel would leave copies behind
    /// that Zeroizing can't reach.
    pub private_key: Box<Zeroizing<[u8; 32]>>,
    pub address: [u8; 20],
}

/// Draws a uniformly random, non-zero scalar in [1, N-1] using rejection
/// sampling, matching the rigor of standard ECDSA key generation.
///
/// If external_entropy is Some (an --extra-entropy fetch succeeded), each
/// draw is additionally mixed with it via mix_entropy before being
/// interpreted as a scalar. Local OS randomness is always drawn fresh on
/// every attempt regardless; external_entropy only ever supplements it, so
/// a doctored or absent external source can never make this weaker than
/// local randomness alone -- only fail to add anything.
fn random_scalar(external_entropy: Option<&[u8; EXTERNAL_ENTROPY_BYTES]>, worker: usize) -> Scalar {
    loop {
        let mut local = Zeroizing::new([0u8; 32]);
        SysRng
            .try_fill_bytes(local.as_mut_slice())
            .expect("OS RNG failed");

        let seed = Zeroizing::new(match external_entropy {
            Some(ext) => mix_entropy(&local, ext, worker),
            None => *local,
        });

        if let Some(scalar) = Option::from(Scalar::from_repr((*seed).into())) {
            let scalar: Scalar = scalar;
            if !bool::from(Field::is_zero(&scalar)) {
                return scalar;
            }
        }
    }
}

/// Combines fresh local randomness with a shared external randomness
/// source into a single 32-byte seed via Keccak256. Hashing preserves the
/// local input's full entropy regardless of the quality of external
/// (even all-zero or attacker-chosen bytes), so this can only add
/// security, never remove it. worker differentiates otherwise identical
/// external entropy across concurrent workers, though each worker's fresh
/// local component already ensures independence on its own.
fn mix_entropy(
    local: &[u8; 32],
    external: &[u8; EXTERNAL_ENTROPY_BYTES],
    worker: usize,
) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(local);
    hasher.update(external);
    hasher.update((worker as u64).to_be_bytes());
    let mut digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    out
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
    external_entropy: Option<&[u8; EXTERNAL_ENTROPY_BYTES]>,
) -> Option<SearchResult> {
    let k0 = Zeroizing::new(random_scalar(external_entropy, worker));
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
            let match_scalar = Zeroizing::new(*k0 + offset);

            let mut key_bytes = match_scalar.to_bytes();
            let mut private_key = Box::new(Zeroizing::new([0u8; 32]));
            private_key.copy_from_slice(&key_bytes);
            key_bytes.as_mut_slice().zeroize();

            return Some(SearchResult {
                private_key,
                address: addr,
            });
        }

        attempts.fetch_add(BATCH_SIZE as u64, Ordering::Relaxed);
    }
}

/// Recomputes the address for a found key by a plain scalar multiplication,
/// a separate route from the batched point walk that found it. A disagreement
/// is a bug in the search: the key would not control the address it was
/// reported under, so nothing must be saved or printed as a success.
pub fn verify(result: &SearchResult) -> anyhow::Result<()> {
    let scalar = Option::<Scalar>::from(Scalar::from_repr((**result.private_key).into()))
        .ok_or_else(|| anyhow::anyhow!("internal error: found key is not a valid scalar"))?;
    let point = ProjectivePoint::GENERATOR * *Zeroizing::new(scalar);
    let derived = address_from_affine(&mut Keccak256::new(), &point.to_affine());
    anyhow::ensure!(
        derived == result.address,
        "internal error: found key derives 0x{}, not the reported 0x{}",
        hex::encode(derived),
        hex::encode(result.address)
    );
    Ok(())
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
    external_entropy: Option<&[u8; EXTERNAL_ENTROPY_BYTES]>,
) -> Option<SearchResult> {
    std::thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::channel();

        for worker in 0..threads {
            let tx = tx.clone();
            scope.spawn(move || {
                if let Some(result) =
                    search_worker(criteria, attempts, running, feed, worker, external_entropy)
                {
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

        let k0 = random_scalar(None, 0);
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

            let result = search(&criteria, 4, &attempts, None, &running, None)
                .expect("search should find a match");

            let mut addr_hex = [0u8; 40];
            hex::encode_to_slice(result.address, &mut addr_hex).unwrap();
            assert!(
                criteria.matches(&addr_hex),
                "address {addr_hex:?} doesn't satisfy criteria"
            );

            let scalar_bytes: [u8; 32] = **result.private_key;
            let scalar = Scalar::from_repr(scalar_bytes.into()).expect("valid scalar");
            let derived = reference_address(scalar);
            assert_eq!(
                derived, result.address,
                "private key does not reproduce the found address"
            );
        }
    }

    #[test]
    fn verify_accepts_a_real_result_and_rejects_a_mismatch() {
        let scalar = random_scalar(None, 0);
        let result = SearchResult {
            private_key: Box::new(Zeroizing::new(scalar.to_bytes().into())),
            address: reference_address(scalar),
        };
        verify(&result).expect("a genuine key/address pair should verify");

        let mut wrong_address = result.address;
        wrong_address[0] ^= 1;
        let tampered = SearchResult {
            address: wrong_address,
            ..result
        };
        assert!(verify(&tampered).is_err());
    }

    #[test]
    fn point_addition_matches_reference_for_small_offsets() {
        for offset in 0u64..20 {
            let k0 = random_scalar(None, 0);
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

    #[test]
    fn mix_entropy_is_deterministic_and_sensitive_to_each_input() {
        let local = [
            1u8, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        let external = [0xABu8; EXTERNAL_ENTROPY_BYTES];

        let got = mix_entropy(&local, &external, 0);

        // Cross-checked independently: Keccak256(local || external || worker_be_u64).
        let mut hasher = Keccak256::new();
        hasher.update(local);
        hasher.update(external);
        hasher.update(0u64.to_be_bytes());
        let want: [u8; 32] = hasher.finalize().into();
        assert_eq!(
            got, want,
            "mix_entropy doesn't match an independently computed Keccak256"
        );

        // Changing any single input should change the output.
        let other_local = [9u8; 32];
        assert_ne!(
            mix_entropy(&other_local, &external, 0),
            got,
            "changing local entropy did not change the mixed seed"
        );
        let other_external = [0xCDu8; EXTERNAL_ENTROPY_BYTES];
        assert_ne!(
            mix_entropy(&local, &other_external, 0),
            got,
            "changing external entropy did not change the mixed seed"
        );
        assert_ne!(
            mix_entropy(&local, &external, 1),
            got,
            "changing worker index did not change the mixed seed"
        );
    }

    #[test]
    fn random_scalar_with_external_entropy_is_valid() {
        let external = [0x11u8; EXTERNAL_ENTROPY_BYTES];
        let scalar = random_scalar(Some(&external), 0);
        assert!(!bool::from(Field::is_zero(&scalar)));
    }

    /// Re-runs the private-key-reproduces-address invariant with a (fake,
    /// fixed) external entropy source mixed in, to make sure that code path
    /// is exercised and still produces a correct, usable key.
    #[test]
    fn search_end_to_end_with_external_entropy() {
        let criteria = MatchCriteria {
            prefix: b"a".to_vec(),
            suffix: vec![],
        };
        let attempts = AtomicU64::new(0);
        let running = AtomicBool::new(true);
        let external = [0x99u8; EXTERNAL_ENTROPY_BYTES];

        let result = search(&criteria, 4, &attempts, None, &running, Some(&external))
            .expect("search should find a match");

        let scalar_bytes: [u8; 32] = **result.private_key;
        let scalar = Scalar::from_repr(scalar_bytes.into()).expect("valid scalar");
        let derived = reference_address(scalar);
        assert_eq!(
            derived, result.address,
            "private key does not reproduce the found address"
        );
    }
}
