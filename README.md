# eth-vanity-rs

A Rust reimplementation of [`eth-vanity`](https://codeberg.org/pasiphae/eth-vanity), built to benchmark against it. 

It has the same feature set and usage: generate an Ethereum keypair matching a `--prefix`/`--suffix` (saved as a geth-compatible encrypted keystore), or mine a `create2` salt for a vanity contract address.

## Build

```
cargo build --release
```

For maximum local throughput (non-portable binary, tied to this CPU):

```
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

## Usage

Same flags as the Go version:

```
eth-vanity-rs --prefix 0000 --suffix 666
eth-vanity-rs create2 --deployer 0x... --init-code-hash 0x... --prefix 000000
```

Run `--help` / `create2 --help` for the full flag list.

## Test

```
cargo test
```

Includes cross-validation of the batched point-increment math against an independently-computed reference (catches batch-boundary bugs), an end-to-end invariant check that the returned private key actually reproduces the returned address, a CREATE2 known-answer test (verified against go-ethereum's own `crypto.CreateAddress2` while building the Go tool), and a full keystore encrypt→decrypt round trip via the `eth-keystore` crate's own decryptor.

## What's different from the Go version, and why

- **Crypto**: [`k256`](https://docs.rs/k256) (RustCrypto's pure-Rust secp256k1), not the `secp256k1` crate (libsecp256k1 C bindings) reth uses in its hot paths. That C library's public API is deliberately opaque and doesn't expose raw point arithmetic, which is exactly what the batched point-increment search needs — the same issue hit with go-ethereum's cgo wrapper in the Go version. `k256` exposes `ProjectivePoint` addition and a built-in `batch_normalize_vartime` (Montgomery's trick, already implemented in the `ff` crate) directly, so the whole batching algorithm is much less code here than the hand-rolled Go version.
- **Hashing**: [`keccak-asm`](https://docs.rs/keccak-asm) instead of `sha3` — hand-written assembly Keccak, same `Digest` trait so it's a drop-in swap.
- **Keystore**: the standard `eth-keystore` crate hardcodes scrypt N=2^13 with no way to override it, much weaker than go-ethereum's default (N=2^18). `src/keystore.rs` reimplements the encryption directly against the same primitives (`scrypt`, `aes`, `ctr`) with N=2^18, so keystores from either tool are equally hard to brute-force. It reuses `eth-keystore`'s public struct types for the JSON schema, so files are still cross-compatible (verified: this tool's output decrypts with go-ethereum's own keystore reader, and vice versa).
- **RNG in the hot loop**: neither search loop calls the OS RNG per candidate. Wallet search draws one random starting scalar per thread, then walks forward via point addition. CREATE2 search draws one random 24-byte prefix per thread, then increments an 8-byte counter for the rest of the salt.
- **Release profile**: `lto = "fat"`, `codegen-units = 1`, `panic = "abort"` (see `Cargo.toml`).

## Benchmark (Apple M4 Max, 16 threads)

| Mode | Go | Rust |
|---|---|---|
| Wallet search | ~14.3M addr/s | ~42.4M addr/s |
| CREATE2 search | ~44.2M addr/s | ~92.9M addr/s |

Both implementations use the same algorithm (batched point-increment for wallet search, plain incrementing-salt hashing for CREATE2) and the same core optimizations (no per-candidate heap allocation, no per-candidate RNG calls). The gap is primarily `k256`'s fixed-base scalar multiplication and point addition being faster than the cgo path Go ends up on, plus `keccak-asm`'s hand-written assembly versus Go's Keccak implementation.
