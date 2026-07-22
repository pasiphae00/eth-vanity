# eth-vanity

A Rust CLI that generates an Ethereum key pair whose public address matches a "vanity" prefix and/or suffix, or (via the `create2` subcommand) mines a salt for a vanity CREATE2 contract address.

## Build

```
cargo build --release
```

For maximum local throughput (non-portable binary, tied to this CPU):

```
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

## Usage

Ethereum addresses are hex-encoded (`0-9`, `A-F`), matched case-insensitively — distinguishing `fedbad` from `fedBAD` via EIP-55 checksum casing would make a match astronomically rarer, so this tool doesn't do that.

```
eth-vanity \
  --prefix 0000 \       # (optional) the first two bytes of the address should be 00 00
  --suffix 1111 \       # (optional) the last two bytes of the address should be 11 11
  --extra-entropy       # (optional) mix in some randomness from random.org atmospheric noise
  --threads 16 \        # (optional) run 16 parallel routines to search for a match
  --output ./keystore   # (optional) save the ouput encrypted keystore file to ./keystore
```

If neither `--prefix` nor `--suffix` is given, a random account is generated immediately. Once a match is found, you're prompted (with confirmation) for a passphrase to encrypt the resulting keystore — there's no flag for this, so it never ends up in shell history or process listings.

Short form:

```
eth-vanity -p 0000 -s 1111 -o ./keystore -t 16 -e
```

Mine a CREATE2 vanity contract address instead of a wallet (pure hashing, no elliptic curve math — much faster than wallet search):

```
eth-vanity create2 \          # find salt for a vanity create2 contract address
  --deployer 0x... \          # the address that will deploy the contract
  --init-code-hash 0x... \    # hex-encoded hash of the init code for the deployment
  --prefix 000000             # the prefix bytes of the desired vanity address
```

Run `--help` / `create2 --help` for the full flag list, including `--extra-entropy` (optionally mix in randomness from random.org, on top of — never instead of — local OS randomness; see `src/entropy.rs`).

## Help
```
eth-vanity --help
```
```
Generates an Ethereum keypair whose public address matches a given prefix and/or suffix, then saves it as an encrypted keystore file.

Usage: eth-vanity [OPTIONS] [COMMAND]

Commands:
  create2  Mine a salt so a CREATE2 deployment lands on a vanity contract address
  help     Print this message or the help of the given subcommand(s)

Options:
  -p, --prefix <PREFIX>    Hex bytes required at the start of the address (no "0x" needed) [default: ""]
  -s, --suffix <SUFFIX>    Hex bytes required at the end of the address [default: ""]
  -o, --output <OUTPUT>    Directory to save the encrypted keystore file [default: .]
  -t, --threads <THREADS>  Number of concurrent threads searching for a match (default: number of CPUs)
  -e, --extra-entropy      Mix in additional randomness from random.org (supplements, never replaces, local OS randomness).
                           Set RANDOM_ORG_API_KEY in the environment to use random.org's authenticated API.
  -h, --help               Print help

Notes:
  - --prefix and --suffix accept only hex characters (0-9, a-f, A-F) and are matched
    case-insensitively. Each extra hex character makes a match ~16x rarer, so long
    values can take a long time to find.
  - If neither --prefix nor --suffix is given, a random account is generated immediately.
  - Once a matching address is found, you'll be prompted (with confirmation) for a
    passphrase to encrypt the keystore -- there's no flag for this, so it never ends up
    in shell history or process listings.
  - This is CPU-bound work; going far past --threads = number of CPUs usually doesn't
    help and can even slow things down.

Subcommands:
  create2   mine a salt for a vanity CREATE2 contract address instead of a wallet
```

## Test

```
cargo test
```

Includes cross-validation of the batched point-increment math against an independently-computed reference (catches batch-boundary bugs), an end-to-end invariant check that the returned private key actually reproduces the returned address, a CREATE2 known-answer test (verified against go-ethereum's own `crypto.CreateAddress2`), a full keystore encrypt→decrypt round trip via the `eth-keystore` crate's own decryptor, and entropy-mixing tests (response parsing against malformed/error cases, and the mixing function cross-checked against an independently computed hash).

## Design notes

- **Crypto**: [`k256`](https://docs.rs/k256) (RustCrypto's pure-Rust secp256k1), not the `secp256k1` crate (libsecp256k1 C bindings) that reth uses in its hot paths. That C library's public API is deliberately opaque and doesn't expose raw point arithmetic, which is exactly what the batched point-increment search needs. `k256` exposes `ProjectivePoint` addition and a built-in `batch_normalize_vartime` (Montgomery's trick, already implemented in the `ff` crate) directly.
- **Search algorithm (wallet mode)**: each thread walks a chain of consecutive private keys from a random starting scalar (`k0*G`, `(k0+1)*G`, ...) via cheap point addition rather than a full scalar multiplication per candidate. Points are buffered in batches and converted to affine coordinates together via one batched modular inversion, amortizing that cost across the whole batch instead of paying it per candidate.
- **Hashing**: [`keccak-asm`](https://docs.rs/keccak-asm) instead of `sha3` — hand-written assembly Keccak, same `Digest` trait so it's a drop-in swap.
- **Keystore**: the standard `eth-keystore` crate hardcodes scrypt N=2^13 with no way to override it, much weaker than go-ethereum's default (N=2^18). `src/keystore.rs` reimplements the encryption directly against the same primitives (`scrypt`, `aes`, `ctr`) with N=2^18, reusing `eth-keystore`'s public struct types for the JSON schema so files stay cross-compatible with geth and other standard keystore readers.
- **RNG in the hot loop**: neither search loop calls the OS RNG per candidate. Wallet search draws one random starting scalar per thread, then walks forward via point addition. CREATE2 search draws one random 24-byte prefix per thread, then increments an 8-byte counter for the rest of the salt.
- **Optional external entropy** (`--extra-entropy`, wallet mode only): local OS randomness is always drawn fresh regardless; when enabled, each thread's starting scalar is derived from `Keccak256(local || external || worker_index)` instead of local bytes directly, so a doctored or unreachable random.org can only fail to add anything, never weaken the result below local-only randomness.
- **Release profile**: `lto = "fat"`, `codegen-units = 1`, `panic = "abort"` (see `Cargo.toml`).

## History

This project started as a Go CLI, then was rewritten from scratch in Rust specifically to benchmark against it. The Rust version won decisively — on an Apple M4 Max (16 threads), wallet search went from ~14.3M addr/s to ~42.4M addr/s, and CREATE2 search from ~44.2M addr/s to ~92.9M addr/s, using the same algorithms and the same core optimizations (no per-candidate heap allocation, no per-candidate RNG calls) in both. The gap is primarily `k256`'s point arithmetic being faster than the cgo path Go ends up on, plus `keccak-asm`'s hand-written assembly versus Go's Keccak implementation.

Given that gap, the Rust implementation replaced the Go one outright; this repository's history contains both projects' full commit history merged together.
