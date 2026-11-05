# eth-vanity

A Rust CLI that generates an Ethereum key pair whose public address matches a "vanity" prefix and/or suffix, or (via the `create2` subcommand) mines a salt for a vanity CREATE2 contract address. The wallet search can also run from a public key alone, so the private key never has to be on the machine doing the search.

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

If neither `--prefix` nor `--suffix` is given, a random account is generated immediately. Once a match is found, you're prompted (with confirmation) for a passphrase (at least 12 characters) to encrypt the resulting keystore — there's no flag for this, so it never ends up in shell history or process listings.

Use `.` as a wildcard for one digit, and repeat a flag to accept any of several patterns:

```
eth-vanity -p ....cafe         # digits 5-8 are cafe: 0x????cafe...
eth-vanity -p dead -p beef     # starts with dead or beef
eth-vanity -p 00 -p 11 -s ff   # starts with 00 or 11, and ends with ff
```

Patterns stay anchored to the start or end of the address. The search stops at the first match, and each extra alternative makes a match more likely, so `-p dead -p beef` takes about half as long as `-p dead`. The same options work with `create2` and `offset`.

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

### Searching on a machine you don't trust

The split-key flow keeps the private key off the machine doing the search, so the search can run on rented hardware. The search only ever sees a public key, and what it finds (an offset) is useless without your seed key.

```
# 1. On a trusted machine: make a seed keystore and print its public key
eth-vanity seed --output ./keystore

# 2. On any machine: search using only the public key
eth-vanity offset --public-key <PUBLIC_KEY> --prefix 0000

# 3. Back on the trusted machine: add the offset to the seed and save the final keystore
eth-vanity combine --seed-keystore ./keystore/UTC--... --offset 0x... --address 0x... --output ./keystore
```

`combine` checks that the final key really controls `--address` before saving anything, so a wrong seed or a bad result from the searching machine can't leave you with the wrong key.

Use a new seed for each vanity address: anyone who learns one final key and the offsets could work out the others from the same seed. Don't send funds to the seed's own address; it's only a starting point. The offset can't take funds on its own, but there's no reason to publish it.

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
  seed     Split-key step 1, on a trusted machine: make a seed keypair to search from
  offset   Split-key step 2, on any machine: search for an offset using only a public key
  combine  Split-key step 3, on the trusted machine: add the offset to the seed and save the key
  help     Print this message or the help of the given subcommand(s)

Options:
  -p, --prefix <PREFIX>    Hex digits required at the start of the address (no "0x" needed); "." is a wildcard.
                           Repeat for alternatives
  -s, --suffix <SUFFIX>    Hex digits required at the end of the address; "." is a wildcard. Repeat for alternatives
  -o, --output <OUTPUT>    Directory to save the encrypted keystore file [default: .]
  -t, --threads <THREADS>  Number of concurrent threads searching for a match (default: number of CPUs)
  -e, --extra-entropy      Mix in additional randomness from random.org (supplements, never replaces, local OS randomness).
                           Set RANDOM_ORG_API_KEY in the environment to use random.org's authenticated API.
  -h, --help               Print help

Notes:
  - --prefix and --suffix accept hex characters (0-9, a-f, A-F), matched
    case-insensitively, and . as a wildcard for one digit. Each extra hex character
    makes a match ~16x rarer, so long values can take a long time to find.
  - Repeat --prefix or --suffix for alternatives: the search stops at the first address
    fitting any prefix and any suffix. Each alternative adds to the odds of a match.
  - If neither --prefix nor --suffix is given, a random account is generated immediately.
  - Once a matching address is found, you'll be prompted (with confirmation) for a
    passphrase (at least 12 characters) to encrypt the keystore -- there's no flag for this, so it never ends up
    in shell history or process listings.
  - This is CPU-bound work; going far past --threads = number of CPUs usually doesn't
    help and can even slow things down.

Subcommands:
  create2   mine a salt for a vanity CREATE2 contract address instead of a wallet
  seed, offset, combine
            search without the private key on the searching machine (split-key flow)
```

## Test

```
cargo test
```

Includes cross-validation of the batched point-increment math against an independently-computed reference (catches batch-boundary bugs), an end-to-end invariant check that the returned private key actually reproduces the returned address, a CREATE2 known-answer test (verified against go-ethereum's own `crypto.CreateAddress2`), a full keystore encrypt→decrypt round trip via the `eth-keystore` crate's own decryptor, and entropy-mixing tests (response parsing against malformed/error cases, and the mixing function cross-checked against an independently computed hash).

## Design notes

- **Crypto**: [`k256`](https://docs.rs/k256) (RustCrypto's pure-Rust secp256k1), not the `secp256k1` crate (libsecp256k1 C bindings) that reth uses in its hot paths. That C library's public API is deliberately opaque and doesn't expose raw point arithmetic, which is exactly what the batched point-increment search needs. `k256` exposes `ProjectivePoint` addition and a built-in `batch_normalize_vartime` (Montgomery's trick, already implemented in the `ff` crate) directly.
- **Search algorithm (wallet mode)**: each thread walks a chain of consecutive private keys from a random starting scalar (`k0*G`, `(k0+1)*G`, ...) via cheap point addition rather than a full scalar multiplication per candidate. Points are buffered in batches and converted to affine coordinates together via one batched modular inversion, amortizing that cost across the whole batch instead of paying it per candidate.
- **Result checking**: every wallet and offset result is re-derived by a plain scalar multiplication, separate from the batched walk, before anything is printed or saved.
- **Split-key search**: `offset` starts each chain at the seed's public key plus a random `k0*G`, using the same walk as wallet mode. The result is a scalar to add to the seed key, and `combine` checks the sum against the found address before saving.
- **Pattern matching**: `.` is the only wildcard because `x` would be ambiguous: `0x12` could mean a 0 and a wildcard, or a `0x` prefix. Masks compare one digit at a time and stop at the first mismatch, so most candidates cost a single comparison per pattern.
- **Hashing**: [`keccak-asm`](https://docs.rs/keccak-asm) instead of `sha3` — hand-written assembly Keccak, same `Digest` trait so it's a drop-in swap.
- **Keystore**: the standard `eth-keystore` crate hardcodes scrypt N=2^13 with no way to override it, much weaker than go-ethereum's default (N=2^18). `src/keystore.rs` reimplements the encryption directly against the same primitives (`scrypt`, `aes`, `ctr`) with N=2^18, reusing `eth-keystore`'s public struct types for the JSON schema so files stay cross-compatible with geth and other standard keystore readers.
- **Keystore files**: created as `0600`, and new directories as `0700`, matching geth. Saving never overwrites an existing file. The output directory is tested before a search starts, and a bad passphrase re-prompts rather than exiting, so a found key isn't lost at the last step.
- **Secrets in memory**: keys, seeds, the scrypt-derived key and passphrases are wiped with `zeroize` when dropped. This is best effort: hasher state, scrypt's internal buffers and temporary copies aren't reached, and memory isn't locked, so a live secret can still reach swap.
- **RNG in the hot loop**: neither search loop calls the OS RNG per candidate. Wallet search draws one random starting scalar per thread, then walks forward via point addition. CREATE2 search draws one random 24-byte prefix per thread, then increments an 8-byte counter for the rest of the salt.
- **Optional external entropy** (`--extra-entropy`, wallet mode only): local OS randomness is always drawn fresh regardless; when enabled, each thread's starting scalar is derived from `Keccak256(local || external || worker_index)` instead of local bytes directly, so a doctored or unreachable random.org can only fail to add anything, never weaken the result below local-only randomness.
- **Release profile**: `lto = "fat"`, `codegen-units = 1`, `panic = "abort"` (see `Cargo.toml`).

## History

This project started as a Go CLI, then was rewritten from scratch in Rust specifically to benchmark against it. The Rust version won decisively — on an Apple M4 Max (16 threads), wallet search went from ~14.3M addr/s to ~42.4M addr/s, and CREATE2 search from ~44.2M addr/s to ~92.9M addr/s, using the same algorithms and the same core optimizations (no per-candidate heap allocation, no per-candidate RNG calls) in both. The gap is primarily `k256`'s point arithmetic being faster than the cgo path Go ends up on, plus `keccak-asm`'s hand-written assembly versus Go's Keccak implementation.

Given that gap, the Rust implementation replaced the Go one outright; this repository's history contains both projects' full commit history merged together.
