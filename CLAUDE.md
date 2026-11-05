# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`eth-vanity` is a Rust CLI that generates an Ethereum keypair whose public address matches a vanity prefix/suffix (saved as a geth-compatible encrypted keystore), or, via the `create2` subcommand, mines a salt for a vanity CREATE2 contract address. The `seed`/`offset`/`combine` subcommands do the wallet search from a public key alone, so it can run on an untrusted machine.

This project started as a Go CLI, then was rewritten from scratch in Rust to benchmark against it (~2-3x faster on both modes with the same algorithms). The Rust version won and replaced the Go one outright; this repo's git history contains both projects' commits merged together, so `git log` before the merge point will show Go commits.

## Commands

```
cargo build --release                                    # build (see Cargo.toml for release profile: lto, codegen-units=1, panic=abort)
RUSTFLAGS="-C target-cpu=native" cargo build --release    # for maximum local throughput; non-portable binary
cargo test                                                 # all tests are #[cfg(test)] modules inline in each source file, not in tests/
cargo clippy
cargo fmt
```

## Architecture

- `src/main.rs` — clap CLI (wallet mode is the default subcommand-less invocation; `create2` and the split-key `seed`/`offset`/`combine` are the others). Orchestrates: validate flags → search → print result → (wallet) verify, prompt passphrase and save keystore, (create2) optionally save JSON, or (offset) verify and print the offset. `seed` and `combine` don't search; they make a seed keystore and turn seed + offset into the final keystore.
- `src/matching.rs` — `MatchCriteria` (prefix/suffix matching) and shared hex validation/parsing helpers used by all search modes.
- `src/search.rs` — wallet-mode key search. The performance-critical core: each thread walks a chain of consecutive private keys from a random starting scalar (`k0*G`, `(k0+1)*G`, ...) via cheap point addition rather than a full scalar multiplication per candidate, batching points and converting to affine coordinates together via one batched modular inversion (`k256`'s built-in `batch_normalize_vartime`) to amortize that cost. Don't reintroduce a full scalar-mult-per-candidate loop without benchmarking first — it was tried and measured meaningfully slower. Offset mode is the same walk started from an optional base point (the seed's public key), so `search_worker` needs only a public key and its result is a scalar to add to the seed. Also holds `verify` and the split-key helpers (`parse_public_key`, `combine`).
- `src/create2.rs` — CREATE2 salt mining per EIP-1014. Pure Keccak256 hashing, no elliptic-curve math, so no batching trick needed — this is close to hash-function-speed-limited already.
- `src/keystore.rs` — encrypted V3 keystore output. Reimplements `eth-keystore`'s `encrypt_key` against the same primitives (`scrypt`/`aes`/`ctr`) because that crate hardcodes a scrypt N far weaker than go-ethereum's default; this uses N=2^18 to match. Reuses `eth-keystore`'s public struct types for JSON-schema compatibility. Files are created `0600` and never overwrite an existing file. Also holds `load` (for `combine`), the passphrase prompts and rules, and `check_output_dir`, which runs before a search so an unusable directory can't lose a found key.
- `src/entropy.rs` — optional `--extra-entropy` (wallet mode only): fetches randomness from random.org (authenticated API if `RANDOM_ORG_API_KEY` is set in the environment, else the free legacy endpoint) to mix into (never replace) local OS randomness. See `mix_entropy` in `search.rs` for the actual combination.
- `src/progress.rs` — live search progress (spinner + flickering candidate address + rate) and the one-time "Est. time to match" range printed after the first stable rate reading, derived from the search space size and measured hash rate (not a countdown).

### Key invariants to preserve

- **The private key returned by `search()` must always reproduce the address returned alongside it.** This is checked by dedicated end-to-end tests and again at runtime by `search::verify` before anything is reported; if you touch the point-increment/batch-inversion math in `search.rs`, run those tests and ideally add a cross-check against an independently computed reference (see existing tests for the pattern) before trusting any change.
- **`offset` must never touch a private key.** It takes a public key and reports a scalar to add to the seed; a private-key input there would defeat the point of the flow. `combine` is the only place the two come together, and it must check the result against the expected address before saving.
- **Secrets stay in `Zeroizing` buffers.** Keys pass around as `search::KeyBytes`, which is boxed so moving one doesn't leave an unwiped copy behind. Keep new key material in that type rather than plain arrays.
- **External entropy only ever supplements local OS randomness, never replaces it.** Local randomness is drawn fresh on every scalar-generation attempt regardless of whether `--extra-entropy` is set.
- Buffers passed into `hasher.Write`/`.update()`-style interface calls must be hoisted out of hot loops (declared once, reused), not declared fresh per iteration — passing a stack slice into an interface/trait method defeats escape analysis in Go and can similarly force unwanted allocation patterns in Rust; this was a real, measured perf bug worth not reintroducing.
