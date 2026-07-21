# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`eth-vanity` is a single-binary Go CLI that generates an Ethereum keypair whose public address matches a user-specified hex prefix and/or suffix ("vanity" bytes), then saves the result as a standard encrypted keystore file (geth/MetaMask-compatible).

## Commands

```
go build -o eth-vanity .   # build the binary
go vet ./...                # static checks
go run . --help             # show usage without building
```

There is no test suite yet.

## Architecture

Flat package `main`, three files:

- **main.go** — flag parsing/validation (`config`, `parseFlags`, `validate`), the passphrase prompt (`readPassphrase`), progress reporting (`reportProgress`), and orchestration in `main()`.
- **search.go** — `MatchCriteria` (lowercase hex prefix/suffix) and `Search`, which fans a candidate-generation loop out across `--threads` goroutines. Each worker repeatedly calls `crypto.GenerateKey()` and checks the resulting address; the first match cancels a shared `context.Context` to stop the rest. Match count is tracked via an `*uint64` incremented with `sync/atomic` so the progress reporter (running on its own goroutine/ticker) can read it without additional locking.
- **keystore.go** — `SaveKeystore` wraps `go-ethereum`'s `accounts/keystore` package (`keystore.NewKeyStore` + `ImportECDSA`, standard/strong scrypt params) to encrypt and write the found key. Zeroes `priv.D` after import.

### Key sequencing detail

The passphrase is **not** a CLI flag. The flow is: parse/validate flags → run the concurrent search → print `Wallet found!` → *then* prompt interactively (no echo, via `golang.org/x/term`) with confirmation → encrypt and save. This was a deliberate choice so the passphrase never appears in shell history or process listings. Don't reintroduce a `--passphrase`/`-k` flag without re-confirming that tradeoff.

### Other implementation notes

- Prefix/suffix matching is case-insensitive against the lowercase hex address (not EIP-55 checksum matching).
- `validate()` strips an optional `0x`/`0X` from prefix/suffix, rejects non-hex characters, and rejects combined prefix+suffix length over 40 (the full address length).
- Ctrl+C / SIGTERM cancels the search's context cleanly (`signal.NotifyContext`) rather than killing goroutines abruptly.
- Dependencies: `github.com/ethereum/go-ethereum` (key generation + keystore encryption) and `golang.org/x/term` (no-echo passphrase input). Both were a deliberate choice over hand-rolled crypto — see conversation history if reconsidering.
