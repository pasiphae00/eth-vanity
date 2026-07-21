package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// MatchCriteria describes the vanity bytes an address must contain.
// Prefix and Suffix are lowercase hex (no "0x") and matched case-insensitively.
type MatchCriteria struct {
	Prefix string
	Suffix string
}

func (m MatchCriteria) matchesBytes(prefix, suffix, addrHex []byte) bool {
	if len(prefix) > 0 && !bytes.HasPrefix(addrHex, prefix) {
		return false
	}
	if len(suffix) > 0 && !bytes.HasSuffix(addrHex, suffix) {
		return false
	}
	return true
}

// SearchResult is a keypair whose address satisfies the match criteria.
type SearchResult struct {
	PrivateKey *ecdsa.PrivateKey
	Address    common.Address
}

// LiveFeed exposes the most recent candidate address tried by each worker,
// for display purposes only (e.g. an animation while the search runs).
// Each worker owns one slot, so reads and writes never contend.
type LiveFeed struct {
	slots []atomic.Pointer[string]
}

// NewLiveFeed creates a feed with one slot per worker goroutine.
func NewLiveFeed(threads int) *LiveFeed {
	return &LiveFeed{slots: make([]atomic.Pointer[string], threads)}
}

func (f *LiveFeed) set(worker int, addrHex string) {
	f.slots[worker].Store(&addrHex)
}

// Sample returns the last candidate address seen by one of the workers,
// chosen round-robin by call count, or "" if nothing has been tried yet.
func (f *LiveFeed) Sample(call int) string {
	if len(f.slots) == 0 {
		return ""
	}
	if p := f.slots[call%len(f.slots)].Load(); p != nil {
		return *p
	}
	return ""
}

// Search spawns `threads` goroutines that each generate random keypairs and
// discard any whose address doesn't satisfy criteria, until one matches or
// ctx is cancelled. attempts is incremented atomically for every keypair
// generated, so callers can report progress from another goroutine. feed
// may be nil if the caller doesn't want live candidate updates.
//
// Key generation goes through go-ethereum's crypto.GenerateKey, which (on a
// cgo build, the default here) calls into libsecp256k1's hand-optimized C
// implementation. A from-scratch pure-Go scalar multiplication was tried and
// benchmarked slower, so this stays as-is; see the perf notes in CLAUDE.md.
func Search(ctx context.Context, criteria MatchCriteria, threads int, attempts *uint64, feed *LiveFeed) (*SearchResult, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	resultCh := make(chan *SearchResult, 1)
	prefix := []byte(criteria.Prefix)
	suffix := []byte(criteria.Suffix)

	var wg sync.WaitGroup
	wg.Add(threads)
	for i := 0; i < threads; i++ {
		go func(worker int) {
			defer wg.Done()

			local := 0
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				key, err := crypto.GenerateKey()
				if err != nil {
					// crypto/rand failure; extremely unlikely, but don't spin forever.
					continue
				}
				addr := crypto.PubkeyToAddress(key.PublicKey)
				atomic.AddUint64(attempts, 1)

				// Encode the raw address bytes directly rather than calling
				// addr.Hex(), which computes an EIP-55 checksum via a *second*
				// Keccak256 hash that we'd immediately discard by lowercasing.
				var addrHex [40]byte
				hex.Encode(addrHex[:], addr.Bytes())

				local++
				if feed != nil && local&0xff == 0 {
					feed.set(worker, string(addrHex[:]))
				}

				if !criteria.matchesBytes(prefix, suffix, addrHex[:]) {
					continue
				}

				result := &SearchResult{PrivateKey: key, Address: addr}
				select {
				case resultCh <- result:
				default:
				}
				cancel()
				return
			}
		}(i)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	if result, ok := <-resultCh; ok {
		return result, nil
	}
	return nil, ctx.Err()
}
