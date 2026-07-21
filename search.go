package main

import (
	"context"
	"crypto/ecdsa"
	"strings"
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

func (m MatchCriteria) matches(addrHex string) bool {
	if m.Prefix != "" && !strings.HasPrefix(addrHex, m.Prefix) {
		return false
	}
	if m.Suffix != "" && !strings.HasSuffix(addrHex, m.Suffix) {
		return false
	}
	return true
}

// SearchResult is a keypair whose address satisfies the match criteria.
type SearchResult struct {
	PrivateKey *ecdsa.PrivateKey
	Address    common.Address
}

// Search spawns `threads` goroutines that each generate random keypairs and
// discard any whose address doesn't satisfy criteria, until one matches or
// ctx is cancelled. attempts is incremented atomically for every keypair
// generated, so callers can report progress from another goroutine.
func Search(ctx context.Context, criteria MatchCriteria, threads int, attempts *uint64) (*SearchResult, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	resultCh := make(chan *SearchResult, 1)

	var wg sync.WaitGroup
	wg.Add(threads)
	for i := 0; i < threads; i++ {
		go func() {
			defer wg.Done()
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
				atomic.AddUint64(attempts, 1)

				addr := crypto.PubkeyToAddress(key.PublicKey)
				addrHex := strings.ToLower(addr.Hex()[2:]) // strip "0x"
				if !criteria.matches(addrHex) {
					continue
				}

				select {
				case resultCh <- &SearchResult{PrivateKey: key, Address: addr}:
				default:
				}
				cancel()
				return
			}
		}()
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
