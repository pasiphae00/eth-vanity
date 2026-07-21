package main

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Create2Result is a salt whose resulting CREATE2 contract address
// satisfies the match criteria. Unlike a wallet private key, a salt isn't
// secret — it has to be supplied on-chain to deploy the contract — so there
// is nothing here to encrypt.
type Create2Result struct {
	Salt    [32]byte
	Address common.Address
}

// create2Batch is how many consecutive salts get hashed before checking for
// cancellation and reporting progress. There's no expensive per-candidate
// step to amortize here (unlike the wallet search's EC math) — this purely
// bounds how often we touch the atomic attempts counter and the context.
const create2Batch = 8192

// create2Address computes the address a CREATE2 deployment would produce,
// per EIP-1014: keccak256(0xff ++ deployer ++ salt ++ keccak256(initCode))[12:].
// hasher, buf and hash are all reused across calls by the caller (and must
// not be shared across goroutines): passing a slice into hasher's interface
// methods (Write/Read) defeats escape analysis, so buf/hash declared fresh
// on every call would otherwise heap-allocate per candidate.
func create2Address(hasher crypto.KeccakState, deployer common.Address, salt, initCodeHash [32]byte, buf *[1 + 20 + 32 + 32]byte, hash *[32]byte) common.Address {
	buf[0] = 0xff
	copy(buf[1:21], deployer[:])
	copy(buf[21:53], salt[:])
	copy(buf[53:85], initCodeHash[:])

	hasher.Reset()
	hasher.Write(buf[:])
	hasher.Read(hash[:])

	var addr common.Address
	copy(addr[:], hash[12:])
	return addr
}

// SearchCreate2 spawns `threads` goroutines that each search an independent
// slice of salt space (a random 24-byte per-worker prefix plus an
// incrementing 8-byte counter, so workers never collide) for a CREATE2
// address matching criteria. Unlike wallet key search this is pure hashing
// with no elliptic-curve math, so no batching trick is needed for speed —
// create2Batch exists only to amortize cancellation checks and the shared
// attempts counter.
func SearchCreate2(ctx context.Context, deployer common.Address, initCodeHash [32]byte, criteria MatchCriteria, threads int, attempts *uint64, feed *LiveFeed) (*Create2Result, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	prefix := []byte(criteria.Prefix)
	suffix := []byte(criteria.Suffix)

	resultCh := make(chan *Create2Result, 1)

	var wg sync.WaitGroup
	wg.Add(threads)
	for i := 0; i < threads; i++ {
		go func(worker int) {
			defer wg.Done()

			var salt [32]byte
			if _, err := cryptorand.Read(salt[:24]); err != nil {
				return
			}
			hasher := crypto.NewKeccakState()
			var buf [1 + 20 + 32 + 32]byte
			var hash [32]byte
			var addrHex [40]byte

			var counter uint64
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				for b := 0; b < create2Batch; b++ {
					binary.BigEndian.PutUint64(salt[24:], counter)
					counter++

					addr := create2Address(hasher, deployer, salt, initCodeHash, &buf, &hash)

					hex.Encode(addrHex[:], addr[:])

					if feed != nil && b == create2Batch-1 {
						feed.set(worker, string(addrHex[:]))
					}

					if !criteria.matchesBytes(prefix, suffix, addrHex[:]) {
						continue
					}

					atomic.AddUint64(attempts, uint64(b+1))

					result := &Create2Result{Salt: salt, Address: addr}
					select {
					case resultCh <- result:
					default:
					}
					cancel()
					return
				}

				atomic.AddUint64(attempts, create2Batch)
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
