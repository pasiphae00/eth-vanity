package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"sync/atomic"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
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

// batchSize is how many consecutive candidate points get accumulated (via
// cheap Jacobian point addition) before paying for a single batched modular
// inversion to convert all of them to affine coordinates at once. See
// batchInvert.
const batchSize = 1024

// generatorPoint returns the secp256k1 base point G as a normalized (Z=1)
// Jacobian point.
func generatorPoint() secp256k1.JacobianPoint {
	params := secp256k1.S256().Params()
	var g secp256k1.JacobianPoint
	g.X.SetByteSlice(params.Gx.Bytes())
	g.Y.SetByteSlice(params.Gy.Bytes())
	g.Z.SetInt(1)
	return g
}

// randomScalar draws a uniformly random, non-zero scalar in [1, N-1] using
// rejection sampling, matching the rigor of crypto/ecdsa's key generation.
func randomScalar() (secp256k1.ModNScalar, error) {
	var buf [32]byte
	var scalar secp256k1.ModNScalar
	for {
		if _, err := cryptorand.Read(buf[:]); err != nil {
			return scalar, err
		}
		if scalar.SetBytes(&buf) == 0 && !scalar.IsZero() {
			return scalar, nil
		}
	}
}

// scalarFromUint64 encodes n as a ModNScalar. n is always well within the
// group order, so this never overflows/reduces.
func scalarFromUint64(n uint64) secp256k1.ModNScalar {
	var buf [32]byte
	binary.BigEndian.PutUint64(buf[24:], n)
	var s secp256k1.ModNScalar
	s.SetBytes(&buf)
	return s
}

// batchInvert computes the modular inverse of every element in zs using a
// single actual field inversion (Montgomery's trick: an inversion of the
// product of all values, then a backward pass of cheap multiplications to
// recover each individual inverse). Results are written into out, which
// must have the same length as zs; out and zs may not alias.
func batchInvert(zs, out []secp256k1.FieldVal) {
	n := len(zs)
	out[0].Set(&zs[0])
	for i := 1; i < n; i++ {
		out[i].Mul2(&out[i-1], &zs[i])
	}

	var u secp256k1.FieldVal
	u.Set(&out[n-1]).Inverse()

	for i := n - 1; i > 0; i-- {
		var inv secp256k1.FieldVal
		inv.Mul2(&u, &out[i-1])
		u.Mul(&zs[i])
		out[i] = inv
	}
	out[0] = u
}

// searchWorker walks a chain of consecutive private keys starting at a
// random k0: k0*G, (k0+1)*G, (k0+2)*G, ... Each step is a cheap Jacobian
// point addition (add G) rather than a full scalar multiplication, which is
// what makes this fast; the results are buffered in batches and converted
// to affine coordinates (needed to hash X||Y into an address) together via
// batchInvert, amortizing the one expensive step (a modular inversion)
// across the whole batch instead of paying it per candidate.
//
// Consecutive points differ from independent random points only by a fixed,
// known offset from G; since Keccak256 output is unrelated to any algebraic
// structure in its input, the resulting addresses are indistinguishable from
// independently sampled ones for search purposes. This is the same
// technique used by other vanity-address generators (e.g. profanity).
func searchWorker(ctx context.Context, criteria MatchCriteria, prefix, suffix []byte, attempts *uint64, feed *LiveFeed, worker int) (*SearchResult, error) {
	k0, err := randomScalar()
	if err != nil {
		return nil, err
	}

	var cur secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&k0, &cur)

	g := generatorPoint()
	hasher := crypto.NewKeccakState()

	xs := make([]secp256k1.FieldVal, batchSize)
	ys := make([]secp256k1.FieldVal, batchSize)
	zs := make([]secp256k1.FieldVal, batchSize)
	zInv := make([]secp256k1.FieldVal, batchSize)

	// pub and hash are reused across every candidate rather than declared
	// fresh each iteration: passing a slice into hasher's interface methods
	// (Write/Read) defeats escape analysis, so a freshly-declared array would
	// otherwise heap-allocate on every single call.
	var pub [64]byte
	var hash [32]byte

	// totalOffset is the number of point additions applied to cur since it
	// started at k0*G; it persists across batches (unlike a per-batch
	// counter) because it's what lets us recover the actual private key
	// scalar (k0 + totalOffset) for whichever candidate matches, no matter
	// which batch it turns up in.
	var totalOffset uint64
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		for i := 0; i < batchSize; i++ {
			var next secp256k1.JacobianPoint
			secp256k1.AddNonConst(&cur, &g, &next)
			cur = next
			xs[i] = next.X
			ys[i] = next.Y
			zs[i] = next.Z
		}

		batchInvert(zs, zInv)

		for i := 0; i < batchSize; i++ {
			var zInv2, zInv3, ax, ay secp256k1.FieldVal
			zInv2.SquareVal(&zInv[i])
			zInv3.Mul2(&zInv2, &zInv[i])
			ax.Mul2(&xs[i], &zInv2).Normalize()
			ay.Mul2(&ys[i], &zInv3).Normalize()

			ax.PutBytesUnchecked(pub[:32])
			ay.PutBytesUnchecked(pub[32:])

			hasher.Reset()
			hasher.Write(pub[:])
			hasher.Read(hash[:])

			var addrHex [40]byte
			hex.Encode(addrHex[:], hash[12:])

			totalOffset++
			if feed != nil && i == batchSize-1 {
				feed.set(worker, string(addrHex[:]))
			}

			if !criteria.matchesBytes(prefix, suffix, addrHex[:]) {
				continue
			}

			atomic.AddUint64(attempts, uint64(i+1))

			offset := scalarFromUint64(totalOffset)
			var matchScalar secp256k1.ModNScalar
			matchScalar.Add2(&k0, &offset)

			priv := secp256k1.NewPrivateKey(&matchScalar)
			var addr common.Address
			copy(addr[:], hash[12:])
			return &SearchResult{PrivateKey: priv.ToECDSA(), Address: addr}, nil
		}

		atomic.AddUint64(attempts, batchSize)
	}
}

// Search spawns `threads` goroutines that each walk an independent chain of
// candidate keys (see searchWorker) until one matches criteria or ctx is
// cancelled. attempts is incremented as batches complete, so callers can
// report progress from another goroutine. feed may be nil if the caller
// doesn't want live candidate updates.
func Search(ctx context.Context, criteria MatchCriteria, threads int, attempts *uint64, feed *LiveFeed) (*SearchResult, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	prefix := []byte(criteria.Prefix)
	suffix := []byte(criteria.Suffix)

	type outcome struct {
		result *SearchResult
		err    error
	}
	resultCh := make(chan outcome, 1)

	var wg sync.WaitGroup
	wg.Add(threads)
	for i := 0; i < threads; i++ {
		go func(worker int) {
			defer wg.Done()
			result, err := searchWorker(ctx, criteria, prefix, suffix, attempts, feed, worker)
			if err != nil {
				return
			}
			select {
			case resultCh <- outcome{result: result}:
				cancel()
			default:
			}
		}(i)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	if o, ok := <-resultCh; ok {
		return o.result, nil
	}
	return nil, ctx.Err()
}
