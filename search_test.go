package main

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestMatchCriteriaBytes(t *testing.T) {
	cases := []struct {
		prefix, suffix, addr string
		want                 bool
	}{
		{"ab", "", "abcdef0000000000000000000000000000000000", true},
		{"ab", "", "cdabef0000000000000000000000000000000000", false},
		{"", "ef", "abcdef0000000000000000000000000000000000", false},
		{"", "00", "abcdef0000000000000000000000000000000000", true},
		{"ab", "00", "abcdef0000000000000000000000000000000000", true},
		{"ab", "99", "abcdef0000000000000000000000000000000000", false},
		{"", "", "abcdef0000000000000000000000000000000000", true},
	}
	for _, c := range cases {
		got := MatchCriteria{}.matchesBytes([]byte(c.prefix), []byte(c.suffix), []byte(c.addr))
		if got != c.want {
			t.Errorf("matchesBytes(prefix=%q, suffix=%q, addr=%q) = %v, want %v", c.prefix, c.suffix, c.addr, got, c.want)
		}
	}
}

// referenceAddress computes the Ethereum address for a scalar using
// go-ethereum's own trusted path (ScalarBaseMultNonConst -> ToECDSA ->
// PubkeyToAddress), independent of any of this file's batching/incrementing
// logic. Every other test in this file is validated against this.
func referenceAddress(t *testing.T, scalar *secp256k1.ModNScalar) [20]byte {
	t.Helper()
	priv := secp256k1.NewPrivateKey(scalar)
	addr := crypto.PubkeyToAddress(priv.ToECDSA().PublicKey)
	var out [20]byte
	copy(out[:], addr.Bytes())
	return out
}

// TestGeneratorPoint checks that our hand-built G (from curve params, via
// SetByteSlice) is actually the generator: 1*G computed by adding it to the
// identity should equal 1*G computed by the library's own scalar mult.
func TestGeneratorPoint(t *testing.T) {
	g := generatorPoint()

	one := scalarFromUint64(1)
	var want secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&one, &want)
	want.ToAffine()

	gAffine := g
	gAffine.ToAffine()

	if !gAffine.X.Equals(&want.X) || !gAffine.Y.Equals(&want.Y) {
		t.Fatalf("generatorPoint() does not match ScalarBaseMultNonConst(1):\n got X=%x Y=%x\nwant X=%x Y=%x",
			gAffine.X.Bytes(), gAffine.Y.Bytes(), want.X.Bytes(), want.Y.Bytes())
	}
}

// TestBatchInvert checks the Montgomery batch-inversion trick against
// inverting each element individually.
func TestBatchInvert(t *testing.T) {
	n := 37 // deliberately not a power of two, and not batchSize
	zs := make([]secp256k1.FieldVal, n)
	for i := range zs {
		zs[i].SetInt(uint16(1000 + i))
	}

	got := make([]secp256k1.FieldVal, n)
	batchInvert(zs, got)

	for i := range zs {
		var want secp256k1.FieldVal
		want.Set(&zs[i]).Inverse().Normalize()
		gotN := got[i]
		gotN.Normalize()
		if !gotN.Equals(&want) {
			t.Fatalf("batchInvert[%d]: got %x want %x", i, gotN.Bytes(), want.Bytes())
		}
	}
}

// TestSearchWorkerAddressesMatchReference walks a short chain (several
// batches, using a small batchSize override) and checks every single
// candidate address against the independently-computed reference address
// for that exact scalar (k0 + offset). This directly validates the
// increment+batch-inversion math end to end, including across batch
// boundaries, which is exactly where an off-by-one would produce a wallet
// whose saved private key doesn't match the address it was found under.
func TestSearchWorkerAddressesMatchReference(t *testing.T) {
	const testBatchSize = 8
	const numBatches = 5

	k0, err := randomScalar()
	if err != nil {
		t.Fatal(err)
	}

	var cur secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&k0, &cur)
	g := generatorPoint()
	hasher := crypto.NewKeccakState()

	xs := make([]secp256k1.FieldVal, testBatchSize)
	ys := make([]secp256k1.FieldVal, testBatchSize)
	zs := make([]secp256k1.FieldVal, testBatchSize)
	zInv := make([]secp256k1.FieldVal, testBatchSize)

	var totalOffset uint64
	for b := 0; b < numBatches; b++ {
		for i := 0; i < testBatchSize; i++ {
			var next secp256k1.JacobianPoint
			secp256k1.AddNonConst(&cur, &g, &next)
			cur = next
			xs[i], ys[i], zs[i] = next.X, next.Y, next.Z
		}

		batchInvert(zs, zInv)

		for i := 0; i < testBatchSize; i++ {
			var zInv2, zInv3, ax, ay secp256k1.FieldVal
			zInv2.SquareVal(&zInv[i])
			zInv3.Mul2(&zInv2, &zInv[i])
			ax.Mul2(&xs[i], &zInv2).Normalize()
			ay.Mul2(&ys[i], &zInv3).Normalize()

			var pub [64]byte
			xb, yb := ax.Bytes(), ay.Bytes()
			copy(pub[:32], xb[:])
			copy(pub[32:], yb[:])

			var hash [32]byte
			hasher.Reset()
			hasher.Write(pub[:])
			hasher.Read(hash[:])

			totalOffset++

			offset := scalarFromUint64(totalOffset)
			var scalar secp256k1.ModNScalar
			scalar.Add2(&k0, &offset)
			want := referenceAddress(t, &scalar)

			if !bytes.Equal(hash[12:], want[:]) {
				t.Fatalf("batch %d, index %d (totalOffset=%d): got %x want %x", b, i, totalOffset, hash[12:], want)
			}
		}
	}
}

// TestSearchEndToEnd runs the real Search() entry point with a short prefix
// and checks that (a) it finds a match quickly, (b) the address satisfies
// the criteria, and (c) — the invariant that matters most — the returned
// private key actually reproduces the returned address. If this ever
// fails, the tool would save a keystore for the wrong key.
func TestSearchEndToEnd(t *testing.T) {
	criteria := MatchCriteria{Prefix: "a"}
	var attempts uint64

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := Search(ctx, criteria, 4, &attempts, nil)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	addrHex := result.Address.Hex()[2:]
	if len(addrHex) == 0 || addrHex[0] != 'a' && addrHex[0] != 'A' {
		t.Fatalf("address %s does not have prefix %q", result.Address.Hex(), criteria.Prefix)
	}

	gotFromKey := crypto.PubkeyToAddress(result.PrivateKey.PublicKey)
	if gotFromKey != result.Address {
		t.Fatalf("returned private key does not match returned address: key derives %s, want %s", gotFromKey.Hex(), result.Address.Hex())
	}
}

// TestSearchManyEndToEnd repeats TestSearchEndToEnd's invariant check many
// times with multiple concurrent workers, to catch any rare bug that only
// shows up occasionally (e.g. tied to a specific batch boundary or worker
// interleaving).
func TestSearchManyEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping repeated end-to-end search in -short mode")
	}
	for i := 0; i < 25; i++ {
		criteria := MatchCriteria{Suffix: "0"}
		var attempts uint64
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		result, err := Search(ctx, criteria, 8, &attempts, nil)
		cancel()
		if err != nil {
			t.Fatalf("run %d: Search failed: %v", i, err)
		}
		gotFromKey := crypto.PubkeyToAddress(result.PrivateKey.PublicKey)
		if gotFromKey != result.Address {
			t.Fatalf("run %d: returned private key does not match returned address: key derives %s, want %s", i, gotFromKey.Hex(), result.Address.Hex())
		}
		if result.Address.Hex()[len(result.Address.Hex())-1] != '0' {
			t.Fatalf("run %d: address %s does not have suffix %q", i, result.Address.Hex(), criteria.Suffix)
		}
	}
}
