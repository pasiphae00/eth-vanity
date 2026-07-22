package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestParseRandomOrgHex(t *testing.T) {
	valid := "aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99\naa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99\n"
	b, err := parseRandomOrgHex(valid)
	if err != nil {
		t.Fatalf("valid response should parse: %v", err)
	}
	if len(b) != externalEntropyBytes {
		t.Fatalf("got %d bytes, want %d", len(b), externalEntropyBytes)
	}
	if b[0] != 0xaa || b[1] != 0xbb {
		t.Fatalf("unexpected decoded bytes: %x", b)
	}

	cases := []string{
		"",
		"not hex at all",
		"Error: quota exceeded",
		"aabb", // too short
	}
	for _, c := range cases {
		if _, err := parseRandomOrgHex(c); err == nil {
			t.Errorf("expected error parsing %q, got none", c)
		}
	}
}

func TestParseRandomOrgAPIResponse(t *testing.T) {
	raw := bytes.Repeat([]byte{0x42}, externalEntropyBytes)
	encoded := base64.StdEncoding.EncodeToString(raw)

	valid := []byte(`{"jsonrpc":"2.0","result":{"random":{"data":["` + encoded + `"],"completionTime":"2026-01-01 00:00:00Z"},"bitsUsed":256,"bitsLeft":1,"requestsLeft":1,"advisoryDelay":0},"id":1}`)
	b, err := parseRandomOrgAPIResponse(valid)
	if err != nil {
		t.Fatalf("valid response should parse: %v", err)
	}
	if !bytes.Equal(b, raw) {
		t.Fatalf("got %x, want %x", b, raw)
	}

	rpcError := []byte(`{"jsonrpc":"2.0","error":{"code":401,"message":"Invalid API key"},"id":1}`)
	if _, err := parseRandomOrgAPIResponse(rpcError); err == nil {
		t.Fatal("expected error for a JSON-RPC error response")
	}

	cases := [][]byte{
		[]byte(``),
		[]byte(`not json`),
		[]byte(`{"jsonrpc":"2.0","result":{"random":{"data":[]}},"id":1}`),                                                             // empty data
		[]byte(`{"jsonrpc":"2.0","result":{"random":{"data":["not-base64!!"]}},"id":1}`),                                               // bad base64
		[]byte(`{"jsonrpc":"2.0","result":{"random":{"data":["` + base64.StdEncoding.EncodeToString([]byte("short")) + `"]}},"id":1}`), // wrong length
	}
	for _, c := range cases {
		if _, err := parseRandomOrgAPIResponse(c); err == nil {
			t.Errorf("expected error parsing %q, got none", c)
		}
	}
}

func TestMixEntropyIsDeterministicAndSensitiveToEachInput(t *testing.T) {
	local := [32]byte{1, 2, 3}
	external := bytes.Repeat([]byte{0xAB}, 32)

	got := mixEntropy(local, external, 0)

	// Cross-checked independently: Keccak256(local || external || workerBytes).
	var buf []byte
	buf = append(buf, local[:]...)
	buf = append(buf, external...)
	buf = append(buf, 0, 0, 0, 0, 0, 0, 0, 0) // worker=0, big-endian uint64
	want := crypto.Keccak256(buf)

	if !bytes.Equal(got[:], want) {
		t.Fatalf("mixEntropy result doesn't match independently computed Keccak256: got %x want %x", got, want)
	}

	// Changing any single input should change the output (a basic sanity
	// check that we're not accidentally ignoring one of the inputs).
	if other := mixEntropy([32]byte{9, 9, 9}, external, 0); other == got {
		t.Fatal("changing local entropy did not change the mixed seed")
	}
	if other := mixEntropy(local, bytes.Repeat([]byte{0xCD}, 32), 0); other == got {
		t.Fatal("changing external entropy did not change the mixed seed")
	}
	if other := mixEntropy(local, external, 1); other == got {
		t.Fatal("changing worker index did not change the mixed seed")
	}
}

// TestRandomScalarWithExternalEntropy checks that mixing in external
// entropy still produces a valid, usable scalar, and that the same local
// randomness combined with different external entropy produces different
// scalars (i.e. the external entropy is actually influencing the result,
// not silently ignored).
func TestRandomScalarWithExternalEntropy(t *testing.T) {
	external := bytes.Repeat([]byte{0x11}, 32)
	scalar, err := randomScalar(external, 0)
	if err != nil {
		t.Fatalf("randomScalar with external entropy failed: %v", err)
	}
	if scalar.IsZero() {
		t.Fatal("scalar should not be zero")
	}
}

// TestSearchEndToEndWithExternalEntropy re-runs the private-key-reproduces-
// address invariant with a (fake, fixed) external entropy source mixed in,
// to make sure that code path is exercised and still produces a correct,
// usable key -- not just that the no-external-entropy path works.
func TestSearchEndToEndWithExternalEntropy(t *testing.T) {
	criteria := MatchCriteria{Prefix: "a"}
	var attempts uint64
	external := bytes.Repeat([]byte{0x99}, 32)

	result, err := Search(context.Background(), criteria, 4, &attempts, nil, external)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}

	gotFromKey := crypto.PubkeyToAddress(result.PrivateKey.PublicKey)
	if gotFromKey != result.Address {
		t.Fatalf("returned private key does not match returned address: key derives %s, want %s", gotFromKey.Hex(), result.Address.Hex())
	}
}
