package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// externalEntropyBytes is how many bytes we ask random.org for. This
// matches our 256-bit security parameter; asking for more wouldn't add
// anything once it's hashed together with local randomness (see
// mixEntropy), and it's considerate of random.org's shared rate limit.
const externalEntropyBytes = 32

const randomOrgTimeout = 8 * time.Second

// randomOrgAPIKeyEnv is the environment variable holding a random.org API
// key (from https://api.random.org/api-keys), if the caller wants to use
// the authenticated JSON-RPC API instead of the free, unauthenticated
// legacy HTTP endpoint. Not a flag: an API key is a credential, and
// credentials belong in the environment/secrets store, not shell history
// or process listings (ps).
const randomOrgAPIKeyEnv = "RANDOM_ORG_API_KEY"

// fetchExternalEntropy fetches externalEntropyBytes of randomness from
// random.org. This is meant to be mixed with, never substituted for, local
// OS randomness (see mixEntropy) -- so a doctored or unreachable random.org
// can only fail to help, never weaken the result below local-only
// randomness.
//
// If RANDOM_ORG_API_KEY is set, this uses random.org's authenticated
// JSON-RPC API (generateBlobs), which has its own per-key quota separate
// from the shared IP-based quota on the free endpoint. Otherwise it falls
// back to the free, unauthenticated legacy HTTP endpoint.
func fetchExternalEntropy() ([]byte, error) {
	if apiKey := strings.TrimSpace(os.Getenv(randomOrgAPIKeyEnv)); apiKey != "" {
		return fetchExternalEntropyAPI(apiKey)
	}
	return fetchExternalEntropyLegacy()
}

// --- Authenticated JSON-RPC API (https://api.random.org/json-rpc/4/invoke) ---

type randomOrgRPCRequest struct {
	JSONRPC string             `json:"jsonrpc"`
	Method  string             `json:"method"`
	Params  randomOrgRPCParams `json:"params"`
	ID      int                `json:"id"`
}

type randomOrgRPCParams struct {
	APIKey string `json:"apiKey"`
	N      int    `json:"n"`
	Size   int    `json:"size"`
}

type randomOrgRPCResponse struct {
	Result *struct {
		Random struct {
			Data []string `json:"data"`
		} `json:"random"`
	} `json:"result"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func fetchExternalEntropyAPI(apiKey string) ([]byte, error) {
	reqBody, err := json.Marshal(randomOrgRPCRequest{
		JSONRPC: "2.0",
		Method:  "generateBlobs",
		Params: randomOrgRPCParams{
			APIKey: apiKey,
			N:      1,
			Size:   externalEntropyBytes * 8, // size is in bits
		},
		ID: 1,
	})
	if err != nil {
		return nil, fmt.Errorf("encoding random.org API request: %w", err)
	}

	client := &http.Client{Timeout: randomOrgTimeout}
	resp, err := client.Post("https://api.random.org/json-rpc/4/invoke", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("requesting randomness from random.org API: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("reading random.org API response: %w", err)
	}

	return parseRandomOrgAPIResponse(body)
}

// parseRandomOrgAPIResponse parses a generateBlobs JSON-RPC response body
// into exactly externalEntropyBytes of raw bytes.
func parseRandomOrgAPIResponse(body []byte) ([]byte, error) {
	var rpcResp randomOrgRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("parsing random.org API response: %w (body: %q)", err, truncate(string(body), 80))
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("random.org API error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	if rpcResp.Result == nil || len(rpcResp.Result.Random.Data) != 1 {
		return nil, fmt.Errorf("unexpected random.org API response shape (body: %q)", truncate(string(body), 80))
	}

	b, err := base64.StdEncoding.DecodeString(rpcResp.Result.Random.Data[0])
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in random.org API response: %w", err)
	}
	if len(b) != externalEntropyBytes {
		return nil, fmt.Errorf("expected %d bytes from random.org API, got %d", externalEntropyBytes, len(b))
	}
	return b, nil
}

// --- Free, unauthenticated legacy HTTP endpoint ---

func fetchExternalEntropyLegacy() ([]byte, error) {
	url := fmt.Sprintf("https://www.random.org/cgi-bin/randbyte?nbytes=%d&format=h", externalEntropyBytes)

	client := &http.Client{Timeout: randomOrgTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("requesting randomness from random.org: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("random.org returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("reading random.org response: %w", err)
	}

	return parseRandomOrgHex(string(body))
}

// parseRandomOrgHex parses random.org's randbyte "format=h" response
// (whitespace-separated hex byte pairs, wrapped across lines) into exactly
// externalEntropyBytes of raw bytes.
func parseRandomOrgHex(body string) ([]byte, error) {
	compact := strings.Join(strings.Fields(body), "")
	if len(compact) != externalEntropyBytes*2 {
		return nil, fmt.Errorf("expected %d hex characters, got %d (response: %q)", externalEntropyBytes*2, len(compact), truncate(body, 80))
	}
	b, err := hex.DecodeString(compact)
	if err != nil {
		return nil, fmt.Errorf("invalid hex in response: %w", err)
	}
	return b, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
