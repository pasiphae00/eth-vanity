// Command eth-vanity generates an Ethereum keypair whose public address
// matches a user-specified prefix and/or suffix, then saves the result as
// an encrypted keystore file.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/term"
)

type config struct {
	Prefix       string
	Suffix       string
	Output       string
	Threads      int
	ExtraEntropy bool
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "create2" {
		runCreate2(os.Args[2:])
		return
	}
	runWallet()
}

func runWallet() {
	cfg := parseFlags()

	if err := validate(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		fmt.Fprintln(os.Stderr)
		flag.Usage()
		os.Exit(2)
	}

	criteria := MatchCriteria{Prefix: cfg.Prefix, Suffix: cfg.Suffix}

	var externalEntropy []byte
	if cfg.ExtraEntropy {
		source := "random.org (free legacy endpoint)"
		if strings.TrimSpace(os.Getenv(randomOrgAPIKeyEnv)) != "" {
			source = "random.org (authenticated API)"
		}
		fmt.Fprintf(os.Stderr, "Fetching additional entropy from %s...\n", source)

		entropy, err := fetchExternalEntropy()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not fetch additional entropy (%v); continuing with OS randomness only.\n", err)
		} else {
			externalEntropy = entropy
			fmt.Fprintln(os.Stderr, "Mixing in additional entropy from random.org.")
		}
	}

	printSearchInfo(criteria, cfg.Threads)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var attempts uint64
	feed := NewLiveFeed(cfg.Threads)
	progressCtx, stopProgress := context.WithCancel(ctx)
	go reportProgress(progressCtx, &attempts, feed, len(criteria.Prefix)+len(criteria.Suffix))

	result, err := Search(ctx, criteria, cfg.Threads, &attempts, feed, externalEntropy)
	stopProgress()
	fmt.Fprintln(os.Stderr)

	if err != nil {
		fmt.Fprintln(os.Stderr, "Interrupted:", err)
		os.Exit(1)
	}

	fmt.Printf("Wallet found! Address: %s (%d attempts)\n", result.Address.Hex(), atomic.LoadUint64(&attempts))

	passphrase, err := readPassphrase()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	path, err := SaveKeystore(result.PrivateKey, passphrase, cfg.Output)
	passphrase = ""
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	fmt.Printf("Keystore saved to: %s\n", path)
}

func parseFlags() *config {
	cfg := &config{}

	flag.StringVar(&cfg.Prefix, "prefix", "", "hex bytes required at the start of the address")
	flag.StringVar(&cfg.Prefix, "p", "", "short for -prefix")
	flag.StringVar(&cfg.Suffix, "suffix", "", "hex bytes required at the end of the address")
	flag.StringVar(&cfg.Suffix, "s", "", "short for -suffix")
	flag.StringVar(&cfg.Output, "output", ".", "directory to save the encrypted keystore file")
	flag.StringVar(&cfg.Output, "o", ".", "short for -output")
	defaultThreads := runtime.NumCPU()
	flag.IntVar(&cfg.Threads, "threads", defaultThreads, "number of concurrent goroutines searching for a match")
	flag.IntVar(&cfg.Threads, "t", defaultThreads, "short for -threads")
	flag.BoolVar(&cfg.ExtraEntropy, "extra-entropy", false, "mix in additional randomness fetched from random.org (supplements, never replaces, local OS randomness)")
	flag.BoolVar(&cfg.ExtraEntropy, "e", false, "short for -extra-entropy")

	flag.Usage = usage
	flag.Parse()
	return cfg
}

func validate(cfg *config) error {
	prefix, suffix, err := validateVanityBytes(cfg.Prefix, cfg.Suffix)
	if err != nil {
		return err
	}
	if cfg.Threads < 1 {
		return fmt.Errorf("--threads must be at least 1, got %d", cfg.Threads)
	}
	if fi, err := os.Stat(cfg.Output); err == nil && !fi.IsDir() {
		return fmt.Errorf("--output %q exists and is not a directory", cfg.Output)
	}

	cfg.Prefix = prefix
	cfg.Suffix = suffix
	return nil
}

// normalizeHex lowercases s and strips an optional "0x"/"0X" prefix.
func normalizeHex(s string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X"))
}

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// validateVanityBytes normalizes and validates a --prefix/--suffix pair
// against the shape of a 20-byte Ethereum address. Shared by both the
// wallet and create2 subcommands, since both search for an address match.
func validateVanityBytes(prefixRaw, suffixRaw string) (prefix, suffix string, err error) {
	prefix = normalizeHex(prefixRaw)
	suffix = normalizeHex(suffixRaw)

	if !isHex(prefix) {
		return "", "", fmt.Errorf("--prefix %q is not valid hex (allowed characters: 0-9, a-f, A-F)", prefixRaw)
	}
	if !isHex(suffix) {
		return "", "", fmt.Errorf("--suffix %q is not valid hex (allowed characters: 0-9, a-f, A-F)", suffixRaw)
	}
	if len(prefix)+len(suffix) > 40 {
		return "", "", fmt.Errorf("combined --prefix and --suffix length (%d) exceeds address length (40 hex chars)", len(prefix)+len(suffix))
	}
	return prefix, suffix, nil
}

// parseHexFixed strips an optional "0x"/"0X" prefix from s and decodes it as
// exactly n bytes of hex.
func parseHexFixed(s string, n int) ([]byte, error) {
	s = normalizeHex(s)
	if len(s) != n*2 {
		return nil, fmt.Errorf("expected %d hex characters, got %d", n*2, len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	return b, nil
}

// hexDecodeFlexible strips an optional "0x"/"0X" prefix from s and decodes
// the rest as hex, whatever its length.
func hexDecodeFlexible(s string) ([]byte, error) {
	b, err := hex.DecodeString(normalizeHex(s))
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	return b, nil
}

// readPassphrase prompts for a passphrase twice (without echoing input) and
// confirms both entries match. Buffers are zeroed as soon as they're no
// longer needed.
func readPassphrase() (string, error) {
	fmt.Fprint(os.Stderr, "Enter a passphrase to encrypt the wallet: ")
	pw1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading passphrase: %w", err)
	}
	defer zero(pw1)

	fmt.Fprint(os.Stderr, "Confirm passphrase: ")
	pw2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading passphrase confirmation: %w", err)
	}
	defer zero(pw2)

	if len(pw1) == 0 {
		return "", fmt.Errorf("passphrase must not be empty")
	}
	if !bytes.Equal(pw1, pw2) {
		return "", fmt.Errorf("passphrases do not match")
	}
	return string(pw1), nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func printSearchInfo(c MatchCriteria, threads int) {
	switch {
	case c.Prefix != "" && c.Suffix != "":
		fmt.Fprintf(os.Stderr, "Searching for address with prefix %q and suffix %q using %d threads...\n", c.Prefix, c.Suffix, threads)
	case c.Prefix != "":
		fmt.Fprintf(os.Stderr, "Searching for address with prefix %q using %d threads...\n", c.Prefix, threads)
	case c.Suffix != "":
		fmt.Fprintf(os.Stderr, "Searching for address with suffix %q using %d threads...\n", c.Suffix, threads)
	default:
		fmt.Fprintf(os.Stderr, "No prefix/suffix specified; generating a random account using %d threads...\n", threads)
	}

	if combined := len(c.Prefix) + len(c.Suffix); combined > 0 {
		expected := math.Pow(16, float64(combined))
		fmt.Fprintf(os.Stderr, "Expected search space: ~1 in %.0f addresses\n", expected)
	}
}

var spinnerFrames = []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}

// reportProgress redraws a single status line ~10x/sec: a spinner, the most
// recently generated (and almost certainly discarded) candidate address
// flickering by, and running attempt/rate stats. Once the hash rate has a
// first real reading, it also prints a one-time estimated-time-to-match
// range (not a countdown) derived from the search space size and that
// rate; combined is the total vanity byte length (0 to skip the estimate,
// e.g. a random account with no prefix/suffix).
func reportProgress(ctx context.Context, attempts *uint64, feed *LiveFeed, combined int) {
	const frameInterval = 100 * time.Millisecond
	ticker := time.NewTicker(frameInterval)
	defer ticker.Stop()

	start := time.Now()
	rateWindowStart := start
	var rateWindowAttempts uint64
	var rate float64
	estimatePrinted := combined == 0

	for frame := 0; ; frame++ {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			total := atomic.LoadUint64(attempts)
			if elapsed := now.Sub(rateWindowStart); elapsed >= time.Second {
				rate = float64(total-rateWindowAttempts) / elapsed.Seconds()
				rateWindowAttempts = total
				rateWindowStart = now

				if !estimatePrinted && rate > 0 {
					fmt.Fprintf(os.Stderr, "\r\x1b[K%s\n", estimateTimeToMatch(combined, rate))
					estimatePrinted = true
				}
			}

			addr := feed.Sample(frame)
			if addr == "" {
				addr = strings.Repeat("·", 40)
			}
			spin := spinnerFrames[frame%len(spinnerFrames)]
			elapsed := now.Sub(start).Round(time.Second)

			fmt.Fprintf(os.Stderr, "\r\x1b[K%c 0x%s   %s tried   %s/s   %s",
				spin, addr, commify(total), commify(uint64(rate)), elapsed)
		}
	}
}

// estimateTimeToMatch computes the mean and a one-standard-deviation range
// for how long finding a match should take, given the search space size
// (16^combined candidates, each an independent 1-in-N chance) and the
// current hash rate. Match count follows a geometric distribution, whose
// standard deviation is very close to its own mean whenever the match
// probability is small (as it always is here) -- so this range is
// naturally wide, and its low end is naturally close to "could happen
// immediately". That's an inherent property of these odds, not an
// approximation error.
func estimateTimeToMatch(combined int, rate float64) string {
	p := 1 / math.Pow(16, float64(combined))
	mean := 1 / p
	stddev := math.Sqrt((1 - p) / (p * p))

	lowAttempts := mean - stddev
	if lowAttempts < 0 {
		lowAttempts = 0
	}
	highAttempts := mean + stddev

	rangeStr, meanStr := formatDurationTriple(lowAttempts/rate, mean/rate, highAttempts/rate)
	return fmt.Sprintf("Est. time to match (1σ range): %s (mean: %s)", rangeStr, meanStr)
}

// formatDurationTriple formats three second counts (a low/high range plus
// the mean) sharing a single human-scaled unit chosen from the largest
// (high) value, e.g. ("6.2-12.4h", "9.3h").
func formatDurationTriple(lowSeconds, meanSeconds, highSeconds float64) (rangeStr, meanStr string) {
	units := []struct {
		secs  float64
		label string
	}{
		{1, "s"},
		{60, "m"},
		{3600, "h"},
		{86400, "d"},
		{86400 * 365.25, "y"},
	}
	unit := units[0]
	for _, u := range units {
		if highSeconds >= u.secs {
			unit = u
		}
	}

	rangeStr = fmt.Sprintf("%s-%s%s", formatNum(lowSeconds/unit.secs), formatNum(highSeconds/unit.secs), unit.label)
	meanStr = fmt.Sprintf("%s%s", formatNum(meanSeconds/unit.secs), unit.label)
	return rangeStr, meanStr
}

func formatNum(v float64) string {
	if v >= 10 {
		return fmt.Sprintf("%.0f", v)
	}
	s := fmt.Sprintf("%.1f", v)
	s = strings.TrimSuffix(s, "0")
	s = strings.TrimSuffix(s, ".")
	return s
}

// commify inserts thousands separators, e.g. 1234567 -> "1,234,567".
func commify(n uint64) string {
	s := strconv.FormatUint(n, 10)
	if len(s) <= 3 {
		return s
	}
	lead := len(s) % 3
	if lead == 0 {
		lead = 3
	}
	out := []byte(s[:lead])
	for i := lead; i < len(s); i += 3 {
		out = append(out, ',')
		out = append(out, s[i:i+3]...)
	}
	return string(out)
}

func usage() {
	fmt.Fprint(os.Stderr, `eth-vanity generates an Ethereum keypair whose public address matches a
given prefix and/or suffix, then saves it as an encrypted keystore file.

Usage:
  eth-vanity [flags]

Flags:
  -p, --prefix string    hex bytes required at the start of the address (no "0x" needed)
  -s, --suffix string    hex bytes required at the end of the address
  -o, --output string    directory to save the encrypted keystore file (default ".")
  -t, --threads int      number of concurrent goroutines searching for a match (default: number of CPUs)
  -e, --extra-entropy    mix in additional randomness from random.org (see Notes)
  -h, --help              show this help message

Notes:
  - --prefix and --suffix accept only hex characters (0-9, a-f, A-F) and are matched
    case-insensitively. Each extra hex character makes a match ~16x rarer, so long
    values can take a long time to find.
  - If neither --prefix nor --suffix is given, a random account is generated immediately.
  - Once a matching address is found, you'll be prompted (with confirmation) for a
    passphrase to encrypt the keystore — there's no flag for this, so it never ends up
    in shell history or process listings.
  - This is CPU-bound work; going far past --threads = number of CPUs usually doesn't
    help and can even slow things down. Benchmark a few values around your core count
    if you want to squeeze out more throughput.
  - --extra-entropy fetches randomness from random.org and mixes it (via Keccak256)
    into each thread's local OS randomness before deriving its starting key — it
    supplements local randomness, never replaces it, so a doctored or unreachable
    random.org can only fail to help, never make key generation weaker. Fetch
    failures fall back to OS randomness only, with a warning. Set RANDOM_ORG_API_KEY
    in the environment to use random.org's authenticated API (separate quota from
    the free endpoint); otherwise the free, unauthenticated legacy endpoint is used.

Examples:
  eth-vanity --prefix 0000 --suffix 666
  eth-vanity -p dead -o ./keys
  eth-vanity -p cafe --extra-entropy

Subcommands:
  create2   mine a salt for a vanity CREATE2 contract address instead of a
            wallet (see 'eth-vanity create2 --help')
`)
}
