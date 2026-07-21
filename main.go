// Command eth-vanity generates an Ethereum keypair whose public address
// matches a user-specified prefix and/or suffix, then saves the result as
// an encrypted keystore file.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/term"
)

type config struct {
	Prefix  string
	Suffix  string
	Output  string
	Threads int
}

func main() {
	cfg := parseFlags()

	if err := validate(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		fmt.Fprintln(os.Stderr)
		flag.Usage()
		os.Exit(2)
	}

	criteria := MatchCriteria{Prefix: cfg.Prefix, Suffix: cfg.Suffix}
	printSearchInfo(criteria, cfg.Threads)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var attempts uint64
	progressCtx, stopProgress := context.WithCancel(ctx)
	go reportProgress(progressCtx, &attempts)

	result, err := Search(ctx, criteria, cfg.Threads, &attempts)
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
	flag.IntVar(&cfg.Threads, "threads", 50, "number of concurrent goroutines searching for a match")
	flag.IntVar(&cfg.Threads, "t", 50, "short for -threads")

	flag.Usage = usage
	flag.Parse()
	return cfg
}

func validate(cfg *config) error {
	prefix := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(cfg.Prefix, "0x"), "0X"))
	suffix := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(cfg.Suffix, "0x"), "0X"))

	if !isHex(prefix) {
		return fmt.Errorf("--prefix %q is not valid hex (allowed characters: 0-9, a-f, A-F)", cfg.Prefix)
	}
	if !isHex(suffix) {
		return fmt.Errorf("--suffix %q is not valid hex (allowed characters: 0-9, a-f, A-F)", cfg.Suffix)
	}
	if len(prefix)+len(suffix) > 40 {
		return fmt.Errorf("combined --prefix and --suffix length (%d) exceeds address length (40 hex chars)", len(prefix)+len(suffix))
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

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
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

func reportProgress(ctx context.Context, attempts *uint64) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	start := time.Now()
	var last uint64
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			total := atomic.LoadUint64(attempts)
			rate := total - last
			last = total
			elapsed := now.Sub(start).Round(time.Second)
			fmt.Fprintf(os.Stderr, "\rsearched %d addresses (%d/s, %s elapsed)   ", total, rate, elapsed)
		}
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `eth-vanity generates an Ethereum keypair whose public address matches a
given prefix and/or suffix, then saves it as an encrypted keystore file.

Usage:
  eth-vanity [flags]

Flags:
  -p, --prefix string   hex bytes required at the start of the address (no "0x" needed)
  -s, --suffix string   hex bytes required at the end of the address
  -o, --output string   directory to save the encrypted keystore file (default ".")
  -t, --threads int     number of concurrent goroutines searching for a match (default 50)
  -h, --help             show this help message

Notes:
  - --prefix and --suffix accept only hex characters (0-9, a-f, A-F) and are matched
    case-insensitively. Each extra hex character makes a match ~16x rarer, so long
    values can take a long time to find.
  - If neither --prefix nor --suffix is given, a random account is generated immediately.
  - Once a matching address is found, you'll be prompted (with confirmation) for a
    passphrase to encrypt the keystore — there's no flag for this, so it never ends up
    in shell history or process listings.

Examples:
  eth-vanity --prefix 0000 --suffix 666
  eth-vanity -p dead -o ./keys -t 100
`)
}
