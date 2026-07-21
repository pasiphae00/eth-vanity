package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sync/atomic"
	"syscall"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type create2Config struct {
	Deployer     string
	InitCodeHash string
	InitCode     string
	Prefix       string
	Suffix       string
	Output       string
	Threads      int
}

func runCreate2(args []string) {
	cfg := parseCreate2Flags(args)

	deployer, initCodeHash, criteria, err := validateCreate2(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		fmt.Fprintln(os.Stderr)
		create2Usage()
		os.Exit(2)
	}

	printSearchInfo(criteria, cfg.Threads)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var attempts uint64
	feed := NewLiveFeed(cfg.Threads)
	progressCtx, stopProgress := context.WithCancel(ctx)
	go reportProgress(progressCtx, &attempts, feed)

	result, err := SearchCreate2(ctx, deployer, initCodeHash, criteria, cfg.Threads, &attempts, feed)
	stopProgress()
	fmt.Fprintln(os.Stderr)

	if err != nil {
		fmt.Fprintln(os.Stderr, "Interrupted:", err)
		os.Exit(1)
	}

	fmt.Printf("Salt found! Address: %s (%d attempts)\n", result.Address.Hex(), atomic.LoadUint64(&attempts))
	fmt.Printf("Salt: 0x%x\n", result.Salt)

	if cfg.Output != "" {
		if err := saveCreate2Result(cfg.Output, deployer, initCodeHash, result); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
		fmt.Printf("Result saved to: %s\n", cfg.Output)
	}
}

func parseCreate2Flags(args []string) *create2Config {
	cfg := &create2Config{}
	fs := flag.NewFlagSet("eth-vanity create2", flag.ExitOnError)

	fs.StringVar(&cfg.Deployer, "deployer", "", "address of the CREATE2 deployer/factory contract")
	fs.StringVar(&cfg.Deployer, "d", "", "short for -deployer")
	fs.StringVar(&cfg.InitCodeHash, "init-code-hash", "", "keccak256 hash of the contract init code, 32 bytes hex")
	fs.StringVar(&cfg.InitCodeHash, "i", "", "short for -init-code-hash")
	fs.StringVar(&cfg.InitCode, "init-code", "", "full contract init code (creation bytecode + constructor args), hex-encoded")
	fs.StringVar(&cfg.InitCode, "c", "", "short for -init-code")
	fs.StringVar(&cfg.Prefix, "prefix", "", "hex bytes required at the start of the resulting contract address")
	fs.StringVar(&cfg.Prefix, "p", "", "short for -prefix")
	fs.StringVar(&cfg.Suffix, "suffix", "", "hex bytes required at the end of the resulting contract address")
	fs.StringVar(&cfg.Suffix, "s", "", "short for -suffix")
	fs.StringVar(&cfg.Output, "output", "", "optional path to save the result as JSON")
	fs.StringVar(&cfg.Output, "o", "", "short for -output")
	defaultThreads := runtime.NumCPU()
	fs.IntVar(&cfg.Threads, "threads", defaultThreads, "number of concurrent goroutines searching for a match")
	fs.IntVar(&cfg.Threads, "t", defaultThreads, "short for -threads")

	fs.Usage = create2Usage
	fs.Parse(args)
	return cfg
}

func validateCreate2(cfg *create2Config) (common.Address, [32]byte, MatchCriteria, error) {
	var deployer common.Address
	var initCodeHash [32]byte

	if cfg.Deployer == "" {
		return deployer, initCodeHash, MatchCriteria{}, fmt.Errorf("--deployer is required")
	}
	deployerBytes, err := parseHexFixed(cfg.Deployer, 20)
	if err != nil {
		return deployer, initCodeHash, MatchCriteria{}, fmt.Errorf("--deployer: %w", err)
	}
	copy(deployer[:], deployerBytes)

	haveHash := cfg.InitCodeHash != ""
	haveCode := cfg.InitCode != ""
	switch {
	case haveHash && haveCode:
		return deployer, initCodeHash, MatchCriteria{}, fmt.Errorf("specify only one of --init-code-hash or --init-code, not both")
	case haveHash:
		hashBytes, err := parseHexFixed(cfg.InitCodeHash, 32)
		if err != nil {
			return deployer, initCodeHash, MatchCriteria{}, fmt.Errorf("--init-code-hash: %w", err)
		}
		copy(initCodeHash[:], hashBytes)
	case haveCode:
		codeBytes, err := hexDecodeFlexible(cfg.InitCode)
		if err != nil {
			return deployer, initCodeHash, MatchCriteria{}, fmt.Errorf("--init-code: %w", err)
		}
		copy(initCodeHash[:], crypto.Keccak256(codeBytes))
	default:
		return deployer, initCodeHash, MatchCriteria{}, fmt.Errorf("one of --init-code-hash or --init-code is required")
	}

	prefix, suffix, err := validateVanityBytes(cfg.Prefix, cfg.Suffix)
	if err != nil {
		return deployer, initCodeHash, MatchCriteria{}, err
	}
	if cfg.Threads < 1 {
		return deployer, initCodeHash, MatchCriteria{}, fmt.Errorf("--threads must be at least 1, got %d", cfg.Threads)
	}

	return deployer, initCodeHash, MatchCriteria{Prefix: prefix, Suffix: suffix}, nil
}

type create2ResultFile struct {
	Deployer     string `json:"deployer"`
	InitCodeHash string `json:"initCodeHash"`
	Salt         string `json:"salt"`
	Address      string `json:"address"`
}

func saveCreate2Result(path string, deployer common.Address, initCodeHash [32]byte, result *Create2Result) error {
	out := create2ResultFile{
		Deployer:     deployer.Hex(),
		InitCodeHash: fmt.Sprintf("0x%x", initCodeHash),
		Salt:         fmt.Sprintf("0x%x", result.Salt),
		Address:      result.Address.Hex(),
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding result: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("saving result: %w", err)
	}
	return nil
}

func create2Usage() {
	fmt.Fprint(os.Stderr, `eth-vanity create2 mines a salt so that a CREATE2 deployment from the given
deployer/factory contract produces an address matching a prefix and/or
suffix (e.g. many leading zero bytes, a common gas-optimization target).

A salt is not secret — it has to be provided on-chain to deploy the
contract — so nothing here is encrypted; the result is just printed (and
optionally saved as plain JSON).

Usage:
  eth-vanity create2 --deployer 0x... (--init-code-hash 0x... | --init-code 0x...) [flags]

Flags:
  -d, --deployer string         address of the CREATE2 deployer/factory contract (required)
  -i, --init-code-hash string   keccak256 hash of the contract init code, 32 bytes hex
  -c, --init-code string        full init code (creation bytecode + constructor args), hex;
                                 hashed for you (specify exactly one of -i or -c)
  -p, --prefix string           hex bytes required at the start of the resulting address
  -s, --suffix string           hex bytes required at the end of the resulting address
  -t, --threads int             number of concurrent goroutines searching for a match
                                 (default: number of CPUs)
  -o, --output string           optional path to save the result as JSON
  -h, --help                    show this help message

Notes:
  - --prefix and --suffix accept only hex characters (0-9, a-f, A-F) and are matched
    case-insensitively against the resulting contract address, same as the wallet mode.
  - This is pure hashing (no elliptic-curve math), so it's dramatically faster than
    wallet-mode search — expect tens of millions of addresses per second on a modern
    multi-core machine.

Examples:
  eth-vanity create2 --deployer 0x4e59b44847b379578588920cA78FbF26c0B4956 \
    --init-code-hash 0x1234...abcd --prefix 0000000
  eth-vanity create2 -d 0x4e59b44847b379578588920cA78FbF26c0B4956 \
    -c 0x60806040... -p 00000 -o result.json
`)
}
