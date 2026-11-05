//! eth-vanity-rs: a Rust reimplementation of eth-vanity (the Go tool it's
//! meant to be benchmarked against), generating an Ethereum keypair whose
//! public address matches a vanity prefix/suffix, or (via the `create2`
//! subcommand) mining a CREATE2 salt for a vanity contract address.

mod create2;
mod entropy;
mod keystore;
mod matching;
mod progress;
mod search;

use clap::{Parser, Subcommand};
use matching::{MatchCriteria, hex_decode_flexible, parse_hex_fixed, validate_vanity_bytes};
use progress::LiveFeed;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Parser)]
#[command(
    name = "eth-vanity-rs",
    about = "Generates an Ethereum keypair whose public address matches a given prefix and/or suffix, then saves it as an encrypted keystore file.",
    after_help = "Notes:\n  - --prefix and --suffix accept only hex characters (0-9, a-f, A-F) and are matched\n    case-insensitively. Each extra hex character makes a match ~16x rarer, so long\n    values can take a long time to find.\n  - If neither --prefix nor --suffix is given, a random account is generated immediately.\n  - Once a matching address is found, you'll be prompted (with confirmation) for a\n    passphrase (at least 12 characters) to encrypt the keystore -- there's no flag for this, so it never ends up\n    in shell history or process listings.\n  - This is CPU-bound work; going far past --threads = number of CPUs usually doesn't\n    help and can even slow things down.\n\nSubcommands:\n  create2   mine a salt for a vanity CREATE2 contract address instead of a wallet\n  seed, offset, combine\n            search without the private key on the searching machine (split-key flow)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Hex bytes required at the start of the address (no "0x" needed)
    #[arg(short = 'p', long, default_value = "")]
    prefix: String,

    /// Hex bytes required at the end of the address
    #[arg(short = 's', long, default_value = "")]
    suffix: String,

    /// Directory to save the encrypted keystore file
    #[arg(short = 'o', long, default_value = ".")]
    output: String,

    /// Number of concurrent threads searching for a match (default: number of CPUs)
    #[arg(short = 't', long)]
    threads: Option<usize>,

    /// Mix in additional randomness from random.org (supplements, never replaces,
    /// local OS randomness). Set RANDOM_ORG_API_KEY in the environment to use
    /// random.org's authenticated API instead of the free legacy endpoint.
    #[arg(short = 'e', long)]
    extra_entropy: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Mine a salt so a CREATE2 deployment lands on a vanity contract address
    Create2 {
        /// Address of the CREATE2 deployer/factory contract
        #[arg(short = 'd', long)]
        deployer: String,

        /// Keccak256 hash of the contract init code, 32 bytes hex
        #[arg(short = 'i', long = "init-code-hash")]
        init_code_hash: Option<String>,

        /// Full init code (creation bytecode + constructor args), hex; hashed for you
        #[arg(short = 'c', long = "init-code")]
        init_code: Option<String>,

        /// Hex bytes required at the start of the resulting contract address
        #[arg(short = 'p', long, default_value = "")]
        prefix: String,

        /// Hex bytes required at the end of the resulting contract address
        #[arg(short = 's', long, default_value = "")]
        suffix: String,

        /// Number of concurrent threads searching for a match (default: number of CPUs)
        #[arg(short = 't', long)]
        threads: Option<usize>,

        /// Optional path to save the result as JSON
        #[arg(short = 'o', long)]
        output: Option<String>,
    },

    /// Split-key step 1, on a trusted machine: make a seed keypair to search from
    Seed {
        /// Directory to save the encrypted seed keystore file
        #[arg(short = 'o', long, default_value = ".")]
        output: String,
    },

    /// Split-key step 2, on any machine: search for an offset using only a public key
    Offset {
        /// The seed's public key, as printed by `seed`
        #[arg(short = 'k', long = "public-key")]
        public_key: String,

        /// Hex bytes required at the start of the address
        #[arg(short = 'p', long, default_value = "")]
        prefix: String,

        /// Hex bytes required at the end of the address
        #[arg(short = 's', long, default_value = "")]
        suffix: String,

        /// Number of concurrent threads searching for a match (default: number of CPUs)
        #[arg(short = 't', long)]
        threads: Option<usize>,
    },

    /// Split-key step 3, on the trusted machine: add the offset to the seed and save the key
    Combine {
        /// Path to the seed keystore file made by `seed`
        #[arg(long = "seed-keystore")]
        seed_keystore: String,

        /// The offset reported by `offset`
        #[arg(long)]
        offset: String,

        /// The address reported by `offset`; the result is checked against it
        #[arg(long)]
        address: String,

        /// Directory to save the final encrypted keystore file
        #[arg(short = 'o', long, default_value = ".")]
        output: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Create2 {
            deployer,
            init_code_hash,
            init_code,
            prefix,
            suffix,
            threads,
            output,
        }) => run_create2(
            deployer,
            init_code_hash,
            init_code,
            prefix,
            suffix,
            threads,
            output,
        ),
        Some(Commands::Seed { output }) => run_seed(output),
        Some(Commands::Offset {
            public_key,
            prefix,
            suffix,
            threads,
        }) => run_offset(public_key, prefix, suffix, threads),
        Some(Commands::Combine {
            seed_keystore,
            offset,
            address,
            output,
        }) => run_combine(seed_keystore, offset, address, output),
        None => run_wallet(
            cli.prefix,
            cli.suffix,
            cli.output,
            cli.threads,
            cli.extra_entropy,
        ),
    }
}

fn default_threads(threads: Option<usize>) -> usize {
    threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    })
}

fn install_ctrlc_handler(running: &Arc<AtomicBool>) {
    let running = running.clone();
    let _ = ctrlc::set_handler(move || {
        running.store(false, Ordering::Relaxed);
    });
}

fn run_wallet(
    prefix: String,
    suffix: String,
    output: String,
    threads: Option<usize>,
    extra_entropy: bool,
) -> anyhow::Result<()> {
    let (prefix, suffix) = validate_vanity_bytes(&prefix, &suffix)?;
    let threads = default_threads(threads);
    if threads < 1 {
        anyhow::bail!("--threads must be at least 1");
    }
    let output_path = output_dir(&output)?;

    let external_entropy = if extra_entropy {
        let source = if entropy::using_authenticated_api() {
            "authenticated API"
        } else {
            "free legacy endpoint"
        };
        eprintln!("Fetching additional entropy from random.org ({source})...");
        match entropy::fetch_external_entropy() {
            Ok(e) => {
                eprintln!("Mixing in additional entropy from random.org.");
                Some(e)
            }
            Err(e) => {
                eprintln!(
                    "Warning: could not fetch additional entropy ({e}); continuing with OS randomness only."
                );
                None
            }
        }
    } else {
        None
    };

    let criteria = MatchCriteria {
        prefix: prefix.into_bytes(),
        suffix: suffix.into_bytes(),
    };
    let (result, attempts) = run_search(&criteria, threads, external_entropy.as_ref(), None);
    search::verify(&result, None)?;

    println!(
        "Wallet found! Address: 0x{} ({attempts} attempts)",
        hex::encode(result.address),
    );

    let passphrase = keystore::read_passphrase()?;
    let path = keystore::save(
        &output_path,
        &result.address,
        &result.scalar,
        passphrase.as_bytes(),
    )?;
    println!("Keystore saved to: {}", path.display());
    Ok(())
}

/// Runs a wallet-style search with the live progress display, exiting the
/// process if it's interrupted. Returns the result and the attempt count.
fn run_search(
    criteria: &MatchCriteria,
    threads: usize,
    external_entropy: Option<&[u8; entropy::EXTERNAL_ENTROPY_BYTES]>,
    base: Option<&k256::ProjectivePoint>,
) -> (search::SearchResult, u64) {
    print_search_info(criteria, threads);

    let running = Arc::new(AtomicBool::new(true));
    install_ctrlc_handler(&running);

    let attempts = AtomicU64::new(0);
    let feed = LiveFeed::new(threads);

    let combined = criteria.prefix.len() + criteria.suffix.len();
    let progress_running = Arc::new(AtomicBool::new(true));
    let attempts_ref = &attempts;
    let feed_ref = &feed;
    let result = std::thread::scope(|scope| {
        let pr = progress_running.clone();
        scope.spawn(move || progress::report_progress(attempts_ref, feed_ref, &pr, combined));

        let result = search::search(
            criteria,
            threads,
            attempts_ref,
            Some(feed_ref),
            &running,
            external_entropy,
            base,
        );
        progress_running.store(false, Ordering::Relaxed);
        result
    });
    eprintln!();

    let Some(result) = result else {
        eprintln!("Interrupted: search cancelled");
        std::process::exit(1);
    };
    (result, attempts.load(Ordering::Relaxed))
}

fn output_dir(output: &str) -> anyhow::Result<PathBuf> {
    let path = PathBuf::from(output);
    if path.exists() && !path.is_dir() {
        anyhow::bail!("--output {output:?} exists and is not a directory");
    }
    keystore::check_output_dir(&path)?;
    Ok(path)
}

/// Step 1 of a split-key search, on a trusted machine.
fn run_seed(output: String) -> anyhow::Result<()> {
    let output_path = output_dir(&output)?;

    let seed = search::generate_key();
    let address = search::address_of_key(&seed)?;
    let public_key = search::public_key_hex(&seed)?;

    let passphrase = keystore::read_passphrase()?;
    let path = keystore::save(&output_path, &address, &seed, passphrase.as_bytes())?;

    println!("Seed keystore saved to: {}", path.display());
    println!("Public key: {public_key}");
    println!("Pass this to `eth-vanity offset --public-key`; it's safe to share.");
    println!("Use one seed per vanity address, and don't fund the seed's own address.");
    Ok(())
}

/// Step 2 of a split-key search. Holds no private key, so this can run on
/// a machine that isn't trusted.
fn run_offset(
    public_key: String,
    prefix: String,
    suffix: String,
    threads: Option<usize>,
) -> anyhow::Result<()> {
    let base = search::parse_public_key(&public_key)?;
    let (prefix, suffix) = validate_vanity_bytes(&prefix, &suffix)?;
    let threads = default_threads(threads);
    if threads < 1 {
        anyhow::bail!("--threads must be at least 1");
    }

    let criteria = MatchCriteria {
        prefix: prefix.into_bytes(),
        suffix: suffix.into_bytes(),
    };
    let (result, attempts) = run_search(&criteria, threads, None, Some(&base));
    search::verify(&result, Some(&base))?;

    let address = hex::encode(result.address);
    let offset = hex::encode(**result.scalar);
    println!("Offset found! Address: 0x{address} ({attempts} attempts)");
    println!("Offset: 0x{offset}");
    println!("Then, where the seed keystore is:");
    println!(
        "  eth-vanity combine --seed-keystore <FILE> --offset 0x{offset} --address 0x{address}"
    );
    Ok(())
}

/// Step 3 of a split-key search, back on the trusted machine.
fn run_combine(
    seed_keystore: String,
    offset: String,
    address: String,
    output: String,
) -> anyhow::Result<()> {
    let offset: [u8; 32] = parse_hex_fixed(&offset, 32)?
        .try_into()
        .expect("parse_hex_fixed returns exactly 32 bytes");
    let address: [u8; 20] = parse_hex_fixed(&address, 20)?
        .try_into()
        .expect("parse_hex_fixed returns exactly 20 bytes");
    let output_path = output_dir(&output)?;

    let seed_passphrase = keystore::read_existing_passphrase("Seed keystore passphrase: ")?;
    let seed = keystore::load(seed_keystore.as_ref(), seed_passphrase.as_bytes())?;

    let key = search::combine(&seed, &offset)?;
    let derived = search::address_of_key(&key)?;
    if derived != address {
        anyhow::bail!(
            "seed + offset gives 0x{}, not 0x{}: this seed or offset doesn't belong to that address. Nothing was saved.",
            hex::encode(derived),
            hex::encode(address)
        );
    }
    println!("Verified: this key controls 0x{}", hex::encode(address));

    let passphrase = keystore::read_passphrase()?;
    let path = keystore::save(&output_path, &address, &key, passphrase.as_bytes())?;
    println!("Keystore saved to: {}", path.display());
    Ok(())
}

fn run_create2(
    deployer: String,
    init_code_hash_flag: Option<String>,
    init_code_flag: Option<String>,
    prefix: String,
    suffix: String,
    threads: Option<usize>,
    output: Option<String>,
) -> anyhow::Result<()> {
    let deployer_bytes = parse_hex_fixed(&deployer, 20)?;
    let mut deployer_arr = [0u8; 20];
    deployer_arr.copy_from_slice(&deployer_bytes);

    let init_code_hash = match (init_code_hash_flag, init_code_flag) {
        (Some(_), Some(_)) => {
            anyhow::bail!("specify only one of --init-code-hash or --init-code, not both")
        }
        (Some(h), None) => {
            let b = parse_hex_fixed(&h, 32)?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        (None, Some(c)) => {
            let code = hex_decode_flexible(&c)?;
            use keccak_asm::Digest;
            let mut hasher = keccak_asm::Keccak256::new();
            hasher.update(&code);
            let hash = hasher.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash);
            arr
        }
        (None, None) => anyhow::bail!("one of --init-code-hash or --init-code is required"),
    };

    let (prefix, suffix) = validate_vanity_bytes(&prefix, &suffix)?;
    let threads = default_threads(threads);
    if threads < 1 {
        anyhow::bail!("--threads must be at least 1");
    }

    let criteria = MatchCriteria {
        prefix: prefix.into_bytes(),
        suffix: suffix.into_bytes(),
    };
    print_search_info(&criteria, threads);

    let running = Arc::new(AtomicBool::new(true));
    install_ctrlc_handler(&running);

    let attempts = AtomicU64::new(0);
    let feed = LiveFeed::new(threads);

    let combined = criteria.prefix.len() + criteria.suffix.len();
    let progress_running = Arc::new(AtomicBool::new(true));
    let attempts_ref = &attempts;
    let feed_ref = &feed;
    let result = std::thread::scope(|scope| {
        let pr = progress_running.clone();
        scope.spawn(move || progress::report_progress(attempts_ref, feed_ref, &pr, combined));

        let result = create2::search(
            &deployer_arr,
            &init_code_hash,
            &criteria,
            threads,
            attempts_ref,
            Some(feed_ref),
            &running,
        );
        progress_running.store(false, Ordering::Relaxed);
        result
    });
    eprintln!();

    let Some(result) = result else {
        eprintln!("Interrupted: search cancelled");
        std::process::exit(1);
    };

    println!(
        "Salt found! Address: 0x{} ({} attempts)",
        hex::encode(result.address),
        attempts.load(Ordering::Relaxed)
    );
    println!("Salt: 0x{}", hex::encode(result.salt));

    if let Some(output) = output {
        let out = serde_json::json!({
            "deployer": format!("0x{}", hex::encode(deployer_arr)),
            "initCodeHash": format!("0x{}", hex::encode(init_code_hash)),
            "salt": format!("0x{}", hex::encode(result.salt)),
            "address": format!("0x{}", hex::encode(result.address)),
        });
        std::fs::write(&output, serde_json::to_string_pretty(&out)? + "\n")?;
        println!("Result saved to: {output}");
    }

    Ok(())
}

fn print_search_info(c: &MatchCriteria, threads: usize) {
    let has_prefix = !c.prefix.is_empty();
    let has_suffix = !c.suffix.is_empty();
    match (has_prefix, has_suffix) {
        (true, true) => eprintln!(
            "Searching for address with prefix {:?} and suffix {:?} using {threads} threads...",
            String::from_utf8_lossy(&c.prefix),
            String::from_utf8_lossy(&c.suffix)
        ),
        (true, false) => eprintln!(
            "Searching for address with prefix {:?} using {threads} threads...",
            String::from_utf8_lossy(&c.prefix)
        ),
        (false, true) => eprintln!(
            "Searching for address with suffix {:?} using {threads} threads...",
            String::from_utf8_lossy(&c.suffix)
        ),
        (false, false) => eprintln!(
            "No prefix/suffix specified; generating a random account using {threads} threads..."
        ),
    }

    let combined = c.prefix.len() + c.suffix.len();
    if combined > 0 {
        let expected = 16f64.powi(combined as i32);
        eprintln!("Expected search space: ~1 in {expected:.0} addresses");
    }
}
