//! eth-vanity-rs: a Rust reimplementation of eth-vanity (the Go tool it's
//! meant to be benchmarked against), generating an Ethereum keypair whose
//! public address matches a vanity prefix/suffix, or (via the `create2`
//! subcommand) mining a CREATE2 salt for a vanity contract address.

mod create2;
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
    after_help = "Notes:\n  - --prefix and --suffix accept only hex characters (0-9, a-f, A-F) and are matched\n    case-insensitively. Each extra hex character makes a match ~16x rarer, so long\n    values can take a long time to find.\n  - If neither --prefix nor --suffix is given, a random account is generated immediately.\n  - Once a matching address is found, you'll be prompted (with confirmation) for a\n    passphrase to encrypt the keystore -- there's no flag for this, so it never ends up\n    in shell history or process listings.\n  - This is CPU-bound work; going far past --threads = number of CPUs usually doesn't\n    help and can even slow things down.\n\nSubcommands:\n  create2   mine a salt for a vanity CREATE2 contract address instead of a wallet"
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
        None => run_wallet(cli.prefix, cli.suffix, cli.output, cli.threads),
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
) -> anyhow::Result<()> {
    let (prefix, suffix) = validate_vanity_bytes(&prefix, &suffix)?;
    let threads = default_threads(threads);
    if threads < 1 {
        anyhow::bail!("--threads must be at least 1");
    }
    let output_path = PathBuf::from(&output);
    if output_path.exists() && !output_path.is_dir() {
        anyhow::bail!("--output {output:?} exists and is not a directory");
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

        let result = search::search(&criteria, threads, attempts_ref, Some(feed_ref), &running);
        progress_running.store(false, Ordering::Relaxed);
        result
    });
    eprintln!();

    let Some(result) = result else {
        eprintln!("Interrupted: search cancelled");
        std::process::exit(1);
    };

    println!(
        "Wallet found! Address: 0x{} ({} attempts)",
        hex::encode(result.address),
        attempts.load(Ordering::Relaxed)
    );

    let mut passphrase = keystore::read_passphrase()?;
    let save_result = keystore::save(
        &output_path,
        &result.address,
        &result.private_key,
        &passphrase,
    );
    for b in passphrase.iter_mut() {
        *b = 0;
    }

    let path = save_result?;
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
