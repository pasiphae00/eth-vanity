//! Encrypted V3 keystore output, matching go-ethereum's format and KDF
//! strength exactly (scrypt N=2^18, same as go-ethereum's StandardScryptN)
//! so keystores from either tool are equally hard to brute-force.
//!
//! `eth-keystore` (the standard crate for this) hardcodes a much weaker
//! N=2^13, with no way to override it, so this reimplements `encrypt_key`
//! directly against the same primitives, reusing eth-keystore's public
//! JSON schema types for on-disk compatibility.

use aes::cipher::{KeyIvInit, StreamCipher};
use eth_keystore::{CipherparamsJson, CryptoJson, EthKeystore, KdfType, KdfparamsType};
use keccak_asm::{Digest, Keccak256};
use rand::TryRng;
use rand::rngs::SysRng;
use std::io::Write;
use std::path::Path;
use zeroize::Zeroizing;

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

/// log2(N) for scrypt, matching go-ethereum's StandardScryptN = 2^18 = 262144.
const SCRYPT_LOG_N: u8 = 18;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const KEY_LEN: usize = 32;

/// Encrypts `private_key` with `passphrase` and writes it to `dir` as a
/// geth-compatible UTC--<timestamp>--<address> keystore file. Returns the
/// path written.
pub fn save(
    dir: &Path,
    address: &[u8; 20],
    private_key: &[u8; 32],
    passphrase: &[u8],
) -> anyhow::Result<std::path::PathBuf> {
    let mut salt = [0u8; KEY_LEN];
    SysRng.try_fill_bytes(&mut salt).expect("OS RNG failed");

    let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P)?;
    let mut derived_key = Zeroizing::new([0u8; KEY_LEN]);
    scrypt::scrypt(passphrase, &salt, &params, derived_key.as_mut_slice())?;

    let mut iv = [0u8; 16];
    SysRng.try_fill_bytes(&mut iv).expect("OS RNG failed");

    let mut ciphertext = private_key.to_vec();
    let mut cipher = Aes128Ctr::new_from_slices(&derived_key[..16], &iv)
        .expect("key and IV lengths are fixed by their types");
    cipher.apply_keystream(&mut ciphertext);

    let mut mac_hasher = Keccak256::new();
    mac_hasher.update(&derived_key[16..32]);
    mac_hasher.update(&ciphertext);
    let mac = mac_hasher.finalize().to_vec();

    let id = uuid::Uuid::new_v4();
    let keystore = EthKeystore {
        crypto: CryptoJson {
            cipher: "aes-128-ctr".to_string(),
            cipherparams: CipherparamsJson { iv: iv.to_vec() },
            ciphertext,
            kdf: KdfType::Scrypt,
            kdfparams: KdfparamsType::Scrypt {
                dklen: KEY_LEN as u8,
                n: 1u32 << SCRYPT_LOG_N,
                p: SCRYPT_P,
                r: SCRYPT_R,
                salt: salt.to_vec(),
            },
            mac,
        },
        id,
        version: 3,
    };

    let contents = serde_json::to_string(&keystore)?;

    let timestamp = time_utc_filename_stamp();
    let filename = format!("UTC--{timestamp}--{}", hex::encode(address));
    let path = dir.join(&filename);
    create_private_dir(dir)?;
    write_private_file(&path, contents.as_bytes())?;

    Ok(path)
}

/// Creates `dir` and any missing parents, owner-only on Unix like geth's
/// keystore directory. Directories that already exist are left as they are.
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Writes a new file that only the owner can read on Unix, setting the mode
/// at creation so there's no window where it's readable by others. Refuses
/// to overwrite an existing file: that could destroy a key.
fn write_private_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(contents)
}

/// Formats the current UTC time to match geth's keystore filename
/// convention: e.g. "2026-07-21T15-02-02.783342000Z".
fn time_utc_filename_stamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let secs = now.as_secs();
    let nanos = now.subsec_nanos();

    let days = secs / 86_400;
    let secs_of_day = secs % 86_400;
    let (year, month, day) = civil_from_days(days as i64);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    format!("{year:04}-{month:02}-{day:02}T{hour:02}-{minute:02}-{second:02}.{nanos:09}Z")
}

/// Converts a day count since the Unix epoch to a (year, month, day) civil
/// date, using Howard Hinnant's well-known algorithm for the proleptic
/// Gregorian calendar.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Prompts for a passphrase twice (without echoing input) and confirms both
/// entries match. Buffers are wiped on drop, on every exit path.
pub fn read_passphrase() -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let pw1 = Zeroizing::new(
        rpassword::prompt_password("Enter a passphrase to encrypt the wallet: ")?.into_bytes(),
    );
    let pw2 = Zeroizing::new(rpassword::prompt_password("Confirm passphrase: ")?.into_bytes());

    if pw1.is_empty() {
        anyhow::bail!("passphrase must not be empty");
    }
    if *pw1 != *pw2 {
        anyhow::bail!("passphrases do not match");
    }
    Ok(pw1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_from_days_matches_known_dates() {
        // 1970-01-01 is day 0 by definition of the Unix epoch.
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2000-03-01 is a well-known fixed point used to sanity-check these
        // algorithms (start of a 400-year cycle boundary region).
        assert_eq!(civil_from_days(10_957), (2000, 1, 1));
        // 2024 is a leap year; day 29 of Feb should round-trip correctly.
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        assert_eq!(civil_from_days(19_783), (2024, 3, 1));
    }

    #[test]
    fn save_produces_a_keystore_eth_keystore_can_decrypt() {
        let dir = std::env::temp_dir().join(format!("eth-vanity-rs-test-{}", uuid::Uuid::new_v4()));
        let address = [0x11u8; 20];
        let private_key = [0x42u8; 32];
        let passphrase = b"correct horse battery staple";

        let path = save(&dir, &address, &private_key, passphrase).expect("save should succeed");

        let decrypted = eth_keystore::decrypt_key(&path, passphrase)
            .expect("eth-keystore should decrypt what we wrote");
        assert_eq!(decrypted, private_key.to_vec());

        // Wrong passphrase must not decrypt (MAC check should fail).
        assert!(eth_keystore::decrypt_key(&path, b"wrong passphrase").is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn save_restricts_keystore_and_new_dir_to_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("eth-vanity-rs-test-{}", uuid::Uuid::new_v4()));
        let path = save(&dir, &[0x11u8; 20], &[0x42u8; 32], b"passphrase").expect("save");

        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600, "keystore file mode");
        assert_eq!(mode(&dir), 0o700, "keystore dir mode");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_private_file_refuses_to_overwrite() {
        let dir = std::env::temp_dir().join(format!("eth-vanity-rs-test-{}", uuid::Uuid::new_v4()));
        create_private_dir(&dir).expect("create dir");
        let path = dir.join("key");

        write_private_file(&path, b"original").expect("first write");
        assert!(write_private_file(&path, b"replacement").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"original");

        std::fs::remove_dir_all(&dir).ok();
    }
}
