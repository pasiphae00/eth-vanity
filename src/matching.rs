//! Vanity-byte matching shared by wallet and create2 search.

/// Lowercase hex prefix/suffix an address must satisfy. Both are matched
/// case-insensitively against the lowercase hex encoding of the address.
#[derive(Clone, Debug, Default)]
pub struct MatchCriteria {
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
}

impl MatchCriteria {
    #[inline]
    pub fn matches(&self, addr_hex: &[u8]) -> bool {
        (self.prefix.is_empty() || addr_hex.starts_with(&self.prefix[..]))
            && (self.suffix.is_empty() || addr_hex.ends_with(&self.suffix[..]))
    }
}

/// Lowercases s and strips an optional "0x"/"0X" prefix.
pub fn normalize_hex(s: &str) -> String {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    s.to_ascii_lowercase()
}

pub fn is_hex(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Normalizes and validates a --prefix/--suffix pair against the shape of a
/// 20-byte Ethereum address. Shared by both the wallet and create2 modes.
pub fn validate_vanity_bytes(
    prefix_raw: &str,
    suffix_raw: &str,
) -> anyhow::Result<(String, String)> {
    let prefix = normalize_hex(prefix_raw);
    let suffix = normalize_hex(suffix_raw);

    if !is_hex(&prefix) {
        anyhow::bail!(
            "--prefix {prefix_raw:?} is not valid hex (allowed characters: 0-9, a-f, A-F)"
        );
    }
    if !is_hex(&suffix) {
        anyhow::bail!(
            "--suffix {suffix_raw:?} is not valid hex (allowed characters: 0-9, a-f, A-F)"
        );
    }
    if prefix.len() + suffix.len() > 40 {
        anyhow::bail!(
            "combined --prefix and --suffix length ({}) exceeds address length (40 hex chars)",
            prefix.len() + suffix.len()
        );
    }
    Ok((prefix, suffix))
}

/// Strips an optional "0x"/"0X" prefix from s and decodes it as exactly n
/// bytes of hex.
pub fn parse_hex_fixed(s: &str, n: usize) -> anyhow::Result<Vec<u8>> {
    let normalized = normalize_hex(s);
    if normalized.len() != n * 2 {
        anyhow::bail!(
            "expected {} hex characters, got {}",
            n * 2,
            normalized.len()
        );
    }
    Ok(hex::decode(&normalized)?)
}

/// Strips an optional "0x"/"0X" prefix from s and decodes the rest as hex,
/// whatever its length.
pub fn hex_decode_flexible(s: &str) -> anyhow::Result<Vec<u8>> {
    Ok(hex::decode(normalize_hex(s))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_prefix_suffix() {
        let addr = b"abcdef0000000000000000000000000000000000";
        let cases: &[(&[u8], &[u8], bool)] = &[
            (b"ab", b"", true),
            (b"cd", b"", false),
            (b"", b"ef", false),
            (b"", b"00", true),
            (b"ab", b"00", true),
            (b"ab", b"99", false),
            (b"", b"", true),
        ];
        for (prefix, suffix, want) in cases {
            let c = MatchCriteria {
                prefix: prefix.to_vec(),
                suffix: suffix.to_vec(),
            };
            assert_eq!(
                c.matches(addr),
                *want,
                "prefix={prefix:?} suffix={suffix:?}"
            );
        }
    }

    #[test]
    fn validate_vanity_bytes_rejects_bad_input() {
        assert!(validate_vanity_bytes("zz", "").is_err());
        assert!(validate_vanity_bytes("", "zz").is_err());
        assert!(validate_vanity_bytes(&"0".repeat(41), "").is_err());
        assert!(validate_vanity_bytes("0x00", "0X ff").is_err()); // space isn't hex
        let (p, s) = validate_vanity_bytes("0xABCD", "00").unwrap();
        assert_eq!(p, "abcd");
        assert_eq!(s, "00");
    }
}
