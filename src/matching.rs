//! Vanity-byte matching shared by wallet and create2 search.

/// Matches any character in a mask.
const WILDCARD: u8 = b'.';

/// Patterns an address must satisfy, as lowercase hex masks matched against
/// the lowercase hex encoding of the address. An address matches if it fits
/// any prefix (when there are prefixes) and any suffix (when there are
/// suffixes).
#[derive(Clone, Debug, Default)]
pub struct MatchCriteria {
    pub prefixes: Vec<Vec<u8>>,
    pub suffixes: Vec<Vec<u8>>,
}

impl MatchCriteria {
    #[inline]
    pub fn matches(&self, addr_hex: &[u8]) -> bool {
        (self.prefixes.is_empty()
            || self
                .prefixes
                .iter()
                .any(|mask| mask_matches(mask, addr_hex)))
            && (self.suffixes.is_empty()
                || self
                    .suffixes
                    .iter()
                    .any(|mask| mask_matches(mask, &addr_hex[addr_hex.len() - mask.len()..])))
    }

    /// Mean candidates per match. Treats patterns as disjoint, so patterns
    /// that overlap (like `de` and `dead`) make this a slight underestimate.
    pub fn expected_attempts(&self) -> f64 {
        1.0 / (any_of_probability(&self.prefixes) * any_of_probability(&self.suffixes))
    }

    pub fn is_empty(&self) -> bool {
        self.prefixes.is_empty() && self.suffixes.is_empty()
    }
}

/// Compares a mask against the start of hex. Most candidates fail on the
/// first digit, so this exits on the first mismatch.
#[inline]
fn mask_matches(mask: &[u8], hex: &[u8]) -> bool {
    mask.iter().zip(hex).all(|(&m, &h)| m == h || m == WILDCARD)
}

fn any_of_probability(masks: &[Vec<u8>]) -> f64 {
    if masks.is_empty() {
        return 1.0;
    }
    let total: f64 = masks
        .iter()
        .map(|mask| 16f64.powi(-fixed_digits(mask)))
        .sum();
    total.min(1.0)
}

fn fixed_digits(mask: &[u8]) -> i32 {
    mask.iter().filter(|&&b| b != WILDCARD).count() as i32
}

/// Lowercases s and strips an optional "0x"/"0X" prefix.
pub fn normalize_hex(s: &str) -> String {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    s.to_ascii_lowercase()
}

/// Normalizes and validates --prefix/--suffix masks against the shape of a
/// 20-byte Ethereum address. Shared by every search mode. Empty masks count
/// as not given.
pub fn parse_criteria(prefixes: &[String], suffixes: &[String]) -> anyhow::Result<MatchCriteria> {
    let prefixes = parse_masks("--prefix", prefixes)?;
    let suffixes = parse_masks("--suffix", suffixes)?;

    let longest = |masks: &[Vec<u8>]| masks.iter().map(Vec::len).max().unwrap_or(0);
    let combined = longest(&prefixes) + longest(&suffixes);
    if combined > 40 {
        anyhow::bail!(
            "combined --prefix and --suffix length ({combined}) exceeds address length (40 hex chars)"
        );
    }
    Ok(MatchCriteria { prefixes, suffixes })
}

fn parse_masks(flag: &str, raw: &[String]) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut masks = Vec::new();
    for mask_raw in raw {
        let mask = normalize_hex(mask_raw);
        if mask.is_empty() {
            continue;
        }
        if !mask.bytes().all(|b| b == WILDCARD || b.is_ascii_hexdigit()) {
            anyhow::bail!(
                "{flag} {mask_raw:?} is not a valid mask (allowed characters: 0-9, a-f, A-F, and . as a wildcard)"
            );
        }
        // One of these would match every address, silently making any other
        // pattern pointless.
        if fixed_digits(mask.as_bytes()) == 0 {
            anyhow::bail!("{flag} {mask_raw:?} has no hex digits, so it would match anything");
        }
        masks.push(mask.into_bytes());
    }
    Ok(masks)
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

    fn strings(masks: &[&str]) -> Vec<String> {
        masks.iter().map(|m| m.to_string()).collect()
    }

    fn criteria(prefixes: &[&str], suffixes: &[&str]) -> MatchCriteria {
        parse_criteria(&strings(prefixes), &strings(suffixes)).unwrap()
    }

    #[test]
    fn matches_prefix_suffix() {
        let addr = b"abcdef0000000000000000000000000000000000";
        let cases: &[(&str, &str, bool)] = &[
            ("ab", "", true),
            ("cd", "", false),
            ("", "ef", false),
            ("", "00", true),
            ("ab", "00", true),
            ("ab", "99", false),
            ("", "", true),
        ];
        for (prefix, suffix, want) in cases {
            assert_eq!(
                criteria(&[prefix], &[suffix]).matches(addr),
                *want,
                "prefix={prefix:?} suffix={suffix:?}"
            );
        }
    }

    #[test]
    fn matches_wildcards() {
        let addr = b"abcdef0000000000000000000000000000001234";
        let cases: &[(&str, &str, bool)] = &[
            ("..cd", "", true),
            ("..ce", "", false),
            ("a.c", "", true),
            ("b.c", "", false),
            ("", "12..", true),
            ("", "13..", false),
            ("", "1.3.", true),
            // Anchored at each end, not floating.
            ("", "12.", false),
            (".bcdef", "..34", true),
        ];
        for (prefix, suffix, want) in cases {
            assert_eq!(
                criteria(&[prefix], &[suffix]).matches(addr),
                *want,
                "prefix={prefix:?} suffix={suffix:?}"
            );
        }
    }

    #[test]
    fn matches_any_of_several_patterns() {
        let addr = b"abcdef0000000000000000000000000000001234";

        assert!(criteria(&["ff", "ab"], &[]).matches(addr));
        assert!(!criteria(&["ff", "ee"], &[]).matches(addr));
        assert!(criteria(&[], &["ff", "34"]).matches(addr));

        // Any prefix and any suffix, not any pattern at all.
        assert!(criteria(&["ff", "ab"], &["ff", "34"]).matches(addr));
        assert!(!criteria(&["ff", "ab"], &["ff"]).matches(addr));
        assert!(!criteria(&["ff"], &["ff", "34"]).matches(addr));
    }

    #[test]
    fn expected_attempts_counts_fixed_digits_and_alternatives() {
        let close = |c: MatchCriteria, want: f64| {
            let got = c.expected_attempts();
            assert!((got - want).abs() < 1e-6, "got {got}, want {want}");
        };
        close(criteria(&[], &[]), 1.0);
        close(criteria(&["dead"], &[]), 65536.0);
        close(criteria(&["de"], &["ad"]), 65536.0);
        // Wildcards don't count.
        close(criteria(&["..ad"], &[]), 256.0);
        // Two four-digit alternatives are twice as likely.
        close(criteria(&["dead", "beef"], &[]), 32768.0);
        // Alternatives on each side multiply.
        close(criteria(&["a", "b"], &["c", "d"]), 64.0);
        // Never below one attempt.
        let every_digit = strings(&[
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f", "0",
        ]);
        close(parse_criteria(&every_digit, &[]).unwrap(), 1.0);
    }

    #[test]
    fn parse_criteria_rejects_bad_input() {
        let parse = |p: &[&str], s: &[&str]| parse_criteria(&strings(p), &strings(s));

        assert!(parse(&["zz"], &[]).is_err());
        assert!(parse(&[], &["zz"]).is_err());
        assert!(parse(&["ab", "zz"], &[]).is_err());
        assert!(parse(&[&"0".repeat(41)], &[]).is_err());
        assert!(parse(&["0x00"], &["0X ff"]).is_err()); // space isn't hex
        // x is not a wildcard: "0x12" would read as a 0x prefix.
        assert!(parse(&["xxcafe"], &[]).is_err());
        assert!(parse(&["...."], &[]).is_err());
        assert!(parse(&["dead", ".."], &[]).is_err());
        // Length is judged per pattern pair, by the longest of each.
        assert!(parse(&[&"0".repeat(20), "a"], &[&"1".repeat(21)]).is_err());
        assert!(parse(&[&"0".repeat(20), "a"], &[&"1".repeat(20)]).is_ok());

        let c = parse(&["0xAB.D"], &["00"]).unwrap();
        assert_eq!(c.prefixes, vec![b"ab.d".to_vec()]);
        assert_eq!(c.suffixes, vec![b"00".to_vec()]);
    }
}
