//! Optional external entropy from random.org, mixed with (never
//! substituted for) local OS randomness -- see search::mix_entropy.

use serde::Deserialize;
use std::time::Duration;

/// How many bytes we ask random.org for. This matches our 256-bit security
/// parameter; asking for more wouldn't add anything once it's hashed
/// together with local randomness, and it's considerate of random.org's
/// shared rate limit.
pub const EXTERNAL_ENTROPY_BYTES: usize = 32;

const RANDOM_ORG_TIMEOUT: Duration = Duration::from_secs(8);

/// Environment variable holding a random.org API key
/// (from https://api.random.org/api-keys), if the caller wants to use the
/// authenticated JSON-RPC API instead of the free, unauthenticated legacy
/// HTTP endpoint. Not a flag: an API key is a credential, and credentials
/// belong in the environment/secrets store, not shell history or process
/// listings.
pub const RANDOM_ORG_API_KEY_ENV: &str = "RANDOM_ORG_API_KEY";

/// Fetches EXTERNAL_ENTROPY_BYTES of randomness from random.org. This is
/// meant to be mixed with, never substituted for, local OS randomness --
/// so a doctored or unreachable random.org can only fail to help, never
/// weaken the result below local-only randomness.
///
/// If RANDOM_ORG_API_KEY is set, this uses random.org's authenticated
/// JSON-RPC API (generateBlobs), which has its own per-key quota separate
/// from the shared IP-based quota on the free endpoint. Otherwise it falls
/// back to the free, unauthenticated legacy HTTP endpoint.
pub fn fetch_external_entropy() -> anyhow::Result<[u8; EXTERNAL_ENTROPY_BYTES]> {
    match std::env::var(RANDOM_ORG_API_KEY_ENV) {
        Ok(key) if !key.trim().is_empty() => fetch_external_entropy_api(key.trim()),
        _ => fetch_external_entropy_legacy(),
    }
}

pub fn using_authenticated_api() -> bool {
    std::env::var(RANDOM_ORG_API_KEY_ENV)
        .map(|k| !k.trim().is_empty())
        .unwrap_or(false)
}

// --- Authenticated JSON-RPC API (https://api.random.org/json-rpc/4/invoke) ---

#[derive(serde::Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'a str,
    method: &'a str,
    params: RpcParams<'a>,
    id: u32,
}

#[derive(serde::Serialize)]
struct RpcParams<'a> {
    #[serde(rename = "apiKey")]
    api_key: &'a str,
    n: u32,
    size: u32,
}

#[derive(Deserialize)]
struct RpcResponse {
    result: Option<RpcResult>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcResult {
    random: RpcRandom,
}

#[derive(Deserialize)]
struct RpcRandom {
    data: Vec<String>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

fn fetch_external_entropy_api(api_key: &str) -> anyhow::Result<[u8; EXTERNAL_ENTROPY_BYTES]> {
    let req = RpcRequest {
        jsonrpc: "2.0",
        method: "generateBlobs",
        params: RpcParams {
            api_key,
            n: 1,
            size: (EXTERNAL_ENTROPY_BYTES * 8) as u32,
        },
        id: 1,
    };

    let config = ureq::Agent::config_builder()
        .timeout_global(Some(RANDOM_ORG_TIMEOUT))
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let body: String = agent
        .post("https://api.random.org/json-rpc/4/invoke")
        .send_json(&req)
        .map_err(|e| anyhow::anyhow!("requesting randomness from random.org API: {e}"))?
        .body_mut()
        .read_to_string()
        .map_err(|e| anyhow::anyhow!("reading random.org API response: {e}"))?;

    parse_api_response(&body)
}

fn parse_api_response(body: &str) -> anyhow::Result<[u8; EXTERNAL_ENTROPY_BYTES]> {
    let resp: RpcResponse = serde_json::from_str(body).map_err(|e| {
        anyhow::anyhow!(
            "parsing random.org API response: {e} (body: {:?})",
            truncate(body, 80)
        )
    })?;

    if let Some(err) = resp.error {
        anyhow::bail!("random.org API error {}: {}", err.code, err.message);
    }
    let Some(result) = resp.result else {
        anyhow::bail!(
            "unexpected random.org API response shape (body: {:?})",
            truncate(body, 80)
        );
    };
    let Some(blob) = result.random.data.first() else {
        anyhow::bail!(
            "random.org API response had no data (body: {:?})",
            truncate(body, 80)
        );
    };

    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(blob)
        .map_err(|e| anyhow::anyhow!("invalid base64 in random.org API response: {e}"))?;

    if decoded.len() != EXTERNAL_ENTROPY_BYTES {
        anyhow::bail!(
            "expected {EXTERNAL_ENTROPY_BYTES} bytes from random.org API, got {}",
            decoded.len()
        );
    }
    let mut out = [0u8; EXTERNAL_ENTROPY_BYTES];
    out.copy_from_slice(&decoded);
    Ok(out)
}

// --- Free, unauthenticated legacy HTTP endpoint ---

fn fetch_external_entropy_legacy() -> anyhow::Result<[u8; EXTERNAL_ENTROPY_BYTES]> {
    let url =
        format!("https://www.random.org/cgi-bin/randbyte?nbytes={EXTERNAL_ENTROPY_BYTES}&format=h");

    let config = ureq::Agent::config_builder()
        .timeout_global(Some(RANDOM_ORG_TIMEOUT))
        .build();
    let agent = ureq::Agent::new_with_config(config);
    let body: String = agent
        .get(&url)
        .call()
        .map_err(|e| anyhow::anyhow!("requesting randomness from random.org: {e}"))?
        .body_mut()
        .read_to_string()
        .map_err(|e| anyhow::anyhow!("reading random.org response: {e}"))?;

    parse_legacy_hex(&body)
}

/// Parses random.org's randbyte "format=h" response (whitespace-separated
/// hex byte pairs, wrapped across lines) into exactly EXTERNAL_ENTROPY_BYTES
/// of raw bytes.
fn parse_legacy_hex(body: &str) -> anyhow::Result<[u8; EXTERNAL_ENTROPY_BYTES]> {
    let compact: String = body.split_whitespace().collect();
    if compact.len() != EXTERNAL_ENTROPY_BYTES * 2 {
        anyhow::bail!(
            "expected {} hex characters, got {} (response: {:?})",
            EXTERNAL_ENTROPY_BYTES * 2,
            compact.len(),
            truncate(body, 80)
        );
    }
    let decoded =
        hex::decode(&compact).map_err(|e| anyhow::anyhow!("invalid hex in response: {e}"))?;
    let mut out = [0u8; EXTERNAL_ENTROPY_BYTES];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn truncate(s: &str, n: usize) -> String {
    match s.char_indices().nth(n) {
        Some((end, _)) => format!("{}...", &s[..end]),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_handles_multibyte_characters() {
        assert_eq!(truncate("short", 80), "short");
        assert_eq!(truncate("abcdef", 3), "abc...");
        // Byte 3 falls inside the second character.
        assert_eq!(truncate("éééé", 3), "ééé...");
    }

    #[test]
    fn parse_legacy_hex_valid_and_invalid() {
        let valid = "aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99\naa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99\n";
        let b = parse_legacy_hex(valid).expect("valid response should parse");
        assert_eq!(b.len(), EXTERNAL_ENTROPY_BYTES);
        assert_eq!(b[0], 0xaa);
        assert_eq!(b[1], 0xbb);

        for bad in ["", "not hex at all", "Error: quota exceeded", "aabb"] {
            assert!(
                parse_legacy_hex(bad).is_err(),
                "expected error parsing {bad:?}"
            );
        }
    }

    #[test]
    fn parse_api_response_valid_and_invalid() {
        use base64::Engine;
        let raw = [0x42u8; EXTERNAL_ENTROPY_BYTES];
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw);

        let valid = format!(
            r#"{{"jsonrpc":"2.0","result":{{"random":{{"data":["{encoded}"],"completionTime":"2026-01-01 00:00:00Z"}},"bitsUsed":256,"bitsLeft":1,"requestsLeft":1,"advisoryDelay":0}},"id":1}}"#
        );
        let b = parse_api_response(&valid).expect("valid response should parse");
        assert_eq!(b, raw);

        let rpc_error =
            r#"{"jsonrpc":"2.0","error":{"code":401,"message":"Invalid API key"},"id":1}"#;
        assert!(parse_api_response(rpc_error).is_err());

        let short = base64::engine::general_purpose::STANDARD.encode(b"short");
        let cases = [
            "".to_string(),
            "not json".to_string(),
            r#"{"jsonrpc":"2.0","result":{"random":{"data":[]}},"id":1}"#.to_string(),
            r#"{"jsonrpc":"2.0","result":{"random":{"data":["not-base64!!"]}},"id":1}"#.to_string(),
            format!(r#"{{"jsonrpc":"2.0","result":{{"random":{{"data":["{short}"]}}}},"id":1}}"#),
        ];
        for c in cases {
            assert!(
                parse_api_response(&c).is_err(),
                "expected error parsing {c:?}"
            );
        }
    }
}
