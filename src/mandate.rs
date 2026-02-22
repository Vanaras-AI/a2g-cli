//! Mandate — Canonical policy documents with ed25519 signing and TTL
//!
//! A Mandate is a TOML document that declares an agent's permissions.
//! It is signed by a sovereign authority and has a time-to-live (TTL).

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Information extracted from a verified mandate
pub struct MandateInfo {
    pub agent_did: String,
    pub agent_name: String,
    pub issuer: String,
    pub expires_at: String,
    pub ttl_remaining_sec: i64,
    pub tools: Vec<String>,
}

/// Parsed mandate structure (matches the TOML schema)
#[derive(Debug, Deserialize, Serialize)]
pub struct Mandate {
    pub mandate: MandateHeader,
    pub capabilities: Capabilities,
    pub boundaries: Boundaries,
    pub limits: Limits,
    #[serde(default)]
    pub output_governance: OutputGovernance,
    #[serde(default)]
    pub jurisdiction: MandateJurisdiction,
    #[serde(default)]
    pub escalation: EscalationRules,
    #[serde(default)]
    pub signature: Option<MandateSignature>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MandateHeader {
    pub version: String,
    pub agent_did: String,
    pub agent_name: String,
    #[serde(default)]
    pub issued_at: String,
    #[serde(default)]
    pub expires_at: String,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub proposal_hash: String,
    #[serde(default)]
    pub workspace_root: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Capabilities {
    pub tools: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Boundaries {
    #[serde(default)]
    pub fs_read: Vec<String>,
    #[serde(default)]
    pub fs_write: Vec<String>,
    #[serde(default)]
    pub fs_deny: Vec<String>,
    #[serde(default)]
    pub net_allow: Vec<String>,
    #[serde(default)]
    pub net_deny: Vec<String>,
    #[serde(default)]
    pub cmd_allow: Vec<String>,
    #[serde(default)]
    pub cmd_deny: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Limits {
    #[serde(default = "default_rate")]
    pub max_calls_per_minute: u64,
    #[serde(default = "default_file_size")]
    pub max_file_size_bytes: u64,
    #[serde(default = "default_tokens")]
    pub max_output_tokens: u64,
    #[serde(default = "default_session")]
    pub max_session_duration_sec: u64,
}

fn default_rate() -> u64 { 60 }
fn default_file_size() -> u64 { 10_485_760 }
fn default_tokens() -> u64 { 4096 }
fn default_session() -> u64 { 3600 }

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct OutputGovernance {
    #[serde(default)]
    pub deny_patterns: Vec<String>,
    #[serde(default)]
    pub redact_patterns: Vec<String>,
    #[serde(default = "default_output_len")]
    pub max_output_length: u64,
}

fn default_output_len() -> u64 { 50_000 }

/// Jurisdictional binding — where and when this mandate is valid
#[derive(Debug, Deserialize, Serialize, Default)]
pub struct MandateJurisdiction {
    /// Geographic region (e.g., "US", "CA", "EU")
    #[serde(default)]
    pub region: String,
    /// Regulatory framework (e.g., "GDPR", "SOC2", "PIPEDA")
    #[serde(default)]
    pub regulatory_framework: String,
    /// Environment constraint (e.g., "production", "staging", "development")
    #[serde(default)]
    pub environment: String,
    /// Classification level (e.g., "public", "internal", "confidential")
    #[serde(default)]
    pub classification: String,
    /// Operating hours in UTC (empty = 24/7, format: "HH:MM-HH:MM")
    #[serde(default)]
    pub operating_hours: String,
}

/// Escalation rules — when to ESCALATE instead of ALLOW
#[derive(Debug, Deserialize, Serialize, Default)]
pub struct EscalationRules {
    /// Tools that trigger ESCALATE instead of ALLOW
    #[serde(default)]
    pub escalate_tools: Vec<String>,
    /// Path patterns that trigger ESCALATE
    #[serde(default)]
    pub escalate_paths: Vec<String>,
    /// Network patterns that trigger ESCALATE
    #[serde(default)]
    pub escalate_hosts: Vec<String>,
    /// DID of the authority to escalate to
    #[serde(default)]
    pub escalate_to: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MandateSignature {
    pub algorithm: String,
    pub issuer_pubkey: String,
    pub signature: String,
    pub signed_at: String,
}

/// Sanitize an agent name: strip control characters, cap length
pub fn sanitize_name(name: &str) -> String {
    let cleaned: String = name.chars()
        .filter(|c| !c.is_control())
        .take(256)
        .collect();
    cleaned
}

/// Generate a mandate template for a new agent
pub fn generate_template(name: &str, did: &str) -> String {
    let name = sanitize_name(name);
    format!(
        r#"[mandate]
version = "0.1.0"
agent_did = "{did}"
agent_name = "{name}"
issued_at = ""
expires_at = ""
issuer = ""
workspace_root = ""

[capabilities]
# Explicit allow-list. Anything not listed here is DENIED.
tools = ["read_file", "write_file"]

[boundaries]
# Filesystem boundaries (glob patterns)
fs_read = ["workspace/**"]
fs_write = ["workspace/output/**"]
fs_deny = ["/etc/**", "~/.ssh/**", "**/*.env", "**/*secret*"]

# Network boundaries
net_allow = []
net_deny = ["*"]

# Command boundaries
cmd_allow = []
cmd_deny = ["rm", "sudo", "chmod", "curl * | *"]

[limits]
max_calls_per_minute = 60
max_file_size_bytes = 10485760
max_output_tokens = 4096
max_session_duration_sec = 3600

[output_governance]
deny_patterns = ["-----BEGIN.*PRIVATE KEY-----", "sk-[a-zA-Z0-9]{{48}}", "AKIA[0-9A-Z]{{16}}"]
redact_patterns = ["\\b\\d{{3}}-\\d{{2}}-\\d{{4}}\\b"]
max_output_length = 50000

[jurisdiction]
region = ""
regulatory_framework = ""
environment = ""
classification = ""
operating_hours = ""

[escalation]
# Tools that require human approval before execution
escalate_tools = []
# Path patterns that trigger escalation
escalate_paths = []
# Network patterns that trigger escalation
escalate_hosts = []
# DID of the authority to escalate to
escalate_to = ""
"#
    )
}

/// Compute the canonical hash of the mandate body (everything except [signature])
fn canonical_body(mandate_str: &str) -> String {
    let mut lines: Vec<&str> = Vec::new();
    let mut in_sig_section = false;

    for line in mandate_str.lines() {
        if line.trim() == "[signature]" {
            in_sig_section = true;
            continue;
        }
        if in_sig_section {
            // Skip all lines in [signature] section
            if line.starts_with('[') && line.trim() != "[signature]" {
                in_sig_section = false;
            } else {
                continue;
            }
        }
        lines.push(line);
    }

    lines.join("\n")
}

/// Sign a mandate with a sovereign ed25519 key
pub fn sign_mandate(
    mandate_str: &str,
    sovereign_secret_hex: &str,
    ttl_hours: u64,
) -> Result<String, Box<dyn std::error::Error>> {
    // Parse to validate structure
    let mut mandate: Mandate = toml::from_str(mandate_str)?;

    // Set timestamps
    let now = Utc::now();
    let expires = now + Duration::hours(ttl_hours as i64);
    mandate.mandate.issued_at = now.to_rfc3339();
    mandate.mandate.expires_at = expires.to_rfc3339();

    // Derive issuer DID from sovereign key
    let secret_bytes = hex::decode(sovereign_secret_hex)?;
    let secret_arr: [u8; 32] = secret_bytes.as_slice().try_into()?;
    let signing_key = SigningKey::from_bytes(&secret_arr);
    let verifying_key = signing_key.verifying_key();
    let issuer_pubkey_hex = hex::encode(verifying_key.to_bytes());
    let issuer_did = format!(
        "did:a2g:{}",
        bs58::encode(verifying_key.to_bytes()).into_string()
    );
    mandate.mandate.issuer = issuer_did;

    // Remove old signature for serialization
    mandate.signature = None;

    // Serialize body (without signature)
    let body_str = toml::to_string_pretty(&mandate)?;

    // Domain separation: prefix body hash with type tag to prevent cross-type replay
    let body_to_hash = format!("MANDATE:{}", body_str);
    let body_hash = Sha256::digest(body_to_hash.as_bytes());
    let signature = signing_key.sign(&body_hash);

    // Build final TOML with signature section
    let signed_toml = format!(
        "{}\n[signature]\nalgorithm = \"ed25519\"\nissuer_pubkey = \"{}\"\nsignature = \"{}\"\nsigned_at = \"{}\"\n",
        body_str.trim(),
        issuer_pubkey_hex,
        hex::encode(signature.to_bytes()),
        now.to_rfc3339()
    );

    Ok(signed_toml)
}

/// Verify a signed mandate — checks signature, TTL, and structural validity
pub fn verify_mandate(mandate_str: &str) -> Result<MandateInfo, Box<dyn std::error::Error>> {
    let mandate: Mandate = toml::from_str(mandate_str)?;

    // 1. Check signature exists
    let sig = mandate
        .signature
        .as_ref()
        .ok_or("mandate is unsigned")?;

    // 2. Verify signature algorithm
    if sig.algorithm != "ed25519" {
        return Err(format!("unsupported algorithm: {}", sig.algorithm).into());
    }

    // 3. Reconstruct body for verification
    let mut verify_mandate = mandate;
    let sig_clone = verify_mandate.signature.take().unwrap();
    let body_str = toml::to_string_pretty(&verify_mandate)?;
    let body_to_hash = format!("MANDATE:{}", body_str);
    let body_hash = Sha256::digest(body_to_hash.as_bytes());

    // 4. Verify ed25519 signature
    let pubkey_bytes = hex::decode(&sig_clone.issuer_pubkey)?;
    let pubkey_arr: [u8; 32] = pubkey_bytes.as_slice().try_into()
        .map_err(|_| "invalid public key length")?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_arr)?;

    let sig_bytes = hex::decode(&sig_clone.signature)?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into()
        .map_err(|_| "invalid signature length")?;
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key.verify(&body_hash, &signature)?;

    // 5. Check TTL
    let expires_at = verify_mandate
        .mandate
        .expires_at
        .parse::<DateTime<Utc>>()
        .map_err(|_| "invalid expires_at timestamp")?;

    let now = Utc::now();
    let ttl_remaining = (expires_at - now).num_seconds();

    if ttl_remaining <= 0 {
        return Err(format!(
            "mandate expired at {} ({} seconds ago)",
            expires_at,
            -ttl_remaining
        )
        .into());
    }

    // 6. Return info
    Ok(MandateInfo {
        agent_did: verify_mandate.mandate.agent_did,
        agent_name: verify_mandate.mandate.agent_name,
        issuer: verify_mandate.mandate.issuer,
        expires_at: expires_at.to_rfc3339(),
        ttl_remaining_sec: ttl_remaining,
        tools: verify_mandate.capabilities.tools,
    })
}

/// Parse a mandate from TOML string
pub fn parse_mandate(mandate_str: &str) -> Result<Mandate, Box<dyn std::error::Error>> {
    let mandate: Mandate = toml::from_str(mandate_str)?;
    Ok(mandate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;

    #[test]
    fn test_sign_and_verify() {
        let (did, _, _) = identity::generate_agent_keypair();
        let (_, sovereign_secret, _) = identity::generate_agent_keypair();

        let template = generate_template("test-agent", &did);
        let signed = sign_mandate(&template, &sovereign_secret, 24).unwrap();
        let info = verify_mandate(&signed).unwrap();

        assert_eq!(info.agent_name, "test-agent");
        assert_eq!(info.agent_did, did);
        assert!(info.ttl_remaining_sec > 0);
    }

    #[test]
    fn test_template_generation() {
        let template = generate_template("my-agent", "did:a2g:test123");
        assert!(template.contains("my-agent"));
        assert!(template.contains("did:a2g:test123"));
    }
}
