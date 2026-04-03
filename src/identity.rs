//! Agent Identity — ed25519 keypair generation and DID derivation
//!
//! DID format: did:a2g:<base58-encoded-public-key>

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

/// Generate a new ed25519 keypair and derive the A2G DID.
/// Returns (did, secret_key_hex, public_key_hex)
pub fn generate_agent_keypair() -> (String, String, String) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let secret_hex = hex::encode(signing_key.to_bytes());
    let public_hex = hex::encode(verifying_key.to_bytes());
    let did = format!(
        "did:a2g:{}",
        bs58::encode(verifying_key.to_bytes()).into_string()
    );

    (did, secret_hex, public_hex)
}

/// Derive DID from a public key hex string
pub fn did_from_pubkey_hex(pubkey_hex: &str) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = hex::decode(pubkey_hex)?;
    Ok(format!("did:a2g:{}", bs58::encode(&bytes).into_string()))
}

/// Extract public key bytes from a DID string
pub fn pubkey_from_did(did: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let prefix = "did:a2g:";
    if !did.starts_with(prefix) {
        return Err("invalid DID format: must start with did:a2g:".into());
    }
    let b58_part = &did[prefix.len()..];
    let bytes = bs58::decode(b58_part).into_vec()?;
    Ok(bytes)
}

/// Validate a DID string format
pub fn validate_did(did: &str) -> Result<(), Box<dyn std::error::Error>> {
    if did.is_empty() {
        return Err("DID must not be empty".into());
    }
    if did.len() > 256 {
        return Err("DID exceeds maximum length of 256 characters".into());
    }
    // Check for control characters
    if did.chars().any(|c| c.is_control()) {
        return Err("DID contains control characters".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (did, secret, public) = generate_agent_keypair();
        assert!(did.starts_with("did:a2g:"));
        assert_eq!(secret.len(), 64); // 32 bytes hex
        assert_eq!(public.len(), 64);
    }

    #[test]
    fn test_did_roundtrip() {
        let (did, _, public_hex) = generate_agent_keypair();
        let derived_did = did_from_pubkey_hex(&public_hex).unwrap();
        assert_eq!(did, derived_did);
    }

    #[test]
    fn test_pubkey_extraction() {
        let (did, _, public_hex) = generate_agent_keypair();
        let extracted = pubkey_from_did(&did).unwrap();
        let expected = hex::decode(&public_hex).unwrap();
        assert_eq!(extracted, expected);
    }
}
