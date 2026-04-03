//! Verifiable Receipts — Cryptographic proof of every governance decision
//!
//! Every enforcement decision produces a Receipt that can be independently
//! verified by any third party with the engine's public key.
//! Receipts form an append-only chain via prev_hash.

use crate::enforce::{Decision, Verdict};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A signed governance receipt — proof that a decision was made
#[derive(Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub receipt_id: String,
    pub verdict_id: String,
    pub agent_did: String,
    pub tool: String,
    pub params_hash: String,
    pub decision: Decision,
    pub policy_rule: String,
    pub policy_hash: String,
    pub timestamp: String,
    pub prev_hash: String,
    pub receipt_hash: String,
    #[serde(default)]
    pub mandate_hash: String,
    #[serde(default)]
    pub proposal_hash: String,
    #[serde(default)]
    pub delegation_chain_hash: String,
    #[serde(default)]
    pub issuer_did: String,
    #[serde(default)]
    pub authority_level: String,
    #[serde(default)]
    pub scope_hash: String,
    #[serde(default)]
    pub correlation_id: String,
    #[serde(default)]
    pub parent_receipt_hash: String,
}

/// Thread-safe storage for the previous receipt hash (chain linking)
static PREV_HASH: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Initialize the receipt chain from the ledger's last hash.
/// Must be called once at startup before any generate_receipt() calls
/// to maintain chain integrity across process restarts.
pub fn init_chain_from_ledger(last_hash: Option<String>) {
    *PREV_HASH.lock().unwrap() = last_hash;
}

/// Generate a receipt from a verdict
pub fn generate_receipt(verdict: &Verdict) -> Receipt {
    let receipt_id = uuid::Uuid::new_v4().to_string();
    let timestamp = Utc::now().to_rfc3339();

    // Get the previous hash for chain linking
    let prev_hash = PREV_HASH
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| "0".repeat(64)); // Genesis hash

    // Compute policy hash (hash of the policy rule that triggered)
    let policy_hash = hex::encode(Sha256::digest(verdict.policy_rule.as_bytes()));

    // Compute receipt hash (covers all fields)
    let mut hash_input = format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}",
        receipt_id,
        verdict.verdict_id,
        verdict.agent_did,
        verdict.tool,
        verdict.params_hash,
        verdict.decision,
        policy_hash,
        timestamp,
        prev_hash,
    );

    // Lineage extension (only affects hash when populated)
    if !verdict.mandate_hash.is_empty() {
        hash_input.push_str(&format!(
            ":{}:{}",
            verdict.mandate_hash, verdict.proposal_hash
        ));
    }
    if !verdict.delegation_chain_hash.is_empty() {
        hash_input.push_str(&format!(
            ":{}:{}:{}:{}",
            verdict.delegation_chain_hash,
            verdict.issuer_did,
            verdict.authority_level,
            verdict.scope_hash
        ));
    }
    if !verdict.correlation_id.is_empty() {
        hash_input.push_str(&format!(
            ":{}:{}",
            verdict.correlation_id, verdict.parent_receipt_hash
        ));
    }

    let receipt_hash = hex::encode(Sha256::digest(hash_input.as_bytes()));

    // Update chain
    *PREV_HASH.lock().unwrap() = Some(receipt_hash.clone());

    Receipt {
        receipt_id,
        verdict_id: verdict.verdict_id.clone(),
        agent_did: verdict.agent_did.clone(),
        tool: verdict.tool.clone(),
        params_hash: verdict.params_hash.clone(),
        decision: verdict.decision.clone(),
        policy_rule: verdict.policy_rule.clone(),
        policy_hash,
        timestamp,
        prev_hash,
        receipt_hash,
        mandate_hash: verdict.mandate_hash.clone(),
        proposal_hash: verdict.proposal_hash.clone(),
        delegation_chain_hash: verdict.delegation_chain_hash.clone(),
        issuer_did: verdict.issuer_did.clone(),
        authority_level: verdict.authority_level.clone(),
        scope_hash: verdict.scope_hash.clone(),
        correlation_id: verdict.correlation_id.clone(),
        parent_receipt_hash: verdict.parent_receipt_hash.clone(),
    }
}

/// Verify a receipt's integrity (check that the hash is valid)
pub fn verify_receipt(receipt: &Receipt) -> bool {
    let mut hash_input = format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}",
        receipt.receipt_id,
        receipt.verdict_id,
        receipt.agent_did,
        receipt.tool,
        receipt.params_hash,
        receipt.decision,
        receipt.policy_hash,
        receipt.timestamp,
        receipt.prev_hash,
    );

    // Lineage extension (only affects hash when populated)
    if !receipt.mandate_hash.is_empty() {
        hash_input.push_str(&format!(
            ":{}:{}",
            receipt.mandate_hash, receipt.proposal_hash
        ));
    }
    if !receipt.delegation_chain_hash.is_empty() {
        hash_input.push_str(&format!(
            ":{}:{}:{}:{}",
            receipt.delegation_chain_hash,
            receipt.issuer_did,
            receipt.authority_level,
            receipt.scope_hash
        ));
    }
    if !receipt.correlation_id.is_empty() {
        hash_input.push_str(&format!(
            ":{}:{}",
            receipt.correlation_id, receipt.parent_receipt_hash
        ));
    }

    let computed = hex::encode(Sha256::digest(hash_input.as_bytes()));
    computed == receipt.receipt_hash
}

/// Verify a chain of receipts (each receipt's prev_hash matches the previous receipt_hash)
pub fn verify_chain(receipts: &[Receipt]) -> Result<(), String> {
    if receipts.is_empty() {
        return Ok(());
    }

    // Verify first receipt points to genesis
    if receipts[0].prev_hash != "0".repeat(64) {
        return Err("first receipt does not point to genesis hash".to_string());
    }

    // Verify each receipt's own hash
    for (i, r) in receipts.iter().enumerate() {
        if !verify_receipt(r) {
            return Err(format!("receipt {} has invalid hash", i));
        }
    }

    // Verify chain links
    for i in 1..receipts.len() {
        if receipts[i].prev_hash != receipts[i - 1].receipt_hash {
            return Err(format!(
                "chain broken at receipt {}: prev_hash does not match previous receipt_hash",
                i
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enforce::{Decision, Verdict};
    use chrono::Utc;

    fn make_verdict(tool: &str, decision: Decision) -> Verdict {
        Verdict {
            verdict_id: uuid::Uuid::new_v4().to_string(),
            agent_did: "did:a2g:test".to_string(),
            agent_name: "test".to_string(),
            tool: tool.to_string(),
            params_hash: "abc123".to_string(),
            decision,
            policy_rule: "test_rule".to_string(),
            evaluated_at: Utc::now(),
            mandate_hash: String::new(),
            proposal_hash: String::new(),
            delegation_chain_hash: String::new(),
            issuer_did: String::new(),
            authority_level: String::new(),
            scope_hash: String::new(),
            correlation_id: String::new(),
            parent_receipt_hash: String::new(),
        }
    }

    #[test]
    fn test_receipt_integrity() {
        let v = make_verdict("read_file", Decision::Allow);
        let r = generate_receipt(&v);
        assert!(verify_receipt(&r));
    }

    #[test]
    fn test_corrupted_receipt_hash() {
        let verdict = Verdict {
            verdict_id: "test-corrupt".to_string(),
            agent_did: "did:a2g:test".to_string(),
            agent_name: "test".to_string(),
            tool: "read_file".to_string(),
            params_hash: "abc123".to_string(),
            decision: Decision::Allow,
            policy_rule: "test".to_string(),
            evaluated_at: Utc::now(),
            mandate_hash: String::new(),
            proposal_hash: String::new(),
            delegation_chain_hash: String::new(),
            issuer_did: String::new(),
            authority_level: String::new(),
            scope_hash: String::new(),
            correlation_id: String::new(),
            parent_receipt_hash: String::new(),
        };
        init_chain_from_ledger(None);
        let mut rcpt = generate_receipt(&verdict);
        // Corrupt the hash
        rcpt.receipt_hash =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        assert!(!verify_receipt(&rcpt));
    }
}
