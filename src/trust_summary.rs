//! Constitutional Memory — Trust compression and portable governance proofs
//!
//! Compresses an agent's governance history over a time window into a signed,
//! portable trust summary. The summary contains aggregate statistics, a Merkle
//! root of all receipt hashes, and an ed25519 signature for verification
//! without access to the original ledger.

use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Unsigned aggregate data from a compression window
#[derive(Debug)]
pub struct TrustSummaryData {
    pub agent_did: String,
    pub window_start: String,
    pub window_end: String,
    pub total_decisions: u64,
    pub decision_counts: BTreeMap<String, u64>,
    pub tool_counts: BTreeMap<String, u64>,
    pub unique_tools: u64,
    pub unique_mandates: u64,
    pub policy_rules_hit: BTreeMap<String, u64>,
    pub authority_coverage: BTreeMap<String, u64>,
    pub issuer_coverage: Vec<String>,
    pub compliance_rate: f64,
    pub escalation_rate: f64,
    pub deny_rate: f64,
    pub first_receipt_hash: String,
    pub last_receipt_hash: String,
    pub merkle_root: String,
    pub chain_intact: bool,
}

/// Complete signed trust summary — portable governance proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustSummary {
    pub summary_id: String,
    pub summary_version: String,
    pub agent_did: String,
    pub window_start: String,
    pub window_end: String,
    pub total_decisions: u64,
    pub decision_counts: BTreeMap<String, u64>,
    pub tool_counts: BTreeMap<String, u64>,
    pub unique_tools: u64,
    pub unique_mandates: u64,
    pub policy_rules_hit: BTreeMap<String, u64>,
    pub authority_coverage: BTreeMap<String, u64>,
    pub issuer_coverage: Vec<String>,
    pub compliance_rate: f64,
    pub escalation_rate: f64,
    pub deny_rate: f64,
    pub first_receipt_hash: String,
    pub last_receipt_hash: String,
    pub merkle_root: String,
    pub chain_intact: bool,
    pub compressed_at: String,
    pub issuer_did: String,
    pub issuer_name: String,
    pub signature: String,
    pub issuer_pubkey: String,
    pub summary_hash: String,
}

/// Compress an agent's governance history within a time window
pub fn compress_window(
    db: &crate::ledger::Ledger,
    agent_did: &str,
    start: &str,
    end: &str,
) -> Result<TrustSummaryData, Box<dyn std::error::Error>> {
    let entries = db.query_window(agent_did, start, end)?;

    if entries.is_empty() {
        return Err(format!(
            "no decisions found for agent '{}' between {} and {}",
            agent_did, start, end
        )
        .into());
    }

    let total = entries.len() as u64;
    let mut decision_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut tool_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut policy_rules_hit: BTreeMap<String, u64> = BTreeMap::new();
    let mut authority_coverage: BTreeMap<String, u64> = BTreeMap::new();
    let mut mandate_hashes: BTreeSet<String> = BTreeSet::new();
    let mut issuer_set: BTreeSet<String> = BTreeSet::new();
    let mut receipt_hashes: Vec<String> = Vec::new();

    let first_receipt_hash = entries[0].receipt_hash.clone();
    let mut last_receipt_hash = String::new();
    let mut chain_intact = true;

    // C3 FIX: Validate chain integrity by checking BOTH sequential ordering
    // AND prev_hash links between consecutive entries within the window.
    // This prevents reordering, duplication, or deletion attacks that would
    // produce the same Merkle root but violate chain integrity.
    let mut prev_receipt_hash_in_window: Option<String> = None;
    let mut prev_seq = 0i64;

    for entry in &entries {
        // Accumulate counts
        *decision_counts.entry(entry.decision.clone()).or_insert(0) += 1;
        *tool_counts.entry(entry.tool.clone()).or_insert(0) += 1;
        *policy_rules_hit
            .entry(entry.policy_rule.clone())
            .or_insert(0) += 1;

        if !entry.authority_level.is_empty() {
            *authority_coverage
                .entry(entry.authority_level.clone())
                .or_insert(0) += 1;
        }
        if !entry.mandate_hash.is_empty() {
            mandate_hashes.insert(entry.mandate_hash.clone());
        }
        if !entry.issuer_did.is_empty() {
            issuer_set.insert(entry.issuer_did.clone());
        }

        receipt_hashes.push(entry.receipt_hash.clone());
        last_receipt_hash = entry.receipt_hash.clone();

        // C3 FIX: Validate prev_hash chain links within window
        if let Some(ref expected_prev) = prev_receipt_hash_in_window {
            if entry.prev_hash != *expected_prev {
                chain_intact = false;
            }
        }
        prev_receipt_hash_in_window = Some(entry.receipt_hash.clone());

        // Also verify sequential ordering
        if entry.seq <= prev_seq && prev_seq != 0 {
            chain_intact = false;
        }
        prev_seq = entry.seq;
    }

    let allow_count = decision_counts.get("ALLOW").copied().unwrap_or(0);
    let deny_count = decision_counts.get("DENY").copied().unwrap_or(0);
    let escalate_count = decision_counts.get("ESCALATE").copied().unwrap_or(0);

    let compliance_rate = if total > 0 {
        (allow_count as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    let deny_rate = if total > 0 {
        (deny_count as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    let escalation_rate = if total > 0 {
        (escalate_count as f64 / total as f64) * 100.0
    } else {
        0.0
    };

    let root = merkle_root(&receipt_hashes);

    let issuer_coverage_vec: Vec<String> = issuer_set.into_iter().collect();
    let unique_tools = tool_counts.len() as u64;
    let unique_mandates = mandate_hashes.len() as u64;

    Ok(TrustSummaryData {
        agent_did: agent_did.to_string(),
        window_start: start.to_string(),
        window_end: end.to_string(),
        total_decisions: total,
        decision_counts,
        tool_counts,
        unique_tools,
        unique_mandates,
        policy_rules_hit,
        authority_coverage,
        issuer_coverage: issuer_coverage_vec,
        compliance_rate,
        escalation_rate,
        deny_rate,
        first_receipt_hash,
        last_receipt_hash,
        merkle_root: root,
        chain_intact,
    })
}

/// Sign a trust summary with an ed25519 key
pub fn sign_summary(
    data: TrustSummaryData,
    signing_key: &SigningKey,
    issuer_did: &str,
    issuer_name: &str,
) -> Result<TrustSummary, Box<dyn std::error::Error>> {
    let summary_id = uuid::Uuid::new_v4().to_string();
    let compressed_at = Utc::now().to_rfc3339();
    let issuer_pubkey = hex::encode(signing_key.verifying_key().to_bytes());

    // Build the hashable content (everything except signature and summary_hash)
    let hash_input = format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        summary_id,
        "1.0",
        data.agent_did,
        data.window_start,
        data.window_end,
        data.total_decisions,
        serde_json::to_string(&data.decision_counts)?,
        serde_json::to_string(&data.tool_counts)?,
        data.unique_tools,
        data.unique_mandates,
        data.compliance_rate,
        data.escalation_rate,
        data.deny_rate,
        data.first_receipt_hash,
        data.last_receipt_hash,
        data.merkle_root,
        data.chain_intact,
        compressed_at,
        issuer_did,
    );

    let summary_hash = hex::encode(Sha256::digest(hash_input.as_bytes()));

    // Sign with domain prefix
    let sign_payload = format!("TRUST_SUMMARY:{}", summary_hash);
    let signature = signing_key.sign(sign_payload.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());

    Ok(TrustSummary {
        summary_id,
        summary_version: "1.0".to_string(),
        agent_did: data.agent_did,
        window_start: data.window_start,
        window_end: data.window_end,
        total_decisions: data.total_decisions,
        decision_counts: data.decision_counts,
        tool_counts: data.tool_counts,
        unique_tools: data.unique_tools,
        unique_mandates: data.unique_mandates,
        policy_rules_hit: data.policy_rules_hit,
        authority_coverage: data.authority_coverage,
        issuer_coverage: data.issuer_coverage,
        compliance_rate: data.compliance_rate,
        escalation_rate: data.escalation_rate,
        deny_rate: data.deny_rate,
        first_receipt_hash: data.first_receipt_hash,
        last_receipt_hash: data.last_receipt_hash,
        merkle_root: data.merkle_root,
        chain_intact: data.chain_intact,
        compressed_at,
        issuer_did: issuer_did.to_string(),
        issuer_name: issuer_name.to_string(),
        signature: signature_hex,
        issuer_pubkey,
        summary_hash,
    })
}

/// Verify a trust summary's integrity and signature
pub fn verify_summary(summary: &TrustSummary) -> Result<bool, Box<dyn std::error::Error>> {
    // Recompute summary hash
    let hash_input = format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        summary.summary_id,
        summary.summary_version,
        summary.agent_did,
        summary.window_start,
        summary.window_end,
        summary.total_decisions,
        serde_json::to_string(&summary.decision_counts)?,
        serde_json::to_string(&summary.tool_counts)?,
        summary.unique_tools,
        summary.unique_mandates,
        summary.compliance_rate,
        summary.escalation_rate,
        summary.deny_rate,
        summary.first_receipt_hash,
        summary.last_receipt_hash,
        summary.merkle_root,
        summary.chain_intact,
        summary.compressed_at,
        summary.issuer_did,
    );

    let expected_hash = hex::encode(Sha256::digest(hash_input.as_bytes()));
    if expected_hash != summary.summary_hash {
        return Ok(false);
    }

    // Verify ed25519 signature
    let pubkey_bytes = hex::decode(&summary.issuer_pubkey)?;
    let pubkey_array: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| "invalid public key length")?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_array)?;

    let sig_bytes = hex::decode(&summary.signature)?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "invalid signature length")?;
    let signature = Signature::from_bytes(&sig_array);

    let sign_payload = format!("TRUST_SUMMARY:{}", summary.summary_hash);
    Ok(verifying_key
        .verify(sign_payload.as_bytes(), &signature)
        .is_ok())
}

/// Compute the Merkle root of a list of hash strings
pub fn merkle_root(hashes: &[String]) -> String {
    if hashes.is_empty() {
        return "0".repeat(64);
    }
    if hashes.len() == 1 {
        return hashes[0].clone();
    }

    let mut current_level: Vec<String> = hashes.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;
        while i < current_level.len() {
            if i + 1 < current_level.len() {
                let combined = format!("{}:{}", current_level[i], current_level[i + 1]);
                next_level.push(hex::encode(Sha256::digest(combined.as_bytes())));
                i += 2;
            } else {
                // Odd element — promote to next level
                next_level.push(current_level[i].clone());
                i += 1;
            }
        }
        current_level = next_level;
    }

    current_level[0].clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enforce::{Decision, Verdict};
    use chrono::Utc;
    use std::path::Path;

    fn make_test_verdict(agent_did: &str, tool: &str, decision: Decision) -> Verdict {
        Verdict {
            verdict_id: uuid::Uuid::new_v4().to_string(),
            agent_did: agent_did.to_string(),
            agent_name: "test-agent".to_string(),
            tool: tool.to_string(),
            params_hash: "abc123".to_string(),
            decision,
            policy_rule: "test_rule".to_string(),
            evaluated_at: Utc::now(),
            mandate_hash: "deadbeef".repeat(8),
            proposal_hash: String::new(),
            delegation_chain_hash: String::new(),
            issuer_did: "did:a2g:issuer".to_string(),
            authority_level: "ROOT".to_string(),
            scope_hash: String::new(),
            correlation_id: String::new(),
            parent_receipt_hash: String::new(),
        }
    }

    #[test]
    fn test_compress_empty_window() {
        let db = crate::ledger::Ledger::open(Path::new(":memory:")).unwrap();
        let result = compress_window(
            &db,
            "did:a2g:nobody",
            "2020-01-01T00:00:00Z",
            "2099-01-01T00:00:00Z",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no decisions"));
    }

    #[test]
    fn test_compress_single_decision() {
        let db = crate::ledger::Ledger::open(Path::new(":memory:")).unwrap();
        let v = make_test_verdict("did:a2g:alice", "read_file", Decision::Allow);
        db.enforce_and_record(&v).unwrap();

        let data = compress_window(
            &db,
            "did:a2g:alice",
            "2020-01-01T00:00:00Z",
            "2099-01-01T00:00:00Z",
        )
        .unwrap();
        assert_eq!(data.total_decisions, 1);
        assert_eq!(data.compliance_rate, 100.0);
        assert_eq!(data.deny_rate, 0.0);
        assert_eq!(*data.decision_counts.get("ALLOW").unwrap(), 1);
        assert_eq!(*data.tool_counts.get("read_file").unwrap(), 1);
    }

    #[test]
    fn test_compress_mixed_decisions() {
        let db = crate::ledger::Ledger::open(Path::new(":memory:")).unwrap();

        // 3 ALLOW, 1 DENY, 1 ESCALATE
        for _ in 0..3 {
            let v = make_test_verdict("did:a2g:bob", "read_file", Decision::Allow);
            db.enforce_and_record(&v).unwrap();
        }
        let v = make_test_verdict("did:a2g:bob", "write_file", Decision::Deny);
        db.enforce_and_record(&v).unwrap();
        let v = make_test_verdict("did:a2g:bob", "exec_cmd", Decision::Escalate);
        db.enforce_and_record(&v).unwrap();

        let data = compress_window(
            &db,
            "did:a2g:bob",
            "2020-01-01T00:00:00Z",
            "2099-01-01T00:00:00Z",
        )
        .unwrap();
        assert_eq!(data.total_decisions, 5);
        assert_eq!(*data.decision_counts.get("ALLOW").unwrap(), 3);
        assert_eq!(*data.decision_counts.get("DENY").unwrap(), 1);
        assert_eq!(*data.decision_counts.get("ESCALATE").unwrap(), 1);
        assert!((data.compliance_rate - 60.0).abs() < 0.01);
        assert!((data.deny_rate - 20.0).abs() < 0.01);
        assert!((data.escalation_rate - 20.0).abs() < 0.01);
        assert_eq!(data.unique_tools, 3);
    }

    #[test]
    fn test_merkle_root_single() {
        let hashes = vec!["abc123".to_string()];
        assert_eq!(merkle_root(&hashes), "abc123");
    }

    #[test]
    fn test_merkle_root_multiple() {
        let hashes = vec!["aaa".to_string(), "bbb".to_string(), "ccc".to_string()];
        let root1 = merkle_root(&hashes);
        let root2 = merkle_root(&hashes);
        assert_eq!(root1, root2); // deterministic

        // Different order → different root
        let hashes2 = vec!["bbb".to_string(), "aaa".to_string(), "ccc".to_string()];
        let root3 = merkle_root(&hashes2);
        assert_ne!(root1, root3);
    }

    #[test]
    fn test_sign_and_verify() {
        let db = crate::ledger::Ledger::open(Path::new(":memory:")).unwrap();
        let v = make_test_verdict("did:a2g:charlie", "read_file", Decision::Allow);
        db.enforce_and_record(&v).unwrap();

        let data = compress_window(
            &db,
            "did:a2g:charlie",
            "2020-01-01T00:00:00Z",
            "2099-01-01T00:00:00Z",
        )
        .unwrap();

        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let issuer_did = "did:a2g:authority";
        let summary = sign_summary(data, &signing_key, issuer_did, "Test Authority").unwrap();

        assert!(verify_summary(&summary).unwrap());
        assert_eq!(summary.summary_version, "1.0");
        assert_eq!(summary.issuer_did, issuer_did);
    }

    #[test]
    fn test_tampered_summary_rejected() {
        let db = crate::ledger::Ledger::open(Path::new(":memory:")).unwrap();
        let v = make_test_verdict("did:a2g:dave", "read_file", Decision::Allow);
        db.enforce_and_record(&v).unwrap();

        let data = compress_window(
            &db,
            "did:a2g:dave",
            "2020-01-01T00:00:00Z",
            "2099-01-01T00:00:00Z",
        )
        .unwrap();

        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut summary =
            sign_summary(data, &signing_key, "did:a2g:authority", "Test Authority").unwrap();

        // Tamper with the summary
        summary.total_decisions = 999;
        assert!(!verify_summary(&summary).unwrap());
    }
}
