//! Lineage Reconstruction — Rebuild full execution provenance from a receipt
//!
//! Given a receipt ID or hash, walks the ledger to reconstruct the complete
//! authority chain: receipt → mandate version → proposal → delegation → correlation.
//! This is the "evidence determinism" layer — proving exactly what authority
//! was in force when a governance decision was made.

use serde::Serialize;

/// Complete execution lineage reconstructed from a receipt
#[derive(Debug, Serialize)]
pub struct ExecutionLineage {
    // Receipt fields
    pub receipt_id: String,
    pub receipt_hash: String,
    pub decision: String,
    pub tool: String,
    pub agent_did: String,
    pub timestamp: String,
    pub policy_rule: String,

    // Policy version (Phase 1)
    pub mandate_hash: String,
    pub proposal_hash: String,

    // Authority context (Phase 2)
    pub delegation_chain_hash: String,
    pub issuer_did: String,
    pub authority_level: String,
    pub scope_hash: String,

    // Correlation (Phase 4)
    pub correlation_id: String,
    pub parent_receipt_hash: String,

    // Recursive parent lineage (if correlated)
    pub parent_lineage: Option<Box<ExecutionLineage>>,

    // Completeness assessment
    pub lineage_complete: bool,
    pub missing_fields: Vec<String>,
}

/// Reconstruct full execution lineage from a receipt ID or hash
///
/// Walks the ledger to find the receipt, extracts all lineage fields,
/// and recursively follows parent_receipt_hash for correlated decisions.
/// max_depth prevents infinite recursion on circular references.
pub fn reconstruct_lineage(
    receipt_id_or_hash: &str,
    db: &crate::ledger::Ledger,
    max_depth: usize,
) -> Result<ExecutionLineage, Box<dyn std::error::Error>> {
    reconstruct_recursive(receipt_id_or_hash, db, max_depth, 0)
}

fn reconstruct_recursive(
    receipt_id_or_hash: &str,
    db: &crate::ledger::Ledger,
    max_depth: usize,
    current_depth: usize,
) -> Result<ExecutionLineage, Box<dyn std::error::Error>> {
    if current_depth >= max_depth {
        return Err(format!(
            "lineage reconstruction exceeded max depth of {} (possible circular reference)",
            max_depth
        )
        .into());
    }

    // Look up the receipt in the ledger
    let entry = db
        .query_decision_by_id(receipt_id_or_hash)?
        .ok_or_else(|| format!("receipt '{}' not found in ledger", receipt_id_or_hash))?;

    // Assess completeness
    let mut missing_fields = Vec::new();

    if entry.mandate_hash.is_empty() {
        missing_fields.push("mandate_hash".to_string());
    }
    if entry.proposal_hash.is_empty() {
        missing_fields.push("proposal_hash".to_string());
    }
    if entry.issuer_did.is_empty() {
        missing_fields.push("issuer_did".to_string());
    }
    if entry.delegation_chain_hash.is_empty() {
        missing_fields.push("delegation_chain_hash".to_string());
    }
    if entry.authority_level.is_empty() {
        missing_fields.push("authority_level".to_string());
    }
    if entry.scope_hash.is_empty() {
        missing_fields.push("scope_hash".to_string());
    }

    let lineage_complete = missing_fields.is_empty();

    // Recursively resolve parent lineage if correlated
    let parent_lineage = if !entry.parent_receipt_hash.is_empty() {
        match reconstruct_recursive(&entry.parent_receipt_hash, db, max_depth, current_depth + 1) {
            Ok(parent) => Some(Box::new(parent)),
            Err(_) => None, // Parent not found — don't fail, just omit
        }
    } else {
        None
    };

    Ok(ExecutionLineage {
        receipt_id: entry.receipt_id,
        receipt_hash: entry.receipt_hash,
        decision: entry.decision,
        tool: entry.tool,
        agent_did: entry.agent_did,
        timestamp: entry.timestamp,
        policy_rule: entry.policy_rule,
        mandate_hash: entry.mandate_hash,
        proposal_hash: entry.proposal_hash,
        delegation_chain_hash: entry.delegation_chain_hash,
        issuer_did: entry.issuer_did,
        authority_level: entry.authority_level,
        scope_hash: entry.scope_hash,
        correlation_id: entry.correlation_id,
        parent_receipt_hash: entry.parent_receipt_hash,
        parent_lineage,
        lineage_complete,
        missing_fields,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_lineage_not_found() {
        let db = crate::ledger::Ledger::open(Path::new(":memory:")).unwrap();
        let result = reconstruct_lineage("nonexistent", &db, 10);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_lineage_reconstruction() {
        use crate::enforce::{Decision, Verdict};
        use chrono::Utc;

        let db = crate::ledger::Ledger::open(Path::new(":memory:")).unwrap();

        // Construct a verdict directly (bypass enforce to avoid needing a signed mandate)
        let verdict = Verdict {
            verdict_id: uuid::Uuid::new_v4().to_string(),
            agent_did: "did:a2g:testLineage".to_string(),
            agent_name: "lineage-test".to_string(),
            tool: "read_file".to_string(),
            params_hash: "abc123".to_string(),
            decision: Decision::Allow,
            policy_rule: "tool_allowed".to_string(),
            evaluated_at: Utc::now(),
            mandate_hash: "deadbeef".repeat(8),
            proposal_hash: "cafebabe".repeat(8),
            delegation_chain_hash: String::new(),
            issuer_did: "did:a2g:issuer".to_string(),
            authority_level: String::new(),
            scope_hash: String::new(),
            correlation_id: String::new(),
            parent_receipt_hash: String::new(),
        };

        // Record atomically (handles chain integrity internally)
        let receipt = db.enforce_and_record(&verdict).unwrap();

        // Reconstruct lineage
        let lineage = reconstruct_lineage(&receipt.receipt_id, &db, 10).unwrap();
        assert_eq!(lineage.receipt_id, receipt.receipt_id);
        assert_eq!(lineage.decision, "ALLOW");
        assert_eq!(lineage.tool, "read_file");
        assert_eq!(lineage.mandate_hash, "deadbeef".repeat(8));
        assert_eq!(lineage.proposal_hash, "cafebabe".repeat(8));
        assert_eq!(lineage.issuer_did, "did:a2g:issuer");
        // Not all fields populated — lineage should be incomplete
        assert!(!lineage.lineage_complete);
    }
}
