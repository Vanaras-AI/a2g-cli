//! Mandate Proposals — Pre-execution authority approval workflow
//!
//! Before a mandate is signed, it exists as a Proposal. The proposal specifies
//! what the agent wants to do. It goes through an approval flow — one or more
//! authorized reviewers must approve before the mandate can be signed.
//!
//! This is the "who decides this agent should have these powers" layer.

use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Status of a mandate proposal
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProposalStatus {
    /// Waiting for approvals
    Pending,
    /// All required approvals received — ready to sign
    Approved,
    /// Explicitly rejected by a reviewer
    Rejected,
    /// Proposal expired before receiving sufficient approvals
    Expired,
    /// Withdrawn by the proposer
    Withdrawn,
}

impl std::fmt::Display for ProposalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposalStatus::Pending => write!(f, "PENDING"),
            ProposalStatus::Approved => write!(f, "APPROVED"),
            ProposalStatus::Rejected => write!(f, "REJECTED"),
            ProposalStatus::Expired => write!(f, "EXPIRED"),
            ProposalStatus::Withdrawn => write!(f, "WITHDRAWN"),
        }
    }
}

/// Risk level assessment for a mandate proposal
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RiskLevel {
    /// Low risk: read-only tools, restricted scope. Requires 1 approval.
    Low,
    /// Medium risk: write tools, network access. Requires 2 approvals.
    Medium,
    /// High risk: command execution, broad scope, production. Requires 3 approvals.
    High,
    /// Critical: unrestricted tools, cross-jurisdiction. Requires all approvers + root.
    Critical,
}

impl RiskLevel {
    /// Minimum number of approvals required
    pub fn required_approvals(&self) -> usize {
        match self {
            RiskLevel::Low => 1,
            RiskLevel::Medium => 2,
            RiskLevel::High => 3,
            RiskLevel::Critical => 4,
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A mandate proposal — what an agent wants to be authorized to do
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub proposal_id: String,
    /// DID of who is requesting this mandate
    pub proposer_did: String,
    /// Human-readable name for the proposal
    pub proposal_name: String,
    /// The full mandate TOML that would be signed if approved
    pub mandate_body: String,
    /// SHA-256 hash of the mandate body
    pub mandate_hash: String,
    /// Justification for why this mandate should be granted
    pub justification: String,
    /// Assessed risk level
    pub risk_level: RiskLevel,
    /// Required number of approvals
    pub required_approvals: usize,
    /// Current status
    pub status: ProposalStatus,
    /// List of approval/rejection records
    pub reviews: Vec<Review>,
    /// Timestamp
    pub created_at: String,
    /// Expiry for the proposal itself (not the mandate)
    pub expires_at: String,
    /// Hash covering all fields
    pub proposal_hash: String,
}

/// A single review (approval or rejection) of a proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Review {
    pub review_id: String,
    pub reviewer_did: String,
    pub reviewer_name: String,
    pub decision: ReviewDecision,
    pub reason: String,
    pub reviewed_at: String,
    pub signature: String,
    pub reviewer_pubkey: String,
    #[serde(default)]
    pub mandate_view_hash: String,
    #[serde(default)]
    pub approval_context_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReviewDecision {
    Approve,
    Reject,
    RequestChanges,
}

impl std::fmt::Display for ReviewDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReviewDecision::Approve => write!(f, "APPROVE"),
            ReviewDecision::Reject => write!(f, "REJECT"),
            ReviewDecision::RequestChanges => write!(f, "REQUEST_CHANGES"),
        }
    }
}

/// Assess risk level from a mandate TOML string
pub fn assess_risk(mandate_str: &str) -> Result<RiskLevel, Box<dyn std::error::Error>> {
    let m: crate::mandate::Mandate = toml::from_str(mandate_str)?;
    let mut score: u32 = 0;

    // Tool risk scoring
    let write_tools = ["write_file", "write", "delete", "delete_file", "move", "rename"];
    let exec_tools = ["execute", "exec", "shell", "command", "run"];
    let net_tools = ["http_get", "http_post", "http_put", "http_delete", "fetch", "curl"];

    for tool in &m.capabilities.tools {
        let t = tool.to_lowercase();
        if exec_tools.iter().any(|e| t.contains(e)) {
            score += 3;
        } else if write_tools.iter().any(|w| t.contains(w)) {
            score += 2;
        } else if net_tools.iter().any(|n| t.contains(n)) {
            score += 2;
        } else {
            score += 1;
        }
    }

    // Boundary risk scoring
    if m.boundaries.fs_deny.is_empty() {
        score += 3; // No deny rules is dangerous
    }
    if m.boundaries.net_deny.is_empty() && !m.boundaries.net_allow.is_empty() {
        score += 2; // Network access without deny rules
    }
    if !m.boundaries.cmd_allow.is_empty() {
        score += 2; // Command execution
    }

    // Rate limit risk
    if m.limits.max_calls_per_minute > 120 {
        score += 2;
    }

    // Classify
    Ok(match score {
        0..=3 => RiskLevel::Low,
        4..=7 => RiskLevel::Medium,
        8..=12 => RiskLevel::High,
        _ => RiskLevel::Critical,
    })
}

/// Create a new proposal for a mandate
pub fn create_proposal(
    proposer_did: &str,
    proposal_name: &str,
    mandate_body: &str,
    justification: &str,
    proposal_ttl_hours: u64,
) -> Result<Proposal, Box<dyn std::error::Error>> {
    let risk_level = assess_risk(mandate_body)?;
    let required_approvals = risk_level.required_approvals();

    let now = Utc::now();
    let expires = now + chrono::Duration::hours(proposal_ttl_hours as i64);
    let mandate_hash = hex::encode(Sha256::digest(mandate_body.as_bytes()));
    let proposal_id = uuid::Uuid::new_v4().to_string();

    let hash_input = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        proposal_id, proposer_did, mandate_hash,
        risk_level, required_approvals,
        now.to_rfc3339(), expires.to_rfc3339(),
    );
    let proposal_hash = hex::encode(Sha256::digest(hash_input.as_bytes()));

    Ok(Proposal {
        proposal_id,
        proposer_did: proposer_did.to_string(),
        proposal_name: proposal_name.to_string(),
        mandate_body: mandate_body.to_string(),
        mandate_hash,
        justification: justification.to_string(),
        risk_level,
        required_approvals,
        status: ProposalStatus::Pending,
        reviews: vec![],
        created_at: now.to_rfc3339(),
        expires_at: expires.to_rfc3339(),
        proposal_hash,
    })
}

/// Submit a review (approval or rejection) for a proposal
pub fn review_proposal(
    proposal: &mut Proposal,
    reviewer_secret_hex: &str,
    reviewer_name: &str,
    decision: ReviewDecision,
    reason: &str,
) -> Result<Review, Box<dyn std::error::Error>> {
    // Check proposal is still pending
    if proposal.status != ProposalStatus::Pending {
        return Err(format!("proposal is not pending (status: {})", proposal.status).into());
    }

    // Check proposal hasn't expired
    let expires = proposal.expires_at.parse::<chrono::DateTime<Utc>>()
        .map_err(|_| "invalid proposal expires_at")?;
    if Utc::now() >= expires {
        proposal.status = ProposalStatus::Expired;
        return Err("proposal has expired".into());
    }

    // Derive reviewer identity
    let secret_bytes = hex::decode(reviewer_secret_hex)?;
    let secret_arr: [u8; 32] = secret_bytes.as_slice().try_into()?;
    let signing_key = SigningKey::from_bytes(&secret_arr);
    let verifying_key = signing_key.verifying_key();
    let pubkey_hex = hex::encode(verifying_key.to_bytes());
    let reviewer_did = format!(
        "did:a2g:{}",
        bs58::encode(verifying_key.to_bytes()).into_string()
    );

    // Check reviewer hasn't already reviewed
    if proposal.reviews.iter().any(|r| r.reviewer_did == reviewer_did) {
        return Err("reviewer has already submitted a review".into());
    }

    let now = Utc::now();
    let review_id = uuid::Uuid::new_v4().to_string();

    // Phase 3: Capture what the reviewer saw
    let mandate_view_hash = hex::encode(Sha256::digest(proposal.mandate_body.as_bytes()));
    let approval_context_hash = hex::encode(Sha256::digest(
        format!("{}:{}:{}", mandate_view_hash, proposal.risk_level, proposal.proposal_hash).as_bytes()
    ));

    // Sign the review with domain separation (includes mandate_view_hash)
    let review_data = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        review_id, reviewer_did, proposal.proposal_hash,
        decision, reason, now.to_rfc3339(), mandate_view_hash,
    );
    let review_payload = format!("REVIEW:{}", review_data);
    let sig = signing_key.sign(review_payload.as_bytes());

    let review = Review {
        review_id,
        reviewer_did,
        reviewer_name: reviewer_name.to_string(),
        decision: decision.clone(),
        reason: reason.to_string(),
        reviewed_at: now.to_rfc3339(),
        signature: hex::encode(sig.to_bytes()),
        reviewer_pubkey: pubkey_hex,
        mandate_view_hash,
        approval_context_hash,
    };

    proposal.reviews.push(review.clone());

    // Update proposal status based on reviews
    match decision {
        ReviewDecision::Reject => {
            proposal.status = ProposalStatus::Rejected;
        }
        ReviewDecision::Approve => {
            let approvals = proposal.reviews.iter()
                .filter(|r| r.decision == ReviewDecision::Approve)
                .count();
            if approvals >= proposal.required_approvals {
                proposal.status = ProposalStatus::Approved;
            }
        }
        ReviewDecision::RequestChanges => {
            // Status stays Pending — changes requested but not rejected
        }
    }

    Ok(review)
}

/// Verify a review's signature
pub fn verify_review(review: &Review, proposal_hash: &str) -> Result<(), Box<dyn std::error::Error>> {
    let pubkey_bytes = hex::decode(&review.reviewer_pubkey)?;
    let pubkey_arr: [u8; 32] = pubkey_bytes.as_slice().try_into()
        .map_err(|_| "invalid reviewer public key")?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_arr)?;

    let sig_bytes = hex::decode(&review.signature)?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into()
        .map_err(|_| "invalid review signature")?;
    let signature = Signature::from_bytes(&sig_arr);

    let review_data = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        review.review_id, review.reviewer_did, proposal_hash,
        review.decision, review.reason, review.reviewed_at, review.mandate_view_hash,
    );
    let review_payload = format!("REVIEW:{}", review_data);

    verifying_key.verify(review_payload.as_bytes(), &signature)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;
    use crate::mandate;

    #[test]
    fn test_risk_assessment() {
        let (did, _, _) = identity::generate_agent_keypair();
        let template = mandate::generate_template("test", &did);
        let risk = assess_risk(&template).unwrap();
        // Default template has read_file + write_file + fs_deny rules
        assert!(risk == RiskLevel::Low || risk == RiskLevel::Medium);
    }

    #[test]
    fn test_proposal_approval_flow() {
        let (proposer_did, _, _) = identity::generate_agent_keypair();
        let (_, reviewer1_secret, _) = identity::generate_agent_keypair();

        let template = crate::mandate::generate_template("test-agent", &proposer_did);

        // Create proposal
        let mut proposal = create_proposal(
            &proposer_did, "Deploy test agent", &template,
            "Need read/write access for data processing", 48,
        ).unwrap();

        assert_eq!(proposal.status, ProposalStatus::Pending);

        // Submit approval
        let review = review_proposal(
            &mut proposal, &reviewer1_secret, "Alice",
            ReviewDecision::Approve, "Looks good, scope is appropriate",
        ).unwrap();

        // Low risk needs 1 approval — should be approved now
        if proposal.risk_level == RiskLevel::Low {
            assert_eq!(proposal.status, ProposalStatus::Approved);
        }

        // Verify the review signature
        verify_review(&review, &proposal.proposal_hash).unwrap();
    }

    #[test]
    fn test_proposal_rejection() {
        let (proposer_did, _, _) = identity::generate_agent_keypair();
        let (_, reviewer_secret, _) = identity::generate_agent_keypair();

        let template = crate::mandate::generate_template("test-agent", &proposer_did);

        let mut proposal = create_proposal(
            &proposer_did, "Risky agent", &template,
            "Needs broad access", 48,
        ).unwrap();

        review_proposal(
            &mut proposal, &reviewer_secret, "Bob",
            ReviewDecision::Reject, "Scope too broad, reduce tools",
        ).unwrap();

        assert_eq!(proposal.status, ProposalStatus::Rejected);
    }

    #[test]
    fn test_duplicate_reviewer_blocked() {
        let (proposer_did, _, _) = identity::generate_agent_keypair();
        let (_, reviewer_secret, _) = identity::generate_agent_keypair();

        let template = crate::mandate::generate_template("test-agent", &proposer_did);

        let mut proposal = create_proposal(
            &proposer_did, "Test agent", &template, "Testing", 48,
        ).unwrap();

        // Use RequestChanges so proposal stays Pending (Approve on low-risk would finalize it)
        review_proposal(
            &mut proposal, &reviewer_secret, "Alice",
            ReviewDecision::RequestChanges, "Needs minor tweaks",
        ).unwrap();

        // Same reviewer tries again — should be blocked
        let result = review_proposal(
            &mut proposal, &reviewer_secret, "Alice",
            ReviewDecision::Approve, "OK now",
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already submitted"));
    }
}
