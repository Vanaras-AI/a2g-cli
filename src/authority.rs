//! Authority Governance — Layer 0: Who is allowed to govern?
//!
//! This module implements hierarchical authority chains with scoped delegation.
//! A root authority delegates to department authorities who delegate to team
//! authorities. Each level can only issue mandates within its own scope.
//!
//! The authority chain answers: "Who decided this agent should have these powers,
//! and were they authorized to make that decision?"

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Authority level in the governance hierarchy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum AuthorityLevel {
    /// Organization root — can delegate anything
    Root,
    /// Department — scoped to a domain (e.g., "engineering", "finance")
    Department,
    /// Team — scoped to specific tools and boundaries
    Team,
    /// Operator — can only issue mandates within pre-approved templates
    Operator,
}

impl std::fmt::Display for AuthorityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorityLevel::Root => write!(f, "ROOT"),
            AuthorityLevel::Department => write!(f, "DEPARTMENT"),
            AuthorityLevel::Team => write!(f, "TEAM"),
            AuthorityLevel::Operator => write!(f, "OPERATOR"),
        }
    }
}

/// A delegation certificate — proof that authority was granted
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    /// Unique delegation ID
    pub delegation_id: String,
    /// DID of the authority granting the delegation
    pub grantor_did: String,
    /// DID of the authority receiving the delegation
    pub grantee_did: String,
    /// Human-readable name of the grantee
    pub grantee_name: String,
    /// Authority level being granted
    pub level: AuthorityLevel,
    /// Scope constraints — what this authority can govern
    pub scope: AuthorityScope,
    /// Jurisdiction binding
    pub jurisdiction: Jurisdiction,
    /// When this delegation was created
    pub delegated_at: String,
    /// When this delegation expires
    pub expires_at: String,
    /// ed25519 signature by the grantor
    pub signature: String,
    /// Grantor's public key (for verification)
    pub grantor_pubkey: String,
    /// SHA-256 hash of the parent delegation (chain linking)
    pub parent_delegation_hash: String,
    /// SHA-256 hash covering all fields
    pub delegation_hash: String,
}

/// What an authority is allowed to govern
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthorityScope {
    /// Tools this authority can include in mandates
    pub allowed_tools: Vec<String>,
    /// Maximum TTL (hours) this authority can grant
    pub max_ttl_hours: u64,
    /// Filesystem paths this authority can grant access to
    pub fs_scope: Vec<String>,
    /// Network hosts this authority can grant access to
    pub net_scope: Vec<String>,
    /// Commands this authority can authorize
    pub cmd_scope: Vec<String>,
    /// Maximum rate limit this authority can set
    pub max_rate_limit: u64,
    /// Maximum number of active mandates this authority can have
    pub max_active_mandates: u64,
}

/// Jurisdictional binding for governance decisions
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Jurisdiction {
    /// Geographic region (e.g., "US", "CA", "EU", "APAC")
    pub region: String,
    /// Regulatory framework (e.g., "GDPR", "CCPA", "PIPEDA", "SOC2")
    pub regulatory_framework: String,
    /// Environment (e.g., "production", "staging", "development")
    pub environment: String,
    /// Classification level (e.g., "public", "internal", "confidential", "restricted")
    pub classification: String,
    /// Operating hours in UTC (empty = 24/7)
    /// Format: "HH:MM-HH:MM" (e.g., "09:00-17:00")
    pub operating_hours: String,
}

/// Result of validating a delegation chain
pub struct ChainValidation {
    pub valid: bool,
    pub chain_depth: usize,
    pub root_did: String,
    pub effective_scope: AuthorityScope,
    pub effective_jurisdiction: Jurisdiction,
    pub reason: String,
}

/// Create a root delegation (self-signed by the organization root authority)
pub fn create_root_delegation(
    root_secret_hex: &str,
    root_name: &str,
    scope: AuthorityScope,
    jurisdiction: Jurisdiction,
    ttl_hours: u64,
) -> Result<Delegation, Box<dyn std::error::Error>> {
    let secret_bytes = hex::decode(root_secret_hex)?;
    let secret_arr: [u8; 32] = secret_bytes.as_slice().try_into()?;
    let signing_key = SigningKey::from_bytes(&secret_arr);
    let verifying_key = signing_key.verifying_key();
    let pubkey_hex = hex::encode(verifying_key.to_bytes());
    let root_did = format!("did:a2g:{}", bs58::encode(verifying_key.to_bytes()).into_string());

    let now = Utc::now();
    let expires = now + Duration::hours(ttl_hours as i64);
    let delegation_id = uuid::Uuid::new_v4().to_string();

    // Root delegation: grantor == grantee (self-delegation)
    let genesis_hash = "0".repeat(64);

    // Build the content to hash and sign
    let delegation_data = format!(
        "{}:{}:{}:{}:{:?}:{:?}:{:?}:{}:{}:{}",
        delegation_id, root_did, root_did, root_name,
        AuthorityLevel::Root, scope, jurisdiction,
        now.to_rfc3339(), expires.to_rfc3339(), genesis_hash,
    );
    let sig_payload = format!("DELEGATION:{}", delegation_data);
    let content_hash = hex::encode(Sha256::digest(sig_payload.as_bytes()));
    let sig = signing_key.sign(content_hash.as_bytes());

    Ok(Delegation {
        delegation_id,
        grantor_did: root_did.clone(),
        grantee_did: root_did,
        grantee_name: root_name.to_string(),
        level: AuthorityLevel::Root,
        scope,
        jurisdiction,
        delegated_at: now.to_rfc3339(),
        expires_at: expires.to_rfc3339(),
        signature: hex::encode(sig.to_bytes()),
        grantor_pubkey: pubkey_hex,
        parent_delegation_hash: genesis_hash,
        delegation_hash: content_hash,
    })
}

/// Delegate authority to a subordinate
pub fn delegate(
    grantor_secret_hex: &str,
    parent_delegation: &Delegation,
    grantee_did: &str,
    grantee_name: &str,
    level: AuthorityLevel,
    scope: AuthorityScope,
    jurisdiction: Jurisdiction,
    ttl_hours: u64,
) -> Result<Delegation, Box<dyn std::error::Error>> {
    // Verify the grantor's level allows this delegation
    // Hierarchy: Root(0) > Department(1) > Team(2) > Operator(3)
    // A higher numeric value means lower authority, so child level must be > parent level
    if level <= parent_delegation.level {
        return Err(format!(
            "cannot delegate {} authority from {} level",
            level, parent_delegation.level
        ).into());
    }

    // Verify scope is a subset of parent's scope
    validate_scope_subset(&scope, &parent_delegation.scope)?;

    // Verify TTL doesn't exceed parent's remaining TTL
    let parent_expires = parent_delegation.expires_at.parse::<DateTime<Utc>>()
        .map_err(|_| "invalid parent expires_at")?;
    let now = Utc::now();
    let parent_remaining_hours = (parent_expires - now).num_hours();
    if ttl_hours as i64 > parent_remaining_hours {
        return Err(format!(
            "requested TTL ({} hours) exceeds parent's remaining TTL ({} hours)",
            ttl_hours, parent_remaining_hours
        ).into());
    }

    let secret_bytes = hex::decode(grantor_secret_hex)?;
    let secret_arr: [u8; 32] = secret_bytes.as_slice().try_into()?;
    let signing_key = SigningKey::from_bytes(&secret_arr);
    let verifying_key = signing_key.verifying_key();
    let pubkey_hex = hex::encode(verifying_key.to_bytes());

    // Verify key-DID binding: signing key must match parent's grantee_did
    let grantor_did_from_key = format!(
        "did:a2g:{}",
        bs58::encode(verifying_key.to_bytes()).into_string()
    );
    if grantor_did_from_key != parent_delegation.grantee_did {
        return Err(format!(
            "key-DID mismatch: signing key derives to '{}' but parent grantee is '{}'",
            grantor_did_from_key, parent_delegation.grantee_did
        ).into());
    }

    let expires = now + Duration::hours(ttl_hours as i64);
    let delegation_id = uuid::Uuid::new_v4().to_string();

    let delegation_data = format!(
        "{}:{}:{}:{}:{:?}:{:?}:{:?}:{}:{}:{}",
        delegation_id, parent_delegation.grantee_did, grantee_did, grantee_name,
        level, scope, jurisdiction,
        now.to_rfc3339(), expires.to_rfc3339(), parent_delegation.delegation_hash,
    );
    let sig_payload = format!("DELEGATION:{}", delegation_data);
    let content_hash = hex::encode(Sha256::digest(sig_payload.as_bytes()));
    let sig = signing_key.sign(content_hash.as_bytes());

    Ok(Delegation {
        delegation_id,
        grantor_did: parent_delegation.grantee_did.clone(),
        grantee_did: grantee_did.to_string(),
        grantee_name: grantee_name.to_string(),
        level,
        scope,
        jurisdiction,
        delegated_at: now.to_rfc3339(),
        expires_at: expires.to_rfc3339(),
        signature: hex::encode(sig.to_bytes()),
        grantor_pubkey: pubkey_hex,
        parent_delegation_hash: parent_delegation.delegation_hash.clone(),
        delegation_hash: content_hash,
    })
}

/// Verify a single delegation's signature and TTL
pub fn verify_delegation(delegation: &Delegation) -> Result<(), Box<dyn std::error::Error>> {
    // Verify signature
    let pubkey_bytes = hex::decode(&delegation.grantor_pubkey)?;
    let pubkey_arr: [u8; 32] = pubkey_bytes.as_slice().try_into()
        .map_err(|_| "invalid public key length")?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_arr)?;

    let sig_bytes = hex::decode(&delegation.signature)?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into()
        .map_err(|_| "invalid signature length")?;
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key.verify(delegation.delegation_hash.as_bytes(), &signature)?;

    // Note: delegation_hash was already computed with "DELEGATION:" domain prefix during creation,
    // so verification uses the hash directly

    // Verify TTL
    let expires = delegation.expires_at.parse::<DateTime<Utc>>()
        .map_err(|_| "invalid expires_at")?;
    if Utc::now() >= expires {
        return Err("delegation expired".into());
    }

    Ok(())
}

/// Verify a complete delegation chain from leaf to root
pub fn verify_chain(chain: &[Delegation]) -> Result<ChainValidation, Box<dyn std::error::Error>> {
    if chain.is_empty() {
        return Err("empty delegation chain".into());
    }

    // First entry must be root (self-delegation)
    let root = &chain[0];
    if root.grantor_did != root.grantee_did {
        return Err("chain root is not a self-delegation".into());
    }
    if root.level != AuthorityLevel::Root {
        return Err("chain root is not ROOT level".into());
    }
    if root.parent_delegation_hash != "0".repeat(64) {
        return Err("chain root does not point to genesis".into());
    }

    // Verify each delegation
    for (i, d) in chain.iter().enumerate() {
        verify_delegation(d)?;

        // Verify chain linking (except root)
        if i > 0 {
            if d.parent_delegation_hash != chain[i - 1].delegation_hash {
                return Err(format!(
                    "chain broken at delegation {}: parent_hash mismatch", i
                ).into());
            }
            // Verify grantor matches previous grantee
            if d.grantor_did != chain[i - 1].grantee_did {
                return Err(format!(
                    "chain broken at delegation {}: grantor is not previous grantee", i
                ).into());
            }
            // Verify authority level decreases (numeric value increases: Root(0) < Dept(1) < Team(2) < Op(3))
            if d.level <= chain[i - 1].level {
                return Err(format!(
                    "chain broken at delegation {}: level does not decrease", i
                ).into());
            }
        }
    }

    // Compute effective scope (intersection of all scopes in chain)
    let effective_scope = compute_effective_scope(chain);
    let leaf = chain.last().unwrap();

    Ok(ChainValidation {
        valid: true,
        chain_depth: chain.len(),
        root_did: root.grantee_did.clone(),
        effective_scope,
        effective_jurisdiction: leaf.jurisdiction.clone(),
        reason: "chain valid".to_string(),
    })
}

/// Validate that a mandate's permissions are within the authority's scope
pub fn validate_mandate_against_authority(
    mandate_str: &str,
    delegation: &Delegation,
) -> Result<(), Box<dyn std::error::Error>> {
    let m: crate::mandate::Mandate = toml::from_str(mandate_str)?;

    // Check tools are within scope
    for tool in &m.capabilities.tools {
        if !delegation.scope.allowed_tools.is_empty()
            && !delegation.scope.allowed_tools.contains(tool)
        {
            return Err(format!(
                "authority scope violation: tool '{}' not in authority's allowed_tools", tool
            ).into());
        }
    }

    // Check rate limit doesn't exceed authority's max
    if delegation.scope.max_rate_limit > 0
        && m.limits.max_calls_per_minute > delegation.scope.max_rate_limit
    {
        return Err(format!(
            "authority scope violation: rate limit {} exceeds authority max {}",
            m.limits.max_calls_per_minute, delegation.scope.max_rate_limit
        ).into());
    }

    // Check jurisdiction context
    check_jurisdiction(&delegation.jurisdiction)?;

    Ok(())
}

/// Check if current context matches jurisdiction constraints
pub fn check_jurisdiction(jurisdiction: &Jurisdiction) -> Result<(), Box<dyn std::error::Error>> {
    // Check operating hours if specified
    if !jurisdiction.operating_hours.is_empty() {
        let now = Utc::now();
        let hour_min = now.format("%H:%M").to_string();

        let parts: Vec<&str> = jurisdiction.operating_hours.split('-').collect();
        if parts.len() == 2 {
            let start = parts[0];
            let end = parts[1];
            if hour_min < start.to_string() || hour_min > end.to_string() {
                return Err(format!(
                    "jurisdiction violation: current time {} is outside operating hours {}",
                    hour_min, jurisdiction.operating_hours
                ).into());
            }
        }
    }

    Ok(())
}

/// Compute effective scope as intersection of all scopes in chain
fn compute_effective_scope(chain: &[Delegation]) -> AuthorityScope {
    if chain.is_empty() {
        return AuthorityScope::default();
    }

    let mut scope = chain[0].scope.clone();

    for d in &chain[1..] {
        // Tools: intersection
        if !d.scope.allowed_tools.is_empty() {
            if scope.allowed_tools.is_empty() {
                scope.allowed_tools = d.scope.allowed_tools.clone();
            } else {
                scope.allowed_tools.retain(|t| d.scope.allowed_tools.contains(t));
            }
        }

        // TTL: minimum
        if d.scope.max_ttl_hours > 0 {
            scope.max_ttl_hours = scope.max_ttl_hours.min(d.scope.max_ttl_hours);
        }

        // Rate limit: minimum
        if d.scope.max_rate_limit > 0 {
            scope.max_rate_limit = scope.max_rate_limit.min(d.scope.max_rate_limit);
        }

        // Active mandates: minimum
        if d.scope.max_active_mandates > 0 {
            scope.max_active_mandates = scope.max_active_mandates.min(d.scope.max_active_mandates);
        }
    }

    scope
}

/// Validate that a requested scope is a subset of the parent scope
fn validate_scope_subset(
    child: &AuthorityScope,
    parent: &AuthorityScope,
) -> Result<(), Box<dyn std::error::Error>> {
    // If parent has tool restrictions, child must be a subset
    if !parent.allowed_tools.is_empty() {
        for tool in &child.allowed_tools {
            if !parent.allowed_tools.contains(tool) {
                return Err(format!(
                    "scope violation: tool '{}' not in parent's allowed_tools", tool
                ).into());
            }
        }
    }

    // Child TTL cannot exceed parent TTL
    if parent.max_ttl_hours > 0 && child.max_ttl_hours > parent.max_ttl_hours {
        return Err(format!(
            "scope violation: max_ttl_hours {} exceeds parent's {}",
            child.max_ttl_hours, parent.max_ttl_hours
        ).into());
    }

    // Child rate limit cannot exceed parent
    if parent.max_rate_limit > 0 && child.max_rate_limit > parent.max_rate_limit {
        return Err(format!(
            "scope violation: max_rate_limit {} exceeds parent's {}",
            child.max_rate_limit, parent.max_rate_limit
        ).into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity;

    fn test_scope() -> AuthorityScope {
        AuthorityScope {
            allowed_tools: vec!["read_file".into(), "write_file".into(), "http_get".into()],
            max_ttl_hours: 720,
            fs_scope: vec!["./workspace/**".into()],
            net_scope: vec!["*.internal.corp".into()],
            cmd_scope: vec![],
            max_rate_limit: 120,
            max_active_mandates: 50,
        }
    }

    fn test_jurisdiction() -> Jurisdiction {
        Jurisdiction {
            region: "US".into(),
            regulatory_framework: "SOC2".into(),
            environment: "production".into(),
            classification: "internal".into(),
            operating_hours: String::new(), // 24/7 for tests
        }
    }

    #[test]
    fn test_root_delegation() {
        let (_, secret, _) = identity::generate_agent_keypair();
        let root = create_root_delegation(
            &secret, "Org Root", test_scope(), test_jurisdiction(), 720,
        ).unwrap();

        assert_eq!(root.level, AuthorityLevel::Root);
        assert_eq!(root.grantor_did, root.grantee_did);
        assert_eq!(root.parent_delegation_hash, "0".repeat(64));
        verify_delegation(&root).unwrap();
    }

    #[test]
    fn test_delegation_chain() {
        let (_, root_secret, _) = identity::generate_agent_keypair();
        let (dept_did, dept_secret, _) = identity::generate_agent_keypair();
        let (team_did, _, _) = identity::generate_agent_keypair();

        // Root delegates to department
        let root = create_root_delegation(
            &root_secret, "Org Root", test_scope(), test_jurisdiction(), 720,
        ).unwrap();

        let dept_scope = AuthorityScope {
            allowed_tools: vec!["read_file".into(), "write_file".into()],
            max_ttl_hours: 168,
            max_rate_limit: 60,
            max_active_mandates: 20,
            ..Default::default()
        };

        let dept = delegate(
            &root_secret, &root, &dept_did, "Engineering",
            AuthorityLevel::Department, dept_scope.clone(), test_jurisdiction(), 168,
        ).unwrap();

        // Department delegates to team
        let team_scope = AuthorityScope {
            allowed_tools: vec!["read_file".into()],
            max_ttl_hours: 24,
            max_rate_limit: 30,
            max_active_mandates: 10,
            ..Default::default()
        };

        let team = delegate(
            &dept_secret, &dept, &team_did, "Backend Team",
            AuthorityLevel::Team, team_scope, test_jurisdiction(), 24,
        ).unwrap();

        // Verify the full chain
        let chain = vec![root, dept, team];
        let validation = verify_chain(&chain).unwrap();
        assert!(validation.valid);
        assert_eq!(validation.chain_depth, 3);

        // Effective scope should be intersection
        assert_eq!(validation.effective_scope.allowed_tools, vec!["read_file".to_string()]);
        assert_eq!(validation.effective_scope.max_ttl_hours, 24);
        assert_eq!(validation.effective_scope.max_rate_limit, 30);
    }

    #[test]
    fn test_scope_violation() {
        let (_, root_secret, _) = identity::generate_agent_keypair();
        let (dept_did, _, _) = identity::generate_agent_keypair();

        let root_scope = AuthorityScope {
            allowed_tools: vec!["read_file".into()],
            max_ttl_hours: 24,
            ..Default::default()
        };

        let root = create_root_delegation(
            &root_secret, "Root", root_scope, test_jurisdiction(), 720,
        ).unwrap();

        // Try to delegate with tools not in parent scope
        let bad_scope = AuthorityScope {
            allowed_tools: vec!["read_file".into(), "delete_file".into()],
            max_ttl_hours: 24,
            ..Default::default()
        };

        let result = delegate(
            &root_secret, &root, &dept_did, "Bad Dept",
            AuthorityLevel::Department, bad_scope, test_jurisdiction(), 24,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("scope violation"));
    }

    #[test]
    fn test_expired_delegation_rejected() {
        let (_, secret, _) = identity::generate_agent_keypair();
        // Create a delegation with 0 hours TTL (already expired)
        let result = create_root_delegation(
            &secret, "Expired Root",
            AuthorityScope { max_ttl_hours: 1, ..Default::default() },
            Jurisdiction::default(),
            0, // 0 hours = expires immediately
        );
        // The delegation itself will be created but verify_delegation should fail
        if let Ok(deleg) = result {
            // Wait a tiny bit or check - with 0 TTL it should be expired
            let verify = verify_delegation(&deleg);
            assert!(verify.is_err());
        }
    }
}
