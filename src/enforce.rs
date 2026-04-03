//! Enforcement Engine — Deterministic policy evaluation
//!
//! Every intent is evaluated through a strict pipeline:
//!   1. Mandate signature check
//!   2. TTL check
//!   3. Tool authorization check
//!   4. Boundary check (fs, network, command)
//!   5. Rate limit check
//!   6. ALLOW or DENY — no "maybe"

use crate::ledger::Ledger;
use crate::mandate::{self, Mandate};
use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Decision {
    Allow,
    Deny,
    Expired,
    /// Action exceeds current mandate scope — requires higher authority approval.
    /// The agent pauses. A human or higher-authority system reviews.
    Escalate,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decision::Allow => write!(f, "ALLOW"),
            Decision::Deny => write!(f, "DENY"),
            Decision::Expired => write!(f, "EXPIRED"),
            Decision::Escalate => write!(f, "ESCALATE"),
        }
    }
}

#[derive(Debug)]
pub struct Verdict {
    pub verdict_id: String,
    pub agent_did: String,
    pub agent_name: String,
    pub tool: String,
    pub params_hash: String,
    pub decision: Decision,
    pub policy_rule: String,
    pub evaluated_at: DateTime<Utc>,
    pub mandate_hash: String,
    pub proposal_hash: String,
    pub delegation_chain_hash: String,
    pub issuer_did: String,
    pub authority_level: String,
    pub scope_hash: String,
    pub correlation_id: String,
    pub parent_receipt_hash: String,
}

/// Run the deterministic enforcement pipeline
pub fn enforce(
    mandate_str: &str,
    tool: &str,
    params: &serde_json::Value,
    ledger: &Ledger,
) -> Result<Verdict, Box<dyn std::error::Error>> {
    let now = Utc::now();
    let params_hash = hex::encode(Sha256::digest(serde_json::to_string(params)?.as_bytes()));

    // Parse mandate
    let m: Mandate = toml::from_str(mandate_str)?;

    let agent_did = m.mandate.agent_did.clone();
    let agent_name = m.mandate.agent_name.clone();

    // ── Step 0: Revocation Check (S1 FIX) ──
    // Compute mandate_hash early for both revocation check and verdict
    let mandate_hash = hex::encode(Sha256::digest(mandate_str.as_bytes()));
    let proposal_hash = m.mandate.proposal_hash.clone();

    let make_verdict = |decision: Decision, rule: &str| -> Verdict {
        Verdict {
            verdict_id: uuid::Uuid::new_v4().to_string(),
            agent_did: agent_did.clone(),
            agent_name: agent_name.clone(),
            tool: tool.to_string(),
            params_hash: params_hash.clone(),
            decision,
            policy_rule: rule.to_string(),
            evaluated_at: now,
            mandate_hash: mandate_hash.clone(),
            proposal_hash: proposal_hash.clone(),
            delegation_chain_hash: String::new(),
            issuer_did: String::new(),
            authority_level: String::new(),
            scope_hash: String::new(),
            correlation_id: String::new(),
            parent_receipt_hash: String::new(),
        }
    };

    // ── Pre-check: Empty tool name ──
    if tool.is_empty() {
        return Ok(make_verdict(
            Decision::Deny,
            "invalid_request: tool name must not be empty",
        ));
    }
    if ledger.is_revoked(&m.mandate.agent_did, &mandate_hash)? {
        return Ok(make_verdict(
            Decision::Deny,
            "mandate_revoked: this mandate has been explicitly revoked",
        ));
    }

    // ── Step 1: Mandate Signature Check ──
    match mandate::verify_mandate(mandate_str) {
        Ok(_) => {}
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("expired") {
                return Ok(make_verdict(Decision::Expired, "mandate_ttl_exceeded"));
            }
            return Ok(make_verdict(
                Decision::Deny,
                &format!("mandate_invalid: {}", msg),
            ));
        }
    }

    // ── Step 2: TTL Check ──
    if !m.mandate.expires_at.is_empty() {
        if let Ok(expires) = m.mandate.expires_at.parse::<DateTime<Utc>>() {
            if now >= expires {
                return Ok(make_verdict(Decision::Expired, "mandate_ttl_exceeded"));
            }
        }
    }

    // ── Step 3: Tool Authorization ──
    if !m.capabilities.tools.contains(&tool.to_string()) {
        return Ok(make_verdict(
            Decision::Deny,
            &format!("tool_not_authorized: '{}' not in capabilities.tools", tool),
        ));
    }

    // ── Workspace Root Resolution ──
    // If mandate specifies a workspace_root, strip that prefix from canonicalized
    // paths before glob matching. This allows relative globs like "workspace/**"
    // to match absolute paths like "/home/agent/workspace/file.txt".
    let workspace_root = if !m.mandate.workspace_root.is_empty() {
        let root = canonicalize_path(&m.mandate.workspace_root);
        Some(root)
    } else {
        None
    };

    // ── Step 4: Boundary Check ──
    if let Some(raw_path) = params.get("path").and_then(|p| p.as_str()) {
        // S3 FIX: Canonicalize path to prevent traversal attacks (../../etc/passwd)
        let full_path = canonicalize_path(raw_path);

        // Strip workspace_root prefix for relative glob matching
        let path = if let Some(ref root) = workspace_root {
            full_path
                .strip_prefix(root)
                .map(|p| p.trim_start_matches('/'))
                .unwrap_or(&full_path)
                .to_string()
        } else {
            full_path.clone()
        };
        let path = &path;

        // 4a: Check deny rules first (deny ALWAYS wins)
        for pattern in &m.boundaries.fs_deny {
            if glob_matches(pattern, path) {
                return Ok(make_verdict(
                    Decision::Deny,
                    &format!(
                        "boundary_violation: path '{}' matches fs_deny '{}'",
                        path, pattern
                    ),
                ));
            }
        }

        // 4b: Check read boundaries
        if tool == "read_file" || tool == "read" {
            if !m.boundaries.fs_read.is_empty() {
                let allowed = m.boundaries.fs_read.iter().any(|p| glob_matches(p, path));
                if !allowed {
                    return Ok(make_verdict(
                        Decision::Deny,
                        &format!(
                            "boundary_violation: path '{}' not in fs_read boundaries",
                            path
                        ),
                    ));
                }
            }
        }

        // 4c: Check write boundaries
        if tool == "write_file" || tool == "write" {
            if !m.boundaries.fs_write.is_empty() {
                let allowed = m.boundaries.fs_write.iter().any(|p| glob_matches(p, path));
                if !allowed {
                    return Ok(make_verdict(
                        Decision::Deny,
                        &format!(
                            "boundary_violation: path '{}' not in fs_write boundaries",
                            path
                        ),
                    ));
                }
            }
        }
    }

    // 4d: Network boundaries
    if let Some(target) = params.get("url").and_then(|u| u.as_str()) {
        let host = extract_host(target);

        // Check deny first
        for pattern in &m.boundaries.net_deny {
            if pattern == "*" || glob_matches(pattern, &host) {
                // Check if explicitly allowed
                let allowed = m
                    .boundaries
                    .net_allow
                    .iter()
                    .any(|p| glob_matches(p, &host));
                if !allowed {
                    return Ok(make_verdict(
                        Decision::Deny,
                        &format!("boundary_violation: host '{}' blocked by net_deny", host),
                    ));
                }
            }
        }
    }

    // 4e: Command boundaries
    if let Some(cmd) = params.get("command").and_then(|c| c.as_str()) {
        // Check deny first
        for pattern in &m.boundaries.cmd_deny {
            if cmd.contains(pattern) || glob_matches(pattern, cmd) {
                return Ok(make_verdict(
                    Decision::Deny,
                    &format!(
                        "boundary_violation: command '{}' matches cmd_deny '{}'",
                        cmd, pattern
                    ),
                ));
            }
        }

        // Check allow
        if !m.boundaries.cmd_allow.is_empty() {
            let cmd_base = cmd.split_whitespace().next().unwrap_or(cmd);
            let allowed = m.boundaries.cmd_allow.iter().any(|p| p == cmd_base);
            if !allowed {
                return Ok(make_verdict(
                    Decision::Deny,
                    &format!(
                        "boundary_violation: command base '{}' not in cmd_allow",
                        cmd_base
                    ),
                ));
            }
        }
    }

    // ── Step 5: Jurisdiction Check ──
    if !m.jurisdiction.operating_hours.is_empty() {
        let (start_hour, start_min, end_hour, end_min) =
            validate_operating_hours(&m.jurisdiction.operating_hours)?;
        let current_hour = now.hour();
        let current_min = now.minute();
        let current_total = current_hour * 60 + current_min;
        let start_total = start_hour * 60 + start_min;
        let end_total = end_hour * 60 + end_min;

        if current_total < start_total || current_total > end_total {
            return Ok(make_verdict(
                Decision::Deny,
                &format!(
                    "jurisdiction_violation: current time {:02}:{:02} outside operating hours {}",
                    current_hour, current_min, m.jurisdiction.operating_hours
                ),
            ));
        }
    }

    // ── Step 6: Escalation Check ──
    if m.escalation.escalate_tools.contains(&tool.to_string()) {
        return Ok(make_verdict(
            Decision::Escalate,
            &format!(
                "escalation_required: tool '{}' requires approval from {}",
                tool,
                if m.escalation.escalate_to.is_empty() {
                    "higher authority"
                } else {
                    &m.escalation.escalate_to
                }
            ),
        ));
    }
    if let Some(raw_path) = params.get("path").and_then(|p| p.as_str()) {
        let full_epath = canonicalize_path(raw_path);

        // Strip workspace_root prefix for relative glob matching (same as boundary checks)
        let epath = if let Some(ref root) = workspace_root {
            full_epath
                .strip_prefix(root)
                .map(|p| p.trim_start_matches('/'))
                .unwrap_or(&full_epath)
                .to_string()
        } else {
            full_epath.clone()
        };
        let epath = &epath;

        for pattern in &m.escalation.escalate_paths {
            if glob_matches(pattern, epath) {
                return Ok(make_verdict(
                    Decision::Escalate,
                    &format!(
                        "escalation_required: path '{}' matches escalate_paths '{}'",
                        epath, pattern
                    ),
                ));
            }
        }
    }
    if let Some(target) = params.get("url").and_then(|u| u.as_str()) {
        let ehost = extract_host(target);
        for pattern in &m.escalation.escalate_hosts {
            if glob_matches(pattern, &ehost) {
                return Ok(make_verdict(
                    Decision::Escalate,
                    &format!(
                        "escalation_required: host '{}' matches escalate_hosts '{}'",
                        ehost, pattern
                    ),
                ));
            }
        }
    }

    // ── Step 7: Rate Limit Check ──
    let recent_count = ledger.count_recent(&m.mandate.agent_did, 60)?;
    if recent_count >= m.limits.max_calls_per_minute {
        return Ok(make_verdict(
            Decision::Deny,
            &format!(
                "rate_limit_exceeded: {} calls in last 60s (max: {})",
                recent_count, m.limits.max_calls_per_minute
            ),
        ));
    }

    // ── Step 8: ALLOW ──
    Ok(make_verdict(Decision::Allow, "all_checks_passed"))
}

/// Validate jurisdiction operating_hours format (HH:MM-HH:MM)
/// Returns tuple of (start_hour, start_min, end_hour, end_min) on success
fn validate_operating_hours(
    hours_str: &str,
) -> Result<(u32, u32, u32, u32), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = hours_str.split('-').collect();
    if parts.len() != 2 {
        return Err(format!(
            "invalid operating_hours format '{}': expected HH:MM-HH:MM",
            hours_str
        )
        .into());
    }
    let start = parts[0].trim();
    let end = parts[1].trim();

    let parse_time = |time_str: &str| -> Result<(u32, u32), Box<dyn std::error::Error>> {
        let time_parts: Vec<&str> = time_str.split(':').collect();
        if time_parts.len() != 2 {
            return Err(format!("invalid time '{}': expected HH:MM", time_str).into());
        }
        let hour: u32 = time_parts[0]
            .parse()
            .map_err(|_| format!("invalid hour in '{}'", time_str))?;
        let minute: u32 = time_parts[1]
            .parse()
            .map_err(|_| format!("invalid minute in '{}'", time_str))?;
        if hour > 23 {
            return Err(format!("hour {} exceeds 23 in '{}'", hour, time_str).into());
        }
        if minute > 59 {
            return Err(format!("minute {} exceeds 59 in '{}'", minute, time_str).into());
        }
        Ok((hour, minute))
    };

    let (sh, sm) = parse_time(start)?;
    let (eh, em) = parse_time(end)?;

    let start_total = sh * 60 + sm;
    let end_total = eh * 60 + em;
    if start_total >= end_total {
        return Err(format!(
            "operating_hours start '{}' must be before end '{}'",
            start, end
        )
        .into());
    }

    Ok((sh, sm, eh, em))
}

/// Canonicalize a path to prevent traversal attacks.
///
/// Resolves `.`, `..`, and double slashes without touching the filesystem.
/// If the path exists on disk, uses std::fs::canonicalize for maximum safety.
/// Otherwise, performs logical normalization.
fn canonicalize_path(raw: &str) -> String {
    // Try real filesystem canonicalization first (resolves symlinks too)
    if let Ok(canonical) = std::fs::canonicalize(raw) {
        return canonical.to_string_lossy().to_string();
    }

    // Fallback: logical normalization for paths that don't exist yet
    let is_absolute = raw.starts_with('/');
    let mut components: Vec<&str> = Vec::new();

    for part in raw.split('/') {
        match part {
            "" | "." => continue,
            ".." => {
                // Don't pop past root for absolute paths
                if !components.is_empty() && (is_absolute || components.last() != Some(&"..")) {
                    components.pop();
                } else if !is_absolute {
                    components.push("..");
                }
            }
            _ => components.push(part),
        }
    }

    let joined = components.join("/");
    if is_absolute {
        format!("/{}", joined)
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

/// Glob matching for path patterns
///
/// Supports:
///   **     — matches any number of path segments (including zero)
///   *      — matches any characters within a single segment
///   exact  — exact string match
fn glob_matches(pattern: &str, path: &str) -> bool {
    // Handle ** (match any depth)
    if pattern.contains("**") {
        let parts: Vec<&str> = pattern.splitn(2, "**").collect();
        if parts.len() == 2 {
            let prefix = parts[0].trim_end_matches('/');
            let suffix = parts[1].trim_start_matches('/');

            let path_matches_prefix = prefix.is_empty() || path.starts_with(prefix);
            if !path_matches_prefix {
                return false;
            }

            if suffix.is_empty() {
                return true;
            }

            // The suffix itself may contain * wildcards — match against the filename
            if suffix.contains('*') {
                // Extract the filename (last path component) and match suffix against it
                let filename = path.rsplit('/').next().unwrap_or(path);
                return simple_wildcard_match(suffix, filename);
            } else {
                return path.ends_with(suffix);
            }
        }
    }

    // Handle * (match single segment — no path separators)
    if pattern.contains('*') {
        return simple_wildcard_match(pattern, path);
    }

    // Exact match
    pattern == path
}

/// Match a simple wildcard pattern (single * only, no **)
fn simple_wildcard_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 2 {
        let prefix = parts[0];
        let suffix = parts[1];
        return text.starts_with(prefix)
            && text.ends_with(suffix)
            && text.len() >= prefix.len() + suffix.len();
    }

    // Multiple * — use recursive matching
    if parts.is_empty() {
        return true; // pattern is just "*"
    }

    // First part must be a prefix
    if !text.starts_with(parts[0]) {
        return false;
    }
    let mut remaining = &text[parts[0].len()..];

    // Middle parts must appear in order
    for part in &parts[1..parts.len() - 1] {
        if let Some(pos) = remaining.find(part) {
            remaining = &remaining[pos + part.len()..];
        } else {
            return false;
        }
    }

    // Last part must be a suffix
    let last = parts[parts.len() - 1];
    remaining.ends_with(last)
}

/// Extract hostname from a URL
fn extract_host(url: &str) -> String {
    url.replace("https://", "")
        .replace("http://", "")
        .split('/')
        .next()
        .unwrap_or(url)
        .split(':')
        .next()
        .unwrap_or(url)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_matches() {
        assert!(glob_matches("/etc/**", "/etc/passwd"));
        assert!(glob_matches("/etc/**", "/etc/ssh/sshd_config"));
        assert!(!glob_matches("/etc/**", "/home/user/file.txt"));
        assert!(glob_matches("**/*.env", "/home/user/.env"));
        assert!(glob_matches("**/*secret*", "/app/secret_keys.json"));
        assert!(glob_matches("*.wikipedia.org", "en.wikipedia.org"));
    }

    #[test]
    fn test_canonicalize_path() {
        // Basic traversal attack
        assert_eq!(
            canonicalize_path("/home/user/../../etc/passwd"),
            "/etc/passwd"
        );
        // Double dots at start of absolute path
        assert_eq!(canonicalize_path("/../../../etc/shadow"), "/etc/shadow");
        // Current dir references
        assert_eq!(
            canonicalize_path("/home/./user/./file.txt"),
            "/home/user/file.txt"
        );
        // Double slashes
        assert_eq!(
            canonicalize_path("/home//user///file.txt"),
            "/home/user/file.txt"
        );
        // Relative path traversal
        assert_eq!(
            canonicalize_path("workspace/../../../etc/passwd"),
            "../../etc/passwd"
        );
        // Clean path stays clean
        assert_eq!(
            canonicalize_path("/home/user/file.txt"),
            "/home/user/file.txt"
        );
    }

    #[test]
    fn test_extract_host() {
        assert_eq!(
            extract_host("https://api.openai.com/v1/chat"),
            "api.openai.com"
        );
        assert_eq!(extract_host("http://localhost:8080/test"), "localhost");
    }

    #[test]
    fn test_validate_operating_hours() {
        // Valid
        assert!(validate_operating_hours("09:00-17:00").is_ok());
        assert!(validate_operating_hours("00:00-23:59").is_ok());
        let (sh, sm, eh, em) = validate_operating_hours("09:00-17:00").unwrap();
        assert_eq!((sh, sm, eh, em), (9, 0, 17, 0));
        // Invalid
        assert!(validate_operating_hours("25:00-17:00").is_err());
        assert!(validate_operating_hours("09:00").is_err());
        assert!(validate_operating_hours("17:00-09:00").is_err());
        assert!(validate_operating_hours("09:60-17:00").is_err());
    }

    #[test]
    fn test_tampered_mandate_denied() {
        // Create and sign a valid mandate, then tamper with it
        let (agent_did, _, _) = crate::identity::generate_agent_keypair();
        let (_, sov_secret, _) = crate::identity::generate_agent_keypair();
        let template = crate::mandate::generate_template("tamper-test", &agent_did);
        let signed = crate::mandate::sign_mandate(&template, &sov_secret, 24).unwrap();

        // Tamper: replace "read_file" with "execute" in the signed mandate
        let tampered = signed.replace("read_file", "execute");

        let db = crate::ledger::Ledger::open(&std::path::PathBuf::from(":memory:")).unwrap();
        let params: serde_json::Value = serde_json::from_str("{}").unwrap();
        let result = enforce(&tampered, "execute", &params, &db).unwrap();
        assert_eq!(result.decision, Decision::Deny);
        assert!(result.policy_rule.contains("mandate_invalid"));
    }

    #[test]
    fn test_workspace_root_relative_match() {
        // Set workspace_root to /home/agent/workspace and verify relative glob matches absolute path
        let (agent_did, _, _) = crate::identity::generate_agent_keypair();
        let (_, sov_secret, _) = crate::identity::generate_agent_keypair();
        let mut template = crate::mandate::generate_template("workspace-test", &agent_did);

        // Replace workspace_root with an absolute path
        template = template.replace(
            "workspace_root = \"\"",
            "workspace_root = \"/home/agent/workspace\"",
        );

        // Set boundaries to use relative glob
        template = template.replace("fs_read = [\"workspace/**\"]", "fs_read = [\"**/*.txt\"]");

        let signed = crate::mandate::sign_mandate(&template, &sov_secret, 24).unwrap();
        let db = crate::ledger::Ledger::open(&std::path::PathBuf::from(":memory:")).unwrap();

        // Try to read /home/agent/workspace/data/test.txt (should match "**/*.txt" after stripping workspace root)
        let params: serde_json::Value = serde_json::json!({
            "path": "/home/agent/workspace/data/test.txt"
        });

        let result = enforce(&signed, "read_file", &params, &db).unwrap();
        assert_eq!(
            result.decision,
            Decision::Allow,
            "Expected ALLOW for file within workspace matching pattern"
        );
    }

    #[test]
    fn test_workspace_root_empty_fallback() {
        // With empty workspace_root, verify current behavior (absolute path matching)
        let (agent_did, _, _) = crate::identity::generate_agent_keypair();
        let (_, sov_secret, _) = crate::identity::generate_agent_keypair();
        let mut template = crate::mandate::generate_template("empty-workspace", &agent_did);

        // Leave workspace_root empty
        template = template.replace(
            "fs_read = [\"workspace/**\"]",
            "fs_read = [\"/home/agent/workspace/**\"]",
        );

        let signed = crate::mandate::sign_mandate(&template, &sov_secret, 24).unwrap();
        let db = crate::ledger::Ledger::open(&std::path::PathBuf::from(":memory:")).unwrap();

        // Try to read /home/agent/workspace/data/test.txt (should match absolute pattern)
        let params: serde_json::Value = serde_json::json!({
            "path": "/home/agent/workspace/data/test.txt"
        });

        let result = enforce(&signed, "read_file", &params, &db).unwrap();
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_workspace_root_deny_still_works() {
        // Verify fs_deny still catches absolute paths even with workspace_root set
        let (agent_did, _, _) = crate::identity::generate_agent_keypair();
        let (_, sov_secret, _) = crate::identity::generate_agent_keypair();
        let mut template = crate::mandate::generate_template("deny-test", &agent_did);

        // Set workspace_root
        template = template.replace(
            "workspace_root = \"\"",
            "workspace_root = \"/home/agent/workspace\"",
        );

        // Keep fs_deny with absolute path
        // (default already has "/etc/**", etc.)

        let signed = crate::mandate::sign_mandate(&template, &sov_secret, 24).unwrap();
        let db = crate::ledger::Ledger::open(&std::path::PathBuf::from(":memory:")).unwrap();

        // Try to read /etc/passwd (should be denied)
        let params: serde_json::Value = serde_json::json!({
            "path": "/etc/passwd"
        });

        let result = enforce(&signed, "read_file", &params, &db).unwrap();
        assert_eq!(
            result.decision,
            Decision::Deny,
            "Expected DENY for /etc/passwd matching fs_deny"
        );
        assert!(result.policy_rule.contains("boundary_violation"));
    }
}
