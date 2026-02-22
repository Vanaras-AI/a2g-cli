//! Declarative Policy Test Harness — Golden case testing for mandate enforcement
//!
//! Allows defining test cases as TOML: "given this mandate + tool call → expected decision".
//! Each test specifies a mandate (inline or file path), a tool call, and the expected
//! enforcement outcome. The harness runs each case through the real enforce() pipeline.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// A single declarative policy test case
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyTest {
    pub test_id: String,
    #[serde(default)]
    pub description: String,
    /// Path to mandate TOML file (relative to suite file), OR inline mandate body
    #[serde(default)]
    pub mandate_path: String,
    /// Inline mandate TOML (used if mandate_path is empty)
    #[serde(default)]
    pub mandate_inline: String,
    /// Tool name to enforce
    pub tool: String,
    /// JSON params for the tool call
    #[serde(default = "default_params")]
    pub params: String,
    /// Expected decision: "ALLOW", "DENY", "ESCALATE", "EXPIRED"
    pub expected_decision: String,
    /// Expected policy rule that triggers (optional — if empty, not checked)
    #[serde(default)]
    pub expected_rule: String,
    /// Tags for filtering (e.g., "boundary", "rate-limit")
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_params() -> String {
    "{}".to_string()
}

/// Result of running a single policy test
#[derive(Debug, Serialize)]
pub struct TestResult {
    pub test_id: String,
    pub passed: bool,
    pub expected_decision: String,
    pub expected_rule: String,
    pub actual_decision: String,
    pub actual_rule: String,
    pub reason: String,
}

/// TOML structure for a test suite file
#[derive(Debug, Deserialize)]
struct TestSuiteFile {
    #[serde(default)]
    suite: SuiteMeta,
    #[serde(rename = "test")]
    tests: Vec<PolicyTest>,
}

#[derive(Debug, Deserialize, Default)]
struct SuiteMeta {
    #[serde(default)]
    #[allow(dead_code)]
    name: String,
    #[serde(default)]
    #[allow(dead_code)]
    description: String,
}

/// Load a test suite from a TOML file
pub fn load_test_suite(path: &Path) -> Result<Vec<PolicyTest>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read test suite '{}': {}", path.display(), e))?;
    let suite: TestSuiteFile = toml::from_str(&content)
        .map_err(|e| format!("failed to parse test suite '{}': {}", path.display(), e))?;
    Ok(suite.tests)
}

/// Run a suite of policy tests, optionally filtered by tag
pub fn run_suite(tests: &[PolicyTest], tag: Option<&str>, ledger_path: &Path) -> Vec<TestResult> {
    let filtered: Vec<&PolicyTest> = if let Some(t) = tag {
        tests.iter().filter(|test| test.tags.contains(&t.to_string())).collect()
    } else {
        tests.iter().collect()
    };

    filtered.iter().map(|test| run_single_test(test, ledger_path)).collect()
}

/// Run a single policy test through the real enforcement pipeline
fn run_single_test(test: &PolicyTest, ledger_path: &Path) -> TestResult {
    let fail = |reason: String| TestResult {
        test_id: test.test_id.clone(),
        passed: false,
        expected_decision: test.expected_decision.clone(),
        expected_rule: test.expected_rule.clone(),
        actual_decision: String::new(),
        actual_rule: String::new(),
        reason,
    };

    // Load mandate (inline or from file)
    let mandate_str = if !test.mandate_inline.is_empty() {
        test.mandate_inline.clone()
    } else if !test.mandate_path.is_empty() {
        match std::fs::read_to_string(&test.mandate_path) {
            Ok(s) => s,
            Err(e) => return fail(format!("failed to read mandate '{}': {}", test.mandate_path, e)),
        }
    } else {
        return fail("no mandate_path or mandate_inline specified".to_string());
    };

    // Parse params
    let params: serde_json::Value = match serde_json::from_str(&test.params) {
        Ok(p) => p,
        Err(e) => return fail(format!("invalid params JSON: {}", e)),
    };

    // Open ledger (use in-memory if path is ":memory:")
    let db = if ledger_path.to_str() == Some(":memory:") {
        match crate::ledger::Ledger::open(Path::new(":memory:")) {
            Ok(db) => db,
            Err(e) => return fail(format!("failed to open ledger: {}", e)),
        }
    } else {
        match crate::ledger::Ledger::open(ledger_path) {
            Ok(db) => db,
            Err(e) => return fail(format!("failed to open ledger: {}", e)),
        }
    };

    // Run enforcement
    match crate::enforce::enforce(&mandate_str, &test.tool, &params, &db) {
        Ok(verdict) => {
            let actual_decision = format!("{}", verdict.decision);
            let actual_rule = verdict.policy_rule.clone();

            let decision_match = actual_decision.to_uppercase() == test.expected_decision.to_uppercase();
            let rule_match = test.expected_rule.is_empty() || actual_rule == test.expected_rule;

            let passed = decision_match && rule_match;
            let reason = if !decision_match {
                format!("decision mismatch: expected {} got {}", test.expected_decision, actual_decision)
            } else if !rule_match {
                format!("rule mismatch: expected '{}' got '{}'", test.expected_rule, actual_rule)
            } else {
                String::new()
            };

            TestResult {
                test_id: test.test_id.clone(),
                passed,
                expected_decision: test.expected_decision.clone(),
                expected_rule: test.expected_rule.clone(),
                actual_decision,
                actual_rule,
                reason,
            }
        }
        Err(e) => {
            // Some errors are expected — e.g., expired mandates produce errors
            let error_str = e.to_string();
            let expected_upper = test.expected_decision.to_uppercase();

            // Check if the error matches the expected outcome
            if expected_upper == "EXPIRED" && error_str.contains("expired") {
                TestResult {
                    test_id: test.test_id.clone(),
                    passed: true,
                    expected_decision: test.expected_decision.clone(),
                    expected_rule: test.expected_rule.clone(),
                    actual_decision: "EXPIRED".to_string(),
                    actual_rule: "ttl_expired".to_string(),
                    reason: String::new(),
                }
            } else if expected_upper == "REVOKED" && error_str.contains("revoked") {
                TestResult {
                    test_id: test.test_id.clone(),
                    passed: true,
                    expected_decision: test.expected_decision.clone(),
                    expected_rule: test.expected_rule.clone(),
                    actual_decision: "REVOKED".to_string(),
                    actual_rule: "mandate_revoked".to_string(),
                    reason: String::new(),
                }
            } else if expected_upper == "ERROR" {
                TestResult {
                    test_id: test.test_id.clone(),
                    passed: true,
                    expected_decision: test.expected_decision.clone(),
                    expected_rule: test.expected_rule.clone(),
                    actual_decision: "ERROR".to_string(),
                    actual_rule: String::new(),
                    reason: String::new(),
                }
            } else {
                fail(format!("enforce error: {}", e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_suite_from_toml() {
        let toml_content = r#"
[suite]
name = "test"

[[test]]
test_id = "T001"
tool = "read_file"
params = '{"path": "/data/input.csv"}'
expected_decision = "ALLOW"
mandate_inline = """
[mandate]
version = "1.0"
agent_did = "did:a2g:test"
agent_name = "test"
issuer = "did:a2g:issuer"
issued_at = "2025-01-01T00:00:00Z"
expires_at = "2099-01-01T00:00:00Z"
mandate_hash = ""
signature = ""
signer_pubkey = ""
proposal_hash = ""

[capabilities]
tools = ["read_file", "write_file"]

[boundaries]
fs_allow = ["/data"]
fs_deny = ["/etc", "/root"]
net_allow = []
net_deny = []
cmd_allow = []
cmd_deny = []

[limits]
max_calls_per_minute = 60
max_payload_bytes = 1048576
"""
tags = ["boundary"]
"#;

        let dir = tempfile::tempdir().unwrap();
        let suite_path = dir.path().join("suite.toml");
        std::fs::write(&suite_path, toml_content).unwrap();

        let tests = load_test_suite(&suite_path).unwrap();
        assert_eq!(tests.len(), 1);
        assert_eq!(tests[0].test_id, "T001");
        assert_eq!(tests[0].tool, "read_file");
    }
}
