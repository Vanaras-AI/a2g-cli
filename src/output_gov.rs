//! Model Output Governance — Content filtering and audit of LLM responses
//!
//! After a tool call is executed, the response passes through output
//! governance before reaching the agent. This ensures sensitive data
//! (credentials, PII) never reaches the agent even if an authorized
//! tool returns it unexpectedly.

use crate::mandate::OutputGovernance;
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum OutputAction {
    /// Output passed all checks unchanged
    Pass,
    /// Output was blocked entirely (matched a deny pattern)
    Denied { pattern: String },
    /// Output had content redacted (matched redact patterns)
    Redacted { count: usize },
    /// Output was truncated (exceeded max length)
    Truncated { original_len: usize, max_len: u64 },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OutputVerdict {
    pub action: OutputAction,
    pub content: String,
}

/// Govern a tool response according to the mandate's output governance rules
pub fn govern_output(response: &str, rules: &OutputGovernance) -> OutputVerdict {
    // Step 1: Check deny patterns — if matched, block entire response
    for pattern_str in &rules.deny_patterns {
        match RegexBuilder::new(pattern_str).size_limit(100_000).build() {
            Ok(re) => {
                if re.is_match(response) {
                    return OutputVerdict {
                        action: OutputAction::Denied {
                            pattern: pattern_str.clone(),
                        },
                        content: "[BLOCKED BY A2G GOVERNANCE: output matched deny pattern]"
                            .to_string(),
                    };
                }
            }
            Err(e) => {
                eprintln!("WARNING: invalid regex pattern '{}': {}", pattern_str, e);
                continue;
            }
        }
    }

    // Step 2: Apply redaction patterns
    let mut content = response.to_string();
    let mut redact_count = 0;

    for pattern_str in &rules.redact_patterns {
        match RegexBuilder::new(pattern_str).size_limit(100_000).build() {
            Ok(re) => {
                let matches: Vec<_> = re.find_iter(&content).collect();
                redact_count += matches.len();
                content = re.replace_all(&content, "[REDACTED]").to_string();
            }
            Err(e) => {
                eprintln!("WARNING: invalid regex pattern '{}': {}", pattern_str, e);
                continue;
            }
        }
    }

    // Step 3: Check length (byte-safe truncation)
    let max_len = rules.max_output_length;
    if max_len > 0 && content.len() as u64 > max_len {
        let original_len = content.len();
        // Find a safe UTF-8 boundary at or before max_len
        let mut end = max_len as usize;
        while end > 0 && !content.is_char_boundary(end) {
            end -= 1;
        }
        content = content[..end].to_string();
        content.push_str("\n[TRUNCATED BY A2G GOVERNANCE]");
        return OutputVerdict {
            action: OutputAction::Truncated {
                original_len,
                max_len,
            },
            content,
        };
    }

    // Return result
    if redact_count > 0 {
        OutputVerdict {
            action: OutputAction::Redacted {
                count: redact_count,
            },
            content,
        }
    } else {
        OutputVerdict {
            action: OutputAction::Pass,
            content,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mandate::OutputGovernance;

    fn test_rules() -> OutputGovernance {
        OutputGovernance {
            deny_patterns: vec![
                r"-----BEGIN.*PRIVATE KEY-----".to_string(),
                r"sk-[a-zA-Z0-9]{48}".to_string(),
                r"AKIA[0-9A-Z]{16}".to_string(),
            ],
            redact_patterns: vec![
                r"\b\d{3}-\d{2}-\d{4}\b".to_string(), // SSN
            ],
            max_output_length: 1000,
        }
    }

    #[test]
    fn test_clean_output_passes() {
        let rules = test_rules();
        let result = govern_output("This is a normal response.", &rules);
        assert!(matches!(result.action, OutputAction::Pass));
        assert_eq!(result.content, "This is a normal response.");
    }

    #[test]
    fn test_private_key_blocked() {
        let rules = test_rules();
        let input = "Here is the key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIE...";
        let result = govern_output(input, &rules);
        assert!(matches!(result.action, OutputAction::Denied { .. }));
        assert!(result.content.contains("BLOCKED"));
    }

    #[test]
    fn test_ssn_redacted() {
        let rules = test_rules();
        let input = "The SSN is 123-45-6789 and another is 987-65-4321.";
        let result = govern_output(input, &rules);
        match &result.action {
            OutputAction::Redacted { count } => assert_eq!(*count, 2),
            _ => panic!("expected Redacted"),
        }
        assert!(result.content.contains("[REDACTED]"));
        assert!(!result.content.contains("123-45-6789"));
    }

    #[test]
    fn test_truncation() {
        let rules = OutputGovernance {
            deny_patterns: vec![],
            redact_patterns: vec![],
            max_output_length: 20,
        };
        let input = "This is a very long response that should be truncated";
        let result = govern_output(input, &rules);
        assert!(matches!(result.action, OutputAction::Truncated { .. }));
        assert!(result.content.contains("TRUNCATED"));
    }
}
