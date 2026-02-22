//! Visual Receipt Renderer — Governance-grade visual audit receipts
//!
//! Produces terminal (ANSI), HTML, or JSON formatted governance receipts
//! showing the full decision chain, lineage, and integrity status.

use crate::ledger::LedgerEntry;
use crate::lineage::ExecutionLineage;

/// Severity classification for policy violations
fn classify_severity(decision: &str, policy_rule: &str) -> (&'static str, &'static str) {
    match decision {
        "DENY" => {
            if policy_rule.contains("boundary") || policy_rule.contains("revoked") {
                ("HIGH", "\x1b[91m")  // bright red
            } else if policy_rule.contains("unauthorized") || policy_rule.contains("tool_not_in_allow_list") {
                ("HIGH", "\x1b[91m")
            } else {
                ("MEDIUM", "\x1b[93m")  // yellow
            }
        }
        "ESCALATE" => ("MEDIUM", "\x1b[93m"),
        "EXPIRED" => ("HIGH", "\x1b[91m"),
        "ALLOW" => ("NONE", "\x1b[92m"),  // green
        _ => ("LOW", "\x1b[37m"),
    }
}

/// Render a terminal-formatted visual receipt
pub fn render_terminal(
    entry: &LedgerEntry,
    lineage: Option<&ExecutionLineage>,
    chain_intact: bool,
) -> String {
    let reset = "\x1b[0m";
    let bold = "\x1b[1m";
    let dim = "\x1b[2m";
    let cyan = "\x1b[96m";
    let green = "\x1b[92m";
    let red = "\x1b[91m";
    let yellow = "\x1b[93m";
    let white = "\x1b[97m";
    let blue = "\x1b[94m";
    let magenta = "\x1b[95m";

    let (severity, sev_color) = classify_severity(&entry.decision, &entry.policy_rule);

    let decision_icon = match entry.decision.as_str() {
        "ALLOW" => format!("{green}ALLOW ✓{reset}"),
        "DENY" => format!("{red}DENY ✗{reset}"),
        "ESCALATE" => format!("{yellow}ESCALATE ⬆{reset}"),
        "EXPIRED" => format!("{red}EXPIRED ✗{reset}"),
        _ => entry.decision.clone(),
    };

    let chain_status = if chain_intact {
        format!("{green}INTACT ✓{reset}")
    } else {
        format!("{red}BROKEN ✗{reset}")
    };

    let lineage_status = if let Some(lin) = lineage {
        if lin.lineage_complete {
            format!("{green}COMPLETE ✓{reset}")
        } else {
            format!("{yellow}INCOMPLETE{reset}")
        }
    } else {
        format!("{dim}N/A{reset}")
    };

    let hash1 = &entry.receipt_hash;
    let prev = &entry.prev_hash;

    let mut out = String::new();

    // Header
    out.push_str(&format!("\n{bold}{cyan}╔══════════════════════════════════════════════════════════════╗{reset}\n"));
    out.push_str(&format!("{bold}{cyan}║{reset}  {bold}{white}A2G GOVERNANCE RECEIPT{reset}                                     {bold}{cyan}║{reset}\n"));
    out.push_str(&format!("{bold}{cyan}╠══════════════════════════════════════════════════════════════╣{reset}\n"));

    // Decision
    out.push_str(&format!("{bold}{cyan}║{reset}  Decision:   {decision_icon:<52}{bold}{cyan}║{reset}\n"));
    if severity != "NONE" {
        out.push_str(&format!("{bold}{cyan}║{reset}  Severity:   {sev_color}{bold}{severity:<50}{reset}{bold}{cyan}║{reset}\n"));
    }
    out.push_str(&format!("{bold}{cyan}║{reset}  Tool:       {white}{:<50}{reset}{bold}{cyan}║{reset}\n", entry.tool));
    out.push_str(&format!("{bold}{cyan}║{reset}  Rule:       {dim}{:<50}{reset}{bold}{cyan}║{reset}\n", truncate_str(&entry.policy_rule, 50)));
    out.push_str(&format!("{bold}{cyan}║{reset}  Agent:      {dim}{:<50}{reset}{bold}{cyan}║{reset}\n", truncate_str(&entry.agent_did, 50)));
    out.push_str(&format!("{bold}{cyan}║{reset}  Timestamp:  {dim}{:<50}{reset}{bold}{cyan}║{reset}\n", &entry.timestamp));

    // Separator
    out.push_str(&format!("{bold}{cyan}╠══════════════════════════════════════════════════════════════╣{reset}\n"));
    out.push_str(&format!("{bold}{cyan}║{reset}  {bold}{blue}HASH CHAIN{reset}                                                {bold}{cyan}║{reset}\n"));
    out.push_str(&format!("{bold}{cyan}║{reset}                                                              {bold}{cyan}║{reset}\n"));

    // Hash chain visualization
    out.push_str(&format!("{bold}{cyan}║{reset}  {dim}prev{reset}  {magenta}{}{reset}  {bold}{cyan}║{reset}\n", truncate_str(prev, 52)));
    out.push_str(&format!("{bold}{cyan}║{reset}          {dim}│{reset}                                                   {bold}{cyan}║{reset}\n"));
    out.push_str(&format!("{bold}{cyan}║{reset}          {dim}▼{reset}                                                   {bold}{cyan}║{reset}\n"));
    out.push_str(&format!("{bold}{cyan}║{reset}  {bold}this{reset}  {green}{}{reset}  {bold}{cyan}║{reset}\n", truncate_str(hash1, 52)));

    // Lineage section
    out.push_str(&format!("{bold}{cyan}╠══════════════════════════════════════════════════════════════╣{reset}\n"));
    out.push_str(&format!("{bold}{cyan}║{reset}  {bold}{blue}LINEAGE{reset}                                                   {bold}{cyan}║{reset}\n"));

    if !entry.mandate_hash.is_empty() {
        out.push_str(&format!("{bold}{cyan}║{reset}  Mandate:    {dim}{}…{reset}                               {bold}{cyan}║{reset}\n", &entry.mandate_hash[..16]));
    }
    if let Some(lin) = lineage {
        if !lin.issuer_did.is_empty() {
            out.push_str(&format!("{bold}{cyan}║{reset}  Issuer:     {dim}{}{reset}                  {bold}{cyan}║{reset}\n", truncate_str(&lin.issuer_did, 38)));
        }
        if !lin.authority_level.is_empty() {
            out.push_str(&format!("{bold}{cyan}║{reset}  Authority:  {white}{:<50}{reset}{bold}{cyan}║{reset}\n", lin.authority_level));
        }
        if !lin.correlation_id.is_empty() {
            out.push_str(&format!("{bold}{cyan}║{reset}  Correlation: {dim}{}{reset}                     {bold}{cyan}║{reset}\n", truncate_str(&lin.correlation_id, 35)));
        }
    }

    // Status bar
    out.push_str(&format!("{bold}{cyan}╠══════════════════════════════════════════════════════════════╣{reset}\n"));

    let pass_fail = match entry.decision.as_str() {
        "ALLOW" => format!("{green}{bold}PASS{reset}"),
        _ => format!("{red}{bold}FAIL{reset}"),
    };

    out.push_str(&format!("{bold}{cyan}║{reset}  {pass_fail} | Chain: {chain_status} | Lineage: {lineage_status}            {bold}{cyan}║{reset}\n"));
    out.push_str(&format!("{bold}{cyan}║{reset}  Receipt: {dim}{}{reset}    {bold}{cyan}║{reset}\n", truncate_str(&entry.receipt_id, 42)));
    out.push_str(&format!("{bold}{cyan}╚══════════════════════════════════════════════════════════════╝{reset}\n"));

    // A2G branding
    out.push_str(&format!("                                        {dim}A2G Protocol • Deterministic Governance{reset}\n"));

    out
}

/// Render an HTML visual receipt
pub fn render_html(
    entry: &LedgerEntry,
    lineage: Option<&ExecutionLineage>,
    chain_intact: bool,
) -> String {
    let (severity, _) = classify_severity(&entry.decision, &entry.policy_rule);

    let decision_class = match entry.decision.as_str() {
        "ALLOW" => "allow",
        "DENY" => "deny",
        "ESCALATE" => "escalate",
        "EXPIRED" => "expired",
        _ => "unknown",
    };

    let decision_icon = match entry.decision.as_str() {
        "ALLOW" => "ALLOW ✓",
        "DENY" => "DENY ✗",
        "ESCALATE" => "ESCALATE ⬆",
        "EXPIRED" => "EXPIRED ✗",
        d => d,
    };

    let chain_html = if chain_intact { "INTACT ✓" } else { "BROKEN ✗" };
    let chain_class = if chain_intact { "pass" } else { "fail" };

    let lineage_html = if let Some(lin) = lineage {
        if lin.lineage_complete { "COMPLETE ✓" } else { "INCOMPLETE" }
    } else { "N/A" };

    let lineage_entries = if let Some(lin) = lineage {
        let mut entries = String::new();
        if !lin.issuer_did.is_empty() {
            entries.push_str(&format!("<div class=\"field\"><span class=\"label\">Issuer:</span> <span class=\"value\">{}</span></div>", html_escape(&lin.issuer_did)));
        }
        if !lin.authority_level.is_empty() {
            entries.push_str(&format!("<div class=\"field\"><span class=\"label\">Authority:</span> <span class=\"value\">{}</span></div>", html_escape(&lin.authority_level)));
        }
        if !lin.correlation_id.is_empty() {
            entries.push_str(&format!("<div class=\"field\"><span class=\"label\">Correlation:</span> <span class=\"value\">{}</span></div>", html_escape(&lin.correlation_id)));
        }
        entries
    } else {
        String::new()
    };

    let pass_fail = match entry.decision.as_str() {
        "ALLOW" => "PASS",
        _ => "FAIL",
    };
    let pass_class = match entry.decision.as_str() {
        "ALLOW" => "pass",
        _ => "fail",
    };

    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>A2G Governance Receipt</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: #0a0a0f; color: #e0e0e0; font-family: 'JetBrains Mono', 'Fira Code', monospace; padding: 2rem; display: flex; justify-content: center; }}
  .receipt {{ max-width: 640px; width: 100%; border: 2px solid #1a3a5c; border-radius: 12px; overflow: hidden; background: #0d1117; box-shadow: 0 0 40px rgba(0, 100, 200, 0.15); }}
  .header {{ background: linear-gradient(135deg, #0d2137, #1a3a5c); padding: 1.5rem; text-align: center; border-bottom: 1px solid #1a3a5c; }}
  .header h1 {{ font-size: 1.2rem; color: #58a6ff; letter-spacing: 0.15em; }}
  .header .sub {{ font-size: 0.75rem; color: #666; margin-top: 0.3rem; }}
  .section {{ padding: 1rem 1.5rem; border-bottom: 1px solid #1a2a3c; }}
  .section-title {{ font-size: 0.7rem; color: #58a6ff; letter-spacing: 0.1em; text-transform: uppercase; margin-bottom: 0.8rem; }}
  .field {{ display: flex; justify-content: space-between; margin-bottom: 0.4rem; }}
  .label {{ color: #666; font-size: 0.85rem; }}
  .value {{ color: #e0e0e0; font-size: 0.85rem; text-align: right; max-width: 60%; word-break: break-all; }}
  .decision {{ font-size: 1.4rem; font-weight: bold; margin: 0.5rem 0; }}
  .decision.allow {{ color: #3fb950; }}
  .decision.deny {{ color: #f85149; }}
  .decision.escalate {{ color: #d29922; }}
  .decision.expired {{ color: #f85149; }}
  .severity {{ display: inline-block; padding: 0.15rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }}
  .severity.HIGH {{ background: rgba(248, 81, 73, 0.2); color: #f85149; border: 1px solid #f85149; }}
  .severity.MEDIUM {{ background: rgba(210, 153, 34, 0.2); color: #d29922; border: 1px solid #d29922; }}
  .severity.LOW {{ background: rgba(100, 100, 100, 0.2); color: #888; border: 1px solid #888; }}
  .severity.NONE {{ background: rgba(63, 185, 80, 0.2); color: #3fb950; border: 1px solid #3fb950; }}
  .hash-chain {{ background: #0a0e14; border-radius: 8px; padding: 1rem; margin-top: 0.5rem; }}
  .hash {{ font-size: 0.72rem; color: #7ee787; word-break: break-all; padding: 0.3rem 0; }}
  .hash.prev {{ color: #8b949e; }}
  .arrow {{ text-align: center; color: #58a6ff; font-size: 1.2rem; padding: 0.2rem; }}
  .status-bar {{ display: flex; justify-content: space-between; align-items: center; padding: 1rem 1.5rem; background: #0a0e14; }}
  .status {{ display: flex; gap: 1rem; font-size: 0.8rem; }}
  .pass {{ color: #3fb950; }}
  .fail {{ color: #f85149; }}
  .brand {{ text-align: right; font-size: 0.7rem; color: #333; }}
  .brand strong {{ color: #58a6ff; }}
</style>
</head>
<body>
<div class="receipt">
  <div class="header">
    <h1>A2G GOVERNANCE RECEIPT</h1>
    <div class="sub">Deterministic Protocol • Immutable Ledger</div>
  </div>

  <div class="section">
    <div class="section-title">Decision</div>
    <div class="decision {decision_class}">{decision_icon}</div>
    {severity_html}
    <div class="field"><span class="label">Tool:</span> <span class="value">{tool}</span></div>
    <div class="field"><span class="label">Rule:</span> <span class="value">{rule}</span></div>
    <div class="field"><span class="label">Agent:</span> <span class="value">{agent}</span></div>
    <div class="field"><span class="label">Timestamp:</span> <span class="value">{timestamp}</span></div>
  </div>

  <div class="section">
    <div class="section-title">Hash Chain</div>
    <div class="hash-chain">
      <div class="hash prev">{prev_hash}</div>
      <div class="arrow">↓</div>
      <div class="hash">{receipt_hash}</div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Lineage</div>
    {mandate_html}
    {lineage_entries}
  </div>

  <div class="status-bar">
    <div class="status">
      <span class="{pass_class}"><strong>{pass_fail}</strong></span>
      <span>Chain: <span class="{chain_class}">{chain_html}</span></span>
      <span>Lineage: {lineage_html}</span>
    </div>
    <div class="brand"><strong>A2G</strong> Protocol</div>
  </div>
</div>
</body>
</html>"#,
        decision_class = decision_class,
        decision_icon = decision_icon,
        severity_html = if severity != "NONE" {
            format!("<span class=\"severity {}\">{}</span>", severity, severity)
        } else { String::new() },
        tool = html_escape(&entry.tool),
        rule = html_escape(&entry.policy_rule),
        agent = html_escape(&entry.agent_did),
        timestamp = html_escape(&entry.timestamp),
        prev_hash = html_escape(&entry.prev_hash),
        receipt_hash = html_escape(&entry.receipt_hash),
        mandate_html = if !entry.mandate_hash.is_empty() {
            format!("<div class=\"field\"><span class=\"label\">Mandate:</span> <span class=\"value\">{}…</span></div>", &entry.mandate_hash[..std::cmp::min(16, entry.mandate_hash.len())])
        } else { String::new() },
        lineage_entries = lineage_entries,
        pass_fail = pass_fail,
        pass_class = pass_class,
        chain_html = chain_html,
        chain_class = chain_class,
        lineage_html = lineage_html,
    )
}

/// Render a JSON visual receipt
pub fn render_json(
    entry: &LedgerEntry,
    lineage: Option<&ExecutionLineage>,
    chain_intact: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    let (severity, _) = classify_severity(&entry.decision, &entry.policy_rule);

    let pass_fail = match entry.decision.as_str() {
        "ALLOW" => "PASS",
        _ => "FAIL",
    };

    let mut output = serde_json::json!({
        "receipt_id": entry.receipt_id,
        "decision": entry.decision,
        "severity": severity,
        "status": pass_fail,
        "tool": entry.tool,
        "policy_rule": entry.policy_rule,
        "agent_did": entry.agent_did,
        "timestamp": entry.timestamp,
        "hash_chain": {
            "prev_hash": entry.prev_hash,
            "receipt_hash": entry.receipt_hash,
            "chain_intact": chain_intact,
        },
        "lineage": {
            "mandate_hash": entry.mandate_hash,
            "proposal_hash": entry.proposal_hash,
            "delegation_chain_hash": entry.delegation_chain_hash,
            "correlation_id": entry.correlation_id,
            "parent_receipt_hash": entry.parent_receipt_hash,
        },
    });

    if let Some(lin) = lineage {
        output["lineage"]["issuer_did"] = serde_json::json!(lin.issuer_did);
        output["lineage"]["authority_level"] = serde_json::json!(lin.authority_level);
        output["lineage"]["lineage_complete"] = serde_json::json!(lin.lineage_complete);
        output["lineage"]["missing_fields"] = serde_json::json!(lin.missing_fields);
    }

    Ok(serde_json::to_string_pretty(&output)?)
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max - 1).collect();
        format!("{}…", truncated)
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
}
