//! A2G CLI — Deterministic Governance Protocol for Autonomous AI Agents
//!
//! Commands:
//!   a2g init     — Generate agent keypair and mandate template
//!   a2g sign     — Sign a mandate with sovereign key
//!   a2g verify   — Verify mandate signature + TTL + identity
//!   a2g enforce  — Evaluate an intent against a mandate (deterministic allow/deny)
//!   a2g receipt  — Verify a governance receipt
//!   a2g audit    — Query the decision ledger

mod authority;
mod enforce;
mod identity;
mod ledger;
mod lineage;
mod mandate;
mod output_gov;
mod proposal;
mod receipt;
mod test_harness;
mod trust_summary;
mod visual_receipt;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Validate a name parameter to prevent path traversal
fn validate_name(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if name.contains("..") || name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err(format!(
            "invalid name '{}': must not contain '..', '/', '\\', or null bytes",
            name
        )
        .into());
    }
    if name.len() > 256 {
        return Err("name exceeds maximum length of 256 characters".into());
    }
    if name.is_empty() {
        return Err("name must not be empty".into());
    }
    Ok(())
}

/// Validate a TTL (time-to-live) parameter
fn validate_ttl(ttl: u64) -> Result<(), Box<dyn std::error::Error>> {
    if ttl == 0 {
        return Err("TTL must be greater than 0".into());
    }
    if ttl > 8760 {
        return Err("TTL exceeds maximum of 8760 hours (1 year)".into());
    }
    Ok(())
}

/// Write a file with restricted permissions (owner-only read/write)
#[cfg(unix)]
fn write_secret(path: &PathBuf, content: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true).mode(0o600);
    let mut file = opts.open(path)?;
    std::io::Write::write_all(&mut file, content.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret(path: &PathBuf, content: &str) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::write(path, content)?;
    Ok(())
}

#[derive(Parser)]
#[command(name = "a2g", version = "0.1.0")]
#[command(about = "Deterministic governance protocol for autonomous AI agents")]
struct Cli {
    /// Output format: text or json
    #[arg(long, default_value = "text", global = true)]
    output: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate agent keypair and mandate template
    Init {
        /// Agent name
        #[arg(long)]
        name: String,
        /// Output directory
        #[arg(long, default_value = ".")]
        out: PathBuf,
    },
    /// Generate a sovereign keypair (governance authority)
    Sovereign {
        /// Output directory
        #[arg(long, default_value = ".")]
        out: PathBuf,
    },
    /// Sign a mandate with sovereign key (sets TTL)
    Sign {
        /// Path to mandate TOML file
        #[arg(long)]
        mandate: PathBuf,
        /// Path to sovereign secret key file
        #[arg(long)]
        key: PathBuf,
        /// TTL in hours (default: 24)
        #[arg(long, default_value = "24")]
        ttl: u64,
        /// Path to approved proposal JSON (REQUIRED — governance enforcement)
        #[arg(long)]
        proposal: PathBuf,
    },
    /// Verify a mandate (signature + TTL + identity)
    Verify {
        /// Path to signed mandate TOML file
        #[arg(long)]
        mandate: PathBuf,
    },
    /// Evaluate an intent against a mandate (deterministic allow/deny)
    Enforce {
        /// Path to signed mandate TOML file
        #[arg(long)]
        mandate: PathBuf,
        /// Tool name
        #[arg(long)]
        tool: String,
        /// JSON params
        #[arg(long, default_value = "{}")]
        params: String,
        /// Path to ledger database
        #[arg(long, default_value = "a2g_ledger.db")]
        ledger: PathBuf,
        /// Comma-separated paths to authority delegation JSON files (chain validation)
        #[arg(long)]
        authority_chain: Option<String>,
        /// Correlation ID for cross-vendor tracing (UUID)
        #[arg(long)]
        correlation_id: Option<String>,
        /// Parent receipt hash (from triggering receipt)
        #[arg(long)]
        parent_receipt: Option<String>,
    },
    /// Verify a governance receipt
    Receipt {
        /// Receipt JSON string or file path
        #[arg(long)]
        receipt: String,
        /// Path to governance engine public key
        #[arg(long)]
        engine_key: PathBuf,
    },
    /// Revoke a mandate (prevent further use before TTL expires)
    Revoke {
        /// Path to the mandate to revoke
        #[arg(long)]
        mandate: PathBuf,
        /// Path to ledger database
        #[arg(long, default_value = "a2g_ledger.db")]
        ledger: PathBuf,
        /// Reason for revocation
        #[arg(long, default_value = "manual revocation")]
        reason: String,
    },
    /// Query the decision ledger
    Audit {
        /// Path to ledger database
        #[arg(long, default_value = "a2g_ledger.db")]
        ledger: PathBuf,
        /// Filter by agent DID
        #[arg(long)]
        agent: Option<String>,
        /// Filter by decision (ALLOW/DENY/EXPIRED)
        #[arg(long)]
        decision: Option<String>,
        /// Show last N entries
        #[arg(long, default_value = "20")]
        last: usize,
    },
    /// Create a root authority delegation (Layer 0)
    AuthorityRoot {
        /// Sovereign secret key file
        #[arg(long)]
        key: PathBuf,
        /// Authority name
        #[arg(long)]
        name: String,
        /// TTL in hours
        #[arg(long, default_value = "720")]
        ttl: u64,
        /// Region (e.g., "US", "EU")
        #[arg(long, default_value = "")]
        region: String,
        /// Environment (e.g., "production", "staging")
        #[arg(long, default_value = "")]
        environment: String,
        /// Output file for the delegation JSON
        #[arg(long, default_value = "root.delegation.json")]
        out: PathBuf,
        /// Ledger path
        #[arg(long, default_value = "a2g_ledger.db")]
        ledger: PathBuf,
        /// Allowed tools (comma-separated, default: all common tools)
        #[arg(long, default_value = "")]
        tools: String,
        /// Maximum rate limit
        #[arg(long, default_value = "120")]
        max_rate_limit: u64,
        /// Maximum TTL hours for delegations
        #[arg(long, default_value = "720")]
        max_ttl: u64,
        /// Maximum active mandates
        #[arg(long, default_value = "100")]
        max_mandates: u64,
    },
    /// Create a mandate proposal (requires approval before signing)
    Propose {
        /// Proposer DID
        #[arg(long)]
        proposer: String,
        /// Proposal name
        #[arg(long)]
        name: String,
        /// Path to mandate TOML file
        #[arg(long)]
        mandate: PathBuf,
        /// Justification
        #[arg(long)]
        justification: String,
        /// Proposal TTL in hours
        #[arg(long, default_value = "48")]
        ttl: u64,
        /// Output file for the proposal JSON
        #[arg(long, default_value = "proposal.json")]
        out: PathBuf,
        /// Ledger path
        #[arg(long, default_value = "a2g_ledger.db")]
        ledger: PathBuf,
    },
    /// Approve or reject a mandate proposal
    Review {
        /// Path to proposal JSON file
        #[arg(long)]
        proposal: PathBuf,
        /// Reviewer secret key file
        #[arg(long)]
        key: PathBuf,
        /// Reviewer name
        #[arg(long)]
        reviewer_name: String,
        /// Decision: approve, reject, or request-changes
        #[arg(long)]
        decision: String,
        /// Reason for the decision
        #[arg(long, default_value = "")]
        reason: String,
        /// Ledger path
        #[arg(long, default_value = "a2g_ledger.db")]
        ledger: PathBuf,
    },
    /// Query the authority governance log (Layer 0 audit)
    AuthorityLog {
        /// Path to ledger database
        #[arg(long, default_value = "a2g_ledger.db")]
        ledger: PathBuf,
        /// Filter by event type
        #[arg(long)]
        event_type: Option<String>,
        /// Filter by actor DID
        #[arg(long)]
        actor: Option<String>,
        /// Show last N entries
        #[arg(long, default_value = "20")]
        last: usize,
    },
    /// Delegate authority to a subordinate (Layer 0 delegation)
    Delegate {
        /// Path to parent delegation JSON file
        #[arg(long)]
        parent: PathBuf,
        /// Grantor secret key file
        #[arg(long)]
        key: PathBuf,
        /// Grantee DID
        #[arg(long)]
        grantee: String,
        /// Grantee name
        #[arg(long)]
        grantee_name: String,
        /// Authority level: department, team, or operator
        #[arg(long)]
        level: String,
        /// Allowed tools (comma-separated)
        #[arg(long, default_value = "")]
        tools: String,
        /// TTL in hours
        #[arg(long, default_value = "168")]
        ttl: u64,
        /// Output file
        #[arg(long, default_value = "delegation.json")]
        out: PathBuf,
        /// Ledger path
        #[arg(long, default_value = "a2g_ledger.db")]
        ledger: PathBuf,
    },
    /// Revoke a delegation
    RevokeDelegation {
        /// Path to delegation JSON
        #[arg(long)]
        delegation: PathBuf,
        /// Ledger path
        #[arg(long, default_value = "a2g_ledger.db")]
        ledger: PathBuf,
        /// Reason for revocation
        #[arg(long)]
        reason: String,
    },
    /// Run declarative policy tests (golden cases)
    Test {
        /// Path to test suite (TOML or JSON)
        #[arg(long)]
        suite: PathBuf,
        /// Path to ledger database (use :memory: for isolation)
        #[arg(long, default_value = ":memory:")]
        ledger: PathBuf,
        /// Filter tests by tag
        #[arg(long)]
        tag: Option<String>,
    },
    /// Reconstruct and verify execution lineage from a receipt
    VerifyLineage {
        /// Receipt ID or receipt hash
        #[arg(long)]
        receipt: String,
        /// Path to ledger database
        #[arg(long, default_value = "a2g_ledger.db")]
        ledger: PathBuf,
    },
    /// Compress governance history into a signed trust summary
    Compress {
        /// Agent DID to compress
        #[arg(long)]
        agent: String,
        /// Window start (ISO 8601 / RFC 3339)
        #[arg(long)]
        start: String,
        /// Window end (ISO 8601 / RFC 3339)
        #[arg(long)]
        end: String,
        /// Path to ledger database
        #[arg(long, default_value = "a2g_ledger.db")]
        ledger: PathBuf,
        /// Path to ed25519 secret key for signing
        #[arg(long)]
        key: PathBuf,
        /// Human-readable issuer name
        #[arg(long)]
        issuer_name: String,
        /// Output path for signed summary JSON
        #[arg(long)]
        out: PathBuf,
        /// Minimum decisions required (default 1)
        #[arg(long, default_value = "1")]
        min_decisions: u64,
    },
    /// Verify a trust summary's integrity and signature
    VerifySummary {
        /// Path to trust summary JSON file
        #[arg(long)]
        summary: PathBuf,
    },
    /// Generate a visual governance receipt (terminal or HTML)
    VisualReceipt {
        /// Receipt ID or receipt hash
        #[arg(long)]
        receipt: String,
        /// Path to ledger database
        #[arg(long, default_value = "a2g_ledger.db")]
        ledger: PathBuf,
        /// Output format: terminal, html, or json
        #[arg(long, default_value = "terminal")]
        format: String,
        /// Output file for HTML format (optional)
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();
    let output_format = cli.output.as_str();

    let result = match cli.command {
        Commands::Init { name, out } => cmd_init(&name, &out, output_format),
        Commands::Sovereign { out } => cmd_sovereign(&out, output_format),
        Commands::Sign {
            mandate,
            key,
            ttl,
            proposal,
        } => cmd_sign(&mandate, &key, ttl, &proposal, output_format),
        Commands::Verify { mandate } => cmd_verify(&mandate, output_format),
        Commands::Enforce {
            mandate,
            tool,
            params,
            ledger,
            authority_chain,
            correlation_id,
            parent_receipt,
        } => cmd_enforce(
            &mandate,
            &tool,
            &params,
            &ledger,
            authority_chain,
            correlation_id,
            parent_receipt,
            output_format,
        ),
        Commands::Receipt {
            receipt,
            engine_key,
        } => cmd_receipt(&receipt, &engine_key, output_format),
        Commands::Revoke {
            mandate,
            ledger,
            reason,
        } => cmd_revoke(&mandate, &ledger, &reason, output_format),
        Commands::Audit {
            ledger,
            agent,
            decision,
            last,
        } => cmd_audit(
            &ledger,
            agent.as_deref(),
            decision.as_deref(),
            last,
            output_format,
        ),
        Commands::AuthorityRoot {
            key,
            name,
            ttl,
            region,
            environment,
            out,
            ledger,
            tools,
            max_rate_limit,
            max_ttl,
            max_mandates,
        } => cmd_authority_root(
            &key,
            &name,
            ttl,
            &region,
            &environment,
            &out,
            &ledger,
            &tools,
            max_rate_limit,
            max_ttl,
            max_mandates,
            output_format,
        ),
        Commands::Propose {
            proposer,
            name,
            mandate,
            justification,
            ttl,
            out,
            ledger,
        } => cmd_propose(
            &proposer,
            &name,
            &mandate,
            &justification,
            ttl,
            &out,
            &ledger,
            output_format,
        ),
        Commands::Review {
            proposal: prop,
            key,
            reviewer_name,
            decision,
            reason,
            ledger,
        } => cmd_review(
            &prop,
            &key,
            &reviewer_name,
            &decision,
            &reason,
            &ledger,
            output_format,
        ),
        Commands::AuthorityLog {
            ledger,
            event_type,
            actor,
            last,
        } => cmd_authority_log(
            &ledger,
            event_type.as_deref(),
            actor.as_deref(),
            last,
            output_format,
        ),
        Commands::Delegate {
            parent,
            key,
            grantee,
            grantee_name,
            level,
            tools,
            ttl,
            out,
            ledger,
        } => cmd_delegate(
            &parent,
            &key,
            &grantee,
            &grantee_name,
            &level,
            &tools,
            ttl,
            &out,
            &ledger,
            output_format,
        ),
        Commands::RevokeDelegation {
            delegation,
            ledger,
            reason,
        } => cmd_revoke_delegation(&delegation, &ledger, &reason, output_format),
        Commands::Test { suite, ledger, tag } => {
            cmd_test(&suite, &ledger, tag.as_deref(), output_format)
        }
        Commands::VerifyLineage { receipt, ledger } => {
            cmd_verify_lineage(&receipt, &ledger, output_format)
        }
        Commands::Compress {
            agent,
            start,
            end,
            ledger,
            key,
            issuer_name,
            out,
            min_decisions,
        } => cmd_compress(
            &agent,
            &start,
            &end,
            &ledger,
            &key,
            &issuer_name,
            &out,
            min_decisions,
            output_format,
        ),
        Commands::VerifySummary { summary } => cmd_verify_summary(&summary, output_format),
        Commands::VisualReceipt {
            receipt,
            ledger,
            format,
            out,
        } => cmd_visual_receipt(&receipt, &ledger, &format, out.as_ref()),
    };

    if let Err(e) = result {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

// ── Commands ──────────────────────────────────────────────────────────

fn cmd_init(
    name: &str,
    out: &PathBuf,
    output_format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate name parameter
    validate_name(name)?;

    // Generate agent keypair
    let (did, secret_hex, public_hex) = identity::generate_agent_keypair();

    // Write secret key (restricted permissions)
    let sk_path = out.join(format!("{}.secret.key", name));
    write_secret(&sk_path, &secret_hex)?;

    // Write public key
    let pk_path = out.join(format!("{}.public.key", name));
    std::fs::write(&pk_path, &public_hex)?;

    // Write DID
    let did_path = out.join(format!("{}.did", name));
    std::fs::write(&did_path, &did)?;

    // Write mandate template
    let mut template = mandate::generate_template(name, &did);

    // Auto-populate workspace_root with the absolute output directory
    let abs_out = std::fs::canonicalize(out).unwrap_or_else(|_| out.clone());
    template = template.replace(
        "workspace_root = \"\"",
        &format!("workspace_root = \"{}\"", abs_out.display()),
    );

    let mandate_path = out.join(format!("{}.mandate.toml", name));
    std::fs::write(&mandate_path, &template)?;

    if output_format == "json" {
        let output = serde_json::json!({
            "did": did,
            "secret_key": sk_path.display().to_string(),
            "public_key": pk_path.display().to_string(),
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("secret key  → {}", sk_path.display());
        println!("public key  → {}", pk_path.display());
        println!("agent DID   → {}", did);
        println!("mandate     → {}", mandate_path.display());
        println!("\nnext: edit the mandate, then sign it:");
        println!(
            "  a2g sign --mandate {} --key <sovereign.secret.key> --ttl 24",
            mandate_path.display()
        );
    }

    Ok(())
}

fn cmd_sovereign(out: &PathBuf, output_format: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (did, secret_hex, public_hex) = identity::generate_agent_keypair();

    let sk_path = out.join("sovereign.secret.key");
    write_secret(&sk_path, &secret_hex)?;

    let pk_path = out.join("sovereign.public.key");
    std::fs::write(&pk_path, &public_hex)?;

    let did_path = out.join("sovereign.did");
    std::fs::write(&did_path, &did)?;

    if output_format == "json" {
        let output = serde_json::json!({
            "did": did,
            "secret_key": sk_path.display().to_string(),
            "public_key": pk_path.display().to_string(),
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("sovereign secret key  → {}", sk_path.display());
        println!("sovereign public key  → {}", pk_path.display());
        println!("sovereign DID         → {}", did);
        println!("\nuse this key to sign agent mandates:");
        println!(
            "  a2g sign --mandate <agent>.mandate.toml --key {} --ttl 24",
            sk_path.display()
        );
    }

    Ok(())
}

fn cmd_sign(
    mandate_path: &PathBuf,
    key_path: &PathBuf,
    ttl_hours: u64,
    proposal_path: &PathBuf,
    output_format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use chrono::DateTime;
    use sha2::{Digest, Sha256};

    // Validate TTL
    validate_ttl(ttl_hours)?;

    let mandate_str = std::fs::read_to_string(mandate_path)?;
    let key_hex = std::fs::read_to_string(key_path)?.trim().to_string();

    // MANDATORY: Load and verify the approved proposal
    let prop_json = std::fs::read_to_string(proposal_path)?;
    let prop: proposal::Proposal = serde_json::from_str(&prop_json)?;

    // Check proposal status is "Approved"
    if prop.status != proposal::ProposalStatus::Approved {
        return Err(format!("proposal is not approved (status: {})", prop.status).into());
    }

    // C1 FIX: Check proposal has not expired
    if let Ok(expires) = DateTime::parse_from_rfc3339(&prop.expires_at) {
        if chrono::Utc::now() >= expires {
            return Err(format!("proposal has expired (expired at {})", prop.expires_at).into());
        }
    }

    // Compute SHA-256 of mandate body
    let mandate_body_hash = hex::encode(Sha256::digest(mandate_str.as_bytes()));

    // Compare to proposal.mandate_hash — prevents mandate modification after approval
    if mandate_body_hash != prop.mandate_hash {
        return Err(
            "mandate modified after proposal approval: hash mismatch (governance violation)".into(),
        );
    }

    if output_format != "json" {
        println!("proposal verified ✓");
        println!("  proposal:    {}", &prop.proposal_hash[..16]);
        println!("  status:      {}", prop.status);
    }

    let signed = mandate::sign_mandate(&mandate_str, &key_hex, ttl_hours)?;

    std::fs::write(mandate_path, &signed)?;

    if output_format == "json" {
        let output = serde_json::json!({
            "signed": true,
            "ttl_hours": ttl_hours,
            "file": mandate_path.display().to_string(),
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("mandate signed ✓");
        println!("  TTL: {} hours", ttl_hours);
        println!("  file: {}", mandate_path.display());
    }

    Ok(())
}

fn cmd_verify(
    mandate_path: &PathBuf,
    output_format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mandate_str = std::fs::read_to_string(mandate_path)?;

    match mandate::verify_mandate(&mandate_str) {
        Ok(info) => {
            if output_format == "json" {
                let output = serde_json::json!({
                    "valid": true,
                    "agent": info.agent_name,
                    "agent_did": info.agent_did,
                    "issuer": info.issuer,
                    "expires": info.expires_at,
                    "ttl_remaining_sec": info.ttl_remaining_sec,
                    "tools": info.tools,
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("mandate valid ✓");
                println!("  agent:   {} ({})", info.agent_name, info.agent_did);
                println!("  issuer:  {}", info.issuer);
                println!("  expires: {}", info.expires_at);
                println!("  ttl remaining: {}s", info.ttl_remaining_sec);
                println!("  tools:   {:?}", info.tools);
            }
        }
        Err(e) => {
            if output_format == "json" {
                let output = serde_json::json!({
                    "valid": false,
                    "reason": e.to_string(),
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("mandate INVALID ✗");
                println!("  reason: {}", e);
            }
            std::process::exit(1);
        }
    }

    Ok(())
}

fn cmd_enforce(
    mandate_path: &PathBuf,
    tool: &str,
    params_json: &str,
    ledger_path: &PathBuf,
    authority_chain: Option<String>,
    correlation_id: Option<String>,
    parent_receipt: Option<String>,
    output_format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};
    // Validate params size (max 1MB)
    if params_json.len() > 1_048_576 {
        return Err("params JSON exceeds maximum size of 1MB".into());
    }

    let mandate_str = std::fs::read_to_string(mandate_path)?;
    let params: serde_json::Value = serde_json::from_str(params_json)?;

    // Initialize ledger
    let db = ledger::Ledger::open(ledger_path)?;

    // S2 FIX: Initialize receipt chain from ledger to maintain chain across restarts
    let last_hash = db.last_receipt_hash()?;
    receipt::init_chain_from_ledger(last_hash);

    // Phase 2-4: Initialize authority lineage variables
    let mut delegation_chain_hash_val = String::new();
    let mut issuer_did_val = String::new();
    let mut authority_level_val = String::new();
    let mut scope_hash_val = String::new();

    // AUTHORITY CHAIN VALIDATION (Fix 2)
    if let Some(chain_str) = authority_chain {
        // Parse comma-separated delegation file paths
        let delegation_paths: Vec<&str> = chain_str.split(',').map(|s| s.trim()).collect();

        // Load each delegation JSON
        let mut chain: Vec<authority::Delegation> = Vec::new();
        for path in delegation_paths {
            let delegation_json = std::fs::read_to_string(path)?;
            let delegation: authority::Delegation = serde_json::from_str(&delegation_json)?;
            chain.push(delegation);
        }

        // Check each delegation for revocation
        for d in &chain {
            if db.is_delegation_revoked(&d.delegation_hash)? {
                if output_format == "json" {
                    let output = serde_json::json!({
                        "decision": "DENY",
                        "reason": "delegation_revoked",
                        "detail": format!("delegation {} has been revoked", d.delegation_hash),
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    println!("DENY ✗");
                    println!("  reason: delegation revoked");
                    println!(
                        "  detail: delegation {} has been revoked",
                        &d.delegation_hash[..16]
                    );
                }
                std::process::exit(1);
            }
        }

        // Verify the chain
        let chain_validation = authority::verify_chain(&chain)?;

        if !chain_validation.valid {
            if output_format == "json" {
                let output = serde_json::json!({
                    "decision": "DENY",
                    "reason": "authority chain validation failed",
                    "detail": chain_validation.reason,
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("DENY ✗");
                println!("  reason: authority chain validation failed");
                println!("  detail: {}", chain_validation.reason);
            }
            std::process::exit(1);
        }

        // Get the leaf delegation for scope validation
        let leaf_delegation = chain.last().ok_or("authority chain is empty")?;

        // Validate mandate against authority scope
        if let Err(e) = authority::validate_mandate_against_authority(&mandate_str, leaf_delegation)
        {
            if output_format == "json" {
                let output = serde_json::json!({
                    "decision": "DENY",
                    "reason": "authority scope violation",
                    "detail": e.to_string(),
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("DENY ✗");
                println!("  reason: authority scope violation");
                println!("  detail: {}", e);
            }
            std::process::exit(1);
        }

        // Phase 2: Compute delegation chain hash and authority lineage
        let chain_hash_input: String = chain
            .iter()
            .map(|d| d.delegation_hash.as_str())
            .collect::<Vec<_>>()
            .join(":");
        delegation_chain_hash_val = hex::encode(Sha256::digest(chain_hash_input.as_bytes()));

        // Extract issuer and authority level
        issuer_did_val = leaf_delegation.grantor_did.clone();
        authority_level_val = leaf_delegation.level.to_string();

        // Compute effective scope hash
        let effective_scope_str = format!("{:?}", chain_validation.effective_scope);
        scope_hash_val = hex::encode(Sha256::digest(effective_scope_str.as_bytes()));

        if output_format == "json" {
            let output = serde_json::json!({
                "authority_chain_verified": true,
                "chain_depth": chain_validation.chain_depth,
                "root": truncate(&chain_validation.root_did, 24),
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!("authority chain verified ✓");
            println!("  chain depth: {}", chain_validation.chain_depth);
            println!(
                "  root:        {}",
                truncate(&chain_validation.root_did, 24)
            );
        }
    }

    // Run enforcement
    let mut verdict = enforce::enforce(&mandate_str, tool, &params, &db)?;

    // Phase 2: Set authority lineage on verdict
    verdict.delegation_chain_hash = delegation_chain_hash_val;
    verdict.issuer_did = issuer_did_val;
    verdict.authority_level = authority_level_val;
    verdict.scope_hash = scope_hash_val;

    // Phase 4: Set correlation
    if let Some(cid) = correlation_id {
        verdict.correlation_id = cid;
    }
    if let Some(pr) = parent_receipt {
        verdict.parent_receipt_hash = pr;
    }

    // Generate and append receipt atomically (Fix 7)
    let rcpt = db.enforce_and_record(&verdict)?;

    // Output
    match verdict.decision {
        enforce::Decision::Allow => {
            if output_format == "json" {
                let mut output = serde_json::json!({
                    "decision": "ALLOW",
                    "tool": tool,
                    "reason": verdict.policy_rule,
                    "receipt_id": rcpt.receipt_id,
                });
                if !rcpt.mandate_hash.is_empty() {
                    output["mandate_hash"] = serde_json::json!(rcpt.mandate_hash);
                }
                if !rcpt.proposal_hash.is_empty() {
                    output["proposal_hash"] = serde_json::json!(rcpt.proposal_hash);
                }
                if !rcpt.correlation_id.is_empty() {
                    output["correlation_id"] = serde_json::json!(rcpt.correlation_id);
                }
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("ALLOW ✓");
                println!("  tool:    {}", tool);
                println!("  rule:    {}", verdict.policy_rule);
                println!("  receipt: {}", rcpt.receipt_id);
            }
        }
        enforce::Decision::Deny => {
            if output_format == "json" {
                let mut output = serde_json::json!({
                    "decision": "DENY",
                    "tool": tool,
                    "reason": verdict.policy_rule,
                    "receipt_id": rcpt.receipt_id,
                });
                if !rcpt.correlation_id.is_empty() {
                    output["correlation_id"] = serde_json::json!(rcpt.correlation_id);
                }
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("DENY ✗");
                println!("  tool:    {}", tool);
                println!("  reason:  {}", verdict.policy_rule);
                println!("  receipt: {}", rcpt.receipt_id);
            }
            std::process::exit(1);
        }
        enforce::Decision::Expired => {
            if output_format == "json" {
                let output = serde_json::json!({
                    "decision": "EXPIRED",
                    "reason": "mandate TTL has elapsed",
                    "receipt_id": rcpt.receipt_id,
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("EXPIRED ✗");
                println!("  mandate TTL has elapsed");
                println!("  receipt: {}", rcpt.receipt_id);
            }
            std::process::exit(1);
        }
        enforce::Decision::Escalate => {
            if output_format == "json" {
                let output = serde_json::json!({
                    "decision": "ESCALATE",
                    "tool": tool,
                    "reason": verdict.policy_rule,
                    "receipt_id": rcpt.receipt_id,
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("ESCALATE ⬆");
                println!("  tool:    {}", tool);
                println!("  reason:  {}", verdict.policy_rule);
                println!("  receipt: {}", rcpt.receipt_id);
                println!("\n  action paused — awaiting higher authority approval");
            }
            std::process::exit(2);
        }
    }

    Ok(())
}

fn cmd_receipt(
    receipt_str: &str,
    _engine_key_path: &PathBuf,
    output_format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Try as file path first, then as raw JSON
    let json_str = if std::path::Path::new(receipt_str).exists() {
        std::fs::read_to_string(receipt_str)?
    } else {
        receipt_str.to_string()
    };

    let rcpt: receipt::Receipt = serde_json::from_str(&json_str)?;

    // Verify receipt hash integrity
    let valid = receipt::verify_receipt(&rcpt);

    if output_format == "json" {
        let output = serde_json::json!({
            "valid": valid,
            "id": rcpt.receipt_id,
            "agent": rcpt.agent_did,
            "tool": rcpt.tool,
            "decision": rcpt.decision,
            "timestamp": rcpt.timestamp,
            "hash": rcpt.receipt_hash,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        if valid {
            println!("receipt valid ✓");
        } else {
            println!("receipt INVALID ✗ (hash mismatch)");
        }
        println!("  id:       {}", rcpt.receipt_id);
        println!("  agent:    {}", rcpt.agent_did);
        println!("  tool:     {}", rcpt.tool);
        println!("  decision: {:?}", rcpt.decision);
        println!("  time:     {}", rcpt.timestamp);
        println!("  hash:     {}", rcpt.receipt_hash);
    }

    if !valid {
        std::process::exit(1);
    }

    Ok(())
}

fn cmd_revoke(
    mandate_path: &PathBuf,
    ledger_path: &PathBuf,
    reason: &str,
    output_format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};

    let mandate_str = std::fs::read_to_string(mandate_path)?;
    let m: mandate::Mandate = toml::from_str(&mandate_str)?;
    let mandate_hash = hex::encode(Sha256::digest(mandate_str.as_bytes()));

    let db = ledger::Ledger::open(ledger_path)?;
    db.revoke_mandate(
        &m.mandate.agent_did,
        &mandate_hash,
        &m.mandate.issuer,
        reason,
    )?;

    if output_format == "json" {
        let output = serde_json::json!({
            "revoked": true,
            "agent": m.mandate.agent_name,
            "agent_did": m.mandate.agent_did,
            "hash": mandate_hash,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("mandate REVOKED ✓");
        println!(
            "  agent:  {} ({})",
            m.mandate.agent_name, m.mandate.agent_did
        );
        println!("  hash:   {}…", &mandate_hash[..16]);
        println!("  reason: {}", reason);
        println!("\nall future enforce calls against this mandate will return DENY.");
    }

    Ok(())
}

fn cmd_audit(
    ledger_path: &PathBuf,
    agent: Option<&str>,
    decision: Option<&str>,
    last: usize,
    output_format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let db = ledger::Ledger::open(ledger_path)?;
    let entries = db.query(agent, decision, last)?;

    if entries.is_empty() {
        if output_format == "json" {
            println!("[]");
        } else {
            println!("no entries found");
        }
        return Ok(());
    }

    if output_format == "json" {
        let entries_json: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "seq": e.seq,
                    "receipt_id": e.receipt_id,
                    "agent_did": e.agent_did,
                    "agent_name": e.agent_name,
                    "tool": e.tool,
                    "decision": e.decision,
                    "policy_rule": e.policy_rule,
                    "timestamp": e.timestamp,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&entries_json)?);
    } else {
        println!(
            "{:<6} {:<8} {:<20} {:<16} {}",
            "seq", "decision", "agent", "tool", "timestamp"
        );
        println!("{}", "-".repeat(80));

        for e in &entries {
            println!(
                "{:<6} {:<8} {:<20} {:<16} {}",
                e.seq,
                e.decision,
                truncate(&e.agent_did, 18),
                e.tool,
                e.timestamp
            );
        }

        println!("\n{} entries", entries.len());
    }

    Ok(())
}

fn cmd_authority_root(
    key_path: &PathBuf,
    name: &str,
    ttl_hours: u64,
    region: &str,
    environment: &str,
    out_path: &PathBuf,
    ledger_path: &PathBuf,
    tools_str: &str,
    max_rate_limit: u64,
    max_ttl: u64,
    max_mandates: u64,
    output_format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate name and TTL
    validate_name(name)?;
    validate_ttl(ttl_hours)?;

    let key_hex = std::fs::read_to_string(key_path)?.trim().to_string();

    // Parse tools: if tools_str is non-empty, split by comma; otherwise use defaults
    let allowed_tools = if tools_str.is_empty() {
        vec![
            "read_file".into(),
            "write_file".into(),
            "read".into(),
            "write".into(),
            "http_get".into(),
            "http_post".into(),
            "execute".into(),
        ]
    } else {
        tools_str
            .split(',')
            .map(|s| s.trim().to_string())
            .collect::<Vec<_>>()
    };

    let scope = authority::AuthorityScope {
        allowed_tools,
        max_ttl_hours: max_ttl,
        fs_scope: vec!["**".into()],
        net_scope: vec!["*".into()],
        cmd_scope: vec![],
        max_rate_limit,
        max_active_mandates: max_mandates,
    };

    let jurisdiction = authority::Jurisdiction {
        region: region.to_string(),
        regulatory_framework: String::new(),
        environment: environment.to_string(),
        classification: "internal".to_string(),
        operating_hours: String::new(),
    };

    let delegation =
        authority::create_root_delegation(&key_hex, name, scope, jurisdiction, ttl_hours)?;

    // Write delegation JSON
    let json = serde_json::to_string_pretty(&delegation)?;
    std::fs::write(out_path, &json)?;

    // Log to authority ledger
    let db = ledger::Ledger::open(ledger_path)?;
    db.log_authority_event(
        "root_delegation",
        &delegation.grantor_did,
        &delegation.grantee_did,
        &format!(
            "create_root(level={}, ttl={}h)",
            delegation.level, ttl_hours
        ),
        &delegation.delegation_hash,
        &delegation.jurisdiction.region,
        &format!("name={}", name),
    )?;

    if output_format == "json" {
        println!("{}", serde_json::to_string_pretty(&delegation)?);
    } else {
        println!("ROOT AUTHORITY CREATED ✓");
        println!("  name:       {}", name);
        println!("  DID:        {}", delegation.grantee_did);
        println!("  level:      {}", delegation.level);
        println!("  expires:    {}", delegation.expires_at);
        println!(
            "  region:     {}",
            if region.is_empty() { "global" } else { region }
        );
        println!("  hash:       {}…", &delegation.delegation_hash[..16]);
        println!("  output:     {}", out_path.display());
        println!("\nnext: delegate authority to departments/teams:");
        println!(
            "  a2g delegate --parent {} --grantee <did> --level department",
            out_path.display()
        );
    }

    Ok(())
}

fn cmd_propose(
    proposer_did: &str,
    name: &str,
    mandate_path: &PathBuf,
    justification: &str,
    ttl_hours: u64,
    out_path: &PathBuf,
    ledger_path: &PathBuf,
    output_format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate proposer DID and TTL
    identity::validate_did(proposer_did)?;
    validate_ttl(ttl_hours)?;

    let mandate_body = std::fs::read_to_string(mandate_path)?;

    let prop =
        proposal::create_proposal(proposer_did, name, &mandate_body, justification, ttl_hours)?;

    // Write proposal JSON
    let json = serde_json::to_string_pretty(&prop)?;
    std::fs::write(out_path, &json)?;

    // Log to authority ledger
    let db = ledger::Ledger::open(ledger_path)?;
    db.log_authority_event(
        "proposal_created",
        proposer_did,
        proposer_did,
        &format!(
            "propose(risk={}, approvals_needed={})",
            prop.risk_level, prop.required_approvals
        ),
        &prop.proposal_hash,
        "",
        &format!("name={}, justification={}", name, justification),
    )?;

    // Phase 3: Log proposal to proposal history
    db.log_proposal(
        &prop.proposal_id,
        proposer_did,
        &prop.mandate_hash,
        &prop.proposal_hash,
        &prop.status.to_string(),
        &prop.risk_level.to_string(),
        prop.required_approvals,
        &prop.created_at,
    )?;

    if output_format == "json" {
        println!("{}", serde_json::to_string_pretty(&prop)?);
    } else {
        println!("PROPOSAL CREATED ✓");
        println!("  name:       {}", name);
        println!("  proposer:   {}", truncate(proposer_did, 30));
        println!("  risk:       {}", prop.risk_level);
        println!("  approvals:  0/{}", prop.required_approvals);
        println!("  status:     {}", prop.status);
        println!("  expires:    {}", prop.expires_at);
        println!("  hash:       {}…", &prop.proposal_hash[..16]);
        println!("  output:     {}", out_path.display());
        println!("\nnext: submit reviews:");
        println!("  a2g review --proposal {} --key <reviewer.secret.key> --reviewer-name Alice --decision approve", out_path.display());
    }

    Ok(())
}

fn cmd_review(
    proposal_path: &PathBuf,
    key_path: &PathBuf,
    reviewer_name: &str,
    decision_str: &str,
    reason: &str,
    ledger_path: &PathBuf,
    output_format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let prop_json = std::fs::read_to_string(proposal_path)?;
    let mut prop: proposal::Proposal = serde_json::from_str(&prop_json)?;
    let key_hex = std::fs::read_to_string(key_path)?.trim().to_string();

    let decision = match decision_str.to_lowercase().as_str() {
        "approve" => proposal::ReviewDecision::Approve,
        "reject" => proposal::ReviewDecision::Reject,
        "request-changes" | "request_changes" => proposal::ReviewDecision::RequestChanges,
        _ => {
            return Err(format!(
                "invalid decision '{}': use approve, reject, or request-changes",
                decision_str
            )
            .into())
        }
    };

    let review = proposal::review_proposal(&mut prop, &key_hex, reviewer_name, decision, reason)?;

    // Write updated proposal back
    let json = serde_json::to_string_pretty(&prop)?;
    std::fs::write(proposal_path, &json)?;

    // Log to authority ledger
    let db = ledger::Ledger::open(ledger_path)?;
    db.log_authority_event(
        "proposal_reviewed",
        &review.reviewer_did,
        &prop.proposer_did,
        &format!(
            "review(decision={}, status={})",
            review.decision, prop.status
        ),
        &prop.proposal_hash,
        "",
        &format!("reviewer={}, reason={}", reviewer_name, reason),
    )?;

    let approvals = prop
        .reviews
        .iter()
        .filter(|r| r.decision == proposal::ReviewDecision::Approve)
        .count();

    if output_format == "json" {
        println!("{}", serde_json::to_string_pretty(&prop)?);
    } else {
        println!("REVIEW SUBMITTED ✓");
        println!(
            "  reviewer:   {} ({})",
            reviewer_name,
            truncate(&review.reviewer_did, 24)
        );
        println!("  decision:   {}", review.decision);
        println!(
            "  reason:     {}",
            if reason.is_empty() { "(none)" } else { reason }
        );
        println!("  approvals:  {}/{}", approvals, prop.required_approvals);
        println!("  status:     {}", prop.status);

        if prop.status == proposal::ProposalStatus::Approved {
            println!("\n  APPROVED — mandate is ready to sign.");
            println!("  a2g sign --mandate <mandate.toml> --key <sovereign.secret.key>");
        } else if prop.status == proposal::ProposalStatus::Rejected {
            println!("\n  REJECTED — mandate cannot be signed.");
        }
    }

    Ok(())
}

fn cmd_authority_log(
    ledger_path: &PathBuf,
    event_type: Option<&str>,
    actor: Option<&str>,
    last: usize,
    output_format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let db = ledger::Ledger::open(ledger_path)?;
    let entries = db.query_authority_log(event_type, actor, last)?;

    if entries.is_empty() {
        if output_format == "json" {
            println!("[]");
        } else {
            println!("no authority log entries found");
        }
        return Ok(());
    }

    if output_format == "json" {
        let entries_json: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "seq": e.seq,
                    "event_type": e.event_type,
                    "actor_did": e.actor_did,
                    "target_did": e.target_did,
                    "action": e.action,
                    "jurisdiction": e.jurisdiction,
                    "timestamp": e.timestamp,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&entries_json)?);
    } else {
        println!(
            "{:<6} {:<22} {:<20} {:<30} {}",
            "seq", "event", "actor", "action", "timestamp"
        );
        println!("{}", "-".repeat(100));

        for e in &entries {
            println!(
                "{:<6} {:<22} {:<20} {:<30} {}",
                e.seq,
                e.event_type,
                truncate(&e.actor_did, 18),
                truncate(&e.action, 28),
                e.timestamp,
            );
        }

        println!("\n{} entries", entries.len());
    }

    Ok(())
}

fn cmd_delegate(
    parent_path: &PathBuf,
    key_path: &PathBuf,
    grantee: &str,
    grantee_name: &str,
    level_str: &str,
    tools_str: &str,
    ttl: u64,
    out_path: &PathBuf,
    ledger_path: &PathBuf,
    output_format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate grantee name, grantee DID, and TTL
    validate_name(grantee_name)?;
    identity::validate_did(grantee)?;
    validate_ttl(ttl)?;

    // Load parent delegation
    let parent_json = std::fs::read_to_string(parent_path)?;
    let parent: authority::Delegation = serde_json::from_str(&parent_json)?;

    // Parse authority level
    let level = match level_str.to_lowercase().as_str() {
        "department" => authority::AuthorityLevel::Department,
        "team" => authority::AuthorityLevel::Team,
        "operator" => authority::AuthorityLevel::Operator,
        _ => {
            return Err(format!(
                "invalid authority level '{}': use department, team, or operator",
                level_str
            )
            .into())
        }
    };

    // Parse tools (comma-separated)
    let allowed_tools = if tools_str.is_empty() {
        parent.scope.allowed_tools.clone()
    } else {
        tools_str
            .split(',')
            .map(|s| s.trim().to_string())
            .collect::<Vec<_>>()
    };

    // Create child scope: inherit from parent but reduce quotas
    let child_scope = authority::AuthorityScope {
        allowed_tools,
        max_ttl_hours: ttl.min(parent.scope.max_ttl_hours),
        fs_scope: parent.scope.fs_scope.clone(),
        net_scope: parent.scope.net_scope.clone(),
        cmd_scope: parent.scope.cmd_scope.clone(),
        max_rate_limit: parent.scope.max_rate_limit.saturating_mul(70) / 100,
        max_active_mandates: parent.scope.max_active_mandates.saturating_mul(50) / 100,
    };

    // Load grantor secret key
    let key_hex = std::fs::read_to_string(key_path)?.trim().to_string();

    // Create delegation
    let delegation = authority::delegate(
        &key_hex,
        &parent,
        grantee,
        grantee_name,
        level,
        child_scope,
        parent.jurisdiction.clone(),
        ttl,
    )?;

    // Write delegation JSON
    let json = serde_json::to_string_pretty(&delegation)?;
    std::fs::write(out_path, &json)?;

    // Log to authority ledger
    let db = ledger::Ledger::open(ledger_path)?;
    db.log_authority_event(
        "child_delegation",
        &delegation.grantor_did,
        &delegation.grantee_did,
        &format!(
            "delegate(level={}, ttl={}h, tools={})",
            delegation.level,
            ttl,
            delegation.scope.allowed_tools.join(",")
        ),
        &delegation.delegation_hash,
        &delegation.jurisdiction.region,
        &format!("grantee_name={}", grantee_name),
    )?;

    if output_format == "json" {
        println!("{}", serde_json::to_string_pretty(&delegation)?);
    } else {
        println!("DELEGATION CREATED ✓");
        println!("  grantor:    {}", delegation.grantor_did);
        println!(
            "  grantee:    {} ({})",
            grantee_name, delegation.grantee_did
        );
        println!("  level:      {}", delegation.level);
        println!("  expires:    {}", delegation.expires_at);
        println!(
            "  tools:      {}",
            delegation.scope.allowed_tools.join(", ")
        );
        println!("  max_ttl:    {}h", delegation.scope.max_ttl_hours);
        println!("  hash:       {}…", &delegation.delegation_hash[..16]);
        println!("  output:     {}", out_path.display());
    }

    Ok(())
}

fn cmd_revoke_delegation(
    delegation_path: &PathBuf,
    ledger_path: &PathBuf,
    reason: &str,
    output_format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let delegation_json = std::fs::read_to_string(delegation_path)?;
    let delegation: authority::Delegation = serde_json::from_str(&delegation_json)?;

    let db = ledger::Ledger::open(ledger_path)?;
    db.revoke_delegation(&delegation.grantor_did, &delegation.delegation_hash, reason)?;

    // Log to authority ledger
    db.log_authority_event(
        "delegation_revoked",
        &delegation.grantor_did,
        &delegation.grantee_did,
        &format!("revoke_delegation(reason={})", reason),
        &delegation.delegation_hash,
        &delegation.jurisdiction.region,
        &format!("grantee_name={}", delegation.grantee_name),
    )?;

    if output_format == "json" {
        let output = serde_json::json!({
            "revoked": true,
            "delegation_hash": delegation.delegation_hash,
            "grantee": delegation.grantee_did,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("DELEGATION REVOKED ✓");
        println!(
            "  grantee:  {} ({})",
            delegation.grantee_name, delegation.grantee_did
        );
        println!("  hash:     {}…", &delegation.delegation_hash[..16]);
        println!("  reason:   {}", reason);
    }

    Ok(())
}

fn cmd_test(
    suite_path: &PathBuf,
    ledger_path: &PathBuf,
    tag: Option<&str>,
    output_format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let tests = test_harness::load_test_suite(suite_path)?;
    let results = test_harness::run_suite(&tests, tag, ledger_path);

    let passed = results.iter().filter(|r| r.passed).count();
    let failed = results.iter().filter(|r| !r.passed).count();
    let total = results.len();

    if output_format == "json" {
        let output = serde_json::json!({
            "total": total,
            "passed": passed,
            "failed": failed,
            "results": results,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("A2G Policy Test Suite");
        println!("{}", "=".repeat(60));
        println!();

        for r in &results {
            let status = if r.passed { "PASS" } else { "FAIL" };
            let icon = if r.passed { "✓" } else { "✗" };
            println!("  {} {} {}", icon, status, r.test_id);
            if !r.passed {
                println!(
                    "      expected: {} ({})",
                    r.expected_decision, r.expected_rule
                );
                println!("      actual:   {} ({})", r.actual_decision, r.actual_rule);
                println!("      reason:   {}", r.reason);
            }
        }

        println!();
        println!("{}", "-".repeat(60));
        println!("  {} passed, {} failed, {} total", passed, failed, total);

        if failed > 0 {
            std::process::exit(1);
        }
    }

    Ok(())
}

fn cmd_verify_lineage(
    receipt_id: &str,
    ledger_path: &PathBuf,
    output_format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let db = ledger::Ledger::open(ledger_path)?;
    let lineage_result = lineage::reconstruct_lineage(receipt_id, &db, 10);

    match lineage_result {
        Ok(lin) => {
            if output_format == "json" {
                println!("{}", serde_json::to_string_pretty(&lin)?);
            } else {
                println!("EXECUTION LINEAGE");
                println!("{}", "=".repeat(60));
                println!("  receipt:     {}", lin.receipt_id);
                println!("  hash:        {}…", &lin.receipt_hash[..16]);
                println!("  decision:    {}", lin.decision);
                println!("  tool:        {}", lin.tool);
                println!("  agent:       {}", lin.agent_did);
                println!("  timestamp:   {}", lin.timestamp);
                println!("  rule:        {}", lin.policy_rule);
                println!();
                println!("POLICY VERSION");
                println!(
                    "  mandate:     {}",
                    if lin.mandate_hash.is_empty() {
                        "(not captured)"
                    } else {
                        &lin.mandate_hash[..16]
                    }
                );
                println!(
                    "  proposal:    {}",
                    if lin.proposal_hash.is_empty() {
                        "(not captured)"
                    } else {
                        &lin.proposal_hash[..16]
                    }
                );
                println!();
                println!("AUTHORITY CONTEXT");
                let issuer_display = truncate(&lin.issuer_did, 30);
                println!(
                    "  issuer:      {}",
                    if lin.issuer_did.is_empty() {
                        "(not captured)"
                    } else {
                        &issuer_display
                    }
                );
                println!(
                    "  chain:       {}",
                    if lin.delegation_chain_hash.is_empty() {
                        "(not captured)"
                    } else {
                        &lin.delegation_chain_hash[..16]
                    }
                );
                println!(
                    "  level:       {}",
                    if lin.authority_level.is_empty() {
                        "(not captured)"
                    } else {
                        &lin.authority_level
                    }
                );
                println!(
                    "  scope:       {}",
                    if lin.scope_hash.is_empty() {
                        "(not captured)"
                    } else {
                        &lin.scope_hash[..16]
                    }
                );
                println!();
                println!("CORRELATION");
                println!(
                    "  correlation: {}",
                    if lin.correlation_id.is_empty() {
                        "(none)"
                    } else {
                        &lin.correlation_id
                    }
                );
                println!(
                    "  parent:      {}",
                    if lin.parent_receipt_hash.is_empty() {
                        "(none)"
                    } else {
                        &lin.parent_receipt_hash[..16]
                    }
                );

                if let Some(ref parent) = lin.parent_lineage {
                    println!();
                    println!("PARENT RECEIPT");
                    println!("  receipt:     {}", parent.receipt_id);
                    println!("  decision:    {}", parent.decision);
                    println!("  tool:        {}", parent.tool);
                }

                println!();
                if lin.lineage_complete {
                    println!("LINEAGE COMPLETE ✓");
                } else {
                    println!("LINEAGE INCOMPLETE ✗");
                    println!("  missing: {}", lin.missing_fields.join(", "));
                }
            }
        }
        Err(e) => {
            if output_format == "json" {
                let output = serde_json::json!({
                    "error": e.to_string(),
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                eprintln!("error: {}", e);
            }
            std::process::exit(1);
        }
    }

    Ok(())
}

fn cmd_compress(
    agent_did: &str,
    start: &str,
    end: &str,
    ledger_path: &PathBuf,
    key_path: &PathBuf,
    issuer_name: &str,
    out_path: &PathBuf,
    min_decisions: u64,
    output_format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let db = ledger::Ledger::open(ledger_path)?;

    // Quick count check
    let count = db.count_window(agent_did, start, end)?;
    if (count as u64) < min_decisions {
        return Err(format!(
            "only {} decisions found (minimum {} required)",
            count, min_decisions
        )
        .into());
    }

    // Compress the window
    let data = trust_summary::compress_window(&db, agent_did, start, end)?;

    // Load signing key
    let key_hex = std::fs::read_to_string(key_path)?.trim().to_string();
    let key_bytes = hex::decode(&key_hex)?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "invalid secret key length (expected 32 bytes / 64 hex chars)")?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_array);

    // Derive issuer DID from signing key
    let issuer_pubkey = signing_key.verifying_key();
    let issuer_did = format!(
        "did:a2g:{}",
        bs58::encode(issuer_pubkey.to_bytes()).into_string()
    );

    // Sign the summary
    let summary = trust_summary::sign_summary(data, &signing_key, &issuer_did, issuer_name)?;

    // Write output
    let json = serde_json::to_string_pretty(&summary)?;
    std::fs::write(out_path, &json)?;

    if output_format == "json" {
        println!("{}", json);
    } else {
        println!("TRUST SUMMARY COMPRESSED");
        println!("{}", "=".repeat(60));
        println!("  agent:       {}", summary.agent_did);
        println!(
            "  window:      {} → {}",
            summary.window_start, summary.window_end
        );
        println!("  decisions:   {}", summary.total_decisions);
        println!("  compliance:  {:.1}%", summary.compliance_rate);
        println!("  deny rate:   {:.1}%", summary.deny_rate);
        println!("  escalation:  {:.1}%", summary.escalation_rate);
        println!("  tools:       {} unique", summary.unique_tools);
        println!("  mandates:    {} unique", summary.unique_mandates);
        println!("  merkle root: {}…", &summary.merkle_root[..16]);
        println!(
            "  chain:       {}",
            if summary.chain_intact {
                "INTACT ✓"
            } else {
                "BROKEN ✗"
            }
        );
        println!(
            "  signed by:   {} ({})",
            summary.issuer_name,
            truncate(&summary.issuer_did, 30)
        );
        println!();
        println!("  output:      {}", out_path.display());
    }

    Ok(())
}

fn cmd_verify_summary(
    summary_path: &PathBuf,
    output_format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = std::fs::read_to_string(summary_path)?;
    let summary: trust_summary::TrustSummary = serde_json::from_str(&json)?;

    let valid = trust_summary::verify_summary(&summary)?;

    if output_format == "json" {
        let output = serde_json::json!({
            "valid": valid,
            "summary_id": summary.summary_id,
            "agent_did": summary.agent_did,
            "window_start": summary.window_start,
            "window_end": summary.window_end,
            "total_decisions": summary.total_decisions,
            "compliance_rate": summary.compliance_rate,
            "merkle_root": summary.merkle_root,
            "chain_intact": summary.chain_intact,
            "issuer_did": summary.issuer_did,
            "issuer_name": summary.issuer_name,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("TRUST SUMMARY VERIFICATION");
        println!("{}", "=".repeat(60));
        println!("  agent:       {}", summary.agent_did);
        println!(
            "  window:      {} → {}",
            summary.window_start, summary.window_end
        );
        println!("  decisions:   {}", summary.total_decisions);
        println!("  compliance:  {:.1}%", summary.compliance_rate);
        println!("  merkle root: {}…", &summary.merkle_root[..16]);
        println!(
            "  chain:       {}",
            if summary.chain_intact {
                "INTACT ✓"
            } else {
                "BROKEN ✗"
            }
        );
        println!(
            "  signature:   {}",
            if valid { "VALID ✓" } else { "INVALID ✗" }
        );
    }

    if !valid {
        std::process::exit(1);
    }

    Ok(())
}

fn cmd_visual_receipt(
    receipt_id: &str,
    ledger_path: &PathBuf,
    format: &str,
    out_path: Option<&PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let db = ledger::Ledger::open(ledger_path)?;

    // Lookup the receipt in the ledger
    let entry = db
        .query_decision_by_id(receipt_id)?
        .ok_or_else(|| format!("receipt '{}' not found in ledger", receipt_id))?;

    // Try to reconstruct lineage (non-fatal if it fails)
    let lineage = lineage::reconstruct_lineage(receipt_id, &db, 5).ok();

    // Verify chain integrity around this receipt
    let (chain_ok, _) = db.verify_chain()?;

    match format {
        "html" => {
            let html = visual_receipt::render_html(&entry, lineage.as_ref(), chain_ok);
            if let Some(path) = out_path {
                std::fs::write(path, &html)?;
                println!("visual receipt → {}", path.display());
            } else {
                println!("{}", html);
            }
        }
        "json" => {
            let json = visual_receipt::render_json(&entry, lineage.as_ref(), chain_ok)?;
            println!("{}", json);
        }
        _ => {
            // Terminal output
            let output = visual_receipt::render_terminal(&entry, lineage.as_ref(), chain_ok);
            println!("{}", output);
        }
    }

    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max - 1).collect();
        format!("{}…", truncated)
    }
}
