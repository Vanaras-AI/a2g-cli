//! Decision Ledger — Append-only SQLite store for governance decisions
//!
//! Every enforcement verdict is persisted here. Records cannot be
//! modified or deleted. The ledger stores params_hash (not raw params)
//! to prevent sensitive data from entering the audit trail.

use crate::enforce::Verdict;
use crate::receipt::Receipt;
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::Digest;
use std::path::Path;

/// A single ledger entry for display
pub struct LedgerEntry {
    pub seq: i64,
    pub receipt_id: String,
    pub agent_did: String,
    pub agent_name: String,
    pub tool: String,
    pub params_hash: String,
    pub decision: String,
    pub policy_rule: String,
    pub timestamp: String,
    pub prev_hash: String,
    pub receipt_hash: String,
    pub mandate_hash: String,
    pub proposal_hash: String,
    pub delegation_chain_hash: String,
    pub issuer_did: String,
    pub authority_level: String,
    pub scope_hash: String,
    pub correlation_id: String,
    pub parent_receipt_hash: String,
}

/// A single authority log entry for display
pub struct AuthorityLogEntry {
    pub seq: i64,
    pub event_type: String,
    pub actor_did: String,
    pub target_did: String,
    pub action: String,
    pub jurisdiction: String,
    pub timestamp: String,
    pub details: String,
    pub event_hash: String,
}

/// Append-only governance decision ledger backed by SQLite
pub struct Ledger {
    conn: Connection,
}

impl Ledger {
    /// Open or create a ledger database
    pub fn open(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let conn = Connection::open(path)?;

        // Enable WAL mode for concurrent reads
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.execute_batch("PRAGMA busy_timeout = 5000;")?;

        // Create tables if not exists
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS decisions (
                seq            INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id     TEXT NOT NULL UNIQUE,
                verdict_id     TEXT NOT NULL,
                agent_did      TEXT NOT NULL,
                agent_name     TEXT NOT NULL,
                tool           TEXT NOT NULL,
                params_hash    TEXT NOT NULL,
                decision       TEXT NOT NULL,
                policy_rule    TEXT NOT NULL,
                policy_hash    TEXT NOT NULL,
                timestamp      TEXT NOT NULL,
                prev_hash      TEXT NOT NULL,
                receipt_hash   TEXT NOT NULL,
                mandate_hash   TEXT DEFAULT '',
                proposal_hash  TEXT DEFAULT '',
                delegation_chain_hash TEXT DEFAULT '',
                issuer_did     TEXT DEFAULT '',
                authority_level TEXT DEFAULT '',
                scope_hash     TEXT DEFAULT '',
                correlation_id TEXT DEFAULT '',
                parent_receipt_hash TEXT DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_agent_did ON decisions(agent_did);
            CREATE INDEX IF NOT EXISTS idx_decision ON decisions(decision);
            CREATE INDEX IF NOT EXISTS idx_timestamp ON decisions(timestamp);

            -- S1 FIX: Revocation table for mandate revocation
            CREATE TABLE IF NOT EXISTS revocations (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_did       TEXT NOT NULL,
                mandate_hash    TEXT NOT NULL,
                revoked_by      TEXT NOT NULL,
                reason          TEXT NOT NULL DEFAULT '',
                revoked_at      TEXT NOT NULL,
                UNIQUE(agent_did, mandate_hash)
            );

            CREATE INDEX IF NOT EXISTS idx_revocations_agent ON revocations(agent_did);
            CREATE INDEX IF NOT EXISTS idx_revocations_hash ON revocations(mandate_hash);"
        )?;

        // Phase 1-4: Lineage columns migration
        let migrations = [
            "ALTER TABLE decisions ADD COLUMN mandate_hash TEXT DEFAULT ''",
            "ALTER TABLE decisions ADD COLUMN proposal_hash TEXT DEFAULT ''",
            "ALTER TABLE decisions ADD COLUMN delegation_chain_hash TEXT DEFAULT ''",
            "ALTER TABLE decisions ADD COLUMN issuer_did TEXT DEFAULT ''",
            "ALTER TABLE decisions ADD COLUMN authority_level TEXT DEFAULT ''",
            "ALTER TABLE decisions ADD COLUMN scope_hash TEXT DEFAULT ''",
            "ALTER TABLE decisions ADD COLUMN correlation_id TEXT DEFAULT ''",
            "ALTER TABLE decisions ADD COLUMN parent_receipt_hash TEXT DEFAULT ''",
        ];
        for sql in &migrations {
            let _ = conn.execute(sql, []); // Ignore "duplicate column" errors
        }
        // Indexes for lineage queries
        let _ = conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_mandate_hash ON decisions(mandate_hash);
             CREATE INDEX IF NOT EXISTS idx_correlation_id ON decisions(correlation_id);
             CREATE INDEX IF NOT EXISTS idx_issuer_did ON decisions(issuer_did);"
        );

        // Phase 3: Proposal history table
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS proposal_history (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                proposal_id TEXT NOT NULL UNIQUE,
                proposer_did TEXT NOT NULL,
                mandate_hash TEXT NOT NULL,
                proposal_hash TEXT NOT NULL,
                status TEXT NOT NULL,
                risk_level TEXT NOT NULL DEFAULT '',
                required_approvals INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                approved_at TEXT DEFAULT NULL,
                approval_context_hash TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_proposal_id ON proposal_history(proposal_id);"
        )?;

        // Re-enable triggers
        conn.execute_batch(
            "-- S5 FIX: Enforce append-only via triggers that prevent UPDATE and DELETE
            CREATE TRIGGER IF NOT EXISTS prevent_decision_update
                BEFORE UPDATE ON decisions
                BEGIN
                    SELECT RAISE(ABORT, 'A2G LEDGER INTEGRITY: decisions table is append-only, UPDATE forbidden');
                END;

            CREATE TRIGGER IF NOT EXISTS prevent_decision_delete
                BEFORE DELETE ON decisions
                BEGIN
                    SELECT RAISE(ABORT, 'A2G LEDGER INTEGRITY: decisions table is append-only, DELETE forbidden');
                END;

            CREATE TRIGGER IF NOT EXISTS prevent_revocation_delete
                BEFORE DELETE ON revocations
                BEGIN
                    SELECT RAISE(ABORT, 'A2G LEDGER INTEGRITY: revocations table is append-only, DELETE forbidden');
                END;

            -- Layer 0: Authority decisions audit trail
            CREATE TABLE IF NOT EXISTS authority_log (
                seq              INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type       TEXT NOT NULL,
                actor_did        TEXT NOT NULL,
                target_did       TEXT NOT NULL,
                action           TEXT NOT NULL,
                scope_hash       TEXT NOT NULL,
                jurisdiction     TEXT NOT NULL DEFAULT '',
                timestamp        TEXT NOT NULL,
                details          TEXT NOT NULL DEFAULT '',
                event_hash       TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_authority_actor ON authority_log(actor_did);
            CREATE INDEX IF NOT EXISTS idx_authority_target ON authority_log(target_did);
            CREATE INDEX IF NOT EXISTS idx_authority_type ON authority_log(event_type);

            CREATE TRIGGER IF NOT EXISTS prevent_authority_log_update
                BEFORE UPDATE ON authority_log
                BEGIN
                    SELECT RAISE(ABORT, 'A2G LEDGER INTEGRITY: authority_log is append-only');
                END;

            CREATE TRIGGER IF NOT EXISTS prevent_authority_log_delete
                BEFORE DELETE ON authority_log
                BEGIN
                    SELECT RAISE(ABORT, 'A2G LEDGER INTEGRITY: authority_log is append-only');
                END;",
        )?;

        Ok(Ledger { conn })
    }

    /// Log an authority governance event (delegation, proposal, approval, revocation)
    pub fn log_authority_event(
        &self,
        event_type: &str,
        actor_did: &str,
        target_did: &str,
        action: &str,
        scope_hash: &str,
        jurisdiction: &str,
        details: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let now = Utc::now().to_rfc3339();
        let hash_input = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            event_type, actor_did, target_did, action,
            scope_hash, jurisdiction, now, details,
        );
        let event_hash = hex::encode(sha2::Sha256::digest(hash_input.as_bytes()));

        self.conn.execute(
            "INSERT INTO authority_log (
                event_type, actor_did, target_did, action,
                scope_hash, jurisdiction, timestamp, details, event_hash
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![event_type, actor_did, target_did, action,
                    scope_hash, jurisdiction, now, details, event_hash],
        )?;
        Ok(())
    }

    /// Query authority log with optional filters
    pub fn query_authority_log(
        &self,
        event_type: Option<&str>,
        actor: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuthorityLogEntry>, Box<dyn std::error::Error>> {
        let mut sql = String::from(
            "SELECT seq, event_type, actor_did, target_did, action,
                    jurisdiction, timestamp, details, event_hash
             FROM authority_log WHERE 1=1",
        );
        let mut bind_values: Vec<String> = Vec::new();

        if let Some(et) = event_type {
            bind_values.push(et.to_string());
            sql.push_str(&format!(" AND event_type = ?{}", bind_values.len()));
        }
        if let Some(a) = actor {
            bind_values.push(a.to_string());
            sql.push_str(&format!(" AND actor_did = ?{}", bind_values.len()));
        }

        sql.push_str(&format!(" ORDER BY seq DESC LIMIT {}", limit));

        let mut stmt = self.conn.prepare(&sql)?;
        let params: Vec<&dyn rusqlite::types::ToSql> =
            bind_values.iter().map(|v| v as &dyn rusqlite::types::ToSql).collect();

        let entries = stmt
            .query_map(params.as_slice(), |row| {
                Ok(AuthorityLogEntry {
                    seq: row.get(0)?,
                    event_type: row.get(1)?,
                    actor_did: row.get(2)?,
                    target_did: row.get(3)?,
                    action: row.get(4)?,
                    jurisdiction: row.get(5)?,
                    timestamp: row.get(6)?,
                    details: row.get(7)?,
                    event_hash: row.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(entries)
    }

    /// Revoke a mandate by agent DID and mandate content hash
    pub fn revoke_mandate(
        &self,
        agent_did: &str,
        mandate_hash: &str,
        revoked_by: &str,
        reason: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT OR IGNORE INTO revocations (agent_did, mandate_hash, revoked_by, reason, revoked_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![agent_did, mandate_hash, revoked_by, reason, now],
        )?;
        Ok(())
    }

    /// Check if a mandate is revoked
    pub fn is_revoked(
        &self,
        agent_did: &str,
        mandate_hash: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM revocations WHERE agent_did = ?1 AND mandate_hash = ?2",
            params![agent_did, mandate_hash],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Check if a delegation has been revoked
    pub fn is_delegation_revoked(&self, delegation_hash: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM revocations WHERE mandate_hash = ?1",
            rusqlite::params![delegation_hash],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Revoke a delegation
    pub fn revoke_delegation(
        &self,
        grantor_did: &str,
        delegation_hash: &str,
        reason: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO revocations (agent_did, mandate_hash, revoked_by, reason, revoked_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![grantor_did, delegation_hash, grantor_did, reason, now],
        )?;
        Ok(())
    }

    /// Append a verdict and its receipt to the ledger.
    /// Validates chain integrity: receipt's prev_hash must match the last entry's receipt_hash.
    pub fn append(
        &self,
        verdict: &Verdict,
        receipt: &Receipt,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // S5 FIX: Verify chain continuity before appending
        let last = self.last_receipt_hash()?;
        let expected_prev = last.unwrap_or_else(|| "0".repeat(64));
        if receipt.prev_hash != expected_prev {
            return Err(format!(
                "chain integrity violation: receipt prev_hash '{}…' does not match ledger last hash '{}…'",
                &receipt.prev_hash[..16],
                &expected_prev[..16],
            ).into());
        }

        self.conn.execute(
            "INSERT INTO decisions (
                receipt_id, verdict_id, agent_did, agent_name,
                tool, params_hash, decision, policy_rule,
                policy_hash, timestamp, prev_hash, receipt_hash,
                mandate_hash, proposal_hash, delegation_chain_hash,
                issuer_did, authority_level, scope_hash,
                correlation_id, parent_receipt_hash
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
            params![
                receipt.receipt_id,
                verdict.verdict_id,
                verdict.agent_did,
                verdict.agent_name,
                verdict.tool,
                verdict.params_hash,
                verdict.decision.to_string(),
                verdict.policy_rule,
                receipt.policy_hash,
                receipt.timestamp,
                receipt.prev_hash,
                receipt.receipt_hash,
                receipt.mandate_hash,
                receipt.proposal_hash,
                receipt.delegation_chain_hash,
                receipt.issuer_did,
                receipt.authority_level,
                receipt.scope_hash,
                receipt.correlation_id,
                receipt.parent_receipt_hash,
            ],
        )?;

        Ok(())
    }

    /// Atomically generate a receipt and append it to the ledger.
    ///
    /// C2 FIX: Uses BEGIN IMMEDIATE to acquire the write lock BEFORE reading
    /// the last hash. This prevents the TOCTOU race where concurrent processes
    /// could read the same prev_hash and produce duplicate chain links.
    /// SQLite's WAL mode + busy_timeout serializes IMMEDIATE transactions
    /// across all processes sharing the same database file.
    pub fn enforce_and_record(
        &self,
        verdict: &Verdict,
    ) -> Result<crate::receipt::Receipt, Box<dyn std::error::Error>> {
        // Acquire write lock IMMEDIATELY — blocks concurrent writers
        self.conn.execute_batch("BEGIN IMMEDIATE")?;

        let result = (|| -> Result<crate::receipt::Receipt, Box<dyn std::error::Error>> {
            // Read last hash inside the exclusive write lock
            let last_hash: Option<String> = self.conn.query_row(
                "SELECT receipt_hash FROM decisions ORDER BY seq DESC LIMIT 1",
                [],
                |row| row.get(0),
            ).optional()?;

            // Initialize chain and generate receipt atomically
            crate::receipt::init_chain_from_ledger(last_hash);
            let receipt = crate::receipt::generate_receipt(verdict);

            // Append inside the same transaction
            self.conn.execute(
                "INSERT INTO decisions (
                    receipt_id, verdict_id, agent_did, agent_name,
                    tool, params_hash, decision, policy_rule,
                    policy_hash, timestamp, prev_hash, receipt_hash,
                    mandate_hash, proposal_hash, delegation_chain_hash,
                    issuer_did, authority_level, scope_hash,
                    correlation_id, parent_receipt_hash
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
                params![
                    receipt.receipt_id, verdict.verdict_id,
                    verdict.agent_did, verdict.agent_name,
                    verdict.tool, verdict.params_hash,
                    verdict.decision.to_string(), verdict.policy_rule,
                    receipt.policy_hash, receipt.timestamp,
                    receipt.prev_hash, receipt.receipt_hash,
                    receipt.mandate_hash, receipt.proposal_hash,
                    receipt.delegation_chain_hash, receipt.issuer_did,
                    receipt.authority_level, receipt.scope_hash,
                    receipt.correlation_id, receipt.parent_receipt_hash,
                ],
            )?;

            Ok(receipt)
        })();

        match result {
            Ok(receipt) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(receipt)
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// Count recent decisions for an agent within the last N seconds
    /// Used for rate limiting
    pub fn count_recent(
        &self,
        agent_did: &str,
        seconds: i64,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let cutoff = (Utc::now() - chrono::Duration::seconds(seconds)).to_rfc3339();

        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM decisions WHERE agent_did = ?1 AND timestamp > ?2",
            params![agent_did, cutoff],
            |row| row.get(0),
        )?;

        Ok(count as u64)
    }

    /// Query the ledger with optional filters
    pub fn query(
        &self,
        agent: Option<&str>,
        decision: Option<&str>,
        limit: usize,
    ) -> Result<Vec<LedgerEntry>, Box<dyn std::error::Error>> {
        let mut sql = String::from(
            "SELECT seq, receipt_id, agent_did, agent_name, tool, params_hash,
                    decision, policy_rule, timestamp, prev_hash, receipt_hash,
                    mandate_hash, proposal_hash, delegation_chain_hash,
                    issuer_did, authority_level, scope_hash,
                    correlation_id, parent_receipt_hash
             FROM decisions WHERE 1=1",
        );
        let mut bind_values: Vec<String> = Vec::new();

        if let Some(a) = agent {
            bind_values.push(a.to_string());
            sql.push_str(&format!(" AND agent_did = ?{}", bind_values.len()));
        }
        if let Some(d) = decision {
            bind_values.push(d.to_string());
            sql.push_str(&format!(" AND decision = ?{}", bind_values.len()));
        }

        sql.push_str(&format!(" ORDER BY seq DESC LIMIT {}", limit));

        let mut stmt = self.conn.prepare(&sql)?;

        let params: Vec<&dyn rusqlite::types::ToSql> =
            bind_values.iter().map(|v| v as &dyn rusqlite::types::ToSql).collect();

        let entries = stmt
            .query_map(params.as_slice(), |row| {
                Ok(LedgerEntry {
                    seq: row.get(0)?,
                    receipt_id: row.get(1)?,
                    agent_did: row.get(2)?,
                    agent_name: row.get(3)?,
                    tool: row.get(4)?,
                    params_hash: row.get(5)?,
                    decision: row.get(6)?,
                    policy_rule: row.get(7)?,
                    timestamp: row.get(8)?,
                    prev_hash: row.get(9)?,
                    receipt_hash: row.get(10)?,
                    mandate_hash: row.get(11)?,
                    proposal_hash: row.get(12)?,
                    delegation_chain_hash: row.get(13)?,
                    issuer_did: row.get(14)?,
                    authority_level: row.get(15)?,
                    scope_hash: row.get(16)?,
                    correlation_id: row.get(17)?,
                    parent_receipt_hash: row.get(18)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(entries)
    }

    /// Log a proposal to the proposal_history table
    pub fn log_proposal(&self, proposal_id: &str, proposer_did: &str, mandate_hash: &str, proposal_hash: &str, status: &str, risk_level: &str, required_approvals: usize, created_at: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.conn.execute(
            "INSERT INTO proposal_history (proposal_id, proposer_did, mandate_hash, proposal_hash, status, risk_level, required_approvals, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![proposal_id, proposer_did, mandate_hash, proposal_hash, status, risk_level, required_approvals as i64, created_at],
        )?;
        Ok(())
    }

    /// Query a decision by receipt ID or receipt hash
    pub fn query_decision_by_id(&self, receipt_id_or_hash: &str) -> Result<Option<LedgerEntry>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, receipt_id, agent_did, agent_name, tool, params_hash,
                    decision, policy_rule, timestamp, prev_hash, receipt_hash,
                    mandate_hash, proposal_hash, delegation_chain_hash,
                    issuer_did, authority_level, scope_hash,
                    correlation_id, parent_receipt_hash
             FROM decisions WHERE receipt_id = ?1 OR receipt_hash = ?1 LIMIT 1"
        )?;
        let result = stmt.query_row(params![receipt_id_or_hash], |row| {
            Ok(LedgerEntry {
                seq: row.get(0)?,
                receipt_id: row.get(1)?,
                agent_did: row.get(2)?,
                agent_name: row.get(3)?,
                tool: row.get(4)?,
                params_hash: row.get(5)?,
                decision: row.get(6)?,
                policy_rule: row.get(7)?,
                timestamp: row.get(8)?,
                prev_hash: row.get(9)?,
                receipt_hash: row.get(10)?,
                mandate_hash: row.get(11)?,
                proposal_hash: row.get(12)?,
                delegation_chain_hash: row.get(13)?,
                issuer_did: row.get(14)?,
                authority_level: row.get(15)?,
                scope_hash: row.get(16)?,
                correlation_id: row.get(17)?,
                parent_receipt_hash: row.get(18)?,
            })
        }).optional()?;
        Ok(result)
    }

    /// Get the last receipt hash in the ledger (for chain linking across process restarts)
    pub fn last_receipt_hash(&self) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT receipt_hash FROM decisions ORDER BY seq DESC LIMIT 1",
        )?;

        let result: Option<String> = stmt
            .query_row([], |row| row.get(0))
            .ok();

        Ok(result)
    }

    /// Get the total number of entries in the ledger
    pub fn count_total(&self) -> Result<i64, Box<dyn std::error::Error>> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM decisions",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Verify ledger chain integrity (check receipt hashes form a valid chain)
    pub fn verify_chain(&self) -> Result<(bool, usize), Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT receipt_hash, prev_hash FROM decisions ORDER BY seq ASC",
        )?;

        let entries: Vec<(String, String)> = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        if entries.is_empty() {
            return Ok((true, 0));
        }

        // First entry should point to genesis
        if entries[0].1 != "0".repeat(64) {
            return Ok((false, 0));
        }

        // Each subsequent entry's prev_hash should match previous receipt_hash
        for i in 1..entries.len() {
            if entries[i].1 != entries[i - 1].0 {
                return Ok((false, i));
            }
        }

        Ok((true, entries.len()))
    }

    /// Query decisions for a specific agent within a time window
    pub fn query_window(
        &self,
        agent_did: &str,
        start: &str,
        end: &str,
    ) -> Result<Vec<LedgerEntry>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, receipt_id, agent_did, agent_name, tool, params_hash,
                    decision, policy_rule, timestamp, prev_hash, receipt_hash,
                    mandate_hash, proposal_hash, delegation_chain_hash,
                    issuer_did, authority_level, scope_hash,
                    correlation_id, parent_receipt_hash
             FROM decisions
             WHERE agent_did = ?1 AND timestamp >= ?2 AND timestamp <= ?3
             ORDER BY seq ASC"
        )?;

        let entries = stmt.query_map(params![agent_did, start, end], |row| {
            Ok(LedgerEntry {
                seq: row.get(0)?,
                receipt_id: row.get(1)?,
                agent_did: row.get(2)?,
                agent_name: row.get(3)?,
                tool: row.get(4)?,
                params_hash: row.get(5)?,
                decision: row.get(6)?,
                policy_rule: row.get(7)?,
                timestamp: row.get(8)?,
                prev_hash: row.get(9)?,
                receipt_hash: row.get(10)?,
                mandate_hash: row.get(11)?,
                proposal_hash: row.get(12)?,
                delegation_chain_hash: row.get(13)?,
                issuer_did: row.get(14)?,
                authority_level: row.get(15)?,
                scope_hash: row.get(16)?,
                correlation_id: row.get(17)?,
                parent_receipt_hash: row.get(18)?,
            })
        })?.collect::<Result<Vec<_>, _>>()?;

        Ok(entries)
    }

    /// Count decisions for a specific agent within a time window (fast check)
    pub fn count_window(
        &self,
        agent_did: &str,
        start: &str,
        end: &str,
    ) -> Result<i64, Box<dyn std::error::Error>> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM decisions WHERE agent_did = ?1 AND timestamp >= ?2 AND timestamp <= ?3",
            params![agent_did, start, end],
            |row| row.get(0),
        )?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enforce::{Decision, Verdict};
    use crate::receipt;
    use chrono::Utc;
    use std::path::PathBuf;

    fn temp_ledger() -> Ledger {
        Ledger::open(&PathBuf::from(":memory:")).unwrap()
    }

    fn make_verdict(tool: &str, decision: Decision) -> Verdict {
        Verdict {
            verdict_id: uuid::Uuid::new_v4().to_string(),
            agent_did: "did:a2g:test".to_string(),
            agent_name: "test-agent".to_string(),
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
    fn test_append_and_query() {
        let db = temp_ledger();
        // Use enforce_and_record which handles chain state atomically (C2 fix)
        let v = make_verdict("read_file", Decision::Allow);
        let _r = db.enforce_and_record(&v).unwrap();

        let entries = db.query(None, None, 10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tool, "read_file");
        assert_eq!(entries[0].decision, "ALLOW");
    }

    #[test]
    fn test_rate_limiting() {
        let db = temp_ledger();
        for _ in 0..5 {
            // Use enforce_and_record which handles chain state atomically (C2 fix)
            let v = make_verdict("write_file", Decision::Allow);
            let _r = db.enforce_and_record(&v).unwrap();
        }

        let count = db.count_recent("did:a2g:test", 60).unwrap();
        assert_eq!(count, 5);
    }
}
