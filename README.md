# A2G Protocol

**Deterministic governance for autonomous AI agents.**

A2G (Agent-to-Governance) is a Rust CLI that enforces what AI agents can and cannot do — before execution, not after. Every tool call passes through an 8-step cryptographic pipeline that produces an immutable audit trail. Zero LLM calls. Every decision is reproducible, verifiable, and legally auditable.

Built by [Vanaras AI](https://github.com/Vanaras-AI).

## Why A2G

Guardrails check if output is safe — probabilistic, post-hoc. A2G checks if the agent is **authorized to act** — deterministic, pre-execution.

When an autonomous agent calls a tool, A2G answers three questions:

1. **Is this agent allowed to use this tool?** (mandate + delegation chain)
2. **Is this action within bounds?** (filesystem, network, time, jurisdiction)
3. **Can we prove it later?** (ed25519 signatures, hash-chained receipts, append-only ledger)

## Quick Start

```bash
# Build
cargo build --release

# Create sovereign identity (governance root)
a2g sovereign

# Create agent identity + mandate template
a2g init --name my-agent

# Create authority root
a2g authority-root --key sovereign.secret.key --name "Org-Root" --ttl 720 --out root.json

# Propose the mandate
a2g propose --proposer $(cat my-agent.did) --name "My Agent" \
    --mandate my-agent.mandate.toml --justification "Data processing"

# Approve it
a2g review --proposal proposal.json --key sovereign.secret.key \
    --reviewer-name "Admin" --decision approve

# Sign the mandate (24h TTL)
a2g sign --mandate my-agent.mandate.toml --key sovereign.secret.key \
    --ttl 24 --proposal proposal.json

# Enforce a tool call
a2g enforce --mandate my-agent.mandate.toml --tool read_file \
    --params '{"path": "data.csv"}' --authority-chain root.json
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        YOUR AI AGENT                                │
│  (LangChain │ CrewAI │ OpenAI Agents │ Claude SDK │ MCP │ Custom)  │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ tool_use / function_call
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    A2G GOVERNANCE LAYER                              │
│                                                                     │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌──────────────────┐  │
│  │ IDENTITY │→ │ MANDATE  │→ │ ENFORCE   │→ │ RECEIPT + LEDGER │  │
│  │ ed25519  │  │ TOML+sig │  │ 8-step    │  │ hash-chained     │  │
│  │ DID:a2g  │  │ TTL+scope│  │ pipeline  │  │ immutable audit  │  │
│  └──────────┘  └──────────┘  └─────┬─────┘  └──────────────────┘  │
│                                    │                                │
│                    ┌───────────────┼───────────────┐                │
│                    ▼               ▼               ▼                │
│                 ALLOW           DENY          ESCALATE              │
│                 execute         block          human-in-loop        │
│                                                                     │
│  ┌─────────────────── LAYER 0: AUTHORITY ──────────────────────┐   │
│  │ Root → Department → Team → Operator delegation chains       │   │
│  │ Mandate proposals with risk-based multi-reviewer approval   │   │
│  │ Jurisdiction binding (region, regulatory, operating hours)  │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

## Enforcement Pipeline

Every `a2g enforce` call runs 8 deterministic steps:

| Step | Check | What It Does |
|------|-------|--------------|
| 0 | **Input Validation** | Rejects empty tools, oversized params (>1MB), path traversal |
| 1 | **Revocation** | Checks if the mandate has been revoked before TTL expiry |
| 2 | **Signature** | ed25519 verification with domain-separated payloads (`MANDATE:`) |
| 3 | **TTL** | Rejects expired mandates (max 8760h / 1 year) |
| 4 | **Tool + Boundary** | Allow/deny list matching, filesystem/network glob enforcement with `workspace_root` resolution |
| 5 | **Jurisdiction** | Region, environment, operating hours (numeric minute comparison) |
| 6 | **Escalation** | Pattern-matched actions that require human approval |
| 7 | **Rate Limit** | Per-minute call cap from mandate |
| 8 | **Authority Chain** | Validates delegation chain signatures, scope constraints, key-DID binding, revocation status |

Result: `ALLOW`, `DENY`, or `ESCALATE` — each producing a signed, hash-chained receipt in the SQLite ledger.

## CLI Reference

### Identity & Setup

| Command | Description |
|---------|-------------|
| `a2g sovereign` | Generate sovereign ed25519 keypair (governance root) |
| `a2g init --name <name>` | Generate agent keypair + mandate template |

### Authority (Layer 0)

| Command | Description |
|---------|-------------|
| `a2g authority-root --key <key> --name <name>` | Create root delegation from sovereign |
| `a2g delegate --parent <delegation.json> --key <key> --grantee <did> --grantee-name <name>` | Sub-delegate authority |
| `a2g revoke-delegation --delegation <file> --key <key> --ledger <db>` | Revoke a delegation |
| `a2g authority-log --ledger <db>` | Query Layer 0 governance events |

### Mandate Lifecycle

| Command | Description |
|---------|-------------|
| `a2g propose --proposer <did> --name <name> --mandate <toml> --justification <text>` | Create a mandate proposal |
| `a2g review --proposal <json> --key <key> --reviewer-name <name> --decision <approve\|reject>` | Review a proposal |
| `a2g sign --mandate <toml> --key <key> --ttl <hours> --proposal <json>` | Sign a mandate (requires approved proposal) |
| `a2g verify --mandate <toml>` | Verify signature + TTL + identity |
| `a2g revoke --mandate <toml> --ledger <db>` | Revoke a mandate |

### Enforcement & Audit

| Command | Description |
|---------|-------------|
| `a2g enforce --mandate <toml> --tool <name> --params <json>` | Evaluate a tool call (returns ALLOW/DENY/ESCALATE) |
| `a2g audit --ledger <db>` | Query the decision ledger |
| `a2g receipt --receipt <json> --engine-key <key>` | Verify a governance receipt |

All commands support `--output json` for machine-readable output.

## Security Hardening

The protocol includes defenses against:

- **Approve-then-tamper**: Signature verification after proposal approval detects any mandate modification
- **Cross-type replay**: Domain-separated signatures (`MANDATE:`, `DELEGATION:`, `REVIEW:` prefixes) prevent using a mandate signature as a delegation
- **Key-DID forgery**: Delegation chain verifies that signing keys actually derive to claimed DIDs
- **Path traversal**: Input validation rejects `..`, `/`, `\`, null bytes in agent names
- **ReDoS**: Output governance regex patterns run with `size_limit(100_000)` via `RegexBuilder`
- **SQLite write starvation**: `PRAGMA busy_timeout = 5000` on all connections
- **Delegation escape**: Revoked delegations checked at enforcement time, not just signing time

## Execution Lineage

Every receipt carries full provenance metadata:

- **mandate_hash** — SHA-256 of the exact mandate version used
- **proposal_hash** — links to the governance proposal that approved this mandate
- **delegation_chain_hash** — links to the authority delegation chain
- **correlation_id** — UUID linking related decisions across vendors and frameworks
- **parent_receipt_hash** — receipt hash of the triggering decision (causal graph)

Reconstruct the full lineage of any decision:
```python
lineage = client.verify_lineage("receipt-uuid-here")
print(lineage.mandate_hash)          # which mandate version authorized this
print(lineage.issuer_did)            # who signed the mandate
print(lineage.authority_level)       # ROOT / DEPARTMENT / TEAM / OPERATOR
print(lineage.lineage_complete)      # True if full chain is intact
```

## Trust Compression

Compress an agent's governance history into a signed, portable trust proof:

```bash
a2g compress --agent did:a2g:my-agent \
    --start 2026-01-01T00:00:00Z --end 2026-03-31T23:59:59Z \
    --ledger gov.db --key sovereign.secret.key \
    --issuer-name "Trust Authority" --out q1-summary.json
```

The trust summary includes:
- Decision aggregates (total, compliance rate, deny rate, escalation rate)
- Tool usage breakdown and authority coverage
- Merkle root of all receipt hashes (verify without full ledger)
- Hash-chain integrity flag
- ed25519 signature by the issuing authority

```bash
# Verify a trust summary
a2g verify-summary --summary q1-summary.json
```

## Framework Integrations

Drop-in governance for 5 major AI agent frameworks. See [`integrations/`](integrations/) for full docs and code.

| Framework | Pattern | Lines to Add |
|-----------|---------|-------------|
| LangChain / LangGraph | Tool wrapper + Toolkit + Callback | 3 |
| CrewAI | Agent wrapper + Crew governance | 3 |
| OpenAI Agents SDK | Function decorator + Guardrail | 3 |
| MCP Server | Governed MCP server (any client) | CLI only |
| Claude Agent SDK | Tool processor + Agent loop | 3 |

**LangChain:**
```python
from a2g_client import A2GClient
from a2g_langchain import A2GToolkit

client = A2GClient(mandate_path="my-agent.mandate.toml")
toolkit = A2GToolkit(tools=your_tools, a2g_client=client)
agent = create_react_agent(llm, toolkit.governed_tools)
```

**CrewAI:**
```python
from a2g_crewai import govern_crew
governed = govern_crew(crew, {"Agent": A2GClient(mandate_path="agent.mandate.toml")})
result = governed.kickoff()
```

**OpenAI Agents SDK:**
```python
from a2g_openai_agents import governed_function_tool

@governed_function_tool(client, "read_file")
def read_file(path: str) -> str:
    return open(path).read()
```

**MCP Server:**
```bash
python integrations/mcp-server/a2g_mcp_server.py --mandate agent.mandate.toml
```

**Claude Agent SDK:**
```python
from a2g_claude_agents import A2GClaudeAgent
agent = A2GClaudeAgent(a2g_client=client, model="claude-sonnet-4-5-20250929")
result = agent.run("Analyze the Q4 report")
```

## Project Structure

```
a2g-cli/
├── Cargo.toml              # Rust dependencies
├── Cargo.lock
├── src/
│   ├── main.rs             # CLI entry, input validation, command dispatch
│   ├── identity.rs         # ed25519 keypair generation, DID:a2g identity
│   ├── mandate.rs          # TOML mandate parsing, signing, verification
│   ├── enforce.rs          # 8-step enforcement pipeline
│   ├── receipt.rs          # Hash-chained cryptographic receipts
│   ├── ledger.rs           # SQLite append-only audit ledger
│   ├── authority.rs        # Layer 0 delegation chains, key-DID binding
│   ├── proposal.rs         # Mandate proposal + multi-reviewer approval
│   └── output_gov.rs       # Output governance (PII redaction, regex filters)
├── integrations/
│   ├── shared/             # A2GClient — Python wrapper for the Rust CLI
│   ├── langchain/          # LangChain/LangGraph integration
│   ├── crewai/             # CrewAI integration
│   ├── openai-agents/      # OpenAI Agents SDK integration
│   ├── claude-agent-sdk/   # Claude Agent SDK integration
│   └── mcp-server/         # MCP protocol server
├── examples/
│   └── langchain_a2g.py    # End-to-end LangChain example
└── tests/
    └── battle_test.sh      # 32-test adversarial battle test suite
```

## Testing

```bash
# Unit tests (29 tests)
cargo test

# Battle tests (32 tests — requires built binary)
cargo build --release
bash tests/battle_test.sh
```

## Requirements

- Rust 1.70+
- Python 3.9+ (for integrations)

## License

MIT

---

**A2G Protocol — Vanaras AI**

Deterministic governance for autonomous AI agents.
