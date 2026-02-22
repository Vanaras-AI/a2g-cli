# A2G Protocol — Agent Framework Integrations

Deterministic governance for every AI agent framework. Drop A2G into your stack in 3 lines.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        YOUR AI AGENT                                │
│  (LangChain │ CrewAI │ OpenAI Agents │ Claude SDK │ MCP │ Custom)  │
└───────────────────────────────────┬─────────────────────────────────┘
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
│                 ALLOW ✓         DENY ✗        ESCALATE ⬆           │
│                 execute         block          pause                │
│                                                notify               │
│                                                                     │
│  ┌─────────────────── LAYER 0: AUTHORITY ──────────────────────┐   │
│  │ Root → Department → Team → Operator delegation chains       │   │
│  │ Mandate proposals with risk-based multi-reviewer approval   │   │
│  │ Jurisdiction binding (region, regulatory, operating hours)  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────── EXECUTION LINEAGE ───────────────────────┐   │
│  │ Content-addressed mandates (mandate_hash on every receipt)  │   │
│  │ Cross-layer lineage (proposal_hash, delegation_chain_hash)  │   │
│  │ Cross-vendor correlation (correlation_id across frameworks) │   │
│  │ Parent receipt chaining (causal execution graphs)           │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────── CONSTITUTIONAL MEMORY ───────────────────┐   │
│  │ Trust compression (governance history → signed proof)       │   │
│  │ Merkle root integrity (verify receipts without full ledger) │   │
│  │ Portable compliance proofs across vendors and time windows  │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     ACTUAL TOOL EXECUTION                           │
│            (filesystem, HTTP, database, shell, APIs)                │
└─────────────────────────────────────────────────────────────────────┘
```

## Integrations

| Framework | File | Pattern | Status |
|-----------|------|---------|--------|
| **LangChain / LangGraph** | `langchain/a2g_langchain.py` | Tool wrapper + Toolkit + Callback | Ready |
| **CrewAI** | `crewai/a2g_crewai.py` | Agent wrapper + Crew governance + Task guard | Ready |
| **OpenAI Agents SDK** | `openai-agents/a2g_openai_agents.py` | Function decorator + Guardrail + Lifecycle | Ready |
| **MCP Server** | `mcp-server/a2g_mcp_server.py` | Governed MCP server (works with ANY MCP client) | Ready |
| **Claude Agent SDK** | `claude-agent-sdk/a2g_claude_agents.py` | Tool processor + Agent loop + Decorator | Ready |

## Quick Start (Any Framework)

### 1. Initialize governance

```bash
# Create sovereign authority
a2g sovereign

# Create root authority delegation
a2g authority-root --key sovereign.secret.key --name "Org-Root" --ttl 720

# Create agent identity
a2g init --name my-agent

# Propose + approve the mandate
a2g propose --proposer $(cat my-agent.did) --name "My Agent" \
    --mandate my-agent.mandate.toml --justification "Data processing"
a2g review --proposal proposal.json --key sovereign.secret.key \
    --reviewer-name "Admin" --decision approve

# Sign the mandate
a2g sign --mandate my-agent.mandate.toml --key sovereign.secret.key --ttl 24
```

### 2. Add to your agent (3 lines)

**LangChain:**
```python
from a2g_client import A2GClient
from a2g_langchain import A2GToolkit

client = A2GClient(mandate_path="my-agent.mandate.toml")
toolkit = A2GToolkit(tools=your_tools, a2g_client=client, correlation_id="session-123")
agent = create_react_agent(llm, toolkit.governed_tools)
```

**CrewAI:**
```python
from a2g_client import A2GClient
from a2g_crewai import govern_crew

clients = {"Researcher": A2GClient(mandate_path="researcher.mandate.toml")}
governed = govern_crew(crew, clients, correlation_id="crew-run-001")
result = governed.kickoff()
```

**OpenAI Agents SDK:**
```python
from a2g_client import A2GClient
from a2g_openai_agents import governed_function_tool

client = A2GClient(mandate_path="my-agent.mandate.toml")

@governed_function_tool(client, "read_file", correlation_id="session-123")
def read_file(path: str) -> str:
    return open(path).read()
```

**MCP (works with any MCP client):**
```bash
python a2g_mcp_server.py --mandate my-agent.mandate.toml --ledger gov.db \
    --correlation-id "session-123"
```

**Claude Agent SDK:**
```python
from a2g_client import A2GClient
from a2g_claude_agents import A2GClaudeAgent

client = A2GClient(mandate_path="my-agent.mandate.toml")
agent = A2GClaudeAgent(
    a2g_client=client, model="claude-sonnet-4-5-20250929",
    correlation_id="session-123",
)
agent.register_tool("read_file", "Read a file", schema, handler)
result = agent.run("Analyze the Q4 report")
```

## What A2G Enforces

Every tool call passes through an 8-step deterministic pipeline:

1. **Revocation Check** — is this mandate still active?
2. **Signature Verification** — ed25519 cryptographic proof
3. **TTL Check** — is the mandate within its time window?
4. **Tool Authorization** — is this tool in the allow-list?
5. **Boundary Enforcement** — filesystem, network, command boundaries
6. **Jurisdiction Check** — operating hours, region, environment
7. **Escalation Rules** — does this action need human approval?
8. **Rate Limiting** — calls per minute within limits?

Every decision (ALLOW, DENY, ESCALATE) produces a cryptographic receipt
stored in an immutable, hash-chained, append-only audit ledger.

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
print(lineage.correlation_id)        # cross-vendor correlation group
print(lineage.lineage_complete)      # True if full chain is intact
```

## Constitutional Memory (Trust Compression)

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

Verify a trust summary's integrity:
```bash
a2g verify-summary --summary q1-summary.json
```

From Python:
```python
summary = client.compress(
    agent_did="did:a2g:my-agent",
    start="2026-01-01T00:00:00Z", end="2026-03-31T23:59:59Z",
    key_path="sovereign.secret.key", issuer_name="Trust Authority",
    out_path="q1-summary.json",
)
print(f"Compliance: {summary.compliance_rate}%")
print(f"Merkle root: {summary.merkle_root}")

verified = client.verify_summary("q1-summary.json")
print(f"Valid: {verified.valid}")
```

## MCP Governance Tools

The MCP server exposes governance tools that any MCP client can use:

| Tool | Description |
|------|-------------|
| `a2g_status` | Check mandate status (valid/expired/revoked) |
| `a2g_audit` | Query the decision audit trail |
| `a2g_authority_log` | Query the Layer 0 authority governance trail |
| `a2g_verify_lineage` | Reconstruct full execution lineage from a receipt |
| `a2g_compress` | Compress governance history into a signed trust proof |
| `a2g_verify_summary` | Verify a trust summary's cryptographic integrity |

## Shared Client

All integrations use `shared/a2g_client.py` which wraps the A2G Rust CLI:

```python
from a2g_client import A2GClient, Decision, governed

client = A2GClient(mandate_path="agent.mandate.toml", ledger_path="gov.db")

# Direct enforcement with lineage
verdict = client.enforce(
    tool="read_file",
    params={"path": "data.csv"},
    correlation_id="session-123",
    parent_receipt="prev-receipt-hash",
)
print(verdict.decision)          # Decision.ALLOW
print(verdict.receipt_id)        # uuid
print(verdict.mandate_hash)      # content-addressed mandate version
print(verdict.correlation_id)    # cross-vendor correlation

# Decorator pattern
@governed(client, "read_file")
def read_file(path: str) -> str:
    return open(path).read()

# Lineage reconstruction
lineage = client.verify_lineage("receipt-uuid")

# Trust compression
summary = client.compress(
    agent_did="did:a2g:agent", start="2026-01-01T00:00:00Z",
    end="2026-03-31T23:59:59Z", key_path="key.secret.key",
    issuer_name="Authority", out_path="summary.json",
)

# Audit
print(client.audit(last=10))
print(client.authority_log(last=10))

# Kill switch
client.revoke(reason="security incident")
```

## Architecture: Why This Works

A2G is **not** another guardrail. It's the authorization layer that sits
beneath every agent framework:

- **Guardrails** check if output is safe → probabilistic, post-hoc
- **A2G** checks if the agent is authorized to act → deterministic, pre-execution

The enforcement pipeline has zero LLM calls. Every decision is reproducible,
cryptographically verifiable, and legally auditable.

The execution lineage and trust compression layers enable:
- Cross-vendor trust portability (prove compliance without the full ledger)
- Seasonal governance audits (compress Q1 → signed summary for compliance)
- Causal execution graphs (trace any outcome back through the full decision chain)
- Ledger archival (compress + sign, then archive old entries with verifiable reference)

## A2G Protocol — Vanaras AI

Built by [Vanaras AI](https://github.com/Vanaras-AI).

Deterministic governance for autonomous AI agents.
License: See repository root
