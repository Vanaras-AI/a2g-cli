# A2G Protocol — Agent Framework Integrations

Deterministic governance for every AI agent framework. Drop A2G into your stack in 3 lines.

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
│                 ALLOW ✓         DENY ✗        ESCALATE ⬆           │
│                 execute         block          pause                │
│                                                notify               │
│                                                                     │
│  ┌─────────────────── LAYER 0: AUTHORITY ──────────────────────┐   │
│  │ Root → Department → Team → Operator delegation chains       │   │
│  │ Mandate proposals with risk-based multi-reviewer approval   │   │
│  │ Jurisdiction binding (region, regulatory, operating hours)  │   │
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
toolkit = A2GToolkit(tools=your_tools, a2g_client=client)
agent = create_react_agent(llm, toolkit.governed_tools)
```

**CrewAI:**
```python
from a2g_client import A2GClient
from a2g_crewai import govern_crew

clients = {"Researcher": A2GClient(mandate_path="researcher.mandate.toml")}
governed = govern_crew(crew, clients)
result = governed.kickoff()
```

**OpenAI Agents SDK:**
```python
from a2g_client import A2GClient
from a2g_openai_agents import governed_function_tool

client = A2GClient(mandate_path="my-agent.mandate.toml")

@governed_function_tool(client, "read_file")
def read_file(path: str) -> str:
    return open(path).read()
```

**MCP (works with any MCP client):**
```bash
python a2g_mcp_server.py --mandate my-agent.mandate.toml --ledger gov.db
```

**Claude Agent SDK:**
```python
from a2g_client import A2GClient
from a2g_claude_agents import A2GClaudeAgent

client = A2GClient(mandate_path="my-agent.mandate.toml")
agent = A2GClaudeAgent(a2g_client=client, model="claude-sonnet-4-5-20250929")
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

## Shared Client

All integrations use `shared/a2g_client.py` which wraps the A2G Rust CLI:

```python
from a2g_client import A2GClient, Decision, governed

client = A2GClient(mandate_path="agent.mandate.toml", ledger_path="gov.db")

# Direct enforcement
verdict = client.enforce(tool="read_file", params={"path": "data.csv"})
print(verdict.decision)   # Decision.ALLOW
print(verdict.receipt_id) # uuid

# Decorator pattern
@governed(client, "read_file")
def read_file(path: str) -> str:
    return open(path).read()

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

## AEON Engine — Vanaras AI

Built by [Vanaras AI](https://github.com/vanaras-ai) as part of the AEON Engine project.

Protocol: A2G (Agent-to-Governance)
License: See repository root
