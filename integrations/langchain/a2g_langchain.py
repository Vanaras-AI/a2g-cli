"""
A2G + LangChain Integration — Governed Agent Tools

Wraps LangChain's tool system so every tool invocation passes through
the A2G enforcement pipeline before execution.

Architecture:
    User Prompt → LangChain Agent → A2G GovernedTool → enforce() → Tool Execution
                                          ↓
                                    ALLOW → execute
                                    DENY  → skip + log
                                    ESCALATE → pause + notify

Features:
    - Per-tool governance enforcement (ALLOW / DENY / ESCALATE)
    - Cross-vendor correlation (link decisions across agent frameworks)
    - Execution lineage (parent_receipt chaining for causal graphs)
    - Trust compression (portable governance proofs via A2GClient.compress)
    - Immutable audit trail with lineage metadata

Usage:
    from a2g_langchain import A2GGovernedTool, A2GToolkit, A2GCallbackHandler

    # Option 1: Wrap individual tools
    governed_tool = A2GGovernedTool(
        tool=my_langchain_tool,
        a2g_client=client,
        a2g_tool_name="read_file",
    )

    # Option 2: Wrap an entire toolkit
    toolkit = A2GToolkit(tools=[tool1, tool2], a2g_client=client)
    agent = create_react_agent(llm, toolkit.governed_tools)

    # Option 3: Use callback handler for audit logging
    agent.invoke({"input": "..."}, config={"callbacks": [A2GCallbackHandler(client)]})
"""

import sys
import json
import logging
from typing import Any, Optional, Callable
from pathlib import Path

# Add shared client to path
sys.path.insert(0, str(Path(__file__).parent.parent / "shared"))
from a2g_client import A2GClient, A2GVerdict, A2GError, EscalationRequired, Decision

logger = logging.getLogger("a2g.langchain")


# ── LangChain Tool Wrapper ───────────────────────────────────────────

class A2GGovernedTool:
    """
    Wraps a LangChain Tool with A2G governance enforcement.

    Every call to this tool goes through:
    1. A2G enforce() — deterministic ALLOW/DENY/ESCALATE
    2. If ALLOW → execute the underlying tool
    3. If DENY → return denial message (no execution)
    4. If ESCALATE → raise for human review

    Lineage support:
    - Pass correlation_id to link decisions across vendors
    - Pass parent_receipt to chain causal execution graphs
    - Verdict includes mandate_hash, proposal_hash for full provenance
    """

    def __init__(
        self,
        tool: Any,  # langchain_core.tools.BaseTool
        a2g_client: A2GClient,
        a2g_tool_name: Optional[str] = None,
        correlation_id: Optional[str] = None,
        on_deny: Optional[Callable] = None,
        on_escalate: Optional[Callable] = None,
    ):
        self.tool = tool
        self.client = a2g_client
        self.a2g_tool_name = a2g_tool_name or tool.name
        self.correlation_id = correlation_id
        self.on_deny = on_deny
        self.on_escalate = on_escalate
        self._last_verdict: Optional[A2GVerdict] = None

        # Preserve LangChain tool interface
        self.name = tool.name
        self.description = tool.description
        self.args_schema = getattr(tool, "args_schema", None)

    @property
    def last_receipt_id(self) -> Optional[str]:
        """Get the receipt ID from the last enforcement decision."""
        return self._last_verdict.receipt_id if self._last_verdict else None

    @property
    def last_verdict(self) -> Optional[A2GVerdict]:
        """Get the full verdict from the last enforcement decision."""
        return self._last_verdict

    def invoke(
        self,
        input: Any,
        config: Optional[dict] = None,
        correlation_id: Optional[str] = None,
        parent_receipt: Optional[str] = None,
        **kwargs,
    ) -> Any:
        """
        LangChain-compatible invoke with A2G enforcement.

        Args:
            input: Tool input (dict or str)
            config: LangChain config
            correlation_id: Override correlation ID for this call
            parent_receipt: Receipt hash from a preceding governed decision
        """
        # Extract params for A2G
        if isinstance(input, dict):
            params = input
        elif isinstance(input, str):
            params = {"input": input}
        else:
            params = {"input": str(input)}

        corr_id = correlation_id or self.correlation_id

        # Enforce governance
        try:
            verdict = self.client.enforce(
                tool=self.a2g_tool_name,
                params={k: str(v) for k, v in params.items()},
                correlation_id=corr_id,
                parent_receipt=parent_receipt,
            )
            self._last_verdict = verdict

            logger.info(
                "A2G enforcement: tool=%s decision=%s receipt=%s mandate_hash=%s correlation=%s",
                self.a2g_tool_name,
                verdict.decision.value,
                verdict.receipt_id,
                verdict.mandate_hash[:16] + "…" if verdict.mandate_hash else "",
                verdict.correlation_id or "none",
            )

            if verdict.allowed:
                return self.tool.invoke(input, config, **kwargs)

            else:  # DENY or EXPIRED
                msg = (
                    f"[A2G DENY] Action '{self.a2g_tool_name}' blocked by governance policy. "
                    f"Reason: {verdict.reason}. Receipt: {verdict.receipt_id}"
                )
                if self.on_deny:
                    return self.on_deny(verdict, input)
                return msg

        except EscalationRequired as e:
            if self.on_escalate:
                return self.on_escalate(e, input)
            return (
                f"[A2G ESCALATE] Action '{self.a2g_tool_name}' requires higher authority approval. "
                f"Reason: {e.reason}"
            )

    def run(self, tool_input: str, **kwargs) -> str:
        """Legacy LangChain run() interface."""
        return self.invoke(tool_input, **kwargs)

    def __call__(self, *args, **kwargs):
        return self.invoke(*args, **kwargs)


# ── Toolkit Wrapper ──────────────────────────────────────────────────

class A2GToolkit:
    """
    Wraps an entire set of LangChain tools with A2G governance.

    All tools share the same correlation_id for cross-vendor tracing.

    Usage:
        toolkit = A2GToolkit(
            tools=[search_tool, file_tool, api_tool],
            a2g_client=client,
            tool_name_map={"search": "http_get", "file": "read_file"},
            correlation_id="uuid-for-this-session",
        )
        agent = create_react_agent(llm, toolkit.governed_tools)
    """

    def __init__(
        self,
        tools: list,
        a2g_client: A2GClient,
        tool_name_map: Optional[dict[str, str]] = None,
        correlation_id: Optional[str] = None,
    ):
        self.client = a2g_client
        self.tool_name_map = tool_name_map or {}
        self.correlation_id = correlation_id

        self.governed_tools = [
            A2GGovernedTool(
                tool=t,
                a2g_client=a2g_client,
                a2g_tool_name=self.tool_name_map.get(t.name, t.name),
                correlation_id=correlation_id,
            )
            for t in tools
        ]

    def get_tools(self) -> list:
        return self.governed_tools


# ── Callback Handler for Audit Logging ───────────────────────────────

class A2GAuditCallback:
    """
    LangChain callback handler that LOGS agent actions (audit only, no enforcement).

    Attach to any LangChain agent to get governance-grade audit logging
    without modifying tool implementations or blocking actions.

    Usage:
        handler = A2GAuditCallback(a2g_client)
        agent.invoke({"input": "..."}, config={"callbacks": [handler]})
    """

    def __init__(self, a2g_client: A2GClient):
        self.client = a2g_client
        self.run_id = None

    def on_tool_start(self, serialized: dict, input_str: str, **kwargs):
        """Called when a tool starts."""
        tool_name = serialized.get("name", "unknown")
        logger.info("A2G: tool_start tool=%s", tool_name)

    def on_tool_end(self, output: str, **kwargs):
        """Called when a tool completes."""
        logger.info("A2G: tool_end output_length=%d", len(str(output)))

    def on_tool_error(self, error: Exception, **kwargs):
        """Called when a tool errors."""
        logger.warning("A2G: tool_error error=%s", str(error))

    def on_chain_start(self, serialized: dict, inputs: dict, **kwargs):
        """Called when the agent chain starts."""
        logger.info("A2G: chain_start inputs=%s", list(inputs.keys()))

    def on_chain_end(self, outputs: dict, **kwargs):
        """Called when the agent chain completes."""
        logger.info("A2G: chain_end outputs=%s", list(outputs.keys()))


class A2GEnforcementCallback:
    """
    LangChain callback handler that ENFORCES A2G governance on tool calls.

    Unlike A2GAuditCallback (audit-only), this handler actively blocks
    unauthorized tool calls by raising an exception in on_tool_start.

    Supports correlation_id for cross-vendor lineage tracking.

    Usage:
        handler = A2GEnforcementCallback(a2g_client, correlation_id="session-uuid")
        agent.invoke({"input": "..."}, config={"callbacks": [handler]})
    """

    def __init__(
        self,
        a2g_client: A2GClient,
        tool_name_map: Optional[dict[str, str]] = None,
        correlation_id: Optional[str] = None,
    ):
        self.client = a2g_client
        self.tool_name_map = tool_name_map or {}
        self.correlation_id = correlation_id

    def on_tool_start(self, serialized: dict, input_str: str, **kwargs):
        """Enforce governance BEFORE tool execution."""
        tool_name = serialized.get("name", "unknown")
        a2g_name = self.tool_name_map.get(tool_name, tool_name)

        params = {"input": input_str} if isinstance(input_str, str) else {}

        try:
            verdict = self.client.enforce(
                tool=a2g_name,
                params=params,
                correlation_id=self.correlation_id,
            )

            logger.info(
                "A2G enforcement: tool=%s decision=%s receipt=%s correlation=%s",
                a2g_name,
                verdict.decision.value,
                verdict.receipt_id,
                verdict.correlation_id or "none",
            )

            if verdict.denied:
                raise ValueError(
                    f"[A2G DENY] Tool '{a2g_name}' blocked by governance. "
                    f"Reason: {verdict.reason}. Receipt: {verdict.receipt_id}"
                )
        except EscalationRequired as e:
            raise ValueError(
                f"[A2G ESCALATE] Tool '{a2g_name}' requires authority approval. "
                f"Reason: {e.reason}"
            )

    def on_tool_end(self, output: str, **kwargs):
        pass

    def on_tool_error(self, error: Exception, **kwargs):
        logger.warning("A2G: tool_error error=%s", str(error))

    def on_chain_start(self, serialized: dict, inputs: dict, **kwargs):
        pass

    def on_chain_end(self, outputs: dict, **kwargs):
        pass


# Backward compatibility
A2GCallbackHandler = A2GAuditCallback


# ── Convenience: create_governed_agent ───────────────────────────────

def create_governed_agent(
    llm: Any,
    tools: list,
    a2g_client: A2GClient,
    tool_name_map: Optional[dict[str, str]] = None,
    correlation_id: Optional[str] = None,
    agent_type: str = "react",
) -> Any:
    """
    Create a LangChain agent with A2G governance baked in.

    Every tool call goes through A2G enforcement before execution.
    All decisions are logged to the immutable audit ledger.

    Args:
        llm: LangChain LLM (ChatOpenAI, ChatAnthropic, etc.)
        tools: List of LangChain tools
        a2g_client: Configured A2GClient instance
        tool_name_map: Optional mapping of LangChain tool names to A2G tool names
        correlation_id: UUID for cross-vendor correlation (links all decisions in this session)
        agent_type: "react" or "structured_chat"

    Returns:
        A governed LangChain agent

    Example:
        client = A2GClient(mandate_path="agent.mandate.toml")
        llm = ChatAnthropic(model="claude-sonnet-4-5-20250929")
        tools = [SearchTool(), FileReadTool()]

        agent = create_governed_agent(llm, tools, client, correlation_id="session-123")
        result = agent.invoke({"input": "Find Q4 revenue data"})
    """
    try:
        from langchain.agents import create_react_agent, AgentExecutor
        from langchain import hub
    except ImportError:
        raise ImportError(
            "langchain is required: pip install langchain langchain-core"
        )

    toolkit = A2GToolkit(tools, a2g_client, tool_name_map, correlation_id)
    handler = A2GEnforcementCallback(a2g_client, tool_name_map, correlation_id)

    if agent_type == "react":
        prompt = hub.pull("hwchase17/react")
        agent = create_react_agent(llm, toolkit.get_tools(), prompt)
    else:
        from langchain.agents import create_structured_chat_agent
        prompt = hub.pull("hwchase17/structured-chat-agent")
        agent = create_structured_chat_agent(llm, toolkit.get_tools(), prompt)

    return AgentExecutor(
        agent=agent,
        tools=toolkit.get_tools(),
        callbacks=[handler],
        verbose=True,
        handle_parsing_errors=True,
        max_iterations=10,
    )


# ── Example Usage ────────────────────────────────────────────────────

if __name__ == "__main__":
    print("A2G + LangChain Integration")
    print("=" * 50)
    print()
    print("Quick Start:")
    print("""
    from a2g_langchain import create_governed_agent
    from a2g_client import A2GClient
    from langchain_anthropic import ChatAnthropic
    from langchain_community.tools import ShellTool, ReadFileTool

    # 1. Configure A2G governance
    client = A2GClient(
        mandate_path="data-agent.mandate.toml",
        ledger_path="gov.db",
    )

    # 2. Create governed agent with cross-vendor correlation
    llm = ChatAnthropic(model="claude-sonnet-4-5-20250929")
    tools = [ReadFileTool(), ShellTool()]

    agent = create_governed_agent(
        llm=llm,
        tools=tools,
        a2g_client=client,
        tool_name_map={"read_file": "read_file", "terminal": "execute"},
        correlation_id="session-abc-123",  # links all decisions
    )

    # 3. Every tool call is now governed by A2G with full lineage
    result = agent.invoke({"input": "Read the Q4 report from workspace/reports/"})
    # → A2G enforces: read_file + path boundary check → ALLOW ✓
    # → Receipt includes mandate_hash, proposal_hash, correlation_id

    # 4. Verify lineage of any decision
    lineage = client.verify_lineage("receipt-uuid-here")
    print(lineage.mandate_hash, lineage.lineage_complete)

    # 5. Compress governance history into a trust proof
    summary = client.compress(
        agent_did="did:a2g:my-agent",
        start="2026-01-01T00:00:00Z",
        end="2026-03-31T23:59:59Z",
        key_path="sovereign.secret.key",
        issuer_name="Trust Authority",
        out_path="q1-summary.json",
    )
    print(f"Compliance: {summary.compliance_rate}%, Merkle: {summary.merkle_root}")
    """)
