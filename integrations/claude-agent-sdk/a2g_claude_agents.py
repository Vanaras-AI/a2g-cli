"""
A2G + Claude Agent SDK Integration — Governed Claude Agents

Integrates A2G governance into the Claude Agent SDK (Anthropic's
framework for building production agents). Wraps the tool_use
pattern with enforcement so every tool call is authorized before
execution.

Architecture:
    Claude Agent → tool_use → A2GToolProcessor → enforce() → Tool Execution
                                    ↓
                              ALLOW → execute + return tool_result
                              DENY  → return error tool_result
                              ESCALATE → return escalation + pause

Features:
    - Tool-level governance enforcement (ALLOW / DENY / ESCALATE)
    - Cross-vendor correlation (link decisions across agent frameworks)
    - Execution lineage (parent_receipt chaining for causal graphs)
    - Trust compression (portable governance proofs via A2GClient.compress)
    - Full agent loop with governance baked into the message cycle

Usage:
    from a2g_claude_agents import A2GToolProcessor, governed_tool

    # Option 1: Process tool calls with governance
    processor = A2GToolProcessor(a2g_client)
    result = processor.process_tool_call(tool_name, tool_input)

    # Option 2: Decorator
    @governed_tool(client, "read_file")
    def read_file(path: str) -> str:
        return open(path).read()
"""

import sys
import json
import logging
import functools
from typing import Any, Optional, Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "shared"))
from a2g_client import A2GClient, A2GVerdict, A2GError, EscalationRequired, Decision

logger = logging.getLogger("a2g.claude_agents")


# ── Tool Processor ───────────────────────────────────────────────────

class A2GToolProcessor:
    """
    Processes Claude Agent SDK tool_use calls with A2G governance.

    The Claude Agent SDK uses a message loop where the model returns
    tool_use blocks and the application executes them. This processor
    sits in that loop and enforces governance before execution.

    Supports correlation_id and parent_receipt for lineage tracking.

    Usage:
        import anthropic
        from a2g_claude_agents import A2GToolProcessor

        client = anthropic.Anthropic()
        a2g = A2GToolProcessor(
            A2GClient(mandate_path="agent.mandate.toml"),
            correlation_id="session-abc",
        )

        # Register tool handlers
        a2g.register("read_file", lambda params: open(params["path"]).read())
        a2g.register("write_file", lambda params: write_file(params["path"], params["content"]))

        # Agent loop
        while True:
            response = client.messages.create(model="claude-sonnet-4-5-20250929", ...)

            if response.stop_reason == "tool_use":
                for block in response.content:
                    if block.type == "tool_use":
                        result = a2g.process(block.name, block.input)
                        # Feed result back to Claude
            else:
                break
    """

    def __init__(
        self,
        a2g_client: A2GClient,
        fail_closed: bool = True,
        correlation_id: Optional[str] = None,
    ):
        self.client = a2g_client
        self.fail_closed = fail_closed
        self.correlation_id = correlation_id
        self.handlers: dict[str, Callable] = {}
        self.tool_name_map: dict[str, str] = {}
        self._last_receipt_hash: Optional[str] = None

    @property
    def last_receipt_hash(self) -> Optional[str]:
        """Get the receipt hash from the last enforcement decision (for chaining)."""
        return self._last_receipt_hash

    def register(
        self,
        tool_name: str,
        handler: Callable,
        a2g_tool_name: Optional[str] = None,
    ):
        """
        Register a tool handler.

        Args:
            tool_name: The tool name as Claude sees it
            handler: Function to execute (receives params dict)
            a2g_tool_name: A2G mandate tool name (defaults to tool_name)
        """
        self.handlers[tool_name] = handler
        if a2g_tool_name:
            self.tool_name_map[tool_name] = a2g_tool_name

    def process(
        self,
        tool_name: str,
        tool_input: dict,
        correlation_id: Optional[str] = None,
        parent_receipt: Optional[str] = None,
    ) -> dict:
        """
        Process a tool_use call with A2G governance.

        Returns a tool_result dict compatible with the Claude API.

        Args:
            tool_name: Tool name from Claude's tool_use block
            tool_input: Tool input parameters
            correlation_id: Override correlation ID for this call
            parent_receipt: Receipt hash from a preceding governed decision

        Returns:
            dict with "content": "...", "is_error": bool
        """
        a2g_name = self.tool_name_map.get(tool_name, tool_name)
        corr_id = correlation_id or self.correlation_id
        parent = parent_receipt or self._last_receipt_hash

        # A2G Enforcement
        try:
            verdict = self.client.enforce(
                tool=a2g_name,
                params={k: str(v) for k, v in tool_input.items()},
                correlation_id=corr_id,
                parent_receipt=parent,
            )

            # Store for automatic chaining
            self._last_receipt_hash = verdict.receipt_id

            logger.info(
                "A2G [Claude]: tool=%s decision=%s receipt=%s mandate=%s correlation=%s",
                a2g_name,
                verdict.decision.value,
                verdict.receipt_id,
                verdict.mandate_hash[:16] + "…" if verdict.mandate_hash else "",
                verdict.correlation_id or "none",
            )

            if verdict.allowed:
                # Execute the tool
                handler = self.handlers.get(tool_name)
                if not handler:
                    return {
                        "content": f"No handler registered for tool '{tool_name}'",
                        "is_error": True,
                    }
                try:
                    result = handler(tool_input)
                    return {"content": str(result), "is_error": False}
                except Exception as e:
                    return {"content": f"Tool error: {str(e)}", "is_error": True}
            else:
                return {
                    "content": (
                        f"[A2G DENY] Action '{a2g_name}' blocked by governance.\n"
                        f"Reason: {verdict.reason}\n"
                        f"Receipt: {verdict.receipt_id}"
                    ),
                    "is_error": True,
                }
        except EscalationRequired as e:
            return {
                "content": (
                    f"[A2G ESCALATE] Action '{a2g_name}' requires higher authority.\n"
                    f"Reason: {e.reason}\n"
                    f"This action has been paused pending approval."
                ),
                "is_error": True,
            }

    def process_response(self, response: Any) -> list[dict]:
        """
        Process all tool_use blocks in a Claude API response.

        Automatically chains parent_receipt between tool calls
        in the same response for causal lineage graphs.

        Returns a list of tool_result dicts ready to send back.
        """
        results = []
        for block in response.content:
            if hasattr(block, "type") and block.type == "tool_use":
                result = self.process(block.name, block.input)
                results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    **result,
                })
        return results


# ── Tool Decorator ───────────────────────────────────────────────────

def governed_tool(
    a2g_client: A2GClient,
    tool_name: str,
    correlation_id: Optional[str] = None,
):
    """
    Decorator for Claude Agent SDK tool functions.

    Supports lineage tracking via correlation_id and parent_receipt.

    Usage:
        @governed_tool(client, "read_file", correlation_id="session-123")
        def read_file(path: str) -> str:
            return open(path).read()
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Extract lineage kwargs
            corr_id = kwargs.pop("_correlation_id", correlation_id)
            parent = kwargs.pop("_parent_receipt", None)

            import inspect
            sig = inspect.signature(func)
            param_names = list(sig.parameters.keys())
            params = {}
            for i, arg in enumerate(args):
                if i < len(param_names):
                    params[param_names[i]] = str(arg)
            params.update({k: str(v) for k, v in kwargs.items()})

            try:
                verdict = a2g_client.enforce(
                    tool=tool_name,
                    params=params,
                    correlation_id=corr_id,
                    parent_receipt=parent,
                )

                logger.info(
                    "A2G [Claude]: tool=%s decision=%s receipt=%s mandate=%s",
                    tool_name,
                    verdict.decision.value,
                    verdict.receipt_id,
                    verdict.mandate_hash[:16] + "…" if verdict.mandate_hash else "",
                )

                if verdict.allowed:
                    return func(*args, **kwargs)
                else:
                    raise A2GError(
                        f"DENY: '{tool_name}' blocked. "
                        f"Reason: {verdict.reason}. Receipt: {verdict.receipt_id}"
                    )
            except EscalationRequired as e:
                raise A2GError(
                    f"ESCALATE: '{tool_name}' requires authority. "
                    f"Reason: {e.reason}"
                )

        wrapper.__a2g_governed__ = True
        wrapper.__a2g_tool_name__ = tool_name
        return wrapper
    return decorator


# ── Full Agent Loop ──────────────────────────────────────────────────

class A2GClaudeAgent:
    """
    Complete Claude agent with A2G governance baked into the message loop.

    This is the highest-level integration — creates a fully governed
    Claude agent that handles the entire tool_use conversation loop.

    Features:
    - Every tool call governed by A2G mandate
    - Automatic parent_receipt chaining across tool calls
    - Cross-vendor correlation via correlation_id
    - Full lineage reconstruction and trust compression via client

    Usage:
        agent = A2GClaudeAgent(
            a2g_client=A2GClient(mandate_path="agent.mandate.toml"),
            model="claude-sonnet-4-5-20250929",
            system="You are a data analyst. Read and process files.",
            correlation_id="session-abc-123",
        )

        agent.register_tool(
            name="read_file",
            description="Read a file from the workspace",
            input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
            handler=lambda params: open(params["path"]).read(),
        )

        result = agent.run("Analyze workspace/reports/q4.csv")
    """

    def __init__(
        self,
        a2g_client: A2GClient,
        model: str = "claude-sonnet-4-5-20250929",
        system: str = "",
        max_turns: int = 10,
        api_key: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ):
        self.a2g_client = a2g_client
        self.model = model
        self.system = system
        self.max_turns = max_turns
        self.processor = A2GToolProcessor(
            a2g_client,
            correlation_id=correlation_id,
        )
        self.tool_definitions: list[dict] = []
        self._api_key = api_key

    def register_tool(
        self,
        name: str,
        description: str,
        input_schema: dict,
        handler: Callable,
        a2g_tool_name: Optional[str] = None,
    ):
        """Register a tool with its handler and schema."""
        self.tool_definitions.append({
            "name": name,
            "description": description,
            "input_schema": input_schema,
        })
        self.processor.register(name, handler, a2g_tool_name)

    def run(self, user_message: str) -> str:
        """
        Run the governed agent loop.

        1. Send user message to Claude
        2. If Claude returns tool_use → enforce with A2G → execute if allowed
        3. Feed results back → repeat until Claude gives final answer
        4. Every tool call is governed, logged, and auditable
        5. Parent receipts are automatically chained for lineage
        """
        try:
            import anthropic
        except ImportError:
            raise ImportError("anthropic is required: pip install anthropic")

        client = anthropic.Anthropic(api_key=self._api_key) if self._api_key else anthropic.Anthropic()

        messages = [{"role": "user", "content": user_message}]

        for turn in range(self.max_turns):
            response = client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=self.system,
                tools=self.tool_definitions,
                messages=messages,
            )

            # Add assistant response to messages
            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "end_turn":
                # Extract text from final response
                for block in response.content:
                    if hasattr(block, "text"):
                        return block.text
                return ""

            elif response.stop_reason == "tool_use":
                # Process all tool calls through A2G (auto-chains parent_receipt)
                tool_results = self.processor.process_response(response)
                messages.append({"role": "user", "content": tool_results})

            else:
                break

        return "[A2G] Agent reached max turns without completing."


# ── Example ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("A2G + Claude Agent SDK Integration")
    print("=" * 50)
    print()
    print("Quick Start:")
    print("""
    from a2g_claude_agents import A2GClaudeAgent
    from a2g_client import A2GClient

    # 1. Configure governance
    client = A2GClient(mandate_path="agent.mandate.toml", ledger_path="gov.db")

    # 2. Create governed agent with cross-vendor correlation
    agent = A2GClaudeAgent(
        a2g_client=client,
        model="claude-sonnet-4-5-20250929",
        system="You are a data analyst. Process files in the workspace.",
        correlation_id="session-abc-123",
    )

    # 3. Register tools (each governed by mandate)
    agent.register_tool(
        name="read_file",
        description="Read a file from the workspace",
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string", "description": "File path"}},
            "required": ["path"],
        },
        handler=lambda params: open(params["path"]).read(),
    )

    agent.register_tool(
        name="write_file",
        description="Write content to a file",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
        },
        handler=lambda params: (
            open(params["path"], "w").write(params["content"]),
            f"Written to {params['path']}"
        )[1],
    )

    # 4. Run — every tool call governed by A2G with full lineage
    result = agent.run("Read workspace/reports/q4.csv and summarize the revenue")
    print(result)

    # 5. Verify lineage of any decision
    lineage = client.verify_lineage("receipt-uuid")
    print(lineage.mandate_hash, lineage.lineage_complete)

    # 6. Compress governance history into a trust proof
    summary = client.compress(
        agent_did="did:a2g:data-analyst",
        start="2026-01-01T00:00:00Z",
        end="2026-03-31T23:59:59Z",
        key_path="sovereign.secret.key",
        issuer_name="Trust Authority",
        out_path="q1-summary.json",
    )
    print(f"Compliance: {summary.compliance_rate}%")

    # 7. Audit what happened
    print(client.audit())
    """)
