"""
A2G + OpenAI Agents SDK Integration — Governed Function Tools

Wraps OpenAI Agents SDK function tools with A2G enforcement.
Uses the guardrails pattern from the Agents SDK to inject
governance at the framework level.

Architecture:
    OpenAI Agent → function_tool → A2GGuardrail → enforce() → execution
                                        ↓
                                  ALLOW → execute function
                                  DENY  → return error to agent
                                  ESCALATE → tripwire → halt agent

Features:
    - Function-level governance enforcement (ALLOW / DENY / ESCALATE)
    - Cross-vendor correlation (link decisions across agent frameworks)
    - Execution lineage (parent_receipt chaining for causal graphs)
    - Trust compression (portable governance proofs via A2GClient.compress)
    - Agent lifecycle management with kill switch

Usage:
    from a2g_openai_agents import governed_function_tool, A2GGuardrail

    # Option 1: Decorator for governed functions
    @governed_function_tool(a2g_client, "read_file")
    def read_file(path: str) -> str:
        return open(path).read()

    # Option 2: Guardrail on the agent
    agent = Agent(
        name="data-processor",
        tools=[read_file, write_file],
        input_guardrails=[A2GGuardrail(client)],
    )
"""

import sys
import json
import logging
import functools
from typing import Any, Optional, Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "shared"))
from a2g_client import A2GClient, A2GVerdict, A2GError, EscalationRequired, Decision

logger = logging.getLogger("a2g.openai_agents")


# ── Function Tool Decorator ──────────────────────────────────────────

def governed_function_tool(
    a2g_client: A2GClient,
    tool_name: str,
    param_extractor: Optional[Callable] = None,
    correlation_id: Optional[str] = None,
):
    """
    Decorator that wraps an OpenAI Agents SDK function tool
    with A2G governance enforcement.

    The decorated function is called normally by the agent,
    but A2G enforce() runs first. If DENIED, the function
    returns an error message instead of executing.

    Supports lineage tracking via correlation_id and parent_receipt.

    Args:
        a2g_client: Configured A2GClient
        tool_name: A2G tool name for enforcement
        param_extractor: Optional function to extract params from args
        correlation_id: UUID for cross-vendor correlation

    Usage:
        @governed_function_tool(client, "read_file", correlation_id="session-123")
        def read_file(path: str) -> str:
            '''Read a file from the workspace.'''
            return open(path).read()

        agent = Agent(
            name="reader",
            tools=[read_file],  # A2G enforcement is baked in
        )
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Extract lineage kwargs (not passed to wrapped function)
            corr_id = kwargs.pop("_correlation_id", correlation_id)
            parent = kwargs.pop("_parent_receipt", None)

            # Extract params for A2G enforcement
            if param_extractor:
                params = param_extractor(*args, **kwargs)
            else:
                import inspect
                sig = inspect.signature(func)
                param_names = list(sig.parameters.keys())
                params = {}
                for i, arg in enumerate(args):
                    if i < len(param_names):
                        params[param_names[i]] = str(arg)
                params.update({k: str(v) for k, v in kwargs.items()})

            # A2G Enforcement
            try:
                verdict = a2g_client.enforce(
                    tool=tool_name,
                    params=params,
                    correlation_id=corr_id,
                    parent_receipt=parent,
                )

                logger.info(
                    "A2G [OpenAI]: tool=%s decision=%s receipt=%s mandate=%s correlation=%s",
                    tool_name,
                    verdict.decision.value,
                    verdict.receipt_id,
                    verdict.mandate_hash[:16] + "…" if verdict.mandate_hash else "",
                    verdict.correlation_id or "none",
                )

                if verdict.allowed:
                    return func(*args, **kwargs)
                else:
                    return (
                        f"Error: Action '{tool_name}' was denied by governance policy. "
                        f"Reason: {verdict.reason}. "
                        f"The agent does not have permission to perform this action."
                    )
            except EscalationRequired as e:
                raise A2GError(
                    f"ESCALATE: '{tool_name}' requires authority approval. "
                    f"Reason: {e.reason}"
                )

        # Preserve metadata for the Agents SDK
        wrapper.__a2g_governed__ = True
        wrapper.__a2g_tool_name__ = tool_name
        return wrapper
    return decorator


# ── Guardrail Implementation ─────────────────────────────────────────

class A2GGuardrail:
    """
    OpenAI Agents SDK Guardrail for A2G governance.

    Validates mandate status on every agent turn. If the mandate
    is expired or revoked, triggers a tripwire to halt the agent.

    Usage:
        from agents import Agent, InputGuardrail

        guardrail = A2GGuardrail(a2g_client)

        agent = Agent(
            name="governed-agent",
            tools=[...],
            input_guardrails=[guardrail.to_input_guardrail()],
        )
    """

    def __init__(self, a2g_client: A2GClient):
        self.client = a2g_client

    async def _check(self, ctx, agent, input_data):
        """Input guardrail check function."""
        try:
            info = self.client.verify_mandate()
            tripwire = not info.get("valid", False)
            return {
                "output_info": {
                    "a2g_status": "mandate_valid" if not tripwire else "mandate_invalid",
                },
                "tripwire_triggered": tripwire,
            }
        except Exception as e:
            logger.error("A2G guardrail error: %s", e)
            return {
                "output_info": {"a2g_error": str(e)},
                "tripwire_triggered": True,  # fail closed
            }

    def to_input_guardrail(self):
        """
        Return an InputGuardrail compatible with the OpenAI Agents SDK.

        Usage:
            agent = Agent(
                input_guardrails=[guardrail.to_input_guardrail()]
            )
        """
        try:
            from agents import InputGuardrail
            return InputGuardrail(guardrail_function=self._check, name="a2g_governance")
        except ImportError:
            # Fallback if agents SDK not installed - return dict
            return {"name": "a2g_governance", "function": self._check}

    def as_input_guardrail(self):
        """Deprecated: use to_input_guardrail() instead."""
        return self.to_input_guardrail()


# ── Agent Lifecycle Manager ──────────────────────────────────────────

class A2GAgentLifecycle:
    """
    Manages the full lifecycle of an OpenAI Agents SDK agent
    under A2G governance.

    Handles:
    - Mandate verification at startup
    - Tool governance during execution
    - Kill switch (revocation) for emergency shutdown
    - Audit trail queries
    - Lineage verification and trust compression

    Usage:
        lifecycle = A2GAgentLifecycle(
            a2g_client=client,
            agent_name="data-processor",
        )

        # Verify before running
        lifecycle.verify_or_halt()

        # Run agent
        result = lifecycle.run(agent, input_data)

        # Verify lineage of a decision
        lineage = lifecycle.verify_lineage("receipt-uuid")

        # Emergency stop
        lifecycle.kill("security incident detected")
    """

    def __init__(self, a2g_client: A2GClient, agent_name: str = "agent"):
        self.client = a2g_client
        self.agent_name = agent_name
        self._active = True

    def verify_or_halt(self):
        """Verify mandate is valid. Raises if not."""
        info = self.client.verify_mandate()
        if not info.get("valid"):
            self._active = False
            raise A2GError(
                f"Agent '{self.agent_name}' mandate is invalid. "
                f"Cannot start execution."
            )
        logger.info("A2G: Agent '%s' mandate verified ✓", self.agent_name)

    def kill(self, reason: str = "emergency shutdown"):
        """Immediately revoke the agent's mandate (kill switch)."""
        self._active = False
        success = self.client.revoke(reason=reason)
        if success:
            logger.warning(
                "A2G: Agent '%s' KILLED. Reason: %s", self.agent_name, reason,
            )
        else:
            logger.error(
                "A2G: Failed to revoke agent '%s' mandate", self.agent_name,
            )
        return success

    @property
    def is_active(self) -> bool:
        return self._active

    def audit(self, last: int = 20) -> str:
        """Get this agent's recent governance decisions."""
        return self.client.audit(last=last)

    def verify_lineage(self, receipt_id: str):
        """Reconstruct full execution lineage from a receipt."""
        return self.client.verify_lineage(receipt_id)

    def compress(self, agent_did: str, start: str, end: str,
                 key_path: str, issuer_name: str, out_path: str):
        """Compress this agent's governance history into a trust proof."""
        return self.client.compress(
            agent_did=agent_did, start=start, end=end,
            key_path=key_path, issuer_name=issuer_name, out_path=out_path,
        )


# ── Example ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("A2G + OpenAI Agents SDK Integration")
    print("=" * 50)
    print()
    print("Quick Start:")
    print("""
    from agents import Agent, Runner
    from a2g_openai_agents import governed_function_tool, A2GGuardrail, A2GAgentLifecycle
    from a2g_client import A2GClient

    # 1. Configure governance
    client = A2GClient(mandate_path="agent.mandate.toml", ledger_path="gov.db")
    lifecycle = A2GAgentLifecycle(client, "data-processor")
    lifecycle.verify_or_halt()

    # 2. Define governed tools with cross-vendor correlation
    @governed_function_tool(client, "read_file", correlation_id="session-123")
    def read_file(path: str) -> str:
        '''Read a file from the workspace.'''
        return open(path).read()

    @governed_function_tool(client, "write_file", correlation_id="session-123")
    def write_file(path: str, content: str) -> str:
        '''Write content to a file.'''
        with open(path, 'w') as f:
            f.write(content)
        return f"Written {len(content)} bytes to {path}"

    # 3. Create agent with governance guardrail
    agent = Agent(
        name="data-processor",
        instructions="Process data files in the workspace directory.",
        tools=[read_file, write_file],
    )

    # 4. Run — every tool call enforced by A2G with lineage
    result = Runner.run_sync(agent, "Read workspace/reports/q4.csv and summarize it")

    # 5. Verify lineage + compress governance history
    lineage = lifecycle.verify_lineage("receipt-uuid")
    summary = lifecycle.compress(
        agent_did="did:a2g:data-processor",
        start="2026-01-01T00:00:00Z", end="2026-03-31T23:59:59Z",
        key_path="sovereign.secret.key", issuer_name="Admin",
        out_path="q1-summary.json",
    )

    # 6. Emergency kill switch
    # lifecycle.kill("anomalous behavior detected")
    """)
