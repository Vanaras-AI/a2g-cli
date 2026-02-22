"""
A2G + CrewAI Integration — Governed Crew of AI Agents

Each CrewAI agent operates under its own A2G mandate. The crew's task
execution is wrapped with governance enforcement so every tool call
is authorized, audited, and revocable.

Architecture:
    CrewAI Task → Agent → A2GGovernedCrewTool → enforce() → Tool Execution
                                    ↓
                              ALLOW → execute
                              DENY  → skip + log
                              ESCALATE → pause crew + notify

Features:
    - Per-agent mandate governance (different permissions per role)
    - Cross-vendor correlation (link crew decisions to external systems)
    - Execution lineage (parent_receipt chaining across crew tasks)
    - Trust compression (governance proofs per agent via A2GClient.compress)
    - Pre-execution task validation against mandates

Usage:
    from a2g_crewai import A2GGovernedAgent, govern_crew

    # Wrap individual agent with governance
    governed_agent = A2GGovernedAgent(
        agent=researcher_agent,
        a2g_client=researcher_client,
    )

    # Or wrap an entire crew
    governed_crew = govern_crew(crew, a2g_clients={
        "researcher": researcher_client,
        "writer": writer_client,
    })
"""

import sys
import json
import logging
from typing import Any, Optional, Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "shared"))
from a2g_client import A2GClient, A2GVerdict, A2GError, EscalationRequired, Decision

logger = logging.getLogger("a2g.crewai")


# ── CrewAI Tool Wrapper ──────────────────────────────────────────────

class A2GCrewTool:
    """
    Wraps a CrewAI tool with A2G governance enforcement.

    CrewAI tools use a different interface than LangChain — this adapter
    handles the translation while maintaining deterministic governance.

    Supports correlation_id and parent_receipt for lineage tracking.
    """

    def __init__(
        self,
        tool: Any,  # crewai.tools.BaseTool
        a2g_client: A2GClient,
        a2g_tool_name: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ):
        self.tool = tool
        self.client = a2g_client
        self.a2g_tool_name = a2g_tool_name or getattr(tool, "name", "unknown")
        self.correlation_id = correlation_id
        self._last_verdict: Optional[A2GVerdict] = None

        # Preserve CrewAI tool interface
        self.name = getattr(tool, "name", "governed_tool")
        self.description = getattr(tool, "description", "A2G governed tool")

    @property
    def last_receipt_id(self) -> Optional[str]:
        """Get the receipt ID from the last enforcement decision."""
        return self._last_verdict.receipt_id if self._last_verdict else None

    def _run(self, *args, **kwargs) -> str:
        """Execute with A2G governance enforcement."""
        # Extract lineage kwargs
        corr_id = kwargs.pop("_correlation_id", self.correlation_id)
        parent = kwargs.pop("_parent_receipt", None)

        # Build params from arguments
        params = {}
        if args:
            params["input"] = str(args[0])
        params.update({k: str(v) for k, v in kwargs.items()})

        # Enforce
        try:
            verdict = self.client.enforce(
                tool=self.a2g_tool_name,
                params=params,
                correlation_id=corr_id,
                parent_receipt=parent,
            )
            self._last_verdict = verdict

            logger.info(
                "A2G [CrewAI]: tool=%s decision=%s receipt=%s mandate=%s correlation=%s",
                self.a2g_tool_name,
                verdict.decision.value,
                verdict.receipt_id,
                verdict.mandate_hash[:16] + "…" if verdict.mandate_hash else "",
                verdict.correlation_id or "none",
            )

            if verdict.allowed:
                return self.tool._run(*args, **kwargs)
            else:
                return (
                    f"[A2G DENY] Tool '{self.a2g_tool_name}' blocked. "
                    f"Reason: {verdict.reason}. Receipt: {verdict.receipt_id}"
                )
        except EscalationRequired as e:
            return (
                f"[A2G ESCALATE] Tool '{self.a2g_tool_name}' paused — "
                f"awaiting authority approval. Reason: {e.reason}"
            )


# ── CrewAI Agent Wrapper ─────────────────────────────────────────────

class A2GGovernedAgent:
    """
    Wraps a CrewAI Agent with per-agent A2G governance.

    Each agent in a crew can have its own mandate with different
    permissions, boundaries, and rate limits.

    Supports correlation_id so all tools used by this agent are
    linked in the same cross-vendor correlation group.

    Usage:
        researcher_client = A2GClient(mandate_path="researcher.mandate.toml")
        governed = A2GGovernedAgent(
            researcher_agent, researcher_client,
            correlation_id="crew-session-abc",
        )

        # All of researcher's tools are now governed
        crew = Crew(agents=[governed.agent], tasks=[...])
    """

    def __init__(
        self,
        agent: Any,  # crewai.Agent
        a2g_client: A2GClient,
        tool_name_map: Optional[dict[str, str]] = None,
        correlation_id: Optional[str] = None,
    ):
        self.original_agent = agent
        self.client = a2g_client
        self.tool_name_map = tool_name_map or {}
        self.correlation_id = correlation_id

        # Wrap all the agent's tools with A2G governance
        if hasattr(agent, "tools") and agent.tools:
            agent.tools = [
                A2GCrewTool(
                    tool=t,
                    a2g_client=a2g_client,
                    a2g_tool_name=self.tool_name_map.get(
                        getattr(t, "name", ""), getattr(t, "name", "unknown")
                    ),
                    correlation_id=correlation_id,
                )
                for t in agent.tools
            ]

        self.agent = agent

    def revoke(self, reason: str = "agent decommissioned"):
        """Kill switch — immediately revoke this agent's mandate."""
        self.client.revoke(reason=reason)
        logger.warning("A2G: Agent mandate REVOKED. Reason: %s", reason)


# ── Crew-Level Governance ────────────────────────────────────────────

def govern_crew(
    crew: Any,  # crewai.Crew
    a2g_clients: dict[str, A2GClient],
    tool_name_maps: Optional[dict[str, dict[str, str]]] = None,
    correlation_id: Optional[str] = None,
    validate_tasks: bool = True,
) -> Any:
    """
    Wrap an entire CrewAI crew with A2G governance.

    Each agent gets its own mandate-scoped governance client,
    so the researcher can read files but not execute commands,
    while the DevOps agent can execute but not read finance data.

    All agents share the same correlation_id for cross-vendor tracing.

    Args:
        crew: CrewAI Crew instance
        a2g_clients: Map of agent role/name → A2GClient
        tool_name_maps: Optional per-agent tool name mappings
        correlation_id: Shared UUID linking all crew decisions
        validate_tasks: Whether to validate tasks before execution

    Returns:
        The same crew with governance-wrapped agents

    Example:
        clients = {
            "researcher": A2GClient(mandate_path="researcher.mandate.toml"),
            "writer": A2GClient(mandate_path="writer.mandate.toml"),
            "reviewer": A2GClient(mandate_path="reviewer.mandate.toml"),
        }
        governed = govern_crew(crew, clients, correlation_id="crew-run-001")
        result = governed.kickoff()
    """
    tool_name_maps = tool_name_maps or {}

    for agent in crew.agents:
        agent_key = getattr(agent, "role", None) or getattr(agent, "name", None)
        if agent_key and agent_key in a2g_clients:
            A2GGovernedAgent(
                agent=agent,
                a2g_client=a2g_clients[agent_key],
                tool_name_map=tool_name_maps.get(agent_key, {}),
                correlation_id=correlation_id,
            )
            logger.info("A2G: Governed agent '%s'", agent_key)
        else:
            logger.warning(
                "A2G: No governance client for agent '%s' — running ungoverned",
                agent_key,
            )

    # Pre-execution task validation
    if validate_tasks and hasattr(crew, 'tasks') and crew.tasks:
        guard = A2GTaskGuard(a2g_clients)
        for task in crew.tasks:
            task_agents = []
            if hasattr(task, 'agent') and task.agent:
                task_agents.append(task.agent)
            for agent in task_agents:
                try:
                    guard.validate_task(task, agent)
                    logger.info("A2G: Task validation passed for agent '%s'",
                        getattr(agent, "role", "unknown"))
                except A2GError as e:
                    logger.error("A2G: Task validation FAILED: %s", e)
                    raise

    return crew


# ── Task-Level Governance Guard ──────────────────────────────────────

class A2GTaskGuard:
    """
    Pre-execution governance check for CrewAI tasks.

    Validates that the assigned agent has authority to perform
    the task before the crew even starts.

    Usage:
        guard = A2GTaskGuard(clients)
        guard.validate_task(task, agent)  # raises if unauthorized
    """

    def __init__(self, a2g_clients: dict[str, A2GClient]):
        self.clients = a2g_clients

    def validate_task(self, task: Any, agent: Any) -> bool:
        """Check if agent's mandate allows the tools this task requires."""
        agent_key = getattr(agent, "role", None) or getattr(agent, "name", None)
        if agent_key not in self.clients:
            raise A2GError(f"No governance mandate for agent '{agent_key}'")

        client = self.clients[agent_key]

        # Verify mandate is still valid
        info = client.verify_mandate()
        if not info.get("valid"):
            raise A2GError(
                f"Agent '{agent_key}' mandate is invalid or expired"
            )

        # Check each tool the task might use
        task_tools = getattr(task, "tools", []) or []
        for tool in task_tools:
            tool_name = getattr(tool, "name", "unknown")
            verdict = client.enforce(tool=tool_name, params={})
            if verdict.denied:
                raise A2GError(
                    f"Agent '{agent_key}' not authorized for tool '{tool_name}': "
                    f"{verdict.reason}"
                )

        return True


# ── Example ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("A2G + CrewAI Integration")
    print("=" * 50)
    print()
    print("Quick Start:")
    print("""
    from crewai import Agent, Task, Crew
    from crewai_tools import FileReadTool, SerperDevTool
    from a2g_crewai import govern_crew
    from a2g_client import A2GClient

    # 1. Each agent gets its own mandate
    clients = {
        "Senior Researcher": A2GClient(mandate_path="researcher.mandate.toml"),
        "Technical Writer":  A2GClient(mandate_path="writer.mandate.toml"),
    }

    # 2. Define agents as usual
    researcher = Agent(
        role="Senior Researcher",
        goal="Find and analyze market data",
        tools=[SerperDevTool(), FileReadTool()],
    )
    writer = Agent(
        role="Technical Writer",
        goal="Write reports from research findings",
        tools=[FileReadTool()],
    )

    # 3. Govern the crew with cross-vendor correlation
    crew = Crew(agents=[researcher, writer], tasks=[...])
    governed = govern_crew(crew, clients, correlation_id="crew-run-001")
    result = governed.kickoff()

    # Researcher can search web (http_get) + read files (read_file)
    # Writer can only read files — web access DENIED
    # Every decision logged with mandate_hash + correlation_id

    # 4. Verify lineage of any decision
    lineage = clients["Senior Researcher"].verify_lineage("receipt-uuid")
    print(lineage.mandate_hash, lineage.lineage_complete)

    # 5. Compress researcher's governance history
    summary = clients["Senior Researcher"].compress(
        agent_did="did:a2g:researcher",
        start="2026-01-01T00:00:00Z",
        end="2026-03-31T23:59:59Z",
        key_path="sovereign.secret.key",
        issuer_name="Trust Authority",
        out_path="researcher-q1.json",
    )
    print(f"Compliance: {summary.compliance_rate}%")
    """)
