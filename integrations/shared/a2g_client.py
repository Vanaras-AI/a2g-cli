"""
A2G Client — Python wrapper for the A2G governance protocol CLI.

Every agent framework integration uses this client to:
1. Enforce actions before execution (ALLOW / DENY / ESCALATE)
2. Verify mandates
3. Query audit trails
4. Manage authority governance (propose, review, revoke)

Usage:
    from a2g_client import A2GClient, A2GDecision

    client = A2GClient(mandate_path="agent.mandate.toml", ledger_path="gov.db")
    decision = client.enforce(tool="read_file", params={"path": "workspace/data.csv"})

    if decision.allowed:
        # proceed with action
    elif decision.escalated:
        # pause and await human approval
    else:
        # action denied — log and skip
"""

import json
import subprocess
import os
import shutil
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Any
from pathlib import Path


class Decision(Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ESCALATE = "ESCALATE"
    EXPIRED = "EXPIRED"
    ERROR = "ERROR"


@dataclass
class A2GVerdict:
    """Result of an enforcement decision."""
    decision: Decision
    tool: str
    reason: str
    receipt_id: str
    exit_code: int
    raw_output: str

    @property
    def allowed(self) -> bool:
        return self.decision == Decision.ALLOW

    @property
    def denied(self) -> bool:
        return self.decision in (Decision.DENY, Decision.EXPIRED)

    @property
    def escalated(self) -> bool:
        return self.decision == Decision.ESCALATE


@dataclass
class A2GAuditEntry:
    """A single audit trail entry."""
    seq: int
    decision: str
    agent_did: str
    tool: str
    timestamp: str


class A2GError(Exception):
    """Raised when A2G encounters a protocol-level error."""
    pass


class EscalationRequired(A2GError):
    """Raised when an action requires escalation to higher authority."""
    def __init__(self, tool: str, reason: str, escalate_to: str = ""):
        self.tool = tool
        self.reason = reason
        self.escalate_to = escalate_to
        super().__init__(f"ESCALATE: {tool} — {reason}")


class A2GClient:
    """
    Python client for the A2G deterministic governance protocol.

    Wraps the A2G CLI binary and provides a clean Python interface
    for enforcing governance decisions on agent actions.
    """

    def __init__(
        self,
        mandate_path: str,
        ledger_path: str = "a2g_ledger.db",
        a2g_binary: Optional[str] = None,
        auto_deny_on_error: bool = True,
    ):
        self.mandate_path = str(Path(mandate_path).resolve())
        self.ledger_path = str(Path(ledger_path).resolve())
        self.auto_deny_on_error = auto_deny_on_error

        # Find the A2G binary
        if a2g_binary:
            self.binary = a2g_binary
        else:
            self.binary = self._find_binary()

        # Fail-fast: verify binary exists at init time
        if not os.path.isfile(self.binary) and not shutil.which(self.binary):
            raise A2GError(f"A2G binary not found at '{self.binary}' and not in PATH. "
                           f"Build with: cargo build --release")

    def _find_binary(self) -> str:
        """Locate the A2G binary in standard locations."""
        candidates = [
            os.path.join(os.path.dirname(__file__), "..", "..", "target", "release", "a2g"),
            os.path.expanduser("~/.local/bin/a2g"),
            "/usr/local/bin/a2g",
            "a2g",  # rely on PATH
        ]
        for c in candidates:
            if os.path.isfile(c):
                return os.path.abspath(c)
        return "a2g"  # fallback to PATH

    def _run(self, args: list[str], allow_nonzero: bool = False, timeout: int = 10) -> tuple[int, str, str]:
        """Execute an A2G CLI command with retry and backoff."""
        cmd = [self.binary] + args
        last_error = None

        for attempt in range(3):  # max 3 retries
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                if not allow_nonzero and result.returncode not in (0, 1, 2):
                    raise A2GError(f"a2g command failed: {result.stderr}")
                return result.returncode, result.stdout, result.stderr
            except subprocess.TimeoutExpired:
                last_error = A2GError(f"A2G enforcement timed out (>{timeout}s) on attempt {attempt+1}/3")
                if attempt < 2:
                    import time
                    time.sleep(0.5 * (attempt + 1))  # backoff: 0.5s, 1s
            except FileNotFoundError:
                raise A2GError(f"A2G binary not found: {self.binary}")

        if last_error:
            raise last_error
        raise A2GError(f"A2G command failed after 3 retries")

    # ── Core Enforcement ─────────────────────────────────────────────

    def enforce(self, tool: str, params: Optional[dict] = None) -> A2GVerdict:
        """
        Enforce a governance decision for an agent action.

        This is the primary method — call it BEFORE every tool/action execution.

        Args:
            tool: The tool name (e.g., "read_file", "http_get", "execute")
            params: Tool parameters as a dict (e.g., {"path": "workspace/data.csv"})

        Returns:
            A2GVerdict with decision, receipt, and metadata

        Raises:
            EscalationRequired: When a tool requires escalation to higher authority
        """
        params_json = json.dumps(params or {})

        exit_code, stdout, stderr = self._run([
            "enforce",
            "--mandate", self.mandate_path,
            "--tool", tool,
            "--params", params_json,
            "--ledger", self.ledger_path,
            "--output", "json",
        ], allow_nonzero=True)

        verdict = self._parse_verdict(exit_code, stdout, stderr, tool)

        # Fail-fast on escalation
        if verdict.decision == Decision.ESCALATE:
            raise EscalationRequired(
                tool=tool,
                reason=verdict.reason,
                escalate_to=verdict.reason  # extract from reason string if available
            )

        return verdict

    def _parse_verdict(self, exit_code: int, stdout: str, stderr: str, tool: str) -> A2GVerdict:
        """Parse CLI output into a structured verdict."""
        # Try JSON parsing first (when --output json is used)
        try:
            data = json.loads(stdout.strip())
            decision_str = data.get("decision", "").upper()
            decision_map = {
                "ALLOW": Decision.ALLOW,
                "DENY": Decision.DENY,
                "ESCALATE": Decision.ESCALATE,
                "EXPIRED": Decision.EXPIRED,
            }
            decision = decision_map.get(decision_str, Decision.ERROR)
            return A2GVerdict(
                decision=decision,
                tool=data.get("tool", tool),
                reason=data.get("reason", ""),
                receipt_id=data.get("receipt_id", ""),
                exit_code=exit_code,
                raw_output=stdout,
            )
        except (json.JSONDecodeError, KeyError):
            pass

        # Fallback to text parsing for older binary versions
        output = stdout + stderr
        receipt_id = ""
        reason = ""

        for line in output.splitlines():
            line = line.strip()
            if line.startswith("receipt:"):
                receipt_id = line.split(":", 1)[1].strip()
            elif line.startswith("reason:") or line.startswith("rule:"):
                reason = line.split(":", 1)[1].strip()

        if exit_code == 0:
            decision = Decision.ALLOW
            reason = reason or "all_checks_passed"
        elif exit_code == 2:
            decision = Decision.ESCALATE
        elif "EXPIRED" in output:
            decision = Decision.EXPIRED
        elif exit_code == 1:
            decision = Decision.DENY
        else:
            if self.auto_deny_on_error:
                decision = Decision.DENY
                reason = f"enforcement_error: exit_code={exit_code}"
            else:
                decision = Decision.ERROR
                reason = f"unexpected exit code: {exit_code}"

        return A2GVerdict(
            decision=decision,
            tool=tool,
            reason=reason,
            receipt_id=receipt_id,
            exit_code=exit_code,
            raw_output=output,
        )

    # ── Mandate Verification ─────────────────────────────────────────

    def verify_mandate(self) -> dict:
        """Verify the current mandate's signature, TTL, and identity."""
        exit_code, stdout, _ = self._run([
            "verify", "--mandate", self.mandate_path,
            "--output", "json",
        ], allow_nonzero=True)

        info = {"valid": exit_code == 0, "raw": stdout}
        for line in stdout.splitlines():
            line = line.strip()
            if "agent:" in line:
                info["agent"] = line.split(":", 1)[1].strip()
            elif "ttl remaining:" in line:
                info["ttl_remaining"] = line.split(":", 1)[1].strip()
        return info

    # ── Revocation ───────────────────────────────────────────────────

    def revoke(self, reason: str = "agent revoked") -> bool:
        """Revoke the current mandate immediately."""
        exit_code, _, _ = self._run([
            "revoke",
            "--mandate", self.mandate_path,
            "--ledger", self.ledger_path,
            "--reason", reason,
        ], allow_nonzero=True)
        return exit_code == 0

    # ── Audit ────────────────────────────────────────────────────────

    def audit(self, last: int = 20, agent: Optional[str] = None, decision: Optional[str] = None) -> str:
        """Query the decision audit trail."""
        args = ["audit", "--ledger", self.ledger_path, "--last", str(last), "--output", "json"]
        if agent:
            args.extend(["--agent", agent])
        if decision:
            args.extend(["--decision", decision])
        _, stdout, _ = self._run(args, allow_nonzero=True)
        return stdout

    def authority_log(self, last: int = 20) -> str:
        """Query the authority governance audit trail (Layer 0)."""
        _, stdout, _ = self._run([
            "authority-log", "--ledger", self.ledger_path, "--last", str(last),
            "--output", "json",
        ], allow_nonzero=True)
        return stdout


# ── Decorator for governed functions ──────────────────────────────────

def governed(client: A2GClient, tool_name: str):
    """
    Decorator that enforces A2G governance before executing a function.

    Usage:
        @governed(a2g_client, "read_file")
        def read_file(path: str) -> str:
            return open(path).read()
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Build params from function arguments
            params = kwargs.copy()
            if args:
                import inspect
                sig = inspect.signature(func)
                param_names = list(sig.parameters.keys())
                for i, arg in enumerate(args):
                    if i < len(param_names):
                        params[param_names[i]] = str(arg)

            verdict = client.enforce(tool=tool_name, params=params)

            if verdict.allowed:
                return func(*args, **kwargs)
            elif verdict.escalated:
                raise A2GError(
                    f"ESCALATE: '{tool_name}' requires higher authority approval. "
                    f"Receipt: {verdict.receipt_id}"
                )
            else:
                raise A2GError(
                    f"DENY: '{tool_name}' blocked by governance policy. "
                    f"Reason: {verdict.reason}. Receipt: {verdict.receipt_id}"
                )
        wrapper.__wrapped__ = func
        wrapper.__a2g_tool__ = tool_name
        return wrapper
    return decorator
