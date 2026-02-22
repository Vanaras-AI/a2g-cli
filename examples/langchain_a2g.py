"""
A2G + LangChain Integration Example

Wraps any LangChain tool with A2G deterministic governance.
Every tool call is enforced against a signed mandate before execution.

Usage:
    1. a2g sovereign --out .
    2. a2g init --name my-agent --out .
    3. Edit my-agent.mandate.toml (set allowed tools/paths)
    4. a2g sign --mandate my-agent.mandate.toml --key sovereign.secret.key --ttl 24
    5. python langchain_a2g.py
"""

import json
import subprocess
from typing import Any, Callable

# ─── A2G Governance Wrapper ──────────────────────────────────────────

class A2GGovernor:
    """
    Wraps tool execution with A2G deterministic enforcement.

    Every call goes through:
      mandate verify → enforce (allow/deny) → execute → output governance
    """

    def __init__(self, a2g_binary: str, mandate_path: str, ledger_path: str = "a2g_ledger.db"):
        self.a2g = a2g_binary
        self.mandate = mandate_path
        self.ledger = ledger_path

        # Verify mandate on startup
        result = self._run(["verify", "--mandate", self.mandate])
        if result.returncode != 0:
            raise RuntimeError(f"Mandate verification failed: {result.stderr}")
        print(f"[A2G] Mandate verified ✓")

    def enforce(self, tool: str, params: dict) -> dict:
        """
        Enforce a tool call against the mandate.
        Returns {"decision": "ALLOW"/"DENY", "reason": "...", "receipt": "..."}
        """
        result = self._run([
            "enforce",
            "--mandate", self.mandate,
            "--tool", tool,
            "--params", json.dumps(params),
            "--ledger", self.ledger,
        ])

        output = result.stdout.strip()

        if "ALLOW" in output:
            return {"decision": "ALLOW", "output": output}
        elif "DENY" in output:
            return {"decision": "DENY", "output": output}
        elif "EXPIRED" in output:
            return {"decision": "EXPIRED", "output": output}
        else:
            return {"decision": "UNKNOWN", "output": output}

    def governed_call(self, tool_name: str, params: dict, execute_fn: Callable) -> Any:
        """
        The core governance loop:
          1. Enforce the intent against the mandate
          2. If ALLOW → execute the tool
          3. If DENY → return denial reason (never execute)
        """
        # Step 1: Enforce
        verdict = self.enforce(tool_name, params)

        if verdict["decision"] != "ALLOW":
            print(f"[A2G] DENIED: {tool_name} — {verdict['output']}")
            return None

        # Step 2: Execute (only if ALLOW)
        print(f"[A2G] ALLOWED: {tool_name}")
        result = execute_fn(**params)

        return result

    def _run(self, args: list) -> subprocess.CompletedProcess:
        return subprocess.run(
            [self.a2g] + args,
            capture_output=True,
            text=True,
        )


# ─── Example: Governed File Tools ────────────────────────────────────

def read_file(path: str) -> str:
    """Simple file read tool."""
    with open(path, "r") as f:
        return f.read()

def write_file(path: str, content: str) -> str:
    """Simple file write tool."""
    with open(path, "w") as f:
        f.write(content)
    return f"Written {len(content)} bytes to {path}"


# ─── Demo ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    a2g_binary = sys.argv[1] if len(sys.argv) > 1 else "./a2g"
    mandate = sys.argv[2] if len(sys.argv) > 2 else "./research-bot.mandate.toml"

    # Initialize governor
    gov = A2GGovernor(a2g_binary, mandate)

    print("\n--- Test 1: Read from allowed path ---")
    result = gov.governed_call(
        "read_file",
        {"path": "./workspace/data.csv"},
        read_file,
    )
    print(f"Result: {result}")

    print("\n--- Test 2: Read from /etc/passwd (should DENY) ---")
    result = gov.governed_call(
        "read_file",
        {"path": "/etc/passwd"},
        read_file,
    )
    print(f"Result: {result}")

    print("\n--- Test 3: Write to allowed path ---")
    result = gov.governed_call(
        "write_file",
        {"path": "./workspace/output/report.md", "content": "# Report\nAll clear."},
        write_file,
    )
    print(f"Result: {result}")

    print("\n--- Test 4: Write to ~/.ssh (should DENY) ---")
    result = gov.governed_call(
        "write_file",
        {"path": "~/.ssh/authorized_keys", "content": "ssh-rsa AAAA..."},
        write_file,
    )
    print(f"Result: {result}")

    print("\n--- Test 5: Unauthorized tool (should DENY) ---")
    result = gov.governed_call(
        "execute_command",
        {"command": "rm -rf /"},
        lambda **kwargs: "this should never execute",
    )
    print(f"Result: {result}")

    print("\n--- Audit Trail ---")
    subprocess.run([a2g_binary, "audit", "--ledger", "a2g_ledger.db"])
