"""
A2G + MCP (Model Context Protocol) Integration — Governance MCP Server

Implements an MCP server that wraps any existing MCP tool server
with A2G governance. The agent connects to this A2G MCP server,
which proxies tool calls through the enforcement pipeline before
forwarding to the underlying tool server.

Architecture:
    Agent → MCP Client → A2G MCP Server → enforce() → Upstream MCP Server
                               ↓
                         ALLOW → proxy to upstream
                         DENY  → return error
                         ESCALATE → return escalation notice

Features:
    - Governed tool proxying (any MCP tool, any MCP client)
    - Built-in governance tools: status, audit, authority_log
    - Lineage tools: verify_lineage (reconstruct provenance from receipt)
    - Trust compression tools: compress, verify_summary
    - Cross-vendor correlation on all governed tool calls
    - Immutable audit trail with full lineage metadata

This is the most powerful integration pattern because it works with
ANY MCP-compatible agent without modifying the agent's code.

Usage:
    # Run as a standalone MCP server:
    python a2g_mcp_server.py --mandate agent.mandate.toml --ledger gov.db

    # In MCP client config (claude_desktop_config.json):
    {
        "mcpServers": {
            "governed-files": {
                "command": "python",
                "args": ["a2g_mcp_server.py", "--mandate", "agent.mandate.toml"]
            }
        }
    }
"""

import sys
import json
import logging
import asyncio
from typing import Any, Optional
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "shared"))
from a2g_client import A2GClient, A2GVerdict, A2GError, Decision

logger = logging.getLogger("a2g.mcp")


# ── MCP Protocol Types ───────────────────────────────────────────────

class MCPToolDefinition:
    """MCP tool definition with A2G governance metadata."""

    def __init__(self, name: str, description: str, input_schema: dict, a2g_tool_name: Optional[str] = None):
        self.name = name
        self.description = description
        self.input_schema = input_schema
        self.a2g_tool_name = a2g_tool_name or name

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": f"[A2G Governed] {self.description}",
            "inputSchema": self.input_schema,
        }


class MCPToolResult:
    """MCP tool call result."""

    def __init__(self, content: list[dict], is_error: bool = False):
        self.content = content
        self.is_error = is_error

    @staticmethod
    def text(text: str, is_error: bool = False) -> "MCPToolResult":
        return MCPToolResult(
            content=[{"type": "text", "text": text}],
            is_error=is_error,
        )

    def to_dict(self) -> dict:
        return {
            "content": self.content,
            "isError": self.is_error,
        }


# ── A2G MCP Server ───────────────────────────────────────────────────

class A2GMCPServer:
    """
    MCP Server that enforces A2G governance on tool calls.

    Sits between the MCP client (agent) and actual tool implementations.
    Every tool call passes through A2G enforce() before execution.

    This server can:
    1. Wrap existing tool functions with governance
    2. Proxy to an upstream MCP server with governance
    3. Expose governance-specific tools (audit, status, revoke)
    4. Expose lineage tools (verify_lineage, compress, verify_summary)
    """

    def __init__(
        self,
        a2g_client: A2GClient,
        server_name: str = "a2g-governed",
        server_version: str = "0.2.0",
        correlation_id: Optional[str] = None,
    ):
        self.client = a2g_client
        self.server_name = server_name
        self.server_version = server_version
        self.correlation_id = correlation_id
        self.tools: dict[str, tuple[MCPToolDefinition, Any]] = {}

        # Register built-in governance tools
        self._register_governance_tools()
        self._register_lineage_tools()

    def _register_governance_tools(self):
        """Register A2G governance tools exposed via MCP."""

        # a2g_status — check mandate status
        self.register_tool(
            MCPToolDefinition(
                name="a2g_status",
                description="Check the governance mandate status (valid/expired/revoked)",
                input_schema={"type": "object", "properties": {}},
                a2g_tool_name="__internal__",
            ),
            handler=self._handle_status,
        )

        # a2g_audit — query recent decisions
        self.register_tool(
            MCPToolDefinition(
                name="a2g_audit",
                description="Query the A2G governance audit trail for recent decisions",
                input_schema={
                    "type": "object",
                    "properties": {
                        "last": {"type": "integer", "description": "Number of recent entries", "default": 10},
                    },
                },
                a2g_tool_name="__internal__",
            ),
            handler=self._handle_audit,
        )

        # a2g_authority_log — query authority governance trail
        self.register_tool(
            MCPToolDefinition(
                name="a2g_authority_log",
                description="Query the Layer 0 authority governance audit trail",
                input_schema={
                    "type": "object",
                    "properties": {
                        "last": {"type": "integer", "description": "Number of recent entries", "default": 10},
                    },
                },
                a2g_tool_name="__internal__",
            ),
            handler=self._handle_authority_log,
        )

    def _register_lineage_tools(self):
        """Register lineage and trust compression tools exposed via MCP."""

        # a2g_verify_lineage — reconstruct execution lineage from a receipt
        self.register_tool(
            MCPToolDefinition(
                name="a2g_verify_lineage",
                description="Reconstruct full execution lineage from a receipt ID. Returns mandate version, proposal, delegation chain, authority, and correlation.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "receipt_id": {"type": "string", "description": "Receipt ID or receipt hash to trace"},
                    },
                    "required": ["receipt_id"],
                },
                a2g_tool_name="__internal__",
            ),
            handler=self._handle_verify_lineage,
        )

        # a2g_compress — compress governance history into a signed trust summary
        self.register_tool(
            MCPToolDefinition(
                name="a2g_compress",
                description="Compress an agent's governance history into a signed, portable trust proof. Requires agent DID, time window, and signing authority.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "agent_did": {"type": "string", "description": "Agent DID to compress"},
                        "start": {"type": "string", "description": "Window start (ISO 8601)"},
                        "end": {"type": "string", "description": "Window end (ISO 8601)"},
                        "key_path": {"type": "string", "description": "Path to ed25519 signing key"},
                        "issuer_name": {"type": "string", "description": "Human-readable signer name"},
                        "out_path": {"type": "string", "description": "Output path for summary JSON"},
                    },
                    "required": ["agent_did", "start", "end", "key_path", "issuer_name", "out_path"],
                },
                a2g_tool_name="__internal__",
            ),
            handler=self._handle_compress,
        )

        # a2g_verify_summary — verify a trust summary's integrity
        self.register_tool(
            MCPToolDefinition(
                name="a2g_verify_summary",
                description="Verify a trust summary's cryptographic integrity and signature. Returns validation status.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "summary_path": {"type": "string", "description": "Path to trust summary JSON file"},
                    },
                    "required": ["summary_path"],
                },
                a2g_tool_name="__internal__",
            ),
            handler=self._handle_verify_summary,
        )

    def register_tool(
        self,
        definition: MCPToolDefinition,
        handler: Any,
    ):
        """Register a tool with its handler."""
        self.tools[definition.name] = (definition, handler)

    def register_governed_tool(
        self,
        name: str,
        description: str,
        input_schema: dict,
        handler: Any,
        a2g_tool_name: Optional[str] = None,
    ):
        """
        Register a tool that will be governed by A2G.

        The handler is only called if A2G allows the action.

        Args:
            name: MCP tool name
            description: Tool description for the agent
            input_schema: JSON Schema for tool inputs
            handler: Async or sync function to execute
            a2g_tool_name: A2G tool name (defaults to MCP tool name)
        """
        defn = MCPToolDefinition(name, description, input_schema, a2g_tool_name)
        self.tools[name] = (defn, self._wrap_with_governance(handler, defn))

    def _wrap_with_governance(self, handler: Any, definition: MCPToolDefinition) -> Any:
        """Wrap a handler with A2G enforcement including lineage support."""
        async def governed_handler(params: dict) -> MCPToolResult:
            # Extract lineage params
            corr_id = params.pop("_correlation_id", self.correlation_id)
            parent = params.pop("_parent_receipt", None)

            # A2G Enforcement
            verdict = self.client.enforce(
                tool=definition.a2g_tool_name,
                params={k: str(v) for k, v in params.items()},
                correlation_id=corr_id,
                parent_receipt=parent,
            )

            logger.info(
                "A2G [MCP]: tool=%s decision=%s receipt=%s mandate=%s correlation=%s",
                definition.a2g_tool_name,
                verdict.decision.value,
                verdict.receipt_id,
                verdict.mandate_hash[:16] + "…" if verdict.mandate_hash else "",
                verdict.correlation_id or "none",
            )

            if verdict.allowed:
                # Execute the actual tool
                if asyncio.iscoroutinefunction(handler):
                    result = await handler(params)
                else:
                    result = handler(params)

                if isinstance(result, MCPToolResult):
                    return result
                return MCPToolResult.text(str(result))

            elif verdict.escalated:
                return MCPToolResult.text(
                    f"[A2G ESCALATE] This action requires higher authority approval.\n"
                    f"Tool: {definition.a2g_tool_name}\n"
                    f"Reason: {verdict.reason}\n"
                    f"Receipt: {verdict.receipt_id}\n"
                    f"Please contact your governance administrator.",
                    is_error=True,
                )
            else:
                return MCPToolResult.text(
                    f"[A2G DENY] This action is blocked by governance policy.\n"
                    f"Tool: {definition.a2g_tool_name}\n"
                    f"Reason: {verdict.reason}\n"
                    f"Receipt: {verdict.receipt_id}",
                    is_error=True,
                )

        return governed_handler

    # ── Built-in Governance Tool Handlers ─────────────────────────────

    async def _handle_status(self, params: dict) -> MCPToolResult:
        info = self.client.verify_mandate()
        return MCPToolResult.text(json.dumps(info, indent=2))

    async def _handle_audit(self, params: dict) -> MCPToolResult:
        last = params.get("last", 10)
        result = self.client.audit(last=last)
        return MCPToolResult.text(result)

    async def _handle_authority_log(self, params: dict) -> MCPToolResult:
        last = params.get("last", 10)
        result = self.client.authority_log(last=last)
        return MCPToolResult.text(result)

    # ── Lineage + Trust Compression Handlers ──────────────────────────

    async def _handle_verify_lineage(self, params: dict) -> MCPToolResult:
        receipt_id = params.get("receipt_id", "")
        if not receipt_id:
            return MCPToolResult.text("Error: receipt_id is required", is_error=True)
        try:
            lineage = self.client.verify_lineage(receipt_id)
            return MCPToolResult.text(json.dumps(lineage.raw, indent=2))
        except A2GError as e:
            return MCPToolResult.text(f"Lineage error: {e}", is_error=True)

    async def _handle_compress(self, params: dict) -> MCPToolResult:
        required = ["agent_did", "start", "end", "key_path", "issuer_name", "out_path"]
        missing = [k for k in required if not params.get(k)]
        if missing:
            return MCPToolResult.text(
                f"Error: missing required params: {', '.join(missing)}", is_error=True,
            )
        try:
            summary = self.client.compress(
                agent_did=params["agent_did"],
                start=params["start"],
                end=params["end"],
                key_path=params["key_path"],
                issuer_name=params["issuer_name"],
                out_path=params["out_path"],
            )
            return MCPToolResult.text(json.dumps({
                "summary_id": summary.summary_id,
                "agent_did": summary.agent_did,
                "total_decisions": summary.total_decisions,
                "compliance_rate": summary.compliance_rate,
                "deny_rate": summary.deny_rate,
                "escalation_rate": summary.escalation_rate,
                "merkle_root": summary.merkle_root,
                "chain_intact": summary.chain_intact,
                "out_path": params["out_path"],
            }, indent=2))
        except A2GError as e:
            return MCPToolResult.text(f"Compression error: {e}", is_error=True)

    async def _handle_verify_summary(self, params: dict) -> MCPToolResult:
        summary_path = params.get("summary_path", "")
        if not summary_path:
            return MCPToolResult.text("Error: summary_path is required", is_error=True)
        try:
            summary = self.client.verify_summary(summary_path)
            return MCPToolResult.text(json.dumps({
                "valid": summary.valid,
                "summary_id": summary.summary_id,
                "agent_did": summary.agent_did,
                "total_decisions": summary.total_decisions,
                "compliance_rate": summary.compliance_rate,
                "merkle_root": summary.merkle_root,
                "chain_intact": summary.chain_intact,
                "issuer_did": summary.issuer_did,
                "issuer_name": summary.issuer_name,
            }, indent=2))
        except A2GError as e:
            return MCPToolResult.text(f"Verification error: {e}", is_error=True)

    # ── MCP Protocol Handlers ─────────────────────────────────────────

    async def handle_initialize(self, params: dict) -> dict:
        """Handle MCP initialize request."""
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": False},
            },
            "serverInfo": {
                "name": self.server_name,
                "version": self.server_version,
            },
        }

    async def handle_list_tools(self) -> dict:
        """Handle MCP tools/list request."""
        return {
            "tools": [defn.to_dict() for defn, _ in self.tools.values()],
        }

    async def handle_call_tool(self, name: str, arguments: dict) -> dict:
        """Handle MCP tools/call request."""
        if name not in self.tools:
            return MCPToolResult.text(
                f"Unknown tool: {name}", is_error=True,
            ).to_dict()

        _, handler = self.tools[name]

        try:
            if asyncio.iscoroutinefunction(handler):
                result = await handler(arguments)
            else:
                result = handler(arguments)

            if isinstance(result, MCPToolResult):
                return result.to_dict()
            return MCPToolResult.text(str(result)).to_dict()

        except Exception as e:
            logger.error("Tool execution error: %s", e)
            return MCPToolResult.text(
                f"Tool error: {str(e)}", is_error=True,
            ).to_dict()

    # ── STDIO Transport ───────────────────────────────────────────────

    async def run_stdio(self):
        """Run the MCP server over STDIO (standard MCP transport)."""
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

        writer_transport, writer_protocol = await asyncio.get_event_loop().connect_write_pipe(
            asyncio.streams.FlowControlMixin, sys.stdout.buffer,
        )
        writer = asyncio.StreamWriter(writer_transport, writer_protocol, reader, asyncio.get_event_loop())

        logger.info("A2G MCP Server started (STDIO transport)")

        while True:
            try:
                line = await reader.readline()
                if not line:
                    break

                try:
                    request = json.loads(line.decode())
                except json.JSONDecodeError as e:
                    error_response = {
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32700,
                            "message": f"Parse error: {str(e)}"
                        },
                        "id": None
                    }
                    response_bytes = json.dumps(error_response).encode() + b"\n"
                    writer.write(response_bytes)
                    await writer.drain()
                    continue

                response = await asyncio.wait_for(self._dispatch(request), timeout=30.0)

                if response:
                    writer.write((json.dumps(response) + "\n").encode())
                    await writer.drain()

            except asyncio.TimeoutError:
                error_response = {
                    "jsonrpc": "2.0",
                    "error": {"code": -32000, "message": "Handler timeout (30s)"},
                    "id": None
                }
                response_bytes = json.dumps(error_response).encode() + b"\n"
                writer.write(response_bytes)
                await writer.drain()
            except Exception as e:
                logger.error("MCP server error: %s", e)
                break

    async def _dispatch(self, request: dict) -> Optional[dict]:
        """Dispatch an MCP JSON-RPC request."""
        method = request.get("method", "")
        params = request.get("params", {})
        req_id = request.get("id")

        if method == "initialize":
            result = await self.handle_initialize(params)
        elif method == "tools/list":
            result = await self.handle_list_tools()
        elif method == "tools/call":
            result = await self.handle_call_tool(
                params.get("name", ""), params.get("arguments", {}),
            )
        elif method == "notifications/initialized":
            return None  # No response for notifications
        else:
            result = {"error": {"code": -32601, "message": f"Unknown method: {method}"}}

        if req_id is not None:
            return {"jsonrpc": "2.0", "id": req_id, "result": result}
        return None


# ── Convenience: Create a governed file system MCP server ─────────────

def create_filesystem_server(
    a2g_client: A2GClient,
    base_dir: str = ".",
    correlation_id: Optional[str] = None,
) -> A2GMCPServer:
    """
    Create a governed filesystem MCP server.

    Provides read_file, write_file, and list_dir tools,
    all governed by A2G mandate boundaries.

    Also includes built-in governance tools:
    - a2g_status, a2g_audit, a2g_authority_log
    - a2g_verify_lineage, a2g_compress, a2g_verify_summary

    This is a drop-in replacement for the standard filesystem MCP server,
    with deterministic governance enforcement on every operation.
    """
    server = A2GMCPServer(
        a2g_client, server_name="a2g-filesystem",
        correlation_id=correlation_id,
    )
    base = Path(base_dir).resolve()

    def read_file(params: dict) -> str:
        path = base / params.get("path", "")
        return path.read_text()

    def write_file(params: dict) -> str:
        path = base / params.get("path", "")
        content = params.get("content", "")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return f"Written {len(content)} bytes to {path.name}"

    def list_dir(params: dict) -> str:
        path = base / params.get("path", ".")
        entries = sorted(path.iterdir())
        return "\n".join(
            f"{'[dir] ' if e.is_dir() else ''}{e.name}" for e in entries
        )

    server.register_governed_tool(
        "read_file", "Read a file's contents",
        {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
        read_file, a2g_tool_name="read_file",
    )
    server.register_governed_tool(
        "write_file", "Write content to a file",
        {"type": "object", "properties": {
            "path": {"type": "string"}, "content": {"type": "string"},
        }, "required": ["path", "content"]},
        write_file, a2g_tool_name="write_file",
    )
    server.register_governed_tool(
        "list_directory", "List directory contents",
        {"type": "object", "properties": {"path": {"type": "string"}}},
        list_dir, a2g_tool_name="read_file",
    )

    return server


# ── CLI Entry Point ───────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="A2G Governed MCP Server")
    parser.add_argument("--mandate", required=True, help="Path to mandate TOML")
    parser.add_argument("--ledger", default="a2g_ledger.db", help="Ledger DB path")
    parser.add_argument("--base-dir", default=".", help="Base directory for file ops")
    parser.add_argument("--correlation-id", default=None, help="Cross-vendor correlation UUID")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    client = A2GClient(mandate_path=args.mandate, ledger_path=args.ledger)
    server = create_filesystem_server(
        client, base_dir=args.base_dir,
        correlation_id=args.correlation_id,
    )

    print("A2G MCP Server — governed filesystem", file=sys.stderr)
    print(f"  mandate:     {args.mandate}", file=sys.stderr)
    print(f"  ledger:      {args.ledger}", file=sys.stderr)
    print(f"  base:        {args.base_dir}", file=sys.stderr)
    print(f"  correlation: {args.correlation_id or 'none'}", file=sys.stderr)
    print(f"  tools:       {len(server.tools)} ({', '.join(server.tools.keys())})", file=sys.stderr)

    asyncio.run(server.run_stdio())
