"""A real MCP client (the official Python SDK) against `sluice mcp`, for scripts/mcp-check.sh.

Usage: python mcp-client.py SLUICE OUT SAMPLES SOURCES RULES

Starts `sluice mcp` over stdio, lists the tools, reads the advice and proves the analysis's own
vector.yaml through the server; exits non-zero on any difference from what Sluice promises.
"""

import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

EXPECTED_TOOLS = [
    "summary",
    "source_plan",
    "problems",
    "files",
    "read_file",
    "prove_vector",
    "prove_transform_kql",
]


def field(obj, camel, snake):
    """An attribute by its 1.x (camelCase) or 2.x (snake_case) name."""
    return getattr(obj, snake) if hasattr(obj, snake) else getattr(obj, camel)


def structured(result):
    if field(result, "isError", "is_error"):
        raise SystemExit(f"tool failed: {result.content[0].text}")
    data = field(result, "structuredContent", "structured_content")
    if data != json.loads(result.content[0].text):
        raise SystemExit("structured content and text differ")
    return data


async def main(sluice, out, samples, sources, rules):
    server = StdioServerParameters(
        command=sluice,
        args=["mcp", "--out", out, "--input", samples, "--sources", sources, "--rules", rules],
    )
    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            version = field(init, "protocolVersion", "protocol_version")
            print(f"protocol {version}, server {field(init, 'serverInfo', 'server_info').name}")
            tools = (await session.list_tools()).tools
            names = [tool.name for tool in tools]
            if names != EXPECTED_TOOLS:
                raise SystemExit(f"tools: {names}")
            if not all(
                tool.annotations and field(tool.annotations, "readOnlyHint", "read_only_hint")
                for tool in tools
            ):
                raise SystemExit("every tool must be read-only")
            summary = structured(await session.call_tool("summary", {}))
            plan = json.loads(Path(out, "plan.json").read_text())
            if summary["proof"] != plan["proof"]:
                raise SystemExit("summary's proof differs from plan.json")
            config = Path(out, "vector.yaml").read_text()
            proof = structured(await session.call_tool("prove_vector", {"config": config}))
            if not proof["holds"] or proof["alerts_full"] != proof["alerts_forwarded"]:
                raise SystemExit(f"the analysis's own vector.yaml does not hold: {proof}")
            refused = await session.call_tool("read_file", {"path": "../plan.json"})
            if not field(refused, "isError", "is_error"):
                raise SystemExit("read_file gave a file outside the analysis")
            print(
                f"{len(names)} tools; {summary['saved_percent']}% saved; vector.yaml proven, "
                f"{proof['alerts_full']} = {proof['alerts_forwarded']} alerts"
            )


if __name__ == "__main__":
    asyncio.run(main(*sys.argv[1:6]))
