"""Call a configured local MCP tool over stdio; never invoke Telegram directly."""

import argparse
import asyncio
import json
import os
from pathlib import Path
import tomllib

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def run(args):
    config_path = Path(args.config).expanduser()
    raw = config_path.read_bytes()
    if config_path.suffix == ".toml":
        servers = tomllib.loads(raw.decode())["mcp_servers"]
    else:
        servers = json.loads(raw)["mcpServers"]
    server = servers[args.server]
    env = {**os.environ, **server.get("env", {})}
    # Independent process uses the client's supported runtime-copy mode to avoid
    # sharing the active MCP client's SQLite connection. All write gates remain.
    env["TG_SESSION_RUNTIME_MODE"] = "copy"
    env["TG_SESSION_RUNTIME_PROFILE"] = "folder_cli"
    params = StdioServerParameters(
        command=server["command"], args=server.get("args", []), env=env,
        cwd=str(Path(__file__).resolve().parents[1]),
    )
    payload = json.loads(Path(args.arguments).read_text()) if args.arguments else {}
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(args.tool, payload)
            data = result.model_dump(mode="json", exclude_none=True)
    encoded = json.dumps(data, ensure_ascii=False, indent=2)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(encoded)
        print(f"MCP result saved to {output}")
    else:
        print(encoded)
    if result.isError:
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=".mcp.json")
    parser.add_argument("--server", default="tgmcp-read")
    parser.add_argument("--tool", required=True)
    parser.add_argument("--arguments")
    parser.add_argument("--output")
    asyncio.run(run(parser.parse_args()))
