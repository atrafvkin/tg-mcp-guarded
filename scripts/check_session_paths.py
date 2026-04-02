#!/usr/bin/env python3
"""Preflight check for read/actions Telegram session separation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _resolve_session_path(raw_path: str) -> str:
    raw = str(raw_path or "").strip()
    if not raw:
        return ""
    return str(Path(raw).expanduser().resolve())


def _extract_session_paths_from_config(
    config_path: Path,
    read_server_name: str,
    actions_server_name: str,
) -> tuple[str, str]:
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    servers = payload.get("mcpServers", {})
    if not isinstance(servers, dict):
        raise ValueError("config does not contain object mcpServers")

    read_server = servers.get(read_server_name)
    actions_server = servers.get(actions_server_name)
    if not isinstance(read_server, dict):
        raise ValueError(f"missing server '{read_server_name}' in mcpServers")
    if not isinstance(actions_server, dict):
        raise ValueError(f"missing server '{actions_server_name}' in mcpServers")

    read_env = read_server.get("env", {})
    actions_env = actions_server.get("env", {})
    if not isinstance(read_env, dict) or not isinstance(actions_env, dict):
        raise ValueError("server env must be an object")

    return (
        _resolve_session_path(str(read_env.get("TG_SESSION_PATH", ""))),
        _resolve_session_path(str(actions_env.get("TG_SESSION_PATH", ""))),
    )


def _print_ok(read_path: str, actions_path: str) -> int:
    print("ok: read/actions use separate session files")
    print(f"read: {read_path}")
    print(f"actions: {actions_path}")
    return 0


def _print_conflict(read_path: str, actions_path: str) -> int:
    print("error: read/actions share one Telegram session file", file=sys.stderr)
    print(f"session: {read_path}", file=sys.stderr)
    print(
        "cause: concurrent Telethon read+write MCP processes can hit sqlite 'database is locked'",
        file=sys.stderr,
    )
    print(
        "fix: use separate sessions by default: read -> *_ro.session, actions -> write session",
        file=sys.stderr,
    )
    return 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", help="Path to .mcp.json or rendered config JSON")
    parser.add_argument("--read-session-path", help="Explicit TG_SESSION_PATH for tgmcp-read")
    parser.add_argument("--actions-session-path", help="Explicit TG_SESSION_PATH for tgmcp-actions")
    parser.add_argument("--read-server-name", default="tgmcp-read")
    parser.add_argument("--actions-server-name", default="tgmcp-actions")
    args = parser.parse_args()

    if args.config:
        config_path = Path(args.config).expanduser().resolve()
        read_path, actions_path = _extract_session_paths_from_config(
            config_path,
            args.read_server_name,
            args.actions_server_name,
        )
    else:
        read_path = _resolve_session_path(args.read_session_path or "")
        actions_path = _resolve_session_path(args.actions_session_path or "")

    if not read_path:
        print("error: read session path is empty", file=sys.stderr)
        return 1
    if not actions_path:
        print("error: actions session path is empty", file=sys.stderr)
        return 1
    if read_path == actions_path:
        return _print_conflict(read_path, actions_path)
    return _print_ok(read_path, actions_path)


if __name__ == "__main__":
    raise SystemExit(main())
