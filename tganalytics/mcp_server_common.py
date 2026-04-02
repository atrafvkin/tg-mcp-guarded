"""Shared state/helpers for tg-mcp MCP servers."""

from __future__ import annotations

import glob
import os
import sys
import time
from typing import Any
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from mcp_actions_state import load_json_dict, update_json_dict
from tganalytics.domain.groups import GroupManager
from tganalytics.infra.tele_client import describe_session_target, get_client, get_client_for_session


def _expected_username() -> str:
    raw = os.environ.get("TG_EXPECTED_USERNAME", "").strip().lstrip("@")
    return raw.lower()


def _build_session_mismatch_error(expected_username: str, actual_username: str | None, account_id: int | None) -> str:
    expected = f"@{expected_username}"
    actual_clean = (actual_username or "").strip()
    actual = f"@{actual_clean}" if actual_clean else "<no_username>"
    return (
        f"Session mismatch: expected account {expected}, got {actual} (id={account_id}). "
        "Set TG_SESSION_PATH to the correct session and restart MCP."
    )


def _validate_expected_account(me: Any) -> str | None:
    expected = _expected_username()
    if not expected:
        return None

    actual_username = (getattr(me, "username", None) or "").strip().lower()
    actual_id = getattr(me, "id", None)
    if actual_username != expected:
        return _build_session_mismatch_error(expected, getattr(me, "username", None), actual_id)
    return None


def _resolve_session_path(raw_path: str) -> str:
    raw = str(raw_path or "").strip()
    if not raw:
        return ""
    return str(Path(raw).expanduser().resolve())


def _normalize_session_conflict_mode(raw_mode: str) -> str:
    mode = str(raw_mode or "").strip().lower()
    if mode in {"off", "warn", "fail"}:
        return mode
    return "warn"


def _session_conflict_registry_file() -> Path:
    raw = os.environ.get("TG_SESSION_CONFLICT_REGISTRY_FILE", "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    return Path("data/anti_spam/session_registry.json").resolve()


def _is_pid_alive(pid: Any) -> bool:
    try:
        value = int(pid)
    except Exception:
        return False
    if value <= 0:
        return False
    try:
        os.kill(value, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:
        return True
    return True


def _declared_session_paths(server_profile: str, session_path: str) -> tuple[str, str]:
    read_path = _resolve_session_path(os.environ.get("TG_READ_SESSION_PATH", ""))
    actions_path = _resolve_session_path(os.environ.get("TG_ACTIONS_SESSION_PATH", ""))
    if not read_path and server_profile == "read":
        read_path = session_path
    if not actions_path and server_profile == "actions":
        actions_path = session_path
    return read_path, actions_path


def _build_declared_session_conflict_message(session_path: str) -> str:
    return (
        f"Read/Actions share one Telegram session file: {session_path}. "
        "Concurrent Telethon read+write processes can hit sqlite 'database is locked'. "
        "Prefer separate sessions by default: read -> *_ro.session, actions -> write session."
    )


def _build_live_session_conflict_message(
    session_path: str,
    *,
    server_profile: str,
    other_profile: str,
) -> str:
    if other_profile == server_profile:
        return (
            f"Multiple live '{server_profile}' MCP processes share one Telegram session file: {session_path}. "
            "This is known to cause sqlite 'database is locked' under concurrent MCP traffic. "
            "Use a dedicated session file per MCP client or stop the duplicate process."
        )
    return (
        f"Read/Actions share one live Telegram session file: {session_path}. "
        "This is known to cause sqlite 'database is locked' under concurrent MCP traffic. "
        "Split sessions: read -> *_ro.session, actions -> write session."
    )


def _detect_declared_session_conflict(server_profile: str, session_path: str) -> dict[str, Any] | None:
    read_path, actions_path = _declared_session_paths(server_profile, session_path)
    if not read_path or not actions_path or read_path != actions_path:
        return None
    return {
        "kind": "same_session_path",
        "source": "declared_paths",
        "message": _build_declared_session_conflict_message(read_path),
        "read_session_path": read_path,
        "actions_session_path": actions_path,
    }


def _register_session_claim(
    registry_file: Path,
    *,
    server_profile: str,
    session_path: str,
) -> str:
    claim_id = f"{server_profile}:{os.getpid()}"
    claim = {
        "pid": os.getpid(),
        "profile": server_profile,
        "session_path": session_path,
        "updated_at": int(time.time()),
    }

    def _mut(claims: dict[str, Any]) -> None:
        stale_keys = []
        for key, value in claims.items():
            pid = value.get("pid") if isinstance(value, dict) else None
            if not _is_pid_alive(pid):
                stale_keys.append(key)
        for key in stale_keys:
            claims.pop(key, None)
        claims[claim_id] = claim

    update_json_dict(registry_file, _mut, root_key="claims")
    return claim_id


def _detect_live_session_conflict(
    registry_file: Path,
    *,
    server_profile: str,
    session_path: str,
    own_claim_id: str,
) -> dict[str, Any] | None:
    if not session_path:
        return None
    claims = load_json_dict(registry_file, root_key="claims")
    for claim_id, value in claims.items():
        if claim_id == own_claim_id or not isinstance(value, dict):
            continue
        other_profile = str(value.get("profile") or "").strip().lower()
        other_session_path = _resolve_session_path(value.get("session_path", ""))
        if other_session_path != session_path:
            continue
        if not _is_pid_alive(value.get("pid")):
            continue
        return {
            "kind": "same_session_path",
            "source": "live_registry",
            "message": _build_live_session_conflict_message(
                session_path,
                server_profile=server_profile,
                other_profile=other_profile,
            ),
            "read_session_path": session_path,
            "actions_session_path": session_path,
            "other_profile": other_profile,
            "other_pid": value.get("pid"),
        }
    return None


class MCPServerContext:
    """Shared runtime state for MCP servers.

    Keeps one active Telegram client/session per server process.
    """

    def __init__(
        self,
        sessions_dir: str | None = None,
        allow_session_switch: bool = True,
        server_profile: str = "read",
    ):
        self.sessions_dir = sessions_dir or os.environ.get("TG_SESSIONS_DIR", "data/sessions")
        self.allow_session_switch = allow_session_switch
        self.server_profile = server_profile

        self._client = None
        self._manager: GroupManager | None = None
        self._current_session: str | None = None
        self._current_session_path = ""
        self._current_effective_session_path = ""
        self._session_runtime_mode = "direct"
        self._session_conflict_mode = _normalize_session_conflict_mode(
            os.environ.get("TG_SESSION_PATH_CONFLICT_MODE", "warn")
        )
        self._session_conflict_registry_file = _session_conflict_registry_file()
        self._last_session_conflict_message: str | None = None
        self._session_conflict: dict[str, Any] | None = None
        self._session_claim_id: str | None = None
        self._registered_session_path: str | None = None

        self._set_current_session_path(os.environ.get("TG_SESSION_PATH", ""))
        self._enforce_session_path_policy()

    @property
    def current_session(self) -> str | None:
        return self._current_session

    @property
    def client(self) -> Any:
        return self._client

    def _set_current_session_path(self, session_path: str) -> None:
        resolved = _resolve_session_path(session_path)
        self._current_session_path = resolved
        self._current_effective_session_path = resolved
        self._session_runtime_mode = "direct"
        if not resolved:
            return

        target = describe_session_target(resolved)
        self._current_session_path = target["source_session_file"]
        self._current_effective_session_path = target["effective_session_file"]
        self._session_runtime_mode = target["mode"]

    def _ensure_session_claim(self) -> None:
        session_path = self._current_effective_session_path or self._current_session_path
        if self._session_conflict_mode == "off" or not session_path:
            return
        if self._registered_session_path == session_path and self._session_claim_id:
            return
        self._session_claim_id = _register_session_claim(
            self._session_conflict_registry_file,
            server_profile=self.server_profile,
            session_path=session_path,
        )
        self._registered_session_path = session_path

    def _enforce_session_path_policy(self) -> dict[str, Any] | None:
        session_path = self._current_session_path
        effective_session_path = self._current_effective_session_path or session_path
        issue = _detect_declared_session_conflict(self.server_profile, session_path)
        if issue is None and effective_session_path and self._session_conflict_mode != "off":
            self._ensure_session_claim()
            issue = _detect_live_session_conflict(
                self._session_conflict_registry_file,
                server_profile=self.server_profile,
                session_path=effective_session_path,
                own_claim_id=self._session_claim_id or "",
            )

        self._session_conflict = issue
        if not issue or self._session_conflict_mode == "off":
            return issue

        message = issue["message"]
        if self._session_conflict_mode == "fail":
            raise RuntimeError(message)
        if message != self._last_session_conflict_message:
            print(f"[tg-mcp][session-warning] {message}", file=sys.stderr)
            self._last_session_conflict_message = message
        return issue

    def session_path_status(self) -> dict[str, Any]:
        issue = self._enforce_session_path_policy()
        read_path, actions_path = _declared_session_paths(self.server_profile, self._current_session_path)
        return {
            "server_profile": self.server_profile,
            "mode": self._session_conflict_mode,
            "session_path": self._current_session_path or None,
            "effective_session_path": self._current_effective_session_path or None,
            "session_runtime_mode": self._session_runtime_mode,
            "declared_read_session_path": read_path or None,
            "declared_actions_session_path": actions_path or None,
            "conflict": issue,
        }

    async def _connect_client(self, client, session_name: str) -> GroupManager:
        self._enforce_session_path_policy()
        await client.connect()
        if not await client.is_user_authorized():
            await client.disconnect()
            raise RuntimeError(
                f"Session '{session_name}' is not authorized. "
                "Run create_telegram_session.py (or scripts/create_session_qr.py) to re-authenticate. "
                "Telegram login code usually arrives in-app (SentCodeTypeApp), not SMS."
            )

        me = await client.get_me()
        mismatch_error = _validate_expected_account(me)
        if mismatch_error:
            await client.disconnect()
            raise RuntimeError(mismatch_error)

        self._client = client
        self._current_session = session_name
        self._manager = GroupManager(client)
        return self._manager

    async def get_manager(self) -> GroupManager:
        """Lazy-init manager and connect on the first call."""
        if self._manager is None:
            session_path = os.environ.get("TG_SESSION_PATH", "").strip()
            if session_path:
                self._set_current_session_path(session_path)
                session_name = os.path.basename(session_path).replace(".session", "")
                client = get_client_for_session(session_path)
            else:
                session_name = os.environ.get("SESSION_NAME", "default")
                client = get_client()

            await self._connect_client(client, session_name)

        return self._manager

    async def list_sessions(self) -> dict[str, Any]:
        sessions = [
            os.path.basename(path).replace(".session", "")
            for path in glob.glob(os.path.join(self.sessions_dir, "*.session"))
        ]
        return {"sessions": sorted(sessions), "current": self._current_session}

    async def use_session(self, session_name: str) -> dict[str, Any]:
        if not self.allow_session_switch:
            return {
                "error": "Session switching is disabled. "
                "Set TG_ALLOW_SESSION_SWITCH=1 to enable tg_use_session."
            }

        path = os.path.join(self.sessions_dir, f"{session_name}.session")
        if not os.path.exists(path):
            return {"error": f"Session '{session_name}' not found"}

        if self._client is not None:
            await self._client.disconnect()

        try:
            self._set_current_session_path(path)
            self._enforce_session_path_policy()
            client = get_client_for_session(path)
            await self._connect_client(client, session_name)
            me = await self._client.get_me()
            return {"switched_to": session_name, "account": me.username or me.first_name}
        except RuntimeError as exc:
            return {"error": str(exc)}
        except Exception as exc:
            return {"error": f"Failed to switch session: {exc}"}

    async def auth_status(self) -> dict[str, Any]:
        """Return authorization status for current/default Telegram session."""
        session_path = os.environ.get("TG_SESSION_PATH", "").strip()
        if session_path:
            resolved_path = str(Path(session_path).expanduser().resolve())
            self._set_current_session_path(resolved_path)
            self._enforce_session_path_policy()
            session_name = Path(session_path).name.replace(".session", "")
            client = self._client or get_client_for_session(session_path)
            is_transient = self._client is None
        else:
            resolved_path = ""
            session_name = os.environ.get("SESSION_NAME", "default")
            client = self._client or get_client()
            is_transient = self._client is None

        try:
            await client.connect()
            authorized = await client.is_user_authorized()
            payload: dict[str, Any] = {
                "authorized": bool(authorized),
                "session_name": session_name,
                "session_path": resolved_path or None,
                "session_path_status": self.session_path_status(),
            }
            if authorized:
                me = await client.get_me()
                payload["account"] = {
                    "id": getattr(me, "id", None),
                    "username": getattr(me, "username", None),
                    "first_name": getattr(me, "first_name", None),
                }
                mismatch_error = _validate_expected_account(me)
                if mismatch_error:
                    payload["authorized"] = False
                    payload["error"] = mismatch_error
            return payload
        except Exception as exc:
            return {
                "authorized": False,
                "session_name": session_name,
                "session_path": resolved_path or None,
                "session_path_status": self.session_path_status(),
                "error": str(exc),
            }
        finally:
            if is_transient:
                try:
                    await client.disconnect()
                except Exception:
                    pass
