"""Account-scoped chat folders, using the existing Action MCP policy gates."""

from __future__ import annotations

from typing import Any

from telethon import utils
from telethon.tl.functions.messages import GetDialogFiltersRequest, UpdateDialogFilterRequest
from telethon.tl.types import DialogFilter, TextWithEntities

from mcp_actions_policy import hash_payload
from tganalytics.infra.limiter import safe_call

FLAGS = (
    "contacts", "non_contacts", "groups", "broadcasts", "bots",
    "exclude_muted", "exclude_read", "exclude_archived",
)
PEERS = ("pinned_peers", "include_peers", "exclude_peers")


def describe_folder(folder: Any) -> dict:
    title = getattr(folder, "title", "")
    return {
        "id": getattr(folder, "id", 0),
        "type": type(folder).__name__,
        "title": getattr(title, "text", title),
        **{flag: bool(getattr(folder, flag, False)) for flag in FLAGS},
        **{
            key: (
                [utils.get_peer_id(peer) for peer in getattr(folder, key, [])]
                if key == "pinned_peers"
                else sorted(utils.get_peer_id(peer) for peer in getattr(folder, key, []))
            )
            for key in PEERS
        },
    }


def state_hash(folders: list) -> str:
    return hash_payload({"folders": [folder.to_dict() for folder in folders]})


async def fetch_folders(client: Any) -> list:
    result = await safe_call(client, GetDialogFiltersRequest(), operation_type="api")
    return list(getattr(result, "filters", result))


class FolderTools:
    def __init__(self, ctx: Any, policy: dict | None = None):
        self.ctx = ctx
        self.policy = policy

    async def tg_get_chat_folders(self, include_dialogs: bool = False) -> dict:
        """Read server folders and a revision hash; optionally list chat IDs/names/archive state.

        No messages are read. Dialog listing fails explicitly above 5000 chats.
        """
        await self.ctx.get_manager()
        client = self.ctx.client
        me = await safe_call(client.get_me, operation_type="api")
        folders = await fetch_folders(client)
        result = {
            "account_id": me.id,
            "username": me.username,
            "is_premium": bool(getattr(me, "premium", False)),
            "state_hash": state_hash(folders),
            "folders": [describe_folder(folder) for folder in folders],
        }
        if include_dialogs:
            dialogs = await safe_call(client.get_dialogs, limit=5001, operation_type="api")
            if len(dialogs) > 5000:
                raise ValueError("More than 5000 dialogs; refusing to return a partial inventory")
            result["dialogs"] = [
                {
                    "id": dialog.id,
                    "title": dialog.name,
                    "archived": bool(dialog.archived),
                    "is_user": dialog.is_user,
                    "is_group": dialog.is_group,
                    "is_channel": dialog.is_channel,
                    "is_bot": bool(getattr(dialog.entity, "bot", False)),
                }
                for dialog in dialogs
            ]
        return result

    async def tg_put_chat_folder(
        self,
        account_id: int,
        folder_id: int,
        title: str,
        expected_state_hash: str,
        include_peer_ids: list[int],
        exclude_peer_ids: list[int],
        include_types: list[str],
        exclude_archived: bool = True,
        dry_run: bool = True,
        confirm: bool = False,
        confirmation_text: str = "",
        approval_code: str = "",
        force_resend: bool = False,
    ) -> dict:
        """Create or replace one personal folder, with preview, approval and server verification.

        Only the account owner's folder settings change; no chats are deleted or left.
        include_types accepts contacts, non_contacts, groups, broadcasts and bots.
        Obtain expected_state_hash from tg_get_chat_folders. The owner account ID
        must be allowlisted. Existing shared folders cannot be replaced.
        """
        policy = self.policy
        if policy is None:
            return {"success": False, "error": "Folder writes require Action MCP"}
        allowed, error = policy["_check_action_preconditions"](
            str(account_id), dry_run, confirm, confirmation_text
        )
        if not allowed:
            return policy["_blocked"](error)
        if not 2 <= folder_id <= 255 or not title.strip() or len(title) > 12:
            return policy["_blocked"]("Use folder_id 2..255 and a title of 1..12 characters")
        if not expected_state_hash or not set(include_types) <= set(FLAGS[:5]):
            return policy["_blocked"]("Invalid revision hash or include_types")
        if exclude_archived and set(include_types) == set(FLAGS[:5]):
            return policy["_blocked"](
                "Telegram rejects all five chat types with exclude_archived. "
                "Omit one type and include its current desired chats explicitly."
            )
        if len(include_peer_ids) > 200 or len(exclude_peer_ids) > 200:
            return policy["_blocked"]("At most 200 explicit include/exclude peers are supported")
        if set(include_peer_ids) & set(exclude_peer_ids):
            return policy["_blocked"]("Include and exclude peers must not overlap")
        if not include_peer_ids and not include_types:
            return policy["_blocked"]("A folder must include peers or chat types")

        await self.ctx.get_manager()
        client = self.ctx.client
        me = await safe_call(client.get_me, operation_type="api")
        if me.id != account_id:
            return policy["_blocked"]("Authenticated account does not match account_id")
        before = await fetch_folders(client)
        if state_hash(before) != expected_state_hash:
            return policy["_blocked"]("Folder state changed; read folders and preview again")
        existing = next((f for f in before if getattr(f, "id", 0) == folder_id), None)
        if existing is not None and not isinstance(existing, DialogFilter):
            return policy["_blocked"]("Cannot replace a shared or system folder")

        cache_refreshed = False

        async def resolve(ids: list[int]) -> list:
            nonlocal cache_refreshed
            peers = []
            for peer_id in sorted(set(ids)):
                try:
                    peer = await safe_call(
                        client.get_input_entity, peer_id, operation_type="api"
                    )
                except ValueError:
                    if cache_refreshed:
                        raise
                    await safe_call(client.get_dialogs, limit=5001, operation_type="api")
                    cache_refreshed = True
                    peer = await safe_call(
                        client.get_input_entity, peer_id, operation_type="api"
                    )
                peers.append(peer)
            return peers

        desired = DialogFilter(
            id=folder_id,
            title=TextWithEntities(text=title, entities=[]),
            pinned_peers=[],
            include_peers=await resolve(include_peer_ids),
            exclude_peers=await resolve(exclude_peer_ids),
            exclude_archived=exclude_archived,
            **{flag: flag in include_types for flag in FLAGS[:5]},
        )
        if existing is not None:
            for attr in ("emoticon", "color", "title_noanimate"):
                setattr(desired, attr, getattr(existing, attr, None))
        summary = describe_folder(desired)
        action_hash = hash_payload({
            "action": "put_chat_folder", "account_id": account_id,
            "expected_state_hash": expected_state_hash, "folder": summary,
        })
        approval_ok, approval_error, approval_meta = policy["_approval_gate"](
            action_hash=action_hash, dry_run=dry_run, approval_code=approval_code
        )
        if not approval_ok:
            return policy["_blocked"](approval_error)
        if dry_run:
            return {
                "success": True, "dry_run": True, "account_id": account_id,
                "before": describe_folder(existing) if existing else None,
                "folder": summary, "action_hash": action_hash,
                "confirmation_text_required": policy["CONFIRMATION_PHRASE"],
                **(approval_meta or {}),
            }
        if not force_resend:
            duplicate, retry_after = policy["_check_recent_duplicate"](action_hash)
            if duplicate:
                return policy["_blocked"](
                    "Duplicate action blocked", retry_after_sec=retry_after
                )

        # Check again immediately before the write, after resolving peer IDs.
        if state_hash(await fetch_folders(client)) != expected_state_hash:
            return policy["_blocked"]("Folder state changed; preview again")
        accepted = await safe_call(
            client, UpdateDialogFilterRequest(id=folder_id, filter=desired),
            operation_type="api",
        )
        after = await fetch_folders(client)
        saved = next((f for f in after if getattr(f, "id", 0) == folder_id), None)
        other_before = [f.to_dict() for f in before if getattr(f, "id", 0) != folder_id]
        other_after = [f.to_dict() for f in after if getattr(f, "id", 0) != folder_id]
        verified = bool(accepted) and saved is not None and describe_folder(saved) == summary
        if not verified or other_before != other_after:
            return policy["_blocked"](
                "Server verification failed; inspect folders before retrying",
                applied=bool(accepted), folders=[describe_folder(f) for f in after],
            )
        policy["_mark_action_executed"](action_hash)
        return {
            "success": True, "server_verified": True, "account_id": account_id,
            "folder": describe_folder(saved), "state_hash": state_hash(after),
        }


def register_folder_tools(mcp: Any, ctx: Any, policy: dict | None = None) -> None:
    handlers = FolderTools(ctx, policy)
    mcp.tool(annotations={"readOnlyHint": True})(handlers.tg_get_chat_folders)
    if policy is not None:
        mcp.tool(annotations={"destructiveHint": True, "idempotentHint": True})(
            handlers.tg_put_chat_folder
        )
        from mcp_archive_tools import ArchiveTools

        mcp.tool(annotations={"destructiveHint": True, "idempotentHint": True})(
            ArchiveTools(ctx, policy).tg_archive_folder_chats
        )
