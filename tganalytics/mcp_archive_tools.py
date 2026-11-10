"""Archive a reviewed folder's members without changing its membership."""

from copy import deepcopy
from typing import Any

from telethon import utils
from telethon.tl.functions.folders import EditPeerFoldersRequest
from telethon.tl.functions.messages import UpdateDialogFilterRequest
from telethon.tl.types import DialogFilter, InputFolderPeer

from mcp_actions_policy import hash_payload
from mcp_folder_tools import describe_folder, fetch_folders, state_hash
from tganalytics.infra.limiter import safe_call


def contains(folder: Any, dialog: Any, account_id: int) -> bool:
    """Match ordinary filters; read/mute filters must be rejected by callers."""
    if dialog.id in {utils.get_peer_id(p) for p in folder.exclude_peers}:
        return False
    if dialog.id in {utils.get_peer_id(p) for p in folder.include_peers + folder.pinned_peers}:
        return True
    if folder.exclude_archived and dialog.archived:
        return False
    if dialog.is_user:
        if getattr(dialog.entity, "bot", False):
            return bool(folder.bots)
        contact = dialog.id == account_id or getattr(dialog.entity, "contact", False)
        return bool(folder.contacts if contact else folder.non_contacts)
    return bool(folder.groups if dialog.is_group else folder.broadcasts)


def archive_plan(folder: Any, dialogs: list, account_id: int) -> tuple:
    if not isinstance(folder, DialogFilter) or folder.exclude_read or folder.exclude_muted:
        raise ValueError("Only personal folders without read/mute filters are supported")
    selected = {d.id for d in dialogs if contains(folder, d, account_id)}
    desired = deepcopy(folder)
    desired.exclude_archived = False
    # Existing archived chats must not become newly visible when archive
    # exclusion is removed. Explicitly exclude only those extra matches.
    extras = [d for d in dialogs if d.id not in selected and contains(desired, d, account_id)]
    desired.exclude_peers += [d.input_entity for d in extras]
    if len(desired.exclude_peers) > 200:
        raise ValueError("Preserving membership would exceed 200 excluded chats")
    if {d.id for d in dialogs if contains(desired, d, account_id)} != selected:
        raise ValueError("Could not preserve exact folder membership")
    return desired, selected, [d for d in dialogs if d.id in selected and not d.archived]


async def inventory(client: Any) -> list:
    dialogs = await safe_call(client.get_dialogs, limit=5001, operation_type="api")
    if len(dialogs) > 5000:
        raise ValueError("More than 5000 dialogs; refusing a partial inventory")
    return list(dialogs)


class ArchiveTools:
    def __init__(self, ctx: Any, policy: dict):
        self.ctx, self.policy = ctx, policy

    async def tg_archive_folder_chats(
        self,
        account_id: int,
        folder_id: int,
        expected_state_hash: str,
        expected_chat_ids: list[int],
        dry_run: bool = True,
        confirm: bool = False,
        confirmation_text: str = "",
        approval_code: str = "",
    ) -> dict:
        """Archive the exact reviewed folder membership and keep it visible in that folder.

        Changes only this account's archive placement and the selected folder's
        archive/exclusion rules. Other folders and chats retain their state.
        No chats/messages are deleted; no notifications or memberships change.
        Requires the usual owner allowlist, confirmation and one-time approval.
        The preview binds both the folder revision and all chat archive states.
        Batch failures return completed IDs for safe inspection and resumption.
        """
        p = self.policy
        ok, error = p["_check_action_preconditions"](
            str(account_id), dry_run, confirm, confirmation_text
        )
        if not ok:
            return p["_blocked"](error)
        if not expected_chat_ids or len(expected_chat_ids) > 5000:
            return p["_blocked"]("Provide 1..5000 exact expected_chat_ids")
        await self.ctx.get_manager()
        client = self.ctx.client
        me = await safe_call(client.get_me, operation_type="api")
        if me.id != account_id:
            return p["_blocked"]("Authenticated account does not match account_id")
        before = await fetch_folders(client)
        if state_hash(before) != expected_state_hash:
            return p["_blocked"]("Folder state changed; read folders and preview again")
        folder = next((f for f in before if getattr(f, "id", 0) == folder_id), None)
        dialogs = await inventory(client)
        try:
            desired, selected, pending = archive_plan(folder, dialogs, account_id)
        except ValueError as exc:
            return p["_blocked"](str(exc))
        if selected != set(expected_chat_ids):
            return p["_blocked"](
                "Folder membership changed; inspect and preview again",
                actual_count=len(selected),
            )
        # Telegram cannot archive Saved Messages or its service-notification
        # dialog (also enforced by TDLib MessagesManager::add_dialog_to_list).
        unarchivable = sorted(selected & {account_id, 777000})
        pending = [d for d in pending if d.id not in unarchivable]
        archive_states = {str(d.id): bool(d.archived) for d in dialogs}
        action_hash = hash_payload({
            "action": "archive_folder_chats", "account_id": account_id,
            "state_hash": expected_state_hash, "archive_states": archive_states,
            "folder": describe_folder(desired), "chat_ids": sorted(selected),
        })
        approved, error, approval = p["_approval_gate"](
            action_hash=action_hash, dry_run=dry_run, approval_code=approval_code
        )
        if not approved:
            return p["_blocked"](error)
        if dry_run:
            return {
                "success": True, "dry_run": True, "account_id": account_id,
                "folder_before": describe_folder(folder),
                "folder_after": describe_folder(desired),
                "folder_members": len(selected), "to_archive": len(pending),
                "unarchivable_chat_ids": unarchivable,
                "chat_ids": sorted(selected), "action_hash": action_hash,
                "confirmation_text_required": p["CONFIRMATION_PHRASE"],
                **(approval or {}),
            }
        duplicate, retry_after = p["_check_recent_duplicate"](action_hash)
        if duplicate:
            return p["_blocked"]("Duplicate action blocked", retry_after_sec=retry_after)
        if state_hash(await fetch_folders(client)) != expected_state_hash:
            return p["_blocked"]("Folder state changed immediately before write")

        completed = []
        try:
            if describe_folder(desired) != describe_folder(folder):
                await safe_call(
                    client, UpdateDialogFilterRequest(id=folder_id, filter=desired),
                    operation_type="api",
                )
            prepared = await fetch_folders(client)
            saved = next((f for f in prepared if getattr(f, "id", 0) == folder_id), None)
            if saved is None or describe_folder(saved) != describe_folder(desired):
                return p["_blocked"]("Folder preparation failed; no chats archived")
            if [f.to_dict() for f in prepared if getattr(f, "id", 0) != folder_id] != [
                f.to_dict() for f in before if getattr(f, "id", 0) != folder_id
            ]:
                return p["_blocked"]("Other folders changed; no chats archived")
            for offset in range(0, len(pending), 100):
                batch = pending[offset:offset + 100]
                await safe_call(
                    client,
                    EditPeerFoldersRequest(folder_peers=[
                        InputFolderPeer(peer=d.input_entity, folder_id=1) for d in batch
                    ]),
                    operation_type="api",
                )
                completed.extend(d.id for d in batch)
        except Exception as exc:
            return p["_blocked"](
                f"Archive operation interrupted: {type(exc).__name__}: {exc}",
                completed_chat_ids=completed,
                next_step="Read actual archive state before preparing a retry",
            )

        after = await fetch_folders(client)
        current = await inventory(client)
        saved = next((f for f in after if getattr(f, "id", 0) == folder_id), None)
        current_by_id = {d.id: d for d in current}
        not_archived = sorted(
            cid for cid in selected - set(unarchivable)
            if cid not in current_by_id or not current_by_id[cid].archived
        )
        outside_changed = sorted(
            int(cid) for cid, archived in archive_states.items()
            if int(cid) not in selected and (
                int(cid) not in current_by_id or current_by_id[int(cid)].archived != archived
            )
        )
        preserved = (
            saved is not None and describe_folder(saved) == describe_folder(desired)
            and {d.id for d in current if contains(saved, d, account_id)} == selected
            and [f.to_dict() for f in after if getattr(f, "id", 0) != folder_id]
            == [f.to_dict() for f in before if getattr(f, "id", 0) != folder_id]
        )
        if not_archived or outside_changed or not preserved:
            return p["_blocked"](
                "Archive verification failed; inspect before retrying",
                not_archived_chat_ids=not_archived,
                outside_changed_chat_ids=outside_changed,
                folder_membership_preserved=preserved,
            )
        p["_mark_action_executed"](action_hash)
        return {
            "success": not unarchivable, "server_verified": True, "account_id": account_id,
            "folder": describe_folder(saved), "archived_now": len(pending),
            "folder_members": len(selected), "remaining_in_all_chats": len(unarchivable),
            "unarchivable_chat_ids": unarchivable,
            "error": "Telegram cannot archive Saved Messages or service notifications" if unarchivable else None,
            "other_chats_unchanged": True, "state_hash": state_hash(after),
        }
