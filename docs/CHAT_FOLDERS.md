# Chat folders over MCP

`tg_get_chat_folders` is available in the read and actions servers. It reads the
server's folder configuration, account identity and a revision hash. Set
`include_dialogs=true` to also retrieve chat IDs, names and archive status. No
message bodies are returned. Inventories above 5000 chats fail instead of being
silently truncated.

`tg_put_chat_folder` is available only in the actions server. It creates or
replaces one personal folder. It cannot delete chats, leave groups, replace a
shared folder or alter any other folder. Replacing a folder replaces its rules
and clears its pinned peers while preserving presentation options; inspect the preview first.

## Examples

1. Inspect the authoritative folder list:
   `tg_get_chat_folders(include_dialogs=false)`.
2. Discover exact chat IDs and archive state:
   `tg_get_chat_folders(include_dialogs=true)`.
3. Preview a new folder with `include_types` such as `contacts`, `non_contacts`,
   `groups`, `bots`, `exclude_archived=true`, and explicit `exclude_peer_ids`.
   Telegram rejects all five types together with archive exclusion, even with
   excluded peers. To capture all current eligible chats, omit one type and put
   its current eligible IDs into `include_peer_ids`. New chats of that omitted
   type will require explicit addition; explicit peers override archive rules.
   Pass the owner `account_id`, an unused `folder_id` (2..255),
   a title up to 12 characters, the desired `include_peer_ids`, and the read's
   `expected_state_hash` to `tg_put_chat_folder(dry_run=true, ...)`.
4. After the human supplies the configured exact confirmation phrase, repeat
   that same payload with `dry_run=false`, `confirm=true`, `confirmation_text`
   and the preview's one-time `approval_code`. Respect its minimum age and expiry.
5. Verify independently with `tg_get_chat_folders` on the read server.

The owner account ID must already be in `TG_ACTIONS_ALLOWED_GROUPS`. Existing
confirmation, approval, allowlist, idempotency, write-process and rate-limit
guards remain active. A changed server revision invalidates the preview. The
action returns success only after re-reading the saved folder and confirming
that all other folders remained unchanged.

Restart MCP clients to discover the new tools. For an immediate stdio call
without restarting a running client, use the installed environment:

```sh
venv/bin/python scripts/call_local_mcp.py --tool tg_get_chat_folders
```

The CLI accepts `--config` (MCP JSON or Codex TOML), `--server`, `--arguments`
(JSON file) and `--output`. It calls MCP tools over the protocol, never Telegram
directly. Runtime session copies avoid sharing a live SQLite session file;
all policy settings are inherited. Output files are private and should live
under the ignored `data/` directory.

Protocol reference: https://core.telegram.org/api/folders

Validation: `venv/bin/python -m pytest tests/test_mcp_folder_tools.py -q`.

## Archive a folder's current members

`tg_archive_folder_chats` is an actions-only workflow. Supply `account_id`,
`folder_id`, `expected_state_hash` and the complete `expected_chat_ids` from a
fresh inventory. The dry run binds the exact chat set, folder settings and
archive placement. Execute with the existing confirmation and approval gates.

It first removes the folder's archive exclusion and explicitly excludes any
previously archived chats that would otherwise become newly visible. It preserves
the title, category rules, pinned/included peers, presentation and other folders.
After verifying this preparation, it archives the selected chats in batches of
100 using `folders.editPeerFolders`, then re-reads both archive placement and
folder membership. It reports success only when the original chat set remains
visible in the folder, all its chats are archived, and other chats are unchanged.

The workflow rejects read/mute filters, inventories above 5000 dialogs, and plans
requiring more than 200 excluded chats. It does not mute notifications or change
automatic unarchiving settings. A partial failure reports completed IDs; inspect
the current server state before preparing a retry. No history is deleted and no
group is left. Archive state remains reversible through Telegram.

Telegram does not permit archiving Saved Messages or service notifications
(user 777000). These IDs are reported in `unarchivable_chat_ids` in the preview
and result and never sent in an archive batch. When present, execution returns
`success=false` with `server_verified=true` after archiving all eligible chats;
`remaining_in_all_chats` makes this unavoidable partial outcome explicit.

Validation: `venv/bin/python -m pytest tests/test_mcp_archive_tools.py -q`.
