# Chat folders over MCP

`tg_get_chat_folders` is available in the read and actions servers. It reads the
server's folder configuration, account identity and a revision hash. Set
`include_dialogs=true` to also retrieve chat IDs, names and archive status. No
message bodies are returned. Inventories above 5000 chats fail instead of being
silently truncated.

`tg_put_chat_folder` is available only in the actions server. It creates or
replaces one personal folder. It cannot delete chats, leave groups, replace a
shared folder or alter any other folder. Replacing a folder replaces its rules
and clears its pinned peers and presentation options; inspect the preview first.

## Examples

1. Inspect the authoritative folder list:
   `tg_get_chat_folders(include_dialogs=false)`.
2. Discover exact chat IDs and archive state:
   `tg_get_chat_folders(include_dialogs=true)`.
3. Preview a new folder with all five `include_types` (`contacts`, `non_contacts`,
   `groups`, `broadcasts`, `bots`), `exclude_archived=true`, and explicit
   `exclude_peer_ids`. Pass the owner `account_id`, an unused `folder_id` (2..255),
   a title up to 12 characters, `include_peer_ids=[]`, and the read's
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
