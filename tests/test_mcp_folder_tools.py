from types import SimpleNamespace

import pytest
from telethon.tl.functions.messages import GetDialogFiltersRequest, UpdateDialogFilterRequest
from telethon.tl.types import DialogFilter, InputPeerUser, TextWithEntities

import mcp_folder_tools as folders
import mcp_server_actions as actions


class FakeClient:
    def __init__(self):
        self.filters = [DialogFilter(
            id=2, title=TextWithEntities("kept", []),
            pinned_peers=[], include_peers=[InputPeerUser(7, 1)], exclude_peers=[],
        )]
        self.writes = 0
        self.drop_write = False

    async def get_me(self):
        return SimpleNamespace(id=1, username="owner", premium=True)

    async def get_input_entity(self, peer_id):
        return InputPeerUser(peer_id, 1)

    async def __call__(self, request):
        if isinstance(request, GetDialogFiltersRequest):
            return SimpleNamespace(filters=list(self.filters))
        assert isinstance(request, UpdateDialogFilterRequest)
        self.writes += 1
        if not self.drop_write:
            self.filters = [f for f in self.filters if f.id != request.id] + [request.filter]
        return True


@pytest.fixture
def setup(monkeypatch, tmp_path):
    async def direct(func, *args, operation_type="api", **kwargs):
        return await func(*args, **kwargs)

    monkeypatch.setattr(folders, "safe_call", direct)
    settings = {
        "SAFE_STARTUP_BLOCK_REASON": None, "ACTIONS_ENABLED": True,
        "REQUIRE_ALLOWLIST": True, "ALLOWED_TARGETS": {"1"},
        "REQUIRE_CONFIRMATION_TEXT": True, "CONFIRMATION_PHRASE": "ok",
        "MIN_CONFIRMATION_TEXT_LEN": 1, "REQUIRE_APPROVAL_CODE": True,
        "APPROVAL_MIN_AGE_SEC": 0, "IDEMPOTENCY_ENABLED": True,
        "APPROVAL_FILE": tmp_path / "approvals.json",
        "IDEMPOTENCY_FILE": tmp_path / "idempotency.json",
    }
    for key, value in settings.items():
        monkeypatch.setattr(actions, key, value)
    client = FakeClient()

    async def get_manager():
        return None

    handler = folders.FolderTools(
        SimpleNamespace(client=client, get_manager=get_manager), vars(actions)
    )
    payload = {
        "account_id": 1, "folder_id": 3, "title": "work",
        "expected_state_hash": folders.state_hash(client.filters),
        "include_peer_ids": [], "exclude_peer_ids": [7, 8],
        "include_types": list(folders.FLAGS[:5]),
    }
    return handler, client, payload


@pytest.mark.asyncio
async def test_preview_requires_confirmation_then_verifies_server_and_preserves_other_folder(setup):
    handler, client, payload = setup
    kept = client.filters[0].to_dict()
    preview = await handler.tg_put_chat_folder(**payload)
    assert preview["success"] and client.writes == 0
    blocked = await handler.tg_put_chat_folder(**payload, dry_run=False)
    assert not blocked["success"] and client.writes == 0
    result = await handler.tg_put_chat_folder(
        **payload, dry_run=False, confirm=True, confirmation_text="ok",
        approval_code=preview["approval_code"],
    )
    assert result["success"] and result["server_verified"]
    assert result["folder"]["exclude_archived"]
    assert result["folder"]["exclude_peers"] == [7, 8]
    assert client.filters[0].to_dict() == kept
    assert client.writes == 1


@pytest.mark.asyncio
async def test_optimistic_api_success_without_saved_folder_is_failure(setup):
    handler, client, payload = setup
    client.drop_write = True
    preview = await handler.tg_put_chat_folder(**payload)
    result = await handler.tg_put_chat_folder(
        **payload, dry_run=False, confirm=True, confirmation_text="ok",
        approval_code=preview["approval_code"],
    )
    assert not result["success"]
    assert "verification failed" in result["error"]
    assert actions._load_idempotency_state() == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["revision", "owner", "overlap", "unknown_type"])
async def test_invalid_or_stale_targets_never_write(setup, change):
    handler, client, payload = setup
    if change == "revision":
        payload["expected_state_hash"] = "outdated"
    elif change == "owner":
        payload["account_id"] = 99
    elif change == "overlap":
        payload["include_peer_ids"] = [7]
    else:
        payload["include_types"] = ["unknown"]
    result = await handler.tg_put_chat_folder(**payload)
    assert not result["success"] and client.writes == 0


@pytest.mark.asyncio
async def test_approval_is_bound_to_exact_folder_payload(setup):
    handler, client, payload = setup
    preview = await handler.tg_put_chat_folder(**payload)
    payload["exclude_peer_ids"] = [7]
    result = await handler.tg_put_chat_folder(
        **payload, dry_run=False, confirm=True, confirmation_text="ok",
        approval_code=preview["approval_code"],
    )
    assert not result["success"] and "match this payload" in result["error"]
    assert client.writes == 0


@pytest.mark.asyncio
async def test_read_profile_registers_no_write_tool():
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("folder-test")
    folders.register_folder_tools(mcp, None)
    tools = await mcp.list_tools()
    assert [tool.name for tool in tools] == ["tg_get_chat_folders"]
