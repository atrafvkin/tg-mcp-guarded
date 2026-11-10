from copy import deepcopy
from types import SimpleNamespace

import pytest
from telethon import utils
from telethon.tl.functions.folders import EditPeerFoldersRequest
from telethon.tl.functions.messages import GetDialogFiltersRequest, UpdateDialogFilterRequest
from telethon.tl.types import DialogFilter, InputPeerUser, TextWithEntities

import mcp_archive_tools as archive
import mcp_folder_tools as folders
import mcp_server_actions as actions


def dialog(cid, archived=False):
    return SimpleNamespace(
        id=cid, archived=archived, is_user=True, is_group=False, is_channel=False,
        entity=SimpleNamespace(bot=False, contact=False), input_entity=InputPeerUser(cid, 1),
    )


class Client:
    def __init__(self):
        self.dialogs = [dialog(i) for i in range(1000, 1205)] + [dialog(7), dialog(8, True)]
        self.filters = [
            DialogFilter(2, TextWithEntities("kept", []), [], [InputPeerUser(7, 1)], []),
            DialogFilter(3, TextWithEntities("work", []), [], [], [InputPeerUser(7, 1)],
                         non_contacts=True, exclude_archived=True),
        ]
        self.batches = []
        self.drop_folder_write = False
        self.fail_batch = 0
        self.all_requests = []

    async def get_me(self):
        return SimpleNamespace(id=1)

    async def get_dialogs(self, limit):
        return deepcopy(self.dialogs)

    async def __call__(self, request):
        self.all_requests.append(request)
        if isinstance(request, GetDialogFiltersRequest):
            return SimpleNamespace(filters=deepcopy(self.filters))
        if isinstance(request, UpdateDialogFilterRequest):
            if not self.drop_folder_write:
                self.filters = [f for f in self.filters if f.id != request.id] + [deepcopy(request.filter)]
            return True
        assert isinstance(request, EditPeerFoldersRequest)
        if self.fail_batch == len(self.batches) + 1:
            raise RuntimeError("simulated archive failure")
        ids = {utils.get_peer_id(p.peer) for p in request.folder_peers}
        assert all(p.folder_id == 1 for p in request.folder_peers)
        self.batches.append(ids)
        for d in self.dialogs:
            if d.id in ids:
                d.archived = True
        return SimpleNamespace()


@pytest.fixture
def setup(monkeypatch, tmp_path):
    async def direct(func, *args, operation_type="api", **kwargs):
        return await func(*args, **kwargs)

    monkeypatch.setattr(archive, "safe_call", direct)
    monkeypatch.setattr(folders, "safe_call", direct)
    for key, value in {
        "SAFE_STARTUP_BLOCK_REASON": None, "ACTIONS_ENABLED": True,
        "REQUIRE_ALLOWLIST": True, "ALLOWED_TARGETS": {"1"},
        "REQUIRE_CONFIRMATION_TEXT": True, "CONFIRMATION_PHRASE": "ok",
        "MIN_CONFIRMATION_TEXT_LEN": 1, "REQUIRE_APPROVAL_CODE": True,
        "APPROVAL_MIN_AGE_SEC": 0, "IDEMPOTENCY_ENABLED": True,
        "APPROVAL_FILE": tmp_path / "approvals.json",
        "IDEMPOTENCY_FILE": tmp_path / "idempotency.json",
    }.items():
        monkeypatch.setattr(actions, key, value)
    client = Client()

    async def get_manager():
        return None

    handler = archive.ArchiveTools(SimpleNamespace(client=client, get_manager=get_manager), vars(actions))
    payload = dict(account_id=1, folder_id=3, expected_state_hash=folders.state_hash(client.filters),
                   expected_chat_ids=list(range(1000, 1205)))
    return handler, client, payload


async def execute(handler, payload, preview):
    return await handler.tg_archive_folder_chats(
        **payload, dry_run=False, confirm=True, confirmation_text="ok",
        approval_code=preview["approval_code"],
    )


@pytest.mark.asyncio
async def test_archive_preserves_folder_and_outside_chats_in_batches(setup):
    handler, client, payload = setup
    kept = client.filters[0].to_dict()
    preview = await handler.tg_archive_folder_chats(**payload)
    assert preview["to_archive"] == 205
    assert preview["folder_after"]["exclude_peers"] == [7, 8]
    assert not preview["folder_after"]["exclude_archived"]
    assert not client.batches and not any(d.archived for d in client.dialogs[:-2])
    result = await execute(handler, payload, preview)
    assert result["success"] and result["server_verified"]
    assert result["archived_now"] == 205 and result["folder_members"] == 205
    assert [len(b) for b in client.batches] == [100, 100, 5]
    assert client.filters[0].to_dict() == kept
    assert not client.dialogs[-2].archived and client.dialogs[-1].archived


@pytest.mark.asyncio
async def test_archive_needs_exact_approval(setup):
    handler, client, payload = setup
    result = await handler.tg_archive_folder_chats(**payload, dry_run=False)
    assert not result["success"] and client.all_requests == []


@pytest.mark.asyncio
async def test_failed_folder_preparation_does_not_archive(setup):
    handler, client, payload = setup
    client.drop_folder_write = True
    preview = await handler.tg_archive_folder_chats(**payload)
    result = await execute(handler, payload, preview)
    assert not result["success"] and client.batches == []


@pytest.mark.asyncio
async def test_membership_drift_blocks_before_preview(setup):
    handler, client, payload = setup
    client.dialogs.append(dialog(999))
    result = await handler.tg_archive_folder_chats(**payload)
    assert not result["success"] and "membership changed" in result["error"]
    assert client.batches == []


@pytest.mark.asyncio
async def test_archive_state_drift_invalidates_approval(setup):
    handler, client, payload = setup
    preview = await handler.tg_archive_folder_chats(**payload)
    client.dialogs[-2].archived = True
    result = await execute(handler, payload, preview)
    assert not result["success"] and "match this payload" in result["error"]
    assert client.batches == []


@pytest.mark.asyncio
async def test_partial_failure_reports_completed_ids(setup):
    handler, client, payload = setup
    client.fail_batch = 2
    preview = await handler.tg_archive_folder_chats(**payload)
    result = await execute(handler, payload, preview)
    assert not result["success"]
    assert len(result["completed_chat_ids"]) == 100
    assert len(client.batches) == 1
    assert actions._load_idempotency_state() == {}


def test_explicit_membership_survives_archive_but_prior_archive_stays_out():
    source = DialogFilter(3, TextWithEntities("work", []), [], [InputPeerUser(7, 1)], [],
                          contacts=True, exclude_archived=True)
    original = [dialog(7, True), dialog(8, True)]
    original[1].entity.contact = True
    desired, ids, pending = archive.archive_plan(source, original, 1)
    assert ids == {7} and pending == []
    assert [utils.get_peer_id(p) for p in desired.exclude_peers] == [8]


@pytest.mark.asyncio
async def test_reports_unarchivable_system_chats_without_attempting_them(setup):
    handler, client, payload = setup
    client.filters[1].contacts = True
    client.dialogs += [dialog(1), dialog(777000)]
    payload["expected_chat_ids"] += [1, 777000]
    payload["expected_state_hash"] = folders.state_hash(client.filters)
    preview = await handler.tg_archive_folder_chats(**payload)
    assert preview["to_archive"] == 205
    assert preview["unarchivable_chat_ids"] == [1, 777000]
    result = await execute(handler, payload, preview)
    assert not result["success"] and result["server_verified"]
    assert result["remaining_in_all_chats"] == 2
    assert result["unarchivable_chat_ids"] == [1, 777000]
    assert not {1, 777000} & set.union(*client.batches)
