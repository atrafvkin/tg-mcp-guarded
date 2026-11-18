from unittest.mock import AsyncMock

import pytest
from telethon.tl.functions.channels import LeaveChannelRequest
from tganalytics.domain.groups import GroupManager


@pytest.mark.asyncio
async def test_self_leave_channel_uses_leave_not_ban(mock_telegram_client, mock_channel, mock_user):
    mock_user.is_self = True
    manager = GroupManager(mock_telegram_client)
    manager._resolve_group_entity_for_admin = AsyncMock(return_value=mock_channel)
    manager._resolve_user_entity_for_admin = AsyncMock(return_value=mock_user)
    result = await manager.remove_member_from_group(str(mock_channel.id), str(mock_user.id))
    assert result['success']
    mock_telegram_client.assert_awaited_once()
    assert isinstance(mock_telegram_client.call_args.args[0], LeaveChannelRequest)


@pytest.mark.asyncio
async def test_self_leave_preview_does_not_leave(mock_telegram_client, mock_channel, mock_user):
    mock_user.is_self = True
    manager = GroupManager(mock_telegram_client)
    manager._resolve_group_entity_for_admin = AsyncMock(return_value=mock_channel)
    manager._resolve_user_entity_for_admin = AsyncMock(return_value=mock_user)
    result = await manager.remove_member_from_group(str(mock_channel.id), str(mock_user.id), dry_run=True)
    assert result['success']
    mock_telegram_client.assert_not_awaited()
