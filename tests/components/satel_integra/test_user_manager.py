"""Offline tests for guarded SATEL user-management workflows."""

import pytest

from homeassistant.components.satel_integra.user_protocol import (
    SatelUserManager,
    UserAccessDenied,
    UserCommand,
    UserProfile,
    UserProtocolError,
)


def make_self() -> bytes:
    """E0 body for master 241 with GUARDX and user-edit permissions."""
    return (
        bytes([241])
        + b"\x00\x00"
        + b"\x03\x00\x00\x00"
        + b"\x00\x00"
        + bytes([0x80, 0, 0x04])
        + b"Master          "
        + b"\x40"
    )


def make_roster() -> bytes:
    """Existing and editable user 3, requester master 241."""
    return bytes([241]) + b"\x04" + bytes(29) + b"\x04" + bytes(29)


def make_user() -> bytes:
    return (
        bytes([3]) + b"\x01\x00\x00\x00"
        + b"\x00\x00\x00"
        + bytes([0x00, 0x00, 0x00])
        + b"Guest           "
        + b"\x00"
    )


@pytest.mark.asyncio
async def test_read_authorized_user() -> None:
    requests = []

    async def transport(req):
        requests.append(req.command)
        if req.command == UserCommand.SELF:
            return UserCommand.SELF, make_self()
        if req.command == UserCommand.LIST:
            return UserCommand.LIST, make_roster()
        if req.command == UserCommand.READ:
            return UserCommand.READ, make_user()
        pytest.fail("Unexpected write request")

    manager = SatelUserManager(transport)
    user = await manager.user("1234", 3)
    assert user.number == 3
    assert user.profile.name == "Guest"
    assert requests == [UserCommand.SELF, UserCommand.LIST, UserCommand.READ]


@pytest.mark.asyncio
async def test_write_rejected_when_scope_exceeds_operator() -> None:
    writes = []

    async def transport(req):
        if req.command in (UserCommand.UPDATE, UserCommand.CREATE, UserCommand.DELETE):
            writes.append(req)
            pytest.fail("Unprivileged write reached transport")
        if req.command == UserCommand.SELF:
            return UserCommand.SELF, make_self()
        if req.command == UserCommand.LIST:
            return UserCommand.LIST, make_roster()
        return UserCommand.READ, make_user()

    manager = SatelUserManager(transport)
    # Operator's partition scope is {1, 2}; partition 3 is forbidden.
    profile = UserProfile(
        name="Guest", partitions=frozenset({3}), rights=b"\x00\x00\x00"
    )
    with pytest.raises(UserAccessDenied):
        await manager.change_user("1234", 3, profile)
    assert writes == []


@pytest.mark.asyncio
async def test_no_write_to_master_or_service_account() -> None:
    async def transport(req):
        pytest.fail("Master/service write should be blocked before transport")

    manager = SatelUserManager(transport)
    with pytest.raises(ValueError):
        await manager.change_user("1234", 241, UserProfile(
            name="New Master", partitions=frozenset(), rights=b"\x00\x00\x00"
        ))
    with pytest.raises(ValueError):
        await manager.remove_user("1234", 255)


@pytest.mark.asyncio
async def test_write_requires_correct_ack_and_readback() -> None:
    writes = []

    async def transport(req):
        if req.command == UserCommand.SELF:
            return UserCommand.SELF, make_self()
        if req.command == UserCommand.LIST:
            return UserCommand.LIST, make_roster()
        if req.command == UserCommand.READ:
            return UserCommand.READ, make_user()
        if req.command == UserCommand.UPDATE:
            writes.append(req.command)
            return UserCommand.RESULT, b"?7\x03\x00"
        pytest.fail("Unexpected command")

    manager = SatelUserManager(transport)
    changed = UserProfile(
        name="Changed Guest", partitions=frozenset({1}), rights=b"\x00\x00\x00"
    )
    with pytest.raises(UserProtocolError, match="not verified"):
        await manager.change_user("1234", 3, changed)
    assert writes == [UserCommand.UPDATE]


@pytest.mark.asyncio
async def test_master_only_creation_does_not_overwrite_existing_user() -> None:
    writes = []

    async def transport(req):
        if req.command == UserCommand.SELF:
            return UserCommand.SELF, make_self()
        if req.command == UserCommand.LIST:
            return UserCommand.LIST, make_roster()
        writes.append(req.command)
        pytest.fail("Existing user must not be overwritten")

    manager = SatelUserManager(transport)
    profile = UserProfile(
        name="Guest", partitions=frozenset({1}), rights=b"\x00\x00\x00"
    )
    with pytest.raises(UserAccessDenied, match="already occupied"):
        await manager.add_user("1234", 3, "5678", profile)
    assert writes == []
