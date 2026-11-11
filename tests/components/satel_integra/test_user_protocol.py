"""Tests for SATEL integration user-protocol staging codecs.

No real panel is accessed. These tests should run with the existing
Home Assistant SATEL integration test environment.
"""

import pytest

from homeassistant.components.satel_integra.user_protocol import (
    PanelUser,
    UserAccessDenied,
    UserCommand,
    UserProfile,
    UserProtocolError,
    create_user,
    delete_user,
    parse_roster,
    parse_self,
    parse_user,
    parse_user_ack,
    read_roster,
    read_self,
    read_user,
    update_user,
)


@pytest.fixture
def profile() -> UserProfile:
    return UserProfile(
        name="Test User",
        partitions=frozenset({1, 4}),
        rights=bytes((0x80, 0x00, 0x04)),
        user_type=0,
        object_number=1,
    )


def test_operator_pin_is_encoded_and_redacted() -> None:
    req = read_self("1234")
    assert req.command is UserCommand.SELF
    assert req.payload == bytes.fromhex("1234FFFFFFFFFFFF")
    assert "1234" not in repr(req)
    assert "redacted" in repr(req)


@pytest.mark.parametrize("code", ["abcd", "123", "12345678901234567", "１２３４"])
def test_operator_pin_validation(code: str) -> None:
    with pytest.raises(ValueError):
        read_self(code)


def test_read_commands_include_scope_and_user_id() -> None:
    assert read_user("1234", 240).command == UserCommand.READ
    assert read_user("1234", 240).payload[-1] == 240
    assert read_roster("1234", 241).payload[-1] == 241


def test_delete_blocks_master_and_service_numbers() -> None:
    with pytest.raises(ValueError):
        delete_user("1234", 241)
    with pytest.raises(ValueError):
        delete_user("1234", 255)


def test_parse_user_data(profile: UserProfile) -> None:
    payload = (
        b"\x02" + b"\x09\x00\x00\x00" + b"\x00"
        + b"\x00\x00" + profile.rights
        + b"Test User       " + b"\x01"
    )
    assert len(payload) == 28
    user = parse_user(payload)
    assert isinstance(user, PanelUser)
    assert user.number == 2
    assert user.profile.name == "Test User"
    assert user.profile.partitions == frozenset({1, 4})
    assert user.can_manage_users
    assert user.can_use_guardx


def test_parse_self_hides_telephone_code() -> None:
    payload = (
        b"\x02" + b"\x12\x34" + b"\x09\x00\x00\x00"
        + b"\x00\x00" + bytes((0x80, 0x00, 0x04))
        + b"Test User       " + b"\x01"
    )
    assert len(payload) == 29
    user = parse_self(payload)
    assert user.number == 2
    assert "1234" not in repr(user)
    assert user.profile.name == "Test User"


def test_roster_decodes_bitmaps_and_editor_permissions() -> None:
    existing = bytes((0b00000101,)) + bytes(29)
    editable = bytes((0b00000100,)) + bytes(29)
    roster = parse_roster(bytes((241,)) + existing + editable)
    assert roster.requester == 241
    assert roster.existing == frozenset({1, 3})
    assert roster.editable == frozenset({3})


def test_roster_rejects_editable_user_that_does_not_exist() -> None:
    with pytest.raises(UserProtocolError):
        parse_roster(bytes((1,)) + bytes(30) + bytes((1,)) + bytes(29))


def test_create_user_payload(profile: UserProfile) -> None:
    req = create_user("1234", 5, "9876", profile)
    assert req.command == UserCommand.CREATE
    assert len(req.payload) == 8 + 1 + 4 + 2 + 4 + 1 + 1 + 1 + 3 + 16 + 1
    assert req.payload[8] == 5
    assert req.payload[9:13] == bytes.fromhex("9876FFFF")
    assert req.payload[13:15] == b"\xff\xff"
    assert "9876" not in repr(req)


def test_update_does_not_rotate_pin_implicitly(profile: UserProfile) -> None:
    req = update_user("1234", 3, profile)
    assert req.command == UserCommand.UPDATE
    assert req.payload[9:13] == b"\xff" * 4
    assert req.payload[13:15] == b"\xff" * 2
    assert len(req.payload) == 8 + 1 + 4 + 2 + 4 + 1 + 1 + 1 + 3 + 16


def test_special_account_creation_is_rejected(profile: UserProfile) -> None:
    profile = UserProfile(
        name=profile.name,
        partitions=profile.partitions,
        rights=profile.rights,
        master=True,
    )
    with pytest.raises(ValueError):
        create_user("1234", 1, "5678", profile)


def test_ack_is_e8_not_generic_ef() -> None:
    assert UserCommand.RESULT == 0xE8
    parse_user_ack(b"?7\x03\x00", UserCommand.UPDATE, 3)
    with pytest.raises(UserAccessDenied):
        parse_user_ack(b"?7\x03\x02", UserCommand.UPDATE, 3)
    with pytest.raises(UserProtocolError):
        parse_user_ack(b"?6\x03\x00", UserCommand.UPDATE, 3)
    with pytest.raises(UserProtocolError):
        parse_user_ack(b"?7\x04\x00", UserCommand.UPDATE, 3)


def test_malformed_reads_are_rejected_without_payload_logging() -> None:
    with pytest.raises(UserProtocolError):
        parse_user(b"\x01\xff")
    with pytest.raises(UserProtocolError):
        parse_roster(b"")
