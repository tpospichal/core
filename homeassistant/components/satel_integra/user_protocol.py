"""Safe SATEL Integra user-management protocol helpers.

Staged only: satel-integra==1.6.0 does not support commands 0xE0..0xE7.
The SDK's debug logging must be redacted before these are exposed in HA.
"""

from dataclasses import dataclass, field
from enum import IntEnum
from satel_integra.utils import decode_bitmask_le, encode_bitmask_le


class UserCommand(IntEnum):
    SELF = 0xE0
    READ = 0xE1
    LIST = 0xE2
    DELETE = 0xE5
    CREATE = 0xE6
    UPDATE = 0xE7
    RESULT = 0xEF


class UserProtocolError(Exception):
    """Malformed or rejected protocol response without secret bytes."""


class UserAccessDenied(UserProtocolError):
    """User operation rejected by privilege checks."""


@dataclass(frozen=True, repr=False)
class UserRequest:
    command: UserCommand
    payload: bytes = field(repr=False)

    def __repr__(self) -> str:
        return f"UserRequest({self.command.name}, <redacted>)"


@dataclass(frozen=True)
class UserProfile:
    """Editable settings, excluding sensitive access and telephone PINs."""

    name: str
    partitions: frozenset[int]
    rights: bytes
    user_type: int = 0
    days: int = 0
    temporary_days: int = 0
    simple: bool = False
    master: bool = False
    can_isolate: bool = False
    object_number: int = 0


@dataclass(frozen=True)
class PanelUser:
    number: int
    profile: UserProfile

    @property
    def can_manage_users(self) -> bool:
        return bool(self.profile.rights[0] & 0x80)

    @property
    def can_use_guardx(self) -> bool:
        return bool(self.profile.rights[2] & 0x04)


@dataclass(frozen=True)
class UserRoster:
    requester: int
    existing: frozenset[int]
    editable: frozenset[int]


def _number(number: int, *, write: bool = False) -> int:
    if not isinstance(number, int) or not 1 <= number <= (240 if write else 248):
        raise ValueError("Invalid SATEL user number")
    return number


def _pin(code: str, count: int) -> bytes:
    if not code.isascii() or not code.isdecimal() or not 4 <= len(code) <= count * 2:
        raise ValueError("PIN must contain 4..8/16 ASCII digits")
    return bytes.fromhex(code.ljust(count * 2, "F"))


def read_self(code: str) -> UserRequest:
    return UserRequest(UserCommand.SELF, _pin(code, 8))


def read_user(code: str, number: int) -> UserRequest:
    return UserRequest(UserCommand.READ, _pin(code, 8) + bytes([_number(number)]))


def read_roster(code: str, requester: int) -> UserRequest:
    return UserRequest(UserCommand.LIST, _pin(code, 8) + bytes([_number(requester)]))


def delete_user(code: str, number: int) -> UserRequest:
    return UserRequest(UserCommand.DELETE, _pin(code, 8) + bytes([_number(number, write=True)]))
