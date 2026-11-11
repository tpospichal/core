"""Safe SATEL Integra user-management protocol helpers.

Staged only: satel-integra==1.6.0 does not support commands 0xE0..0xE7.
The SDK's debug logging must be redacted before these are exposed in HA.
"""

from dataclasses import dataclass, field
from enum import IntEnum
from collections.abc import Awaitable, Callable
from satel_integra.utils import decode_bitmask_le, encode_bitmask_le


class UserCommand(IntEnum):
    SELF = 0xE0
    READ = 0xE1
    LIST = 0xE2
    DELETE = 0xE5
    CREATE = 0xE6
    UPDATE = 0xE7
    RESULT = 0xE8  # SATEL user-management acknowledgement, NOT generic 0xEF


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

def _require_length(data: bytes, length: int) -> None:
    if len(data) != length:
        raise UserProtocolError("Unexpected SATEL user response length")


def _decode_profile(
    partitions: bytes,
    type_flags: int,
    days: int,
    temporary_days: int,
    rights: bytes,
    name_bytes: bytes,
    attributes: int,
    *,
    encoding: str,
) -> UserProfile:
    try:
        name = name_bytes.decode(encoding, "strict").rstrip("\x00 ").strip()
        if not name:
            raise UserProtocolError("SATEL returned an empty user name")
        return UserProfile(
            name=name,
            partitions=frozenset(decode_bitmask_le(partitions, 4)),
            rights=rights,
            user_type=type_flags & 0x0F,
            days=days,
            temporary_days=temporary_days,
            simple=bool(attributes & 0x80),
            master=bool(attributes & 0x40),
            can_isolate=bool(type_flags & 0x20),
            object_number=attributes & 0x07,
        )
    except (ValueError, UnicodeError) as exc:
        raise UserProtocolError("Cannot decode user profile") from exc


def parse_self(data: bytes, *, encoding: str = "latin-1") -> PanelUser:
    """Decode E0 response body (29 bytes, excludes command byte).

    The telephone code is deliberately not exposed in the result.
    """
    _require_length(data, 29)
    number = data[0]
    if number != 255:
        _number(number)
    return PanelUser(
        number=number,
        profile=_decode_profile(
            data[3:7], data[7], data[8], 0,
            data[9:12], data[12:28], data[28], encoding=encoding,
        ),
    )


def parse_user(data: bytes, *, encoding: str = "latin-1") -> PanelUser:
    """Decode E1 response body (28 bytes, excludes command byte)."""
    _require_length(data, 28)
    number = _number(data[0])
    return PanelUser(
        number=number,
        profile=_decode_profile(
            data[1:5], data[5], data[6], data[7],
            data[8:11], data[11:27], data[27], encoding=encoding,
        ),
    )


def parse_roster(data: bytes) -> UserRoster:
    """Decode E2 body: requesting user, existing mask, editable mask."""
    _require_length(data, 61)
    requester = _number(data[0])
    existing = frozenset(decode_bitmask_le(data[1:31], 30))
    editable = frozenset(decode_bitmask_le(data[31:61], 30))
    if editable - existing:
        raise UserProtocolError("Editable roster contains absent users")
    return UserRoster(requester, existing, editable)


def parse_user_ack(data: bytes, expected_command: UserCommand, user: int) -> None:
    """Decode E8/? confirmation for E5/E6/E7.

    An E8 success is not evidence that data can be read back; the caller must
    verify the panel state. This function does not retry failed writes.
    """
    _require_length(data, 4)
    command_character = {UserCommand.DELETE: ord("5"),
                         UserCommand.CREATE: ord("6"),
                         UserCommand.UPDATE: ord("7")}.get(expected_command)
    if command_character is None:
        raise ValueError("Not a supported user write operation")
    if data[0] != ord("?") or data[1] != command_character:
        raise UserProtocolError("Unexpected SATEL acknowledgement")
    if data[2] != user:
        raise UserProtocolError("SATEL acknowledgement user mismatch")
    if data[3] == 1 or data[3] == 2:
        raise UserAccessDenied("SATEL rejected operator code or privileges")
    if data[3] != 0:
        raise UserProtocolError(f"SATEL rejected user operation (0x{data[3]:02X})")


def _profile_payload(profile: UserProfile, encoding: str) -> bytes:
    if not 1 <= len(profile.name) <= 16 or not 0 <= profile.user_type <= 10:
        raise ValueError("Invalid user profile")
    if len(profile.rights) != 3 or not 0 <= profile.days <= 255:
        raise ValueError("Invalid rights or time")
    if not 0 <= profile.temporary_days <= 255:
        raise ValueError("Invalid temporary time")
    if any(not 1 <= n <= 32 for n in profile.partitions):
        raise ValueError("Invalid partition")
    if not 0 <= profile.object_number <= 7:
        raise ValueError("Invalid object number")
    if profile.master or profile.simple:
        raise ValueError("Privileged/special user edits are blocked")
    encoded = profile.name.encode(encoding, "strict")
    if len(encoded) > 16:
        raise ValueError("User name exceeds 16 encoded bytes")
    flags = profile.user_type | (0x20 if profile.can_isolate else 0)
    return (
        encode_bitmask_le(sorted(profile.partitions), 4)
        + bytes((flags, profile.days, profile.temporary_days))
        + profile.rights
        + encoded.ljust(16, b" ")
    )


def create_user(
    operator_code: str,
    number: int,
    new_code: str,
    profile: UserProfile,
    *,
    encoding: str = "latin-1",
) -> UserRequest:
    """Encode E6. Never generate privileged master accounts."""
    _number(number, write=True)
    if not 0 <= profile.object_number <= 7:
        raise ValueError("Invalid object number")
    return UserRequest(
        UserCommand.CREATE,
        _pin(operator_code, 8)
        + bytes((number,))
        + _pin(new_code, 4)
        + b"\xff" * 2
        + _profile_payload(profile, encoding)
        + bytes((profile.object_number,)),
    )


def update_user(
    operator_code: str,
    number: int,
    profile: UserProfile,
    *,
    new_code: str | None = None,
    encoding: str = "latin-1",
) -> UserRequest:
    """Encode E7, preserving existing PIN unless new_code is provided."""
    _number(number, write=True)
    return UserRequest(
        UserCommand.UPDATE,
        _pin(operator_code, 8)
        + bytes((number,))
        + (_pin(new_code, 4) if new_code is not None else b"\xff" * 4)
        + b"\xff" * 2
        + _profile_payload(profile, encoding),
    )

UserTransport = Callable[[UserRequest], Awaitable[tuple[int, bytes]]]


class SatelUserManager:
    """Guarded user operations over an SDK-managed shared SATEL connection.

    The supplied transport MUST serialize with all other SATEL requests and
    suppress request/response hex logging. This staging class does NOT
    open a separate socket and is not exposed as a HA service.
    """

    def __init__(self, transport: UserTransport):
        self._transport = transport

    async def _query(self, request: UserRequest) -> bytes:
        command, body = await self._transport(request)
        if command == UserCommand.RESULT:
            # E8/? may also report failure of a READ request.
            if len(body) == 4 and body[0] == ord("?"):
                if body[3] in (1, 2):
                    raise UserAccessDenied("SATEL denied user query")
            raise UserProtocolError("SATEL user query failed")
        if command != request.command:
            raise UserProtocolError("SATEL unexpected response")
        return body

    async def _write(self, request: UserRequest, number: int) -> None:
        command, body = await self._transport(request)
        if command != UserCommand.RESULT:
            raise UserProtocolError("SATEL write outcome unknown")
        parse_user_ack(body, request.command, number)

    async def authenticate(self, code: str) -> PanelUser:
        actor = parse_self(await self._query(read_self(code)))
        if not actor.can_use_guardx:
            raise UserAccessDenied("Operator has no GUARDX access")
        return actor

    async def roster(self, code: str) -> tuple[PanelUser, UserRoster]:
        actor = await self.authenticate(code)
        if actor.number == 255:
            raise UserAccessDenied("Service account is excluded from user management")
        roster = parse_roster(await self._query(read_roster(code, actor.number)))
        if roster.requester != actor.number:
            raise UserProtocolError("User list scope mismatch")
        return actor, roster

    async def user(self, code: str, number: int) -> PanelUser:
        _number(number)
        _, roster = await self.roster(code)
        if number <= 240 and number not in roster.existing:
            raise UserAccessDenied("User not visible in operator roster")
        user = parse_user(await self._query(read_user(code, number)))
        if user.number != number:
            raise UserProtocolError("User read-back ID mismatch")
        return user

    async def _require_edit(self, code: str, number: int) -> PanelUser:
        _number(number, write=True)
        actor, roster = await self.roster(code)
        if not actor.can_manage_users:
            raise UserAccessDenied("Operator has no user-edit right")
        if number == actor.number:
            raise UserAccessDenied("Self-edit must use panel's own-code command")
        if number not in roster.existing or number not in roster.editable:
            raise UserAccessDenied("User is not editable by this operator")
        existing = await self.user(code, number)
        if existing.profile.master or existing.profile.simple:
            raise UserAccessDenied("Special user types cannot be edited here")
        return actor

    async def change_user(
        self, code: str, number: int, profile: UserProfile,
        *, new_code: str | None = None,
    ) -> PanelUser:
        actor = await self._require_edit(code, number)
        if not profile.partitions.issubset(actor.profile.partitions):
            raise UserAccessDenied("Cannot grant partitions outside operator scope")
        if any(new & ~allowed for new, allowed in zip(profile.rights, actor.profile.rights)):
            raise UserAccessDenied("Cannot grant rights held by neither operator")
        await self._write(
            update_user(code, number, profile, new_code=new_code), number
        )
        result = await self.user(code, number)
        if result.profile != profile:
            raise UserProtocolError("Changed user state not verified")
        return result

    async def remove_user(self, code: str, number: int) -> None:
        await self._require_edit(code, number)
        await self._write(delete_user(code, number), number)
        _, roster = await self.roster(code)
        if number in roster.existing:
            raise UserProtocolError("User removal not verified")
