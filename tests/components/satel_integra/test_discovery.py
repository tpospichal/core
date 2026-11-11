"""Test read-only discovery of Satel Integra devices."""

from unittest.mock import AsyncMock

from pytest_homeassistant.common import MockConfigEntry
from satel_integra.models import SatelOutputInfo, SatelPartitionInfo, SatelZoneInfo

from homeassistant.components.satel_integra.const import (
    CONF_PARTITION_ASSIGNMENT,
    CONF_ZONE_NUMBER,
    SUBENTRY_TYPE_OUTPUT,
    SUBENTRY_TYPE_PARTITION,
    SUBENTRY_TYPE_ZONE,
)
from homeassistant.components.satel_integra.discovery import (
    async_discover_device_subentries,
)
from homeassistant.core import HomeAssistant


async def test_discovery_creates_only_configured_devices(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    mock_satel: AsyncMock,
) -> None:
    """Auto-discovery must skip addresses unused by the panel."""
    mock_config_entry.add_to_hass(hass)
    mock_satel.connected = True
    mock_satel.read_partition_info.side_effect = lambda n: (
        SatelPartitionInfo(
            device_number=n,
            name="Ground floor",
            type_code=3,
            object_assignment=1,
        )
        if n == 1
        else None
    )
    mock_satel.read_zone_info.side_effect = lambda n: (
        SatelZoneInfo(
            device_number=n,
            name="Front door",
            type_code=42,
            partition_assignment=1,
        )
        if n == 2
        else None
    )
    mock_satel.read_output_info.side_effect = lambda n: (
        SatelOutputInfo(device_number=n, name="Garden light", type_code=16)
        if n == 3
        else None
    )
    panel_info = await mock_satel.read_panel_info()

    assert await async_discover_device_subentries(
        hass, mock_config_entry, mock_satel, panel_info
    ) == 3

    by_uid = {s.unique_id: s for s in mock_config_entry.subentries.values()}
    assert set(by_uid) == {"partition_1", "zone_2", "output_3"}
    assert by_uid["zone_2"].subentry_type == SUBENTRY_TYPE_ZONE
    assert by_uid["zone_2"].data[CONF_ZONE_NUMBER] == 2
    assert by_uid["zone_2"].data[CONF_PARTITION_ASSIGNMENT] == 1
    assert by_uid["zone_2"].title == "Front door (2)"
    assert by_uid["partition_1"].subentry_type == SUBENTRY_TYPE_PARTITION
    assert by_uid["output_3"].subentry_type == SUBENTRY_TYPE_OUTPUT

    # Scanning again must never create duplicate entities.
    assert await async_discover_device_subentries(
        hass, mock_config_entry, mock_satel, panel_info
    ) == 0
    assert len(mock_config_entry.subentries) == 3


async def test_discovery_preserves_existing_manual_configuration(
    hass: HomeAssistant,
    mock_config_entry_with_subentries: MockConfigEntry,
    mock_satel: AsyncMock,
) -> None:
    """Do not modify names, types or entity IDs set by the user."""
    entry = mock_config_entry_with_subentries
    entry.add_to_hass(hass)
    original = {s.unique_id: s for s in entry.subentries.values()}
    mock_satel.connected = True
    mock_satel.read_partition_info.side_effect = lambda n: (
        SatelPartitionInfo(n, "Renamed in DLOADX", 3, 1) if n == 1 else None
    )
    mock_satel.read_zone_info.side_effect = lambda n: (
        SatelZoneInfo(n, "Renamed in DLOADX", 42, 1) if n == 1 else None
    )
    mock_satel.read_output_info.side_effect = lambda n: (
        SatelOutputInfo(n, "Renamed in DLOADX", 16) if n == 1 else None
    )
    panel_info = await mock_satel.read_panel_info()

    assert await async_discover_device_subentries(
        hass, entry, mock_satel, panel_info
    ) == 0

    new = {s.unique_id: s for s in entry.subentries.values()}
    assert new.keys() == original.keys()
    for key in original:
        assert new[key].title == original[key].title
        assert new[key].data == original[key].data


async def test_discovery_skips_unassigned_and_disabled_devices(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    mock_satel: AsyncMock,
) -> None:
    """Nonempty names alone do not indicate an enabled alarm device."""
    mock_config_entry.add_to_hass(hass)
    mock_satel.connected = True
    mock_satel.read_partition_info.side_effect = lambda n: (
        SatelPartitionInfo(n, "Unused", 0, None) if n == 1 else None
    )
    mock_satel.read_zone_info.side_effect = lambda n: (
        SatelZoneInfo(n, "Unused", 0, None) if n == 1 else None
    )
    mock_satel.read_output_info.side_effect = lambda n: (
        SatelOutputInfo(n, "Unused", 0) if n == 1 else None
    )
    panel_info = await mock_satel.read_panel_info()

    assert await async_discover_device_subentries(
        hass, mock_config_entry, mock_satel, panel_info
    ) == 0
    assert not mock_config_entry.subentries


async def test_discovery_stops_after_disconnect(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    mock_satel: AsyncMock,
) -> None:
    """Stop gracefully if the security panel disconnects mid-scan."""
    mock_config_entry.add_to_hass(hass)
    mock_satel.connected = False
    panel_info = await mock_satel.read_panel_info()

    assert await async_discover_device_subentries(
        hass, mock_config_entry, mock_satel, panel_info
    ) == 0
    mock_satel.read_partition_info.assert_not_awaited()
    mock_satel.read_zone_info.assert_not_awaited()
    mock_satel.read_output_info.assert_not_awaited()
