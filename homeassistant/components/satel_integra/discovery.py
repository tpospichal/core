"""Discover configured SATEL Integra devices over ETHM-1 Plus.

This module only reads panel metadata; it never changes alarm configuration.
"""

import logging
from types import MappingProxyType

from satel_integra import AsyncSatel, SatelIntegraError
from satel_integra.models import SatelPanelInfo

from homeassistant.components.binary_sensor import BinarySensorDeviceClass
from homeassistant.config_entries import ConfigSubentry
from homeassistant.const import CONF_NAME
from homeassistant.core import HomeAssistant

from .const import (
    CONF_ARM_HOME_MODE,
    CONF_ENABLE_TEMPERATURE_SENSOR,
    CONF_OUTPUT_NUMBER,
    CONF_PARTITION_ASSIGNMENT,
    CONF_PARTITION_NUMBER,
    CONF_ZONE_NUMBER,
    CONF_ZONE_TYPE,
    DEFAULT_CONF_ARM_HOME_MODE,
    SUBENTRY_TYPE_OUTPUT,
    SUBENTRY_TYPE_PARTITION,
    SUBENTRY_TYPE_ZONE,
)
from .coordinator import SatelConfigEntry

_LOGGER = logging.getLogger(__name__)

# Panel type codes are defined by satel-integra's SatelPanelInfo model.
# Unknown models use the protocol's maximum device address range.
_DEVICE_LIMITS = {
    0: 24,   # Integra 24
    1: 32,   # Integra 32
    2: 64,   # Integra 64
    3: 128,  # Integra 128
    4: 128,  # Integra 128-WRL
    66: 64,  # Integra 64 Plus
    67: 128, # Integra 128 Plus
    72: 256, # Integra 256 Plus
    132: 128, # Integra 128-WRL
}
_MAX_PARTITIONS = 32
_MAX_DEVICE_ID = 256


def _add_subentry(
    hass: HomeAssistant,
    entry: SatelConfigEntry,
    existing_ids: set[str],
    subentry_type: str,
    number: int,
    name: str,
    data: dict,
) -> bool:
    """Add an automatically discovered item, without touching existing entries."""
    unique_id = f"{subentry_type}_{number}"
    if unique_id in existing_ids:
        return False

    hass.config_entries.async_add_subentry(
        entry,
        ConfigSubentry(
            subentry_type=subentry_type,
            unique_id=unique_id,
            title=f"{name} ({number})",
            data=MappingProxyType({CONF_NAME: name, **data}),
        ),
    )
    existing_ids.add(unique_id)
    return True


async def async_discover_device_subentries(
    hass: HomeAssistant,
    entry: SatelConfigEntry,
    controller: AsyncSatel,
    panel_info: SatelPanelInfo | None,
) -> int:
    """Read available metadata and add missing config subentries.

    An item must be configured at the panel, not merely addressable:
    zones require a partition assignment, partitions require an object
    assignment, and outputs require a non-zero output function.
    """
    existing_ids = {item.unique_id for item in entry.subentries.values()}
    device_limit = (
        _DEVICE_LIMITS.get(panel_info.type_code, _MAX_DEVICE_ID)
        if panel_info
        else _MAX_DEVICE_ID
    )
    discovered = 0

    for number in range(1, _MAX_PARTITIONS + 1):
        if not controller.connected:
            _LOGGER.warning("SATEL discovery interrupted: panel disconnected")
            return discovered
        try:
            info = await controller.read_partition_info(number)
        except (SatelIntegraError, ValueError) as err:
            _LOGGER.debug("Cannot read SATEL partition %s: %s", number, err)
            continue
        if not info or not info.name or info.object_assignment is None:
            continue
        discovered += _add_subentry(
            hass,
            entry,
            existing_ids,
            SUBENTRY_TYPE_PARTITION,
            number,
            info.name,
            {
                CONF_PARTITION_NUMBER: number,
                CONF_ARM_HOME_MODE: int(DEFAULT_CONF_ARM_HOME_MODE),
            },
        )

    for number in range(1, device_limit + 1):
        if not controller.connected:
            _LOGGER.warning("SATEL discovery interrupted: panel disconnected")
            return discovered
        try:
            info = await controller.read_zone_info(number)
        except (SatelIntegraError, ValueError) as err:
            _LOGGER.debug("Cannot read SATEL zone %s: %s", number, err)
            continue
        if not info or not info.name or info.partition_assignment is None:
            continue
        discovered += _add_subentry(
            hass,
            entry,
            existing_ids,
            SUBENTRY_TYPE_ZONE,
            number,
            info.name,
            {
                CONF_ZONE_NUMBER: number,
                CONF_ZONE_TYPE: BinarySensorDeviceClass.MOTION,
                CONF_ENABLE_TEMPERATURE_SENSOR: False,
                CONF_PARTITION_ASSIGNMENT: info.partition_assignment,
            },
        )

    for number in range(1, device_limit + 1):
        if not controller.connected:
            _LOGGER.warning("SATEL discovery interrupted: panel disconnected")
            return discovered
        try:
            info = await controller.read_output_info(number)
        except (SatelIntegraError, ValueError) as err:
            _LOGGER.debug("Cannot read SATEL output %s: %s", number, err)
            continue
        if not info or not info.name or info.type_code == 0:
            continue
        # Outputs are deliberately created read-only: controlling alarm
        # outputs (including sirens) needs explicit user configuration.
        discovered += _add_subentry(
            hass,
            entry,
            existing_ids,
            SUBENTRY_TYPE_OUTPUT,
            number,
            info.name,
            {
                CONF_OUTPUT_NUMBER: number,
                CONF_ZONE_TYPE: BinarySensorDeviceClass.POWER,
            },
        )

    _LOGGER.info(
        "SATEL discovery finished for %s: added %s items",
        entry.title,
        discovered,
    )
    return discovered
