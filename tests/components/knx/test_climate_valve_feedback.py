"""Integration regressions for independent KNX valve feedback.

Run in the Home Assistant development environment with the proposed XKNX installed.
"""

import probatio
import pytest
from homeassistant.components.knx.climate import _create_climate_ui
from homeassistant.components.knx.schema import ClimateSchema
from homeassistant.components.knx.storage.entity_store_schema import (
    ClimateKnxConfig,
    ClimateTargetTemperature,
)
from homeassistant.components.knx.storage.knx_selector import GroupAddressConfig
from homeassistant.core import HomeAssistant
from xknx import XKNX

from .conftest import KNXTestKit


@pytest.mark.parametrize(
    "heating,cooling,expected",
    [(0, 0, "idle"), (1, 0, "heating"), (0, 1, "cooling"), (1, 1, None)],
)
async def test_binary_feedback(
    hass: HomeAssistant,
    knx: KNXTestKit,
    heating: int,
    cooling: int,
    expected: str | None,
) -> None:
    """Read true action from both valves, including simultaneous activity."""
    await knx.setup_integration(
        {
            "climate": {
                "name": "test",
                "temperature_address": "1/2/3",
                "target_temperature_state_address": "1/2/5",
                "heating_active_state_address": "2/1/1",
                "cooling_active_state_address": "2/1/2",
            }
        }
    )
    assert hass.states.get("climate.test").attributes.get("hvac_action") is None
    await knx.receive_write("2/1/1", heating)
    assert hass.states.get("climate.test").attributes.get("hvac_action") is None
    await knx.receive_write("2/1/2", cooling)
    state = hass.states.get("climate.test")
    assert state.attributes.get("hvac_action") == expected
    assert state.attributes["heating_active"] is bool(heating)
    assert state.attributes["cooling_active"] is bool(cooling)
    assert state.attributes["valve_activity_conflict"] is bool(heating and cooling)


async def test_mixed_feedback_priority_and_threshold(
    hass: HomeAssistant, knx: KNXTestKit
) -> None:
    """Unknown binary feedback must not fall back to percent or shared activity."""
    await knx.setup_integration(
        {
            "climate": {
                "name": "test",
                "temperature_address": "1/2/3",
                "target_temperature_state_address": "1/2/5",
                "active_state_address": "2/1/5",
                "heating_active_state_address": "2/1/1",
                "heating_command_value_state_address": "2/1/3",
                "cooling_command_value_state_address": "2/1/2",
                "cooling_activity_threshold": 20,
            }
        }
    )
    await knx.receive_write("2/1/5", 1)
    await knx.receive_write("2/1/3", (255,))
    await knx.receive_write("2/1/2", (51,))  # exactly 20%
    assert hass.states.get("climate.test").attributes.get("hvac_action") is None
    await knx.receive_write("2/1/1", 0)
    assert hass.states.get("climate.test").attributes.get("hvac_action") == "idle"

    await knx.receive_write("2/1/2", (52,))  # 20.392...%, above threshold
    assert hass.states.get("climate.test").attributes.get("hvac_action") == "cooling"
    await knx.receive_write("2/1/2", (0,))
    assert hass.states.get("climate.test").attributes.get("hvac_action") == "idle"


def test_ui_factory_feedback_mapping() -> None:
    """Map UI state/passive addresses and thresholds to both XKNX channels."""
    config = ClimateKnxConfig(
        ga_temperature_current=GroupAddressConfig(state="1/2/3"),
        target_temperature=ClimateTargetTemperature(
            ga_temperature_target=GroupAddressConfig(write="1/2/4", state="1/2/5")
        ),
        ga_heating_active=GroupAddressConfig(state="2/1/1", passive=["2/1/3"]),
        ga_cooling_valve=GroupAddressConfig(state="2/1/2"),
        heating_activity_threshold=3,
        cooling_activity_threshold=20,
    )
    device = _create_climate_ui(XKNX(), config, "test")
    assert device.has_independent_activity
    assert device.heating_active.initialized
    assert device.cooling_command_value.initialized
    assert device.heating_activity_threshold == 3
    assert device.cooling_activity_threshold == 20
    assert device.is_heating is None
    assert device.is_cooling is None


@pytest.mark.parametrize(
    "config",
    [
        {"heating_active_state_address": "2/1/1"},
        {"cooling_command_value_state_address": "2/1/2"},
        {"heating_activity_threshold": -1},
        {"cooling_activity_threshold": 100},
        {"heating_activity_threshold": float("nan")},
    ],
)
def test_yaml_feedback_validation(config: dict) -> None:
    """Reject incomplete pairs and invalid thresholds at configuration time."""
    with pytest.raises(probatio.Invalid):
        ClimateSchema.ENTITY_SCHEMA(
            {
                "temperature_address": "1/2/3",
                "target_temperature_state_address": "1/2/5",
                **config,
            }
        )
