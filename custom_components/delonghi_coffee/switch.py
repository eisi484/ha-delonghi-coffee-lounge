"""Switch entities for De'Longhi Coffee — UserConf boolean fields in MachineSettings.Editable.

All switches correspond to fields inside MachineSettings.Editable.UserConf,
confirmed present in the live dump from ECAM47080 (2026-08-13):
  DisableTurnON   - false   lock remote power-on
  Mode1224        - false   12/24-hour clock display
  SoundEnable     - false   machine sound (beeps)
  ExLed           - false   external LED
  EnergySavingMode- false   energy saving
  CupWarmer       - true    cup warmer plate on top
  ShutoffOn       - false   auto shut-off enabled
  FilterInstall   - false   water filter installed

Control path (same as select.py):
  HA switch → DeLonghiMqttClient.publish_settings({"UserConf": {"Field": bool}})
  → Shadow desired write → machine echoes on MachineSettings/update/accepted
"""

from __future__ import annotations

from homeassistant.components.switch import SwitchDeviceClass, SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, SIGNAL_UPDATE


class DeLonghiSwitchBase(SwitchEntity):
    """Base for De'Longhi boolean switches (UserConf fields)."""

    _attr_should_poll = False
    _attr_has_entity_name = True

    def __init__(self, mqtt_client, device_info: dict, field: str,
                 translation_key: str, icon: str) -> None:
        self._mqtt       = mqtt_client
        self._device_info= device_info
        self._machine    = device_info["machineName"]
        self._field      = field
        self._attr_unique_id     = f"{self._machine}_switch_{field.lower()}"
        self._attr_translation_key = translation_key
        self._attr_icon  = icon

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                SIGNAL_UPDATE.format(machine_name=self._machine),
                self._handle_update,
            )
        )

    def _handle_update(self) -> None:
        self.schedule_update_ha_state()

    @property
    def device_info(self) -> dict:
        caps = self._mqtt.data.get("capabilities", {})
        return {
            "identifiers": {(DOMAIN, self._machine)},
            "name": "De'Longhi Coffee Lounge",
            "manufacturer": "De'Longhi",
            "model": caps.get("MachineModelUI") or self._device_info.get("machineModel"),
        }

    def _user_conf(self) -> dict:
        return (
            self._mqtt.data
            .get("settings", {})
            .get("Editable", {})
            .get("UserConf", {})
        )

    @property
    def is_on(self) -> bool | None:
        val = self._user_conf().get(self._field)
        if val is None:
            return None
        return bool(val)

    async def async_turn_on(self, **kwargs) -> None:
        await self.hass.async_add_executor_job(
            self._mqtt.publish_settings, {"UserConf": {self._field: True}}
        )

    async def async_turn_off(self, **kwargs) -> None:
        await self.hass.async_add_executor_job(
            self._mqtt.publish_settings, {"UserConf": {self._field: False}}
        )


# ---------------------------------------------------------------------------
# Individual switch entities — one per UserConf boolean field
# ---------------------------------------------------------------------------

# (field_name, translation_key, icon, device_class)
_SWITCH_DEFS: list[tuple[str, str, str]] = [
    ("SoundEnable",      "sound_enable",       "mdi:volume-high"),
    ("EnergySavingMode", "energy_saving_mode",  "mdi:leaf"),
    ("CupWarmer",        "cup_warmer",          "mdi:cup-water"),
    ("ShutoffOn",        "auto_shutoff",        "mdi:timer-off-outline"),
    ("DisableTurnON",    "disable_power_on",    "mdi:power-off"),
    ("FilterInstall",    "filter_installed",    "mdi:water-check"),
    ("Mode1224",         "clock_24h",           "mdi:clock-outline"),
    ("ExLed",            "external_led",        "mdi:led-on"),
]


# ---------------------------------------------------------------------------
# Platform setup
# ---------------------------------------------------------------------------

async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    data        = hass.data[DOMAIN][entry.entry_id]
    mqtt_client = data["mqtt"]
    device_info = data["device_info"]

    entities = [
        DeLonghiSwitchBase(mqtt_client, device_info, field, tr_key, icon)
        for field, tr_key, icon in _SWITCH_DEFS
    ]
    async_add_entities(entities)
