"""Binary sensors for De'Longhi Coffee (Coffee Lounge / Daedalus, MQTT push).

All values come from the MachineStatus shadow (state.reported.alarms /
peripherals / accessories), confirmed live 2026-08-11.

Alarm fields confirmed in dump (all bool):
  TankLevel, Waste, Descale, Filter, GroundFine, General, HeaterNTC,
  Imbocco, MotorPos, Drain, Bubble, TankPresence, Clean, BrokenGrinder,
  NoCoffee, Infuser, UIMemory, WifiDown, Fan, BrewUnitClean, Fridge

Peripheral fields (all bool):
  Switch, WaterSpout, Jug, TankPresence, WaterTankLow, DripPresence,
  HotJug, Grinder1ZSW, MotDwSw, MotUpSw

Accessory fields (all bool):
  None, Water, IDFHot, CleanHot, IDFCold, CleanCold, SteamWand
"""

from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, SIGNAL_UPDATE


class DeLonghiPushBinarySensor(BinarySensorEntity):
    _attr_should_poll = False
    _attr_has_entity_name = True

    def __init__(self, mqtt_client, device_info) -> None:
        self._mqtt = mqtt_client
        self._device_info = device_info
        self._machine_name = device_info["machineName"]

    async def async_added_to_hass(self) -> None:
        signal = SIGNAL_UPDATE.format(machine_name=self._machine_name)
        self.async_on_remove(
            async_dispatcher_connect(self.hass, signal, self._handle_update)
        )

    def _handle_update(self) -> None:
        self.schedule_update_ha_state()

    @property
    def device_info(self):
        caps = self._mqtt.data.get("capabilities", {})
        return {
            "identifiers": {(DOMAIN, self._machine_name)},
            "name": "De'Longhi Coffee Lounge",
            "manufacturer": "De'Longhi",
            "model": caps.get("MachineModelUI") or self._device_info.get("machineModel"),
        }


# ---------------------------------------------------------------------------
# Connectivity
# ---------------------------------------------------------------------------

class DeLonghiConnectivitySensor(DeLonghiPushBinarySensor):
    """True once the integration has received at least one live status update."""

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_icon = "mdi:coffee-maker"
    _attr_translation_key = "online"

    def __init__(self, mqtt_client, device_info) -> None:
        super().__init__(mqtt_client, device_info)
        self._attr_unique_id = f"{self._machine_name}_online"

    @property
    def is_on(self):
        return bool(self._mqtt.data.get("status"))


# ---------------------------------------------------------------------------
# Alarm binary sensors  (source: MachineStatus.alarms)
# ---------------------------------------------------------------------------

class DeLonghiAlarmSensor(DeLonghiPushBinarySensor):
    """Generic binary sensor for a single alarm flag."""

    _attr_device_class = BinarySensorDeviceClass.PROBLEM

    def __init__(self, mqtt_client, device_info, field, translation_key, icon) -> None:
        super().__init__(mqtt_client, device_info)
        self._field = field
        self._attr_unique_id = f"{self._machine_name}_alarm_{field.lower()}"
        self._attr_translation_key = translation_key
        self._attr_icon = icon

    @property
    def is_on(self):
        return bool(
            self._mqtt.data.get("status", {}).get("alarms", {}).get(self._field)
        )


# field_name → (translation_key, icon)
# Every alarm confirmed present in the live dump from ECAM47080 (2026-08-11).
ALARM_SENSORS: dict[str, tuple[str, str]] = {
    "Descale":      ("alarm_descale",       "mdi:water-alert"),
    "TankLevel":    ("alarm_tank_level",    "mdi:water-off"),
    "NoCoffee":     ("alarm_no_coffee",     "mdi:coffee-off"),
    "Waste":        ("alarm_waste",         "mdi:trash-can-outline"),
    "Filter":       ("alarm_filter",        "mdi:water-check"),
    "GroundFine":   ("alarm_ground_fine",   "mdi:grain"),
    "BrokenGrinder":("alarm_broken_grinder","mdi:alert-circle"),
    "BrewUnitClean":("alarm_brew_unit_clean","mdi:broom"),
    "Clean":        ("alarm_clean",         "mdi:spray-bottle"),
    "Drain":        ("alarm_drain",         "mdi:pipe-leak"),
    "Infuser":      ("alarm_infuser",       "mdi:coffee-maker-outline"),
    "MotorPos":     ("alarm_motor_pos",     "mdi:cog-off"),
    "HeaterNTC":    ("alarm_heater_ntc",    "mdi:thermometer-alert"),
    "Bubble":       ("alarm_bubble",        "mdi:chart-bubble"),
    "Imbocco":      ("alarm_imbocco",       "mdi:alert"),
    "Fan":          ("alarm_fan",           "mdi:fan-alert"),
    "Fridge":       ("alarm_fridge",        "mdi:fridge-alert"),
    "General":      ("alarm_general",       "mdi:alert-circle-outline"),
    "UIMemory":     ("alarm_ui_memory",     "mdi:memory"),
    "WifiDown":     ("alarm_wifi_down",     "mdi:wifi-off"),
    "TankPresence": ("alarm_tank_presence", "mdi:tray-alert"),
}


# ---------------------------------------------------------------------------
# Peripheral binary sensors  (source: MachineStatus.peripherals)
# ---------------------------------------------------------------------------

class DeLonghiPeripheralSensor(DeLonghiPushBinarySensor):
    """Generic binary sensor for one field under status.peripherals."""

    def __init__(self, mqtt_client, device_info, field, translation_key, icon) -> None:
        super().__init__(mqtt_client, device_info)
        self._field = field
        self._attr_unique_id = f"{self._machine_name}_peripheral_{field.lower()}"
        self._attr_translation_key = translation_key
        self._attr_icon = icon

    @property
    def is_on(self):
        return bool(
            self._mqtt.data.get("status", {}).get("peripherals", {}).get(self._field)
        )


# Naming notes (confirmed on ECAM47080):
#   - "Jug" fires when ANY LatteCrema container is attached (Hot or Cold).
#   - "HotJug" is a type-flag that fires alongside "Jug" when the Hot variant
#     is detected; there is no matching "ColdJug" field.
#   - "DripPresence" is True when the drip tray is inserted.
#   - "TankPresence" (peripheral) is True when the water tank is present.
PERIPHERAL_SENSORS: dict[str, tuple[str, str]] = {
    "WaterSpout":  ("water_spout",    "mdi:water-pump"),
    "Jug":         ("jug",            "mdi:cup"),
    "HotJug":      ("hot_jug",        "mdi:cup-outline"),
    "TankPresence":("tank_presence",  "mdi:tray-full"),
    "WaterTankLow":("water_tank_low", "mdi:water-alert"),
    "DripPresence":("drip_presence",  "mdi:tray"),
    "Switch":      ("switch",         "mdi:toggle-switch"),
    "Grinder1ZSW": ("grinder",        "mdi:coffee-outline"),
    "MotDwSw":     ("brew_unit_down", "mdi:arrow-down-bold-box-outline"),
    "MotUpSw":     ("brew_unit_up",   "mdi:arrow-up-bold-box-outline"),
}


# ---------------------------------------------------------------------------
# Accessory binary sensors  (source: MachineStatus.accessories)
# ---------------------------------------------------------------------------

class DeLonghiAccessorySensor(DeLonghiPushBinarySensor):
    """Generic binary sensor for one field under status.accessories."""

    def __init__(self, mqtt_client, device_info, field, translation_key, icon) -> None:
        super().__init__(mqtt_client, device_info)
        self._field = field
        self._attr_unique_id = f"{self._machine_name}_accessory_{field.lower()}"
        self._attr_translation_key = translation_key
        self._attr_icon = icon

    @property
    def is_on(self):
        return bool(
            self._mqtt.data.get("status", {}).get("accessories", {}).get(self._field)
        )


# "None" = no accessory attached (the machine reports "None": true when
# nothing is connected).  We skip it here — it's redundant with all others
# being False.
ACCESSORY_SENSORS: dict[str, tuple[str, str]] = {
    "Water":     ("water_accessory", "mdi:cup-water"),
    "IDFHot":    ("hot_frother",     "mdi:coffee"),
    "CleanHot":  ("hot_cleaning",    "mdi:spray-bottle"),
    "IDFCold":   ("cold_frother",    "mdi:coffee-outline"),
    "CleanCold": ("cold_cleaning",   "mdi:spray-bottle"),
    "SteamWand": ("steam_wand",      "mdi:kettle-steam"),
}


# ---------------------------------------------------------------------------
# Settings-based binary sensors  (source: MachineSettings.Editable.UserConf)
# ---------------------------------------------------------------------------

class DeLonghiSettingsBinarySensor(DeLonghiPushBinarySensor):
    """Generic binary sensor for a user-configurable boolean in MachineSettings."""

    def __init__(self, mqtt_client, device_info, field, translation_key, icon) -> None:
        super().__init__(mqtt_client, device_info)
        self._field = field
        self._attr_unique_id = f"{self._machine_name}_setting_{field.lower()}"
        self._attr_translation_key = translation_key
        self._attr_icon = icon

    @property
    def is_on(self):
        return bool(
            self._mqtt.data.get("settings", {})
            .get("Editable", {})
            .get("UserConf", {})
            .get(self._field)
        )


SETTINGS_BINARY_SENSORS: dict[str, tuple[str, str]] = {
    "SoundEnable":      ("setting_sound",        "mdi:volume-high"),
    "EnergySavingMode": ("setting_energy_saving", "mdi:leaf"),
    "CupWarmer":        ("setting_cup_warmer",    "mdi:cup-water"),
    "ShutoffOn":        ("setting_auto_off",      "mdi:power-sleep"),
    "DisableTurnON":    ("setting_remote_lock",   "mdi:lock"),
    "FilterInstall":    ("setting_filter",        "mdi:water-check"),
}


# ---------------------------------------------------------------------------
# Platform setup
# ---------------------------------------------------------------------------

async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    data = hass.data[DOMAIN][entry.entry_id]
    mqtt_client = data["mqtt"]
    device_info = data["device_info"]

    entities: list[BinarySensorEntity] = [
        DeLonghiConnectivitySensor(mqtt_client, device_info),
    ]

    # Individual alarm sensors
    for field, (translation_key, icon) in ALARM_SENSORS.items():
        entities.append(
            DeLonghiAlarmSensor(mqtt_client, device_info, field, translation_key, icon)
        )

    # Peripheral presence sensors
    for field, (translation_key, icon) in PERIPHERAL_SENSORS.items():
        entities.append(
            DeLonghiPeripheralSensor(mqtt_client, device_info, field, translation_key, icon)
        )

    # Accessory presence sensors
    for field, (translation_key, icon) in ACCESSORY_SENSORS.items():
        entities.append(
            DeLonghiAccessorySensor(mqtt_client, device_info, field, translation_key, icon)
        )

    # User-configurable settings
    for field, (translation_key, icon) in SETTINGS_BINARY_SENSORS.items():
        entities.append(
            DeLonghiSettingsBinarySensor(mqtt_client, device_info, field, translation_key, icon)
        )

    async_add_entities(entities)
