"""Sensor platform for De'Longhi Coffee (Coffee Lounge / Daedalus, MQTT push).

All values come from three AWS IoT device-shadow topics that the machine pushes
automatically (confirmed working 2026-08-11 with client-id prefix
'dlg-appliance-kit-android-{uuid}'):

  MachineStatus    → state.reported  (live status, alarms, peripherals, …)
  MachineCapabilities → state.reported (model/firmware/feature flags, static)
  MachineSettings  → state.reported  (maintenance counters, user settings)
"""

from __future__ import annotations

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE, UnitOfVolume
from homeassistant.core import HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, SIGNAL_UPDATE


class DeLonghiPushEntity(SensorEntity):
    """Base class: listens for MQTT shadow push updates for this machine."""

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
            "serial_number": caps.get("SN") or self._device_info.get("serialNumber"),
            "sw_version": caps.get("FWUIVersion"),
            "hw_version": caps.get("FWMainboardVersion"),
            "connections": (
                {("mac", caps["MAC"])} if caps.get("MAC") else set()
            ),
        }


# ---------------------------------------------------------------------------
# Status sensors  (source: MachineStatus shadow)
# ---------------------------------------------------------------------------

class DeLonghiStatusSensor(DeLonghiPushEntity):
    """Current machine status string: Standby / Initialization / Busy / …"""

    _attr_icon = "mdi:coffee-maker"
    _attr_translation_key = "status"

    def __init__(self, mqtt_client, device_info) -> None:
        super().__init__(mqtt_client, device_info)
        self._attr_unique_id = f"{self._machine_name}_status"

    @property
    def native_value(self):
        return self._mqtt.data.get("status", {}).get("Status")

    @property
    def extra_state_attributes(self):
        status = self._mqtt.data.get("status", {})
        return {
            "step_description": status.get("StepDescr"),
            "current_mode": status.get("CurrMode"),
            "function_progress": status.get("CurrFuncProgress"),
            "beverage_dispensing_pct": status.get("BeverageDispensing"),
            "exit_beverage_with_error": status.get("ExitBeverageWithError"),
            "lan_ip": status.get("LanIpAddress"),
        }


class DeLonghiBeverageProgressSensor(DeLonghiPushEntity):
    """Beverage dispensing progress (0–100 %)."""

    _attr_icon = "mdi:coffee"
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_translation_key = "beverage_progress"

    def __init__(self, mqtt_client, device_info) -> None:
        super().__init__(mqtt_client, device_info)
        self._attr_unique_id = f"{self._machine_name}_beverage_progress"

    @property
    def native_value(self):
        return self._mqtt.data.get("status", {}).get("BeverageDispensing")


class DeLonghiLanIpSensor(DeLonghiPushEntity):
    """Machine's current LAN IP, as reported by the machine itself."""

    _attr_icon = "mdi:ip-network"
    _attr_translation_key = "lan_ip"

    def __init__(self, mqtt_client, device_info) -> None:
        super().__init__(mqtt_client, device_info)
        self._attr_unique_id = f"{self._machine_name}_lan_ip"

    @property
    def native_value(self):
        return self._mqtt.data.get("status", {}).get("LanIpAddress")


# ---------------------------------------------------------------------------
# Capabilities sensors  (source: MachineCapabilities shadow, mostly static)
# ---------------------------------------------------------------------------

class DeLonghiModelSensor(DeLonghiPushEntity):
    """Model / firmware info from the Capabilities shadow."""

    _attr_icon = "mdi:information-outline"
    _attr_translation_key = "model"

    def __init__(self, mqtt_client, device_info) -> None:
        super().__init__(mqtt_client, device_info)
        self._attr_unique_id = f"{self._machine_name}_model"

    @property
    def native_value(self):
        caps = self._mqtt.data.get("capabilities", {})
        return caps.get("MachineModelUI") or self._device_info.get("machineModel")

    @property
    def extra_state_attributes(self):
        caps = self._mqtt.data.get("capabilities", {})
        return {
            "serial_number": caps.get("SN") or self._device_info.get("serialNumber"),
            "sku": caps.get("SKU") or self._device_info.get("sku"),
            "mac_address": caps.get("MAC"),
            "fw_ui_version": caps.get("FWUIVersion"),
            "fw_mainboard_version": caps.get("FWMainboardVersion"),
            "fw_wifi_version": caps.get("FWWiFiVersion"),
            "aws_agent_version": caps.get("DLAWSAgentVersion"),
            "grinder_type": caps.get("Grinder"),
            "bean_adapt_type": caps.get("BeanAdaptType"),
            "customized_drinks": caps.get("CustomizedDrinks"),
            "user_profiles": caps.get("MachineUserProfiles"),
            "drink_clusters": caps.get("DrinkClusters"),
        }


# ---------------------------------------------------------------------------
# Maintenance / settings sensors  (source: MachineSettings shadow)
# ---------------------------------------------------------------------------

class DeLonghiDescalePercentSensor(DeLonghiPushEntity):
    """Descale fill level — how full the calc counter is (0–100 %).
    The machine triggers an alarm when this reaches 100 %.
    Source: MachineSettings.NotEditable.DecalPerc
    """

    _attr_icon = "mdi:water-alert"
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_translation_key = "descale_pct"

    def __init__(self, mqtt_client, device_info) -> None:
        super().__init__(mqtt_client, device_info)
        self._attr_unique_id = f"{self._machine_name}_descale_pct"

    @property
    def native_value(self):
        return (
            self._mqtt.data.get("settings", {})
            .get("NotEditable", {})
            .get("DecalPerc")
        )


class DeLonghiGroundCntPercentSensor(DeLonghiPushEntity):
    """Grounds container fill level (0–100 %).
    The machine shows an alarm when this reaches 100 %.
    Source: MachineSettings.NotEditable.GroundCntPerc
    """

    _attr_icon = "mdi:coffee-outline"
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_translation_key = "grounds_pct"

    def __init__(self, mqtt_client, device_info) -> None:
        super().__init__(mqtt_client, device_info)
        self._attr_unique_id = f"{self._machine_name}_grounds_pct"

    @property
    def native_value(self):
        return (
            self._mqtt.data.get("settings", {})
            .get("NotEditable", {})
            .get("GroundCntPerc")
        )


class DeLonghiFilterPercentSensor(DeLonghiPushEntity):
    """Water filter usage level (0–100 %).
    Source: MachineSettings.NotEditable.FilterUsagePerc
    """

    _attr_icon = "mdi:water-check"
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_translation_key = "filter_pct"

    def __init__(self, mqtt_client, device_info) -> None:
        super().__init__(mqtt_client, device_info)
        self._attr_unique_id = f"{self._machine_name}_filter_pct"

    @property
    def native_value(self):
        return (
            self._mqtt.data.get("settings", {})
            .get("NotEditable", {})
            .get("FilterUsagePerc")
        )


class DeLonghiCoffeeGroundsCountSensor(DeLonghiPushEntity):
    """Total grounds container cycle count (CoffeeGroundsCnt).

    NOTE: This is NOT the total number of beverages. CoffeeGroundsCnt counts
    the number of grounds-deposit cycles (each double espresso = 2 units).
    The machine does NOT expose a simple beverage counter via MQTT shadow;
    the Statistics shadow returns notImplemented on ECAM472.85.MB.
    Source: MachineSettings.NotEditable.CoffeeGroundsCnt
    """

    _attr_icon = "mdi:coffee-maker-outline"
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_translation_key = "grounds_count"

    def __init__(self, mqtt_client, device_info) -> None:
        super().__init__(mqtt_client, device_info)
        self._attr_unique_id = f"{self._machine_name}_grounds_count"

    @property
    def native_value(self):
        return (
            self._mqtt.data.get("settings", {})
            .get("NotEditable", {})
            .get("CoffeeGroundsCnt")
        )


class DeLonghiGranulometrySensor(DeLonghiPushEntity):
    """Current grind fineness setting (1 = finest, 7 = coarsest).
    Source: MachineSettings.NotEditable.Granulometry
    """

    _attr_icon = "mdi:grain"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_translation_key = "granulometry"

    def __init__(self, mqtt_client, device_info) -> None:
        super().__init__(mqtt_client, device_info)
        self._attr_unique_id = f"{self._machine_name}_granulometry"

    @property
    def native_value(self):
        return (
            self._mqtt.data.get("settings", {})
            .get("NotEditable", {})
            .get("Granulometry")
        )


class DeLonghiCoffeeTempSensor(DeLonghiPushEntity):
    """Coffee temperature setting (0 = low, 1 = medium, 2 = high).
    Source: MachineSettings.Editable.CoffeeTemp
    """

    _attr_icon = "mdi:thermometer"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_translation_key = "coffee_temp"

    def __init__(self, mqtt_client, device_info) -> None:
        super().__init__(mqtt_client, device_info)
        self._attr_unique_id = f"{self._machine_name}_coffee_temp"

    @property
    def native_value(self):
        return (
            self._mqtt.data.get("settings", {})
            .get("Editable", {})
            .get("CoffeeTemp")
        )


class DeLonghiWaterTotalSensor(DeLonghiPushEntity):
    """Water pump pulses since last descale (resets after descale cycle).
    Source: MachineSettings.NotEditable.WaterCalcQty
    The raw unit is water-pump pulses; no official litre conversion is known.
    NOTE: Resets to 0 after each descale, so state_class is MEASUREMENT.
    """

    _attr_icon = "mdi:water-sync"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_translation_key = "water_total"

    def __init__(self, mqtt_client, device_info) -> None:
        super().__init__(mqtt_client, device_info)
        self._attr_unique_id = f"{self._machine_name}_water_total"

    @property
    def native_value(self):
        return (
            self._mqtt.data.get("settings", {})
            .get("NotEditable", {})
            .get("WaterCalcQty")
        )

    @property
    def extra_state_attributes(self):
        ne = self._mqtt.data.get("settings", {}).get("NotEditable", {})
        return {
            "milk_clean_count": ne.get("MilkCleanCnt"),
            "filter_total_count": ne.get("FilterTotCnt"),
        }


class DeLonghiWaterLifetimeSensor(DeLonghiPushEntity):
    """Total water pumped over machine lifetime (absolute pump pulses, never resets).
    Source: MachineSettings.NotEditable.WaterTotQty
    """

    _attr_icon = "mdi:water"
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_translation_key = "water_lifetime"

    def __init__(self, mqtt_client, device_info) -> None:
        super().__init__(mqtt_client, device_info)
        self._attr_unique_id = f"{self._machine_name}_water_lifetime"

    @property
    def native_value(self):
        return (
            self._mqtt.data.get("settings", {})
            .get("NotEditable", {})
            .get("WaterTotQty")
        )


class DeLonghiDescaleCountSensor(DeLonghiPushEntity):
    """Total number of completed descale cycles.
    Source: MachineSettings.NotEditable.CalcTotCnt
    """

    _attr_icon = "mdi:counter"
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_translation_key = "descale_count"

    def __init__(self, mqtt_client, device_info) -> None:
        super().__init__(mqtt_client, device_info)
        self._attr_unique_id = f"{self._machine_name}_descale_count"

    @property
    def native_value(self):
        return (
            self._mqtt.data.get("settings", {})
            .get("NotEditable", {})
            .get("CalcTotCnt")
        )


class DeLonghiFilterChangeCountSensor(DeLonghiPushEntity):
    """Total number of water filter changes.
    Source: MachineSettings.NotEditable.FilterTotCnt
    """

    _attr_icon = "mdi:counter"
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_translation_key = "filter_change_count"

    def __init__(self, mqtt_client, device_info) -> None:
        super().__init__(mqtt_client, device_info)
        self._attr_unique_id = f"{self._machine_name}_filter_change_count"

    @property
    def native_value(self):
        return (
            self._mqtt.data.get("settings", {})
            .get("NotEditable", {})
            .get("FilterTotCnt")
        )


class DeLonghiActiveProfileSensor(DeLonghiPushEntity):
    """Currently active user profile (1-4).
    Source: MachineSettings.Editable.SetProfile
    """

    _attr_icon = "mdi:account-circle-outline"
    _attr_translation_key = "active_profile_sensor"

    def __init__(self, mqtt_client, device_info) -> None:
        super().__init__(mqtt_client, device_info)
        self._attr_unique_id = f"{self._machine_name}_active_profile_sensor"

    @property
    def native_value(self):
        return (
            self._mqtt.data.get("settings", {})
            .get("Editable", {})
            .get("SetProfile")
        )


# ---------------------------------------------------------------------------
# Platform setup
# ---------------------------------------------------------------------------

async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    data = hass.data[DOMAIN][entry.entry_id]
    mqtt_client = data["mqtt"]
    device_info = data["device_info"]

    async_add_entities(
        [
            # Status (MachineStatus shadow)
            DeLonghiStatusSensor(mqtt_client, device_info),
            DeLonghiBeverageProgressSensor(mqtt_client, device_info),
            DeLonghiLanIpSensor(mqtt_client, device_info),
            # Capabilities (static device info)
            DeLonghiModelSensor(mqtt_client, device_info),
            # Maintenance percentages (MachineSettings.NotEditable.*Perc)
            DeLonghiDescalePercentSensor(mqtt_client, device_info),
            DeLonghiGroundCntPercentSensor(mqtt_client, device_info),
            DeLonghiFilterPercentSensor(mqtt_client, device_info),
            # Counters (MachineSettings.NotEditable)
            DeLonghiCoffeeGroundsCountSensor(mqtt_client, device_info),
            DeLonghiWaterLifetimeSensor(mqtt_client, device_info),
            DeLonghiDescaleCountSensor(mqtt_client, device_info),
            DeLonghiFilterChangeCountSensor(mqtt_client, device_info),
            # Settings read-only (also controlled via select/switch entities)
            DeLonghiGranulometrySensor(mqtt_client, device_info),
            DeLonghiCoffeeTempSensor(mqtt_client, device_info),
            DeLonghiWaterTotalSensor(mqtt_client, device_info),
            DeLonghiActiveProfileSensor(mqtt_client, device_info),
        ]
    )
