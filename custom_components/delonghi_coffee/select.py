"""Select entities for De'Longhi Coffee — writable MachineSettings.Editable fields.

All values come from MachineCapabilities (option lists) and MachineSettings.Editable
(current values), both confirmed live 2026-08-13 (ECAM47080).

Control path:
  HA select → DeLonghiMqttClient.publish_settings({"FieldName": value})
  → $aws/things/{mac}/shadow/name/MachineSettings/update
    payload: {"state": {"desired": {"Editable": {"FieldName": value}}}}
  ← machine echoes new value on MachineSettings/update/accepted → entity updates

Confirmed Editable fields (from MachineSettings.Editable, 2026-08-13):
  CoffeeTemp:          int 0-2   (Low / Medium / High)
  AutoTurnOffTimeInMin:int 15|30|60|180
  WaterHardness:       int 0-3   (Very Soft / Soft / Medium / Hard)
  SetProfile:          int 1-4   (active user profile)

Granulometry lives in MachineSettings.NotEditable in some pushes and Editable
in others; we treat it as editable (the app clearly shows it as a setting).
"""

from __future__ import annotations

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, SIGNAL_UPDATE


class DeLonghiSelectBase(SelectEntity):
    """Base class for De'Longhi select entities (writable via Shadow desired)."""

    _attr_should_poll = False
    _attr_has_entity_name = True

    def __init__(self, mqtt_client, device_info: dict) -> None:
        self._mqtt = mqtt_client
        self._device_info = device_info
        self._machine_name = device_info["machineName"]

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                SIGNAL_UPDATE.format(machine_name=self._machine_name),
                self._handle_update,
            )
        )

    def _handle_update(self) -> None:
        self.schedule_update_ha_state()

    @property
    def device_info(self) -> dict:
        caps = self._mqtt.data.get("capabilities", {})
        return {
            "identifiers": {(DOMAIN, self._machine_name)},
            "name": "De'Longhi Coffee Lounge",
            "manufacturer": "De'Longhi",
            "model": caps.get("MachineModelUI") or self._device_info.get("machineModel"),
        }

    def _editable(self) -> dict:
        return self._mqtt.data.get("settings", {}).get("Editable", {})

    def _caps(self) -> dict:
        return self._mqtt.data.get("capabilities", {})

    async def _async_set(self, patch: dict) -> None:
        """Write a partial Editable update via Shadow desired (executor-safe)."""
        await self.hass.async_add_executor_job(self._mqtt.publish_settings, patch)


# ---------------------------------------------------------------------------
# Coffee Temperature
# ---------------------------------------------------------------------------

class DeLonghiCoffeeTempSelect(DeLonghiSelectBase):
    """Coffee temperature: 0=Low, 1=Medium, 2=High.

    Options come from MachineCapabilities.CoffeeTemperatures (confirmed: [0,1,2]).
    """

    _attr_translation_key = "coffee_temperature"
    _attr_icon = "mdi:thermometer"

    # Human-readable labels indexed by the machine's integer value
    _LABELS = {0: "Low", 1: "Medium", 2: "High"}

    def __init__(self, mqtt_client, device_info: dict) -> None:
        super().__init__(mqtt_client, device_info)
        self._attr_unique_id = f"{self._machine_name}_coffee_temperature"

    @property
    def options(self) -> list[str]:
        cap_vals = self._caps().get("CoffeeTemperatures", [0, 1, 2])
        return [self._LABELS.get(v, str(v)) for v in cap_vals]

    @property
    def current_option(self) -> str | None:
        val = self._editable().get("CoffeeTemp")
        if val is None:
            return None
        return self._LABELS.get(val, str(val))

    async def async_select_option(self, option: str) -> None:
        rev = {v: k for k, v in self._LABELS.items()}
        if option not in rev:
            return
        await self._async_set({"CoffeeTemp": rev[option]})


# ---------------------------------------------------------------------------
# Auto Turn-Off Time
# ---------------------------------------------------------------------------

class DeLonghiAutoOffSelect(DeLonghiSelectBase):
    """Auto turn-off time in minutes.

    Options from MachineCapabilities.AutoTurnOffTimeInMinutes (confirmed: [15,30,60,180]).
    """

    _attr_translation_key = "auto_off_time"
    _attr_icon = "mdi:timer-off-outline"

    def __init__(self, mqtt_client, device_info: dict) -> None:
        super().__init__(mqtt_client, device_info)
        self._attr_unique_id = f"{self._machine_name}_auto_off_time"

    @property
    def options(self) -> list[str]:
        vals = self._caps().get("AutoTurnOffTimeInMinutes", [15, 30, 60, 180])
        return [f"{v} min" for v in vals]

    @property
    def current_option(self) -> str | None:
        val = self._editable().get("AutoTurnOffTimeInMin")
        if val is None:
            return None
        return f"{val} min"

    async def async_select_option(self, option: str) -> None:
        # Strip " min" suffix and convert to int
        try:
            minutes = int(option.replace(" min", "").strip())
        except ValueError:
            return
        await self._async_set({"AutoTurnOffTimeInMin": minutes})


# ---------------------------------------------------------------------------
# Water Hardness
# ---------------------------------------------------------------------------

class DeLonghiWaterHardnessSelect(DeLonghiSelectBase):
    """Water hardness level: 0=Very Soft, 1=Soft, 2=Medium, 3=Hard.

    Options from MachineCapabilities.WaterHardness (confirmed: [0,1,2,3]).
    """

    _attr_translation_key = "water_hardness"
    _attr_icon = "mdi:water-check"

    _LABELS = {0: "Very Soft", 1: "Soft", 2: "Medium", 3: "Hard"}

    def __init__(self, mqtt_client, device_info: dict) -> None:
        super().__init__(mqtt_client, device_info)
        self._attr_unique_id = f"{self._machine_name}_water_hardness"

    @property
    def options(self) -> list[str]:
        vals = self._caps().get("WaterHardness", [0, 1, 2, 3])
        return [self._LABELS.get(v, str(v)) for v in vals]

    @property
    def current_option(self) -> str | None:
        val = self._editable().get("WaterHardness")
        if val is None:
            return None
        return self._LABELS.get(val, str(val))

    async def async_select_option(self, option: str) -> None:
        rev = {v: k for k, v in self._LABELS.items()}
        if option not in rev:
            return
        await self._async_set({"WaterHardness": rev[option]})


# ---------------------------------------------------------------------------
# Grind Setting (Granulometry)
# ---------------------------------------------------------------------------

class DeLonghiGranulometrySelect(DeLonghiSelectBase):
    """Grind setting: 1 (finest) to 7 (coarsest).

    Options from MachineCapabilities.Granulometries (confirmed: [1,2,3,4,5,6,7]).
    Current value from MachineSettings.NotEditable.Granulometry (or Editable
    in some firmware pushes — we check both).
    """

    _attr_translation_key = "grind_setting"
    _attr_icon = "mdi:coffee-outline"

    def __init__(self, mqtt_client, device_info: dict) -> None:
        super().__init__(mqtt_client, device_info)
        self._attr_unique_id = f"{self._machine_name}_granulometry"

    @property
    def options(self) -> list[str]:
        vals = self._caps().get("Granulometries", list(range(1, 8)))
        return [str(v) for v in vals]

    @property
    def current_option(self) -> str | None:
        settings = self._mqtt.data.get("settings", {})
        # The field appears in both Editable and NotEditable depending on firmware push
        val = (
            settings.get("Editable", {}).get("Granulometry")
            or settings.get("NotEditable", {}).get("Granulometry")
        )
        if val is None:
            return None
        return str(val)

    async def async_select_option(self, option: str) -> None:
        try:
            val = int(option)
        except ValueError:
            return
        await self._async_set({"Granulometry": val})


# ---------------------------------------------------------------------------
# Active User Profile
# ---------------------------------------------------------------------------

class DeLonghiProfileSelect(DeLonghiSelectBase):
    """Active user profile: 1-4.

    Number of profiles from MachineCapabilities.MachineUserProfiles (confirmed: 4).
    Current value from MachineSettings.Editable.SetProfile (confirmed: 1).
    """

    _attr_translation_key = "active_profile"
    _attr_icon = "mdi:account-circle-outline"

    def __init__(self, mqtt_client, device_info: dict) -> None:
        super().__init__(mqtt_client, device_info)
        self._attr_unique_id = f"{self._machine_name}_active_profile"

    @property
    def options(self) -> list[str]:
        num = self._caps().get("MachineUserProfiles", 4)
        return [str(i) for i in range(1, num + 1)]

    @property
    def current_option(self) -> str | None:
        val = self._editable().get("SetProfile")
        if val is None:
            return None
        return str(val)

    async def async_select_option(self, option: str) -> None:
        try:
            val = int(option)
        except ValueError:
            return
        await self._async_set({"SetProfile": val})


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

    async_add_entities([
        DeLonghiCoffeeTempSelect(mqtt_client, device_info),
        DeLonghiAutoOffSelect(mqtt_client, device_info),
        DeLonghiWaterHardnessSelect(mqtt_client, device_info),
        DeLonghiGranulometrySelect(mqtt_client, device_info),
        DeLonghiProfileSelect(mqtt_client, device_info),
    ])
