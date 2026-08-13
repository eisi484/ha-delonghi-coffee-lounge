# De'Longhi Coffee Lounge Integration for Home Assistant

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/default)
[![GitHub release](https://img.shields.io/github/v/release/eisi484/ha-delonghi-coffee-lounge?include_prereleases)](https://github.com/eisi484/ha-delonghi-coffee-lounge/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Custom integration for Home Assistant providing full real-time telemetry, status sensors, interactive controls (temperature, grind size, profile, switches), and BLE pairing for De'Longhi coffee machines connected via the **De'Longhi Coffee Lounge** app (e.g. Eletta Explore ECAM47080).

> [!NOTE]  
> This integration communicates directly with **AWS IoT Core** via long-lived MQTT push connections (no polling delay) and supports setting machine options using AWS IoT Shadow updates.

---

## ✨ Features

- ⚡ **Real-Time Telemetry (Push):** Immediate state updates via persistent AWS IoT MQTT5 push connection.
- 🎛️ **5 Interactive Select Controls:** Temperature, auto turn-off delay, water hardness, grind setting (granulometry), active profile.
- 🔘 **8 Interactive Switches:** Audio beeps, energy saving, cup warmer plate, auto shut-off, remote power-on lock, water filter installed, 24h clock, external LED.
- 📊 **16 Telemetry & Statistic Sensors:** Live status, beverage progress, total coffees, water volume (descale & lifetime), descale/filter counters, maintenance percentages.
- 🚨 **44 Binary Sensors & Alarms:** Complete breakdown of machine alarms, peripherals, accessories, and settings status.
- 🔵 **Bluetooth LE (BLE) Pairing Service:** Built-in `delonghi_coffee.ble_pair` service to pair unprovisioned/reset machines via Bluetooth.

---

## 🛠️ Installation via HACS (Recommended)

1. Make sure [HACS](https://hacs.xyz/) is installed in your Home Assistant instance.
2. Open **HACS** in Home Assistant.
3. Click on the **3 dots** in the top right corner and choose **Custom repositories**.
4. Add the repository URL:
   ```text
   https://github.com/eisi484/ha-delonghi-coffee-lounge
   ```
   Category: **Integration**
5. Click **Add**, then search for **De'Longhi Coffee Lounge** in HACS and click **Download**.
6. Restart Home Assistant.

---

## ⚙️ Setup & Configuration

1. In Home Assistant, navigate to **Settings → Devices & Services → Add Integration**.
2. Search for **De'Longhi Coffee Lounge**.
3. Enter your **De'Longhi Coffee Lounge** app credentials (email & password).
4. The integration will automatically discover your machine(s) and start receiving real-time updates.

---

## 📖 Complete Entity Reference

### 🎛️ Select Entities (Writable Controls)
| Entity | Options | Description |
|---|---|---|
| `select.coffee_temperature` | Low, Medium, High | Writable coffee temperature setting |
| `select.auto_turn_off_time` | 15 min, 30 min, 60 min, 180 min | Writable auto shut-off delay |
| `select.water_hardness` | Very Soft, Soft, Medium, Hard | Writable water hardness level |
| `select.grind_setting` | 1 - 7 | Writable grinder setting (Granulometry) |
| `select.active_profile` | Profile 1 - 4 | Active user profile on machine |

---

### 🔘 Switch Entities (Writable Controls)
| Entity | Description |
|---|---|
| `switch.machine_sound` | Toggle machine audio beeps |
| `switch.energy_saving_mode` | Toggle eco / energy saving mode |
| `switch.cup_warmer` | Toggle cup warming plate |
| `switch.auto_shutoff` | Toggle automatic shut-off feature |
| `switch.remote_power_on_disabled` | Lock remote power-on functionality |
| `switch.water_filter_installed` | Toggle filter installed status |
| `switch.24_hour_clock` | Toggle 12/24 hour display |
| `switch.external_led` | Toggle external LED light |

---

### 📊 Telemetry & Statistic Sensors (16 Entities)
| Sensor | Unit / Options | Description |
|---|---|---|
| `sensor.status` | Text | Current machine state (Standby, Initialization, BeverageDispensing, Busy, Cleaning...) |
| `sensor.beverage_progress` | % | Active dispensing progress percentage |
| `sensor.total_coffees_dispensed` | Count | Lifetime total coffee counter |
| `sensor.water_pumped_since_descale` | Pulses | Water pumped since last descale |
| `sensor.water_pumped_lifetime` | Pulses | Total lifetime water pumped |
| `sensor.descale_cycles` | Count | Completed descale cycles counter |
| `sensor.filter_changes` | Count | Total water filter replacements counter |
| `sensor.descale_level` | % | Remaining capacity percentage before descale |
| `sensor.grounds_container_level` | % | Capacity level of grounds container |
| `sensor.water_filter_level` | % | Remaining filter capacity percentage |
| `sensor.grind_setting` | 1 - 7 | Current grind setting |
| `sensor.coffee_temperature_setting` | 0 - 2 | Current coffee temperature level |
| `sensor.water_pump_cycles_since_descale` | Pulses | Raw water pump pulses since descale |
| `sensor.active_user_profile` | 1 - 4 | Active user profile number |
| `sensor.lan_ip` | IP Address | Machine IP on local Wi-Fi |
| `sensor.model` | Text | Machine model identifier |

---

### 🚨 Alarm & Problem Binary Sensors (21 Entities)
| Binary Sensor | Description |
|---|---|
| `binary_sensor.descale_needed` | Descale cycle required alarm |
| `binary_sensor.water_tank_low` | Water tank empty / low alarm |
| `binary_sensor.coffee_beans_empty` | Coffee bean hopper empty alarm |
| `binary_sensor.empty_grounds_container` | Grounds container full / missing alarm |
| `binary_sensor.replace_water_filter` | Water filter replacement required |
| `binary_sensor.grind_too_fine` | Grinding too fine alarm |
| `binary_sensor.grinder_fault` | Grinder motor fault alarm |
| `binary_sensor.clean_brew_unit` | Brew unit cleaning required |
| `binary_sensor.cleaning_required` | General cleaning required alarm |
| `binary_sensor.drain_fault` | Water drain fault alarm |
| `binary_sensor.infuser_fault` | Infuser mechanism fault alarm |
| `binary_sensor.motor_position_fault` | Motor position sensor fault |
| `binary_sensor.heater_temperature_fault` | Heater NTC sensor fault |
| `binary_sensor.air_bubble_detected` | Air bubble in hydraulic circuit |
| `binary_sensor.coffee_inlet_fault` | Coffee funnel / inlet fault |
| `binary_sensor.fan_fault` | Internal cooling fan fault |
| `binary_sensor.fridge_fault` | Milk fridge fault alarm |
| `binary_sensor.general_alarm` | General machine hardware alarm |
| `binary_sensor.display_memory_fault` | UI / display memory fault |
| `binary_sensor.wi_fi_down` | Machine Wi-Fi connection down |
| `binary_sensor.water_tank_missing` | Water tank not present alarm |

---

### 🔌 Peripherals Binary Sensors (10 Entities)
| Binary Sensor | Description |
|---|---|
| `binary_sensor.water_spout_attached` | Water spout attached to machine |
| `binary_sensor.milk_container_attached` | Milk container (LatteCrema) attached |
| `binary_sensor.lattecrema_hot_detected` | LatteCrema Hot variant container detected |
| `binary_sensor.water_tank_inserted` | Water tank physically inserted |
| `binary_sensor.water_tank_low` | Water tank level sensor |
| `binary_sensor.drip_tray_inserted` | Drip tray inserted |
| `binary_sensor.front_switch_active` | Front power / door switch active |
| `binary_sensor.grinder_switch` | Grinder position microswitch |
| `binary_sensor.brew_unit_down_position` | Brew unit motor at bottom position |
| `binary_sensor.brew_unit_up_position` | Brew unit motor at top position |

---

### 🥛 Accessories Binary Sensors (6 Entities)
| Binary Sensor | Description |
|---|---|
| `binary_sensor.water_accessory_attached` | Hot water accessory attached |
| `binary_sensor.hot_milk_frother_attached` | Hot milk frother attached |
| `binary_sensor.hot_cleaning_accessory_attached` | Hot cleaning spout attached |
| `binary_sensor.cold_milk_frother_attached` | Cold milk frother attached |
| `binary_sensor.milk_container_in_cleaning_position` | Milk container knob set to CLEAN |
| `binary_sensor.steam_wand_attached` | Steam wand accessory attached |

---

### ⚙️ Settings Binary Sensors (6 Entities)
| Binary Sensor | Description |
|---|---|
| `binary_sensor.sound_enabled` | Sound / beeps enabled status |
| `binary_sensor.energy_saving_mode` | Energy saving mode active |
| `binary_sensor.cup_warmer` | Cup warmer active |
| `binary_sensor.auto_shut_off_enabled` | Auto shut-off feature active |
| `binary_sensor.power_on_disabled_remote_lock` | Remote power-on locked status |
| `binary_sensor.water_filter_installed` | Water filter installed status |

---

### 📶 Connectivity Binary Sensor (1 Entity)
| Binary Sensor | Description |
|---|---|
| `binary_sensor.online` | Integration connected & receiving AWS IoT push updates |

---

## 🔵 BLE Pairing Service

The integration includes a custom service `delonghi_coffee.ble_pair` to pair a machine over Bluetooth (e.g. after a Wi-Fi reset or initial setup):

```yaml
service: delonghi_coffee.ble_pair
data:
  ble_mac: "84:1F:E8:3B:9A:94"
  pin: "123456"
  ssid: "Your_WiFi_Name"
  password: "Your_WiFi_Password"
```

---

## 🔒 Security & Architecture

- **Identity Provider:** Gigya (`accounts.eu1.gigya.com`) for authenticating user credentials.
- **Push Telemetry:** AWS IoT Core (`a2612mo23mfrw1-ats.iot.eu-central-1.amazonaws.com`) via an unsigned Custom Authorizer (`dlg-prod-token-authorizer`).
- **Shadow Desired Updates:** Writable options publish JSON patches to `$aws/things/{MachineName}/shadow/name/MachineSettings/update` under `state.desired.Editable`.

---

## 📄 License

Distributed under the [MIT License](LICENSE).
