"""Diagnostics support for the De'Longhi Coffee (Coffee Lounge) integration.

Provides a HA-native "Download diagnostics" payload that triages auth /
MQTT-connectivity bugs without asking users to scrape logs by hand. All
fields that could leak the user's account, session, or machine identity are
redacted via `homeassistant.components.diagnostics.async_redact_data`.
"""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN

# Anything with one of these keys is replaced with "**REDACTED**" in the
# payload, recursively, wherever it appears (entry.data, device_info, the
# MQTT shadow snapshot, ...). Conservative on purpose: even the email and
# serial number are redacted, since the support zip can end up attached to
# a public GitHub issue.
REDACT_KEYS: set[str] = {
    "email",
    "password",  # stored in every entry now — see api.DeLonghiAPI's docstring for why
    "session_token",
    "id_token",
    "jwt",
    "AuthToken",
    "apiKey",
    "uid",
    "uidSignature",
    "signatureTimestamp",
    # Machine / account identity (from the AWS /devices response and MQTT
    # shadow payloads):
    "machineName",
    "serialNumber",
    "SN",
    "SKU",
    "sku",
    "MAC",
    "mac_address",
    "LanIpAddress",
}


async def async_get_config_entry_diagnostics(hass: HomeAssistant, entry: ConfigEntry) -> dict[str, Any]:
    """Return a redacted diagnostics dump for a De'Longhi config entry."""
    entry_runtime_data = hass.data.get(DOMAIN, {}).get(entry.entry_id, {})

    mqtt_client = entry_runtime_data.get("mqtt")
    device_info = entry_runtime_data.get("device_info", {})

    mqtt_state: dict[str, Any] = {"configured": mqtt_client is not None}
    if mqtt_client is not None:
        mqtt_state.update(
            {
                "shadow_data_present": {
                    "status": "status" in mqtt_client.data,
                    "capabilities": "capabilities" in mqtt_client.data,
                },
                # Full shadow payloads can be large and contain the
                # machine's MAC/serial in nested fields — redact recursively
                # rather than hand-picking which nested keys are safe.
                "shadow_data": async_redact_data(mqtt_client.data, REDACT_KEYS),
            }
        )

    return {
        "entry": {
            "version": entry.version,
            "data": async_redact_data(dict(entry.data), REDACT_KEYS),
            "options": async_redact_data(dict(entry.options), REDACT_KEYS),
        },
        "device_info": async_redact_data(dict(device_info), REDACT_KEYS),
        "mqtt": mqtt_state,
    }


async def async_get_device_diagnostics(
    hass: HomeAssistant,
    entry: ConfigEntry,
    device,  # noqa: ANN001 — DeviceEntry, type avoided to skip an import cycle
) -> dict[str, Any]:
    """Device-scoped diagnostics — same payload as entry-scoped (single device per entry today)."""
    return await async_get_config_entry_diagnostics(hass, entry)
