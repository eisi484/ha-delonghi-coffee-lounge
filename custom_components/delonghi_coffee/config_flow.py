"""Config flow for De'Longhi Coffee (Coffee Lounge / Daedalus).

The account password is stored in the config entry (see `__init__.py`'s
module docstring for why — short version: this Gigya site has no working
password-free token-refresh call, confirmed against a real account with
`tools/gigya_diagnose.py`). Home Assistant's reauth flow is still wired up
for when the stored password is actually rejected (changed elsewhere,
account issue, ...), not for routine token rotation.
"""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.data_entry_flow import FlowResult

from .api import DeLonghiAPI, DeLonghiApiError, DeLonghiAuthError, extract_owned_devices
from .const import CONF_POOL, DOMAIN

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_EMAIL): str,
        vol.Required(CONF_PASSWORD): str,
    }
)

STEP_REAUTH_DATA_SCHEMA = vol.Schema({vol.Required(CONF_PASSWORD): str})


class DeLonghiConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for De'Longhi Coffee (Coffee Lounge)."""

    VERSION = 1

    def __init__(self) -> None:
        super().__init__()
        # Override-able at test time to inject a mock API client without
        # touching the network.
        self._api_factory = DeLonghiAPI
        self._reauth_entry: config_entries.ConfigEntry | None = None

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            email = user_input[CONF_EMAIL]
            password = user_input[CONF_PASSWORD]
            try:
                api = await self.hass.async_add_executor_job(
                    self._api_factory.from_password, email, password
                )
                devices = await self.hass.async_add_executor_job(api.get_devices)
            except DeLonghiAuthError:
                errors["base"] = "auth_failed"
            except DeLonghiApiError:
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected error during config flow")
                errors["base"] = "unknown"
            else:
                owned = extract_owned_devices(devices)
                if not owned:
                    errors["base"] = "no_devices"
                else:
                    await self.async_set_unique_id(email)
                    self._abort_if_unique_id_configured()
                    # CONF_POOL is cached so later logins (every MQTT
                    # reconnect) skip probing all three pools — see
                    # api.DeLonghiAPI._login_probing_pools.
                    return self.async_create_entry(
                        title="De'Longhi Coffee Lounge",
                        data={
                            CONF_EMAIL: email,
                            CONF_PASSWORD: password,
                            CONF_POOL: api.pool,
                        },
                    )

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
        )

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> FlowResult:
        """Triggered by HA (via ConfigEntryAuthFailed) when the stored
        password is rejected by Gigya, or on a leftover 0.4.x entry that
        has no password stored at all (see __init__._migrate_legacy_password_entry)."""
        self._reauth_entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Ask only for the password; email and everything else stays as configured."""
        errors: dict[str, str] = {}
        entry = self._reauth_entry

        if user_input is not None and entry is not None:
            email = entry.data[CONF_EMAIL]
            password = user_input[CONF_PASSWORD]
            try:
                api = await self.hass.async_add_executor_job(
                    self._api_factory.from_password, email, password
                )
            except DeLonghiAuthError:
                errors["base"] = "auth_failed"
            except DeLonghiApiError:
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected error during De'Longhi reauth")
                errors["base"] = "unknown"
            else:
                # A password change can also move the account to a
                # different pool server-side, so always take whatever pool
                # *this* login resolved to, not the entry's old one.
                self.hass.config_entries.async_update_entry(
                    entry,
                    data={**entry.data, CONF_PASSWORD: password, CONF_POOL: api.pool},
                )
                await self.hass.config_entries.async_reload(entry.entry_id)
                return self.async_abort(reason="reauth_successful")

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=STEP_REAUTH_DATA_SCHEMA,
            description_placeholders={"email": entry.data[CONF_EMAIL] if entry else ""},
            errors=errors,
        )
