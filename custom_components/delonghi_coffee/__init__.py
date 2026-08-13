"""De'Longhi Coffee (Coffee Lounge / Daedalus) integration for Home Assistant.

Communication model (verified working for status/telemetry, see
SESSION_NOTES.md):

    Gigya login (email/password -> id_token, every refresh)
        -> AWS REST GET /devices (Bearer id_token, once at setup)
        -> persistent AWS IoT Core MQTT5 connection (unsigned Custom
           Authorizer, password = raw Gigya id_token)
        -> subscribe to the machine's MachineStatus / MachineCapabilities
           device-shadow topics
        -> every push updates entities via a dispatcher signal (cloud_push,
           no polling)

Auth/credential handling (see api.py / gigya_auth.py / config_flow.py):
    The account password IS stored in the config entry and is resent on
    every id_token refresh (every MQTT reconnect, effectively). This was
    NOT the original design of this file: 0.4.0 tried to avoid storing the
    password by persisting a Gigya `session_token` instead and rotating a
    fresh id_token via a password-free `accounts.getJWT` call. That call
    was confirmed non-functional for this Gigya site's `targetEnv=mobile`
    sessions — error 403005, "Session not found" — against a real account
    on 2026-08-10 (see tools/gigya_diagnose.py and gigya_auth.py's module
    docstring for the full writeup). There is currently no known
    password-free way to mint a fresh id_token for this app, so this
    reverts to the original, pre-0.4.0 approach: a full login on every
    refresh. Home Assistant's config entry storage isn't field-level
    encrypted regardless of which credential is stored here, so this
    carries the same exposure the pre-0.4.0 code always had.

    `async_setup_entry` still raises `ConfigEntryAuthFailed` (surfaced by
    HA as a reauth flow) when the stored password is actually rejected —
    e.g. the account password was changed elsewhere — rather than retrying
    forever.

    Entries left over from the 0.4.0/0.4.1 session_token-only design (no
    password stored) can't be un-broken automatically — see
    `_migrate_legacy_password_entry` — and get one clean reauth prompt.

Sending commands to the machine (brewing, power on/off, ...) is NOT
implemented. The command topic (`{machineName}/commands/request`) is known,
but the JSON payload schema is assembled in the app's Flutter/Dart layer and
is not visible via static analysis or MITM (Flutter uses its own BoringSSL
and ignores the system proxy/cert store). See SESSION_NOTES.md section 5 for
the planned Frida-based approach to recover it. Until then, this integration
is read-only.
"""

from __future__ import annotations

import json
import logging
import uuid
from concurrent.futures import Future

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady, HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.dispatcher import async_dispatcher_send

from .api import DeLonghiAPI, DeLonghiApiError, DeLonghiAuthError, extract_owned_devices
from .ble_pairing import DeLonghiBleProvisioner, async_aws_confirm_pairing
from .const import (
    CONF_POOL,
    CONF_SESSION_TOKEN,
    DEFAULT_GIGYA_POOL,
    DOMAIN,
    MQTT_AUTHORIZER,
    MQTT_CONNECT_TIMEOUT_SECONDS,
    MQTT_ENDPOINT,
    MQTT_KEEPALIVE_SECONDS,
    MQTT_SUBSCRIBE_TIMEOUT_SECONDS,
    PLATFORMS,
    SHADOW_MACHINE_CAPABILITIES,
    SHADOW_MACHINE_SETTINGS,
    SHADOW_MACHINE_STATUS,
    SIGNAL_UPDATE,
)

_LOGGER = logging.getLogger(__name__)

# Re-exported for backwards compatibility: earlier versions defined these
# names directly in this module. config_flow.py and any external code that
# still does `from . import DeLonghiAPI` (rather than `from .api import
# DeLonghiAPI`) keeps working.
__all__ = [
    "DOMAIN",
    "DeLonghiAPI",
    "DeLonghiApiError",
    "DeLonghiAuthError",
    "async_setup_entry",
    "async_unload_entry",
]


class DeLonghiMqttClient:
    """Wraps an awscrt MQTT5 client with the machine's unsigned Custom Authorizer.

    Keeps a long-lived push connection to AWS IoT and republishes shadow
    updates to Home Assistant via the dispatcher, so entities update
    immediately instead of on a poll interval.
    """

    def __init__(self, hass: HomeAssistant, api: DeLonghiAPI, machine_name: str) -> None:
        self.hass = hass
        self.api = api
        self.machine_name = machine_name
        self.data: dict = {}
        self._client = None
        self._client_id = f"dlg-appliance-kit-android-{uuid.uuid4()}"
        self._stopped = False

    async def async_start(self) -> None:
        await self.hass.async_add_executor_job(self._connect_blocking)

    async def async_stop(self) -> None:
        self._stopped = True
        if self._client is not None:
            await self.hass.async_add_executor_job(self._client.stop)

    # -- everything below runs on the executor thread --------------------

    def _connect_blocking(self) -> None:
        from awscrt import io, mqtt5

        token = self.api.get_fresh_token()

        def ws_handshake_transform(transform_args):
            request = transform_args.http_request
            request.path = request.path + f"?x-amz-customauthorizer-name={MQTT_AUTHORIZER}"
            transform_args.set_done()

        connected_future: Future = Future()

        def on_success(data):
            if not connected_future.done():
                connected_future.set_result(True)

        def on_failure(data):
            if not connected_future.done():
                connected_future.set_exception(data.exception)

        def on_disconnection(data):
            _LOGGER.warning("De'Longhi MQTT disconnected: %s", data)
            if not self._stopped:
                # Reconnect with a fresh token; awscrt's own auto-reconnect
                # would reuse the stale one, which the authorizer will reject.
                self.hass.add_job(self._schedule_reconnect)

        def on_publish(publish_packet_data):
            self._handle_publish(publish_packet_data)

        event_loop_group = io.EventLoopGroup(1)
        host_resolver = io.DefaultHostResolver(event_loop_group)
        client_bootstrap = io.ClientBootstrap(event_loop_group, host_resolver)
        tls_ctx_options = io.TlsContextOptions()
        tls_ctx = io.ClientTlsContext(tls_ctx_options)

        # awscrt >= 0.21 moved client_id / username / password /
        # keep_alive_interval_sec out of ClientOptions into ConnectPacket.
        connect_options = mqtt5.ConnectPacket(
            client_id=self._client_id,
            username=MQTT_AUTHORIZER,
            password=token.encode("utf-8"),
            keep_alive_interval_sec=MQTT_KEEPALIVE_SECONDS,
        )

        client_options = mqtt5.ClientOptions(
            host_name=MQTT_ENDPOINT,
            port=443,
            bootstrap=client_bootstrap,
            tls_ctx=tls_ctx,
            connect_options=connect_options,
            websocket_handshake_transform=ws_handshake_transform,
            on_lifecycle_event_connection_success_fn=on_success,
            on_lifecycle_event_connection_failure_fn=on_failure,
            on_lifecycle_event_disconnection_fn=on_disconnection,
            on_publish_callback_fn=on_publish,
        )

        client = mqtt5.Client(client_options)
        client.start()
        connected_future.result(timeout=MQTT_CONNECT_TIMEOUT_SECONDS)
        self._client = client

        self._subscribe_and_request(mqtt5)
        _LOGGER.info("De'Longhi MQTT connected for %s", self.machine_name)

    def _subscribe_and_request(self, mqtt5) -> None:
        base = f"$aws/things/{self.machine_name}/shadow/name"
        topics = [
            f"{base}/{SHADOW_MACHINE_STATUS}/update/accepted",
            f"{base}/{SHADOW_MACHINE_STATUS}/get/accepted",
            f"{base}/{SHADOW_MACHINE_CAPABILITIES}/get/accepted",
            f"{base}/{SHADOW_MACHINE_CAPABILITIES}/update/accepted",
            f"{base}/{SHADOW_MACHINE_SETTINGS}/get/accepted",
            f"{base}/{SHADOW_MACHINE_SETTINGS}/update/accepted",
        ]
        sub_future = self._client.subscribe(
            mqtt5.SubscribePacket(
                subscriptions=[
                    mqtt5.Subscription(topic_filter=t, qos=mqtt5.QoS.AT_LEAST_ONCE)
                    for t in topics
                ]
            )
        )
        sub_future.result(timeout=MQTT_SUBSCRIBE_TIMEOUT_SECONDS)

        # Pull current state immediately so entities aren't empty until the
        # next spontaneous update from the machine.
        for shadow in (SHADOW_MACHINE_STATUS, SHADOW_MACHINE_CAPABILITIES, SHADOW_MACHINE_SETTINGS):
            self._client.publish(
                mqtt5.PublishPacket(
                    topic=f"{base}/{shadow}/get",
                    payload=b"",
                    qos=mqtt5.QoS.AT_LEAST_ONCE,
                )
            )

    def _handle_publish(self, publish_packet_data) -> None:
        topic = publish_packet_data.publish_packet.topic
        try:
            payload = json.loads(publish_packet_data.publish_packet.payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _LOGGER.debug("Non-JSON payload on %s", topic)
            return

        reported = payload.get("state", {}).get("reported", {})
        if SHADOW_MACHINE_STATUS in topic:
            self.data["status"] = reported
        elif SHADOW_MACHINE_CAPABILITIES in topic:
            self.data["capabilities"] = reported
        elif SHADOW_MACHINE_SETTINGS in topic:
            self.data["settings"] = reported
        else:
            _LOGGER.debug("Unhandled shadow topic: %s", topic)
            return

        self.hass.loop.call_soon_threadsafe(
            async_dispatcher_send, self.hass, SIGNAL_UPDATE.format(machine_name=self.machine_name)
        )

    def publish_settings(self, editable_patch: dict) -> None:
        """Write a partial update to MachineSettings.Editable via Shadow desired.

        Publishes to:
          $aws/things/{machine}/shadow/name/MachineSettings/update
        with payload:
          {"state": {"desired": {"Editable": {...editable_patch...}}}}

        The machine processes the desired state and reports back the new
        value on the MachineSettings/update/accepted topic, which triggers
        a normal dispatcher update for all entities.

        Must be called from an executor thread (e.g. via
        hass.async_add_executor_job), not from the HA event loop.
        """
        from awscrt import mqtt5  # already imported by _connect_blocking

        if self._client is None:
            _LOGGER.warning("De'Longhi: publish_settings called before MQTT connected")
            return

        topic = (
            f"$aws/things/{self.machine_name}/shadow/name"
            f"/{SHADOW_MACHINE_SETTINGS}/update"
        )
        payload = json.dumps(
            {"state": {"desired": {"Editable": editable_patch}}}
        ).encode("utf-8")

        try:
            self._client.publish(
                mqtt5.PublishPacket(
                    topic=topic,
                    payload=payload,
                    qos=mqtt5.QoS.AT_LEAST_ONCE,
                )
            ).result(timeout=5)
            _LOGGER.debug("De'Longhi settings published: %s", editable_patch)
        except Exception:  # noqa: BLE001
            _LOGGER.exception("De'Longhi: failed to publish settings %s", editable_patch)

    def _schedule_reconnect(self) -> None:
        if self._stopped:
            return
        _LOGGER.info("Reconnecting De'Longhi MQTT with a fresh token...")
        try:
            self._connect_blocking()
        except Exception:  # noqa: BLE001 — reconnect loop must never die
            _LOGGER.exception("De'Longhi MQTT reconnect failed, will retry on next disconnect")


SERVICE_BLE_PAIR = "ble_pair"

SERVICE_BLE_PAIR_SCHEMA = vol.Schema(
    {
        vol.Required("ble_mac"): cv.string,
        vol.Required("pin"): cv.string,
        vol.Optional("ssid", default=""): cv.string,
        vol.Optional("password", default=""): cv.string,
    }
)


def _first_api(hass: HomeAssistant) -> DeLonghiAPI | None:
    """Return the DeLonghiAPI of the first configured account, if any.

    BLE pairing needs a logged-in Gigya session to confirm the pairing with
    the cloud afterwards, but is not itself tied to a specific config entry
    (it's how you'd add a *new* machine before it has one).
    """
    for entry_data in hass.data.get(DOMAIN, {}).values():
        api = entry_data.get("api")
        if api is not None:
            return api
    return None


async def _handle_ble_pair(hass: HomeAssistant, call: ServiceCall) -> None:
    """Pair a machine over BLE: Security1 handshake, optional WiFi provisioning,
    machine-ID read, and AWS-side pairing confirmation.

    Does NOT establish the local LAN2LAN connection — the AuthToken for that
    is still unknown (see SESSION_NOTES.md section 7). This only completes
    the same steps the official app performs during first-time setup.
    """
    ble_mac: str = call.data["ble_mac"]
    pin: str = call.data["pin"]
    ssid: str = call.data.get("ssid", "")
    password: str = call.data.get("password", "")

    api = _first_api(hass)
    if api is None:
        raise HomeAssistantError(
            "No De'Longhi Coffee Lounge account configured — set up the "
            "integration (email/password) before pairing a machine."
        )

    provisioner = DeLonghiBleProvisioner(ble_mac, hass=hass)
    try:
        machine_id = await provisioner.async_pair_full(pin, ssid=ssid, password=password)
    except Exception as err:  # noqa: BLE001 — surface any BLE/crypto failure to the UI
        raise HomeAssistantError(f"BLE pairing failed: {err}") from err

    if not machine_id:
        raise HomeAssistantError(
            "BLE handshake succeeded but no machine ID could be read via "
            "custom-data — cannot confirm pairing with the De'Longhi cloud."
        )

    result = await async_aws_confirm_pairing(hass, api, machine_id, pin)
    if not result["ok"]:
        raise HomeAssistantError(
            f"BLE pairing succeeded (machine_id={machine_id}) but the AWS "
            f"pairing confirmation failed: HTTP {result['status']} — {result['body'][:200]}"
        )

    _LOGGER.info(
        "BLE pairing complete for machine_id=%s. AWS confirm: HTTP %d.%s",
        machine_id,
        result["status"],
        f" Token-like fields found in response: {result['token_candidates']}"
        if result["token_candidates"]
        else "",
    )


async def _migrate_legacy_password_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Detect entries left over from the 0.4.0/0.4.1 session_token-only
    design and force a clean reauth for them.

    That design stored a Gigya `session_token` instead of the password and
    relied on `accounts.getJWT` to mint fresh id_tokens from it
    password-free. getJWT was confirmed non-functional for this app's
    sessions (see this module's docstring), so any entry that only has a
    session_token (no password) is permanently unusable as-is — there is
    no password-free way to recover it. Rather than looping on
    ConfigEntryAuthFailed with an opaque Gigya 403005 every time (what
    actually happened in practice — see the GitHub issue this fix came
    from), detect the specific shape of a 0.4.x entry and raise a clear,
    actionable error so the reauth prompt at least makes sense.

    Entries that already have a password (pre-0.4.0 entries, or any entry
    created/reauthed after this fix) are left untouched — this is a no-op
    for the now-normal case.
    """
    if entry.data.get(CONF_PASSWORD):
        return

    if entry.data.get(CONF_SESSION_TOKEN):
        raise DeLonghiAuthError(
            f"Config entry {entry.entry_id} was created by a previous version "
            "that stored a Gigya session_token instead of your password, and "
            "that session_token can no longer be used to obtain a fresh login "
            "token (Gigya's accounts.getJWT doesn't work for this app's "
            "sessions) — reauth required to store your password again"
        )

    raise DeLonghiAuthError(
        "Config entry has no stored password and no legacy session_token — reauth required"
    )


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up De'Longhi Coffee (Coffee Lounge) from a config entry."""
    email = entry.data[CONF_EMAIL]
    pool = entry.data.get(CONF_POOL, DEFAULT_GIGYA_POOL)

    try:
        await _migrate_legacy_password_entry(hass, entry)
        api = DeLonghiAPI(email, entry.data[CONF_PASSWORD], pool=pool)
        devices = await hass.async_add_executor_job(api.get_devices)
    except DeLonghiAuthError as err:
        # Covers "password rejected by Gigya", "leftover 0.4.x
        # session_token-only entry" (see _migrate_legacy_password_entry),
        # and "no usable credential at all". Either way HA should prompt
        # for the password again rather than retry forever.
        raise ConfigEntryAuthFailed(f"Invalid or expired session: {err}") from err
    except DeLonghiApiError as err:
        raise ConfigEntryNotReady(f"Cannot connect: {err}") from err

    if not entry.data.get(CONF_POOL):
        # First run after upgrade / a pre-CONF_POOL entry — cache the
        # resolved pool so future restarts don't need to probe again.
        hass.config_entries.async_update_entry(entry, data={**entry.data, CONF_POOL: api.pool})

    owned = extract_owned_devices(devices)
    if not owned:
        raise ConfigEntryNotReady("No De'Longhi machines found on this account")

    device_info = owned[0]
    machine_name = device_info["machineName"]

    mqtt_client = DeLonghiMqttClient(hass, api, machine_name)
    try:
        await mqtt_client.async_start()
    except DeLonghiAuthError as err:
        raise ConfigEntryAuthFailed(f"Invalid or expired session: {err}") from err
    except Exception as err:  # noqa: BLE001 — awscrt raises plain Exceptions
        raise ConfigEntryNotReady(f"Could not open MQTT connection: {err}") from err

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {
        "api": api,
        "mqtt": mqtt_client,
        "device_info": device_info,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    if not hass.services.has_service(DOMAIN, SERVICE_BLE_PAIR):

        async def _service_ble_pair(call: ServiceCall) -> None:
            await _handle_ble_pair(hass, call)

        hass.services.async_register(
            DOMAIN,
            SERVICE_BLE_PAIR,
            _service_ble_pair,
            schema=SERVICE_BLE_PAIR_SCHEMA,
        )

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        data = hass.data[DOMAIN].pop(entry.entry_id)
        await data["mqtt"].async_stop()
        if not hass.data.get(DOMAIN):
            hass.services.async_remove(DOMAIN, SERVICE_BLE_PAIR)
    return unload_ok
