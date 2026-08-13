"""Constants for the De'Longhi Coffee (Coffee Lounge / Daedalus) integration.

This integration targets machines paired through the **De'Longhi Coffee
Lounge** app (internal codename "Daedalus"), e.g. the Eletta Ultra
(ECAM47080). These machines communicate exclusively via:

  1. Gigya (identity provider) for login,
  2. a one-shot AWS REST call to resolve the account's devices, and
  3. a persistent AWS IoT Core MQTT connection (device shadow push).

There is **no Ayla Networks involvement whatsoever** for this device family
— that cloud belongs to the older "Coffee Link" app used by earlier
machines (PrimaDonna, Dinamica, etc.) and does not apply here. See
SESSION_NOTES.md for the reverse-engineering trail that established this.
"""

from __future__ import annotations

from typing import Final

DOMAIN: Final = "delonghi_coffee"
PLATFORMS: Final[list[str]] = ["sensor", "binary_sensor", "select", "switch"]

# ---------------------------------------------------------------------------
# Gigya (De'Longhi identity provider). Public, app-wide API keys extracted
# from the Coffee Lounge Android app — not user secrets, every install of
# the official app shares them.
#
# The app ships THREE production apiKeys, one per Gigya "pool" / region,
# and picks between them at runtime based on where the account was
# registered. There's no way to know which pool a given account is in
# ahead of time from a static manifest dump — confirmed the hard way via a
# real account that got Gigya error 403005 ("Unauthorized user") against
# the EU key alone. So instead of guessing, `DeLonghiAPI.from_password()`
# tries all three, EU first, and only escalates 403005 to the next pool —
# any other error (wrong password, rate-limit) short-circuits immediately
# so a typo doesn't burn through all three pools. The resolved pool is
# cached in CONF_POOL so later logins go straight to the right one.
#
# Auth model (see gigya_auth.py / api.py for the full flow, and their
# docstrings for the full "why" — short version below):
#   accounts.login (email + password, targetEnv=mobile, include=id_token)
#   is called on EVERY token refresh (initial setup, every MQTT reconnect,
#   reauth, ...) and returns a fresh `id_token` directly. That id_token is
#   what's used as the MQTT password for the AWS IoT Custom Authorizer and
#   as the AWS REST bearer token.
#
#   0.4.0 tried to avoid storing the password by persisting Gigya's
#   long-lived `sessionToken` instead and rotating a fresh id_token via a
#   standalone `accounts.getJWT` call (no password needed). That call
#   turned out to fail with error 403005 ("Session not found") for every
#   session this app's `targetEnv=mobile` login produces — Gigya's
#   getJWT-lookup machinery apparently only backs `targetEnv=web` browser
#   sessions, not mobile ones. Confirmed against a real account with
#   tools/gigya_diagnose.py on 2026-08-10; see that script's output format
#   if this ever needs re-verifying (e.g. after a Gigya-side config change
#   on De'Longhi's end). Until/unless that changes, minting a fresh
#   id_token requires the password every time, so `DeLonghiAPI` stores it
#   (see api.py's class docstring) — same as the original, pre-0.4.0
#   implementation.
# ---------------------------------------------------------------------------
GIGYA_URL: Final = "https://accounts.eu1.gigya.com"

GIGYA_POOL_EU: Final = "EU"
GIGYA_POOL_EU_US: Final = "EU_US"
GIGYA_POOL_CH: Final = "CH"

GIGYA_API_KEYS: Final[dict[str, str]] = {
    GIGYA_POOL_EU: "4_mXSplGaqrFT0H88TAjqJuA",
    GIGYA_POOL_EU_US: "3_e5qn7USZK-QtsIso1wCelqUKAK_IVEsYshRIssQ-X-k55haiZXmKWDHDRul2e5Y2",
    GIGYA_POOL_CH: "3_WP_c8OVu_yOoqYXN3Dq-Oi7nNkbS2bwqS3rQXJ6SPkodgE4FOpyuE_UVlrCuSGEm",
}

# Default probing order: EU first, then whichever pools remain.
DEFAULT_GIGYA_POOL: Final = GIGYA_POOL_EU

# TTL assumed for each id_token minted at login, and the internal cache
# margin applied before logging in again (60s safety buffer). Only affects
# how often `_ensure_jwt()` re-logs-in between explicit `get_fresh_token()`
# calls (e.g. repeated `get_devices()` calls in a short window) — MQTT
# reconnects always force a fresh login regardless via get_fresh_token().
GIGYA_JWT_EXPIRATION_SECONDS: Final = 900
GIGYA_JWT_CACHE_SECONDS: Final = 840

# Config-entry data keys. CONF_EMAIL/CONF_PASSWORD come from
# homeassistant.const — CONF_PASSWORD IS stored in new entries again (see
# the Gigya auth model note above for why). CONF_SESSION_TOKEN/CONF_POOL
# are ours since HA doesn't define them:
#   - CONF_SESSION_TOKEN: no longer written to new entries — kept only so
#     async_setup_entry can recognize and clean up 0.4.0/0.4.1 entries that
#     stored a session_token instead of a password (see
#     _migrate_legacy_password_entry in __init__.py), which are unusable
#     without a fresh reauth now that getJWT is confirmed dead.
#   - CONF_POOL: which Gigya pool the account resolved to, cached so
#     `_login_probing_pools` doesn't need to re-probe all three on every
#     restart.
CONF_SESSION_TOKEN: Final = "session_token"  # noqa: S105 — entry-data key, not a secret literal
CONF_POOL: Final = "pool"


# ---------------------------------------------------------------------------
# AWS REST API ("My Coffee Lounge" / Daedalus). Used ONCE at config-flow /
# setup time purely to resolve which machine(s) the account owns. All
# subsequent communication happens over the AWS IoT MQTT connection below —
# this REST API is not polled.
# ---------------------------------------------------------------------------
AWS_REST_URL: Final = "https://8q8c9xktb0.execute-api.eu-central-1.amazonaws.com/dlg-prod"

# ---------------------------------------------------------------------------
# AWS IoT Core — persistent MQTT5 push connection, authenticated via an
# *unsigned* Custom Authorizer (no signature needed): username is the fixed
# authorizer-name string below, password is the raw Gigya id_token.
#
# Only the verified prod/eu-central-1 endpoint is wired up. SESSION_NOTES.md
# lists dev/qlt endpoints and a us-east-1 region found in the decompiled
# app, but none of those were tested — do not assume they work.
# ---------------------------------------------------------------------------
MQTT_ENDPOINT: Final = "a2612mo23mfrw1-ats.iot.eu-central-1.amazonaws.com"
MQTT_PORT: Final = 443
MQTT_AUTHORIZER: Final = "dlg-prod-token-authorizer"
MQTT_KEEPALIVE_SECONDS: Final = 90
MQTT_CONNECT_TIMEOUT_SECONDS: Final = 15
MQTT_SUBSCRIBE_TIMEOUT_SECONDS: Final = 10

# Device shadow names confirmed working (all GRANTED with correct client-id
# prefix "dlg-appliance-kit-android-{uuid}", verified 2026-08-11 by parsing
# jadx output and running delonghi_final_test.py — see SESSION_NOTES.md).
SHADOW_MACHINE_STATUS: Final = "MachineStatus"
SHADOW_MACHINE_CAPABILITIES: Final = "MachineCapabilities"
SHADOW_MACHINE_SETTINGS: Final = "MachineSettings"
# Confirmed granted via delonghi_shadow_discover_dump1.json (2026-08-12):
SHADOW_BEAN_SYSTEMS: Final = "BeanSystems"
SHADOW_SCHEDULES: Final = "Schedules"
# Topic suffix for writing desired state (Shadow update):
SHADOW_UPDATE_SUFFIX: Final = "update"

# Dispatcher signal used to notify entities that a fresh shadow push arrived
# for a given machine.
SIGNAL_UPDATE: Final = f"{DOMAIN}_update_{{machine_name}}"
