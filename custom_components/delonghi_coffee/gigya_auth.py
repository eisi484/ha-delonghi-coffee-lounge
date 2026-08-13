"""Pure helpers for the Gigya (SAP CDC) login flow used by De'Longhi Coffee
Lounge.

Deliberately I/O-free: no `requests`/`aiohttp` calls in this module, so the
request-building and response-parsing logic can be unit-tested without a
network connection and without importing Home Assistant at all. The actual
HTTP calls live in `api.py`.

Flow (this is now the ONLY Gigya call this integration ever makes):
    POST /accounts.login  (email + password, targetEnv=mobile, include=id_token)
        -> {"sessionInfo": {"sessionToken": ...}, "id_token": "<JWT>"}

`id_token` is the value used as the MQTT password for the AWS IoT Custom
Authorizer (and as the AWS REST bearer token).

-------------------------------------------------------------------------
Why there's no `accounts.getJWT` here (there used to be)
-------------------------------------------------------------------------
0.4.0 tried to avoid storing the password by persisting the long-lived
`sessionToken` instead, and rotating a fresh `id_token` via a standalone
`accounts.getJWT` call (oauth_token=sessionToken) whenever the cached one
expired. That call fails with Gigya error 403005 ("Unauthorized user",
errorDetails "Session not found") for EVERY session obtained through this
app's `targetEnv=mobile` login, regardless of pool, session expiration, or
extra parameters — confirmed against a real account with
`tools/gigya_diagnose.py` on 2026-08-10. The `sessionToken` mobile logins
return is apparently not backed by a server-side session Gigya can look up
later; that machinery seems to exist only for `targetEnv=web` browser
sessions.

Net effect: for this Gigya site, minting a fresh `id_token` is only
possible via a full `accounts.login`, which needs the password every time.
`DeLonghiAPI` therefore stores the password (see its docstring in api.py)
and calls this module's `build_login_params`/`parse_login_response` on
every token refresh — same as the original, pre-0.4.0 implementation.
`sessionToken` is still returned by `parse_login_response` and kept around
for diagnostics/pool-caching purposes, but nothing in this integration
uses it to fetch a JWT anymore.
"""

from __future__ import annotations

from typing import Any, Final

# Requested Gigya session lifetime. Since sessionToken is no longer used to
# mint a later JWT (see module docstring), this mostly just bounds how long
# an old session lingers server-side; matches the interval this integration
# already re-logs-in at (see const.GIGYA_JWT_CACHE_SECONDS), so nothing is
# ever relying on a session that's about to lapse.
GIGYA_LOGIN_SESSION_EXPIRATION: Final = "900"

# errorCode returned when the account exists but isn't recognized under the
# apiKey/pool used for this request — i.e. "wrong pool", not "wrong
# password". api.py's pool-probing treats this one specially: try the next
# pool instead of giving up.
GIGYA_UNAUTHORIZED_USER_ERROR_CODE: Final = "403005"


class GigyaAuthError(RuntimeError):
    """Raised when Gigya returns a non-zero errorCode or a malformed payload."""


def build_login_params(
    *,
    email: str,
    password: str,
    api_key: str,
) -> dict[str, str]:
    """Construct the POST body for `accounts.login`.

    `include=id_token` piggy-backs a usable JWT onto the login response
    itself — the only way (see module docstring) this integration can get
    one at all.
    """
    return {
        "apiKey": api_key,
        "loginID": email,
        "password": password,
        "targetEnv": "mobile",
        "include": "id_token",
        "sessionExpiration": GIGYA_LOGIN_SESSION_EXPIRATION,
    }


def parse_login_response(payload: dict[str, Any]) -> tuple[str, str | None]:
    """Extract (session_token, id_token) from a login response.

    `session_token` is kept for pool-caching/diagnostics purposes only (see
    module docstring — it can't be exchanged for a fresh JWT later).
    `id_token` may in principle be `None` if the response doesn't include
    one inline despite `include=id_token` being requested; callers must
    treat that as an error (there is no fallback call left to make it up
    with). Raises GigyaAuthError on a non-zero errorCode or a missing
    session block.
    """
    _check_gigya_error(payload)
    session = payload.get("sessionInfo")
    if not isinstance(session, dict):
        raise GigyaAuthError("Gigya login succeeded but sessionInfo is missing")
    session_token = session.get("sessionToken")
    if not session_token:
        raise GigyaAuthError("Gigya login succeeded but sessionToken is empty")
    return session_token, payload.get("id_token")


def _check_gigya_error(payload: dict[str, Any]) -> None:
    error_code = payload.get("errorCode", 0)
    if error_code:
        # Gigya often puts the useful, specific detail in `errorDetails`
        # (e.g. "Session not found") alongside a generic `errorMessage`
        # (e.g. "Unauthorized user") — include both when present, since the
        # generic one alone previously hid the exact cause during
        # diagnosis (see tools/gigya_diagnose.py history).
        message = payload.get("errorMessage") or "unknown"
        details = payload.get("errorDetails")
        if details and details != message:
            message = f"{message} ({details})"
        raise GigyaAuthError(f"Gigya error {error_code}: {message}")
