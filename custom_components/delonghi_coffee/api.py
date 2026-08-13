"""Synchronous REST client for De'Longhi Coffee Lounge (Gigya + AWS REST).

Kept synchronous (plain `requests`, not aiohttp) because it is only ever
called from Home Assistant executor jobs — the awscrt MQTT5 client this
integration wraps is itself a blocking/threaded API, so there's no benefit
to an async HTTP stack here, and it keeps this module dependency-light.

All request-building and response-parsing logic lives in `gigya_auth.py`
(pure, no I/O). This module is intentionally a thin, easily-mockable shell
around it plus the plain `requests` calls — see tests/test_api.py, which
mocks `requests.post`/`requests.get` directly with no HA runtime needed.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import requests

from .const import (
    AWS_REST_URL,
    DEFAULT_GIGYA_POOL,
    GIGYA_API_KEYS,
    GIGYA_JWT_CACHE_SECONDS,
    GIGYA_URL,
)
from .gigya_auth import (
    GIGYA_UNAUTHORIZED_USER_ERROR_CODE,
    GigyaAuthError,
    build_login_params,
    parse_login_response,
)

_LOGGER = logging.getLogger(__name__)

REQUEST_TIMEOUT = 15


class DeLonghiAuthError(Exception):
    """Gigya login failed (bad credentials or every pool rejected the account)."""


class DeLonghiApiError(Exception):
    """Any other API communication error (network, HTTP, malformed body)."""


def extract_owned_devices(raw: dict) -> list[dict]:
    """Pull the owned-device list out of the AWS REST /devices response.

    Confirmed shape (SESSION_NOTES.md section 1): {"ownedByMe": [...]}.
    Pure/I/O-free — lives here rather than gigya_auth.py since it parses
    the AWS REST response, not a Gigya one.
    """
    if isinstance(raw, dict):
        return raw.get("ownedByMe") or []
    return []


class DeLonghiAPI:
    """Thin REST client.

    Holds the account email + password, plus which Gigya `pool` the
    account lives in (see const.GIGYA_API_KEYS, cached after the first
    successful login so later refreshes don't re-probe all three pools),
    plus a short-lived cached JWT (`id_token`) used as the MQTT password /
    AWS REST bearer token.

    The password IS stored on this instance and is re-sent on every token
    refresh. This is a deliberate change from the 0.4.0/0.4.1 design,
    which tried to avoid that by persisting a Gigya `session_token` instead
    and rotating a fresh JWT via `accounts.getJWT`. That call was confirmed
    non-functional for this Gigya site's `targetEnv=mobile` sessions (error
    403005, "Session not found" — see gigya_auth.py's module docstring and
    `tools/gigya_diagnose.py`), so there is currently no way to mint a
    fresh id_token without a full password login. Home Assistant's config
    entry storage isn't field-level encrypted regardless of which
    credential is stored here, so this is the same exposure the original
    (pre-0.4.0) implementation always had — see `__init__.py`'s module
    docstring for the fuller writeup and what was actually tried.
    """

    def __init__(self, email: str, password: str, pool: str = DEFAULT_GIGYA_POOL) -> None:
        self.email = email
        self._password = password
        self.pool = pool
        self._jwt: str | None = None
        self._jwt_expiry: float = 0

    @property
    def _api_key(self) -> str:
        # Falls back to the default pool's key for a pool string we don't
        # recognise (e.g. a future 4th pool added server-side) rather than
        # raising — worst case we get the same 403005 a stale/unknown pool
        # would've produced anyway, surfaced the normal way.
        return GIGYA_API_KEYS.get(self.pool, GIGYA_API_KEYS[DEFAULT_GIGYA_POOL])

    # -- construction ------------------------------------------------------

    @classmethod
    def from_password(cls, email: str, password: str, preferred_pool: str = DEFAULT_GIGYA_POOL) -> DeLonghiAPI:
        """Log in once to find which Gigya pool this account lives in, and
        cache the id_token that same login returns.

        Used at initial config-flow setup and again during a HA reauth
        flow, but — unlike 0.4.0 — the resulting `DeLonghiAPI` keeps the
        password too, since every *subsequent* token refresh needs it as
        well (see class docstring).

        Tries every Gigya pool, `preferred_pool` first, since which pool a
        given account belongs to can't be known ahead of time (see the
        module docstring in const.py). A pool returning errorCode 403005
        ("Unauthorized user" — right password, wrong pool) falls through to
        the next pool; any other error (wrong password, rate-limit, ...)
        short-circuits immediately so a typo doesn't burn through all three.
        """
        _session_token, id_token, resolved_pool = cls._login_probing_pools(
            email, password, preferred_pool
        )
        api = cls(email, password, pool=resolved_pool)
        if not id_token:
            raise DeLonghiAuthError(
                "Gigya login succeeded but returned no id_token despite include=id_token"
            )
        api._jwt = id_token
        api._jwt_expiry = time.time() + GIGYA_JWT_CACHE_SECONDS
        return api

    # -- Gigya ---------------------------------------------------------------

    @classmethod
    def _login_probing_pools(
        cls, email: str, password: str, preferred_pool: str
    ) -> tuple[str, str | None, str]:
        """Try `accounts.login` across all pools, preferred pool first.

        Returns (session_token, id_token, pool) for the first pool that
        accepts the credentials. Raises DeLonghiAuthError with a message
        starting with "all_pools:" only if every pool returns 403005 —
        callers (config_flow.py) map that prefix to a dedicated,
        clearer-than-"wrong password" translation key.
        """
        pools_ordered = [preferred_pool] + [p for p in GIGYA_API_KEYS if p != preferred_pool]
        last_err: DeLonghiAuthError | None = None

        for pool in pools_ordered:
            try:
                session_token, id_token = cls._gigya_login(email, password, GIGYA_API_KEYS[pool])
                if pool != preferred_pool:
                    _LOGGER.info(
                        "De'Longhi: preferred pool %s returned 403005, succeeded with pool %s",
                        preferred_pool,
                        pool,
                    )
                return session_token, id_token, pool
            except DeLonghiAuthError as err:
                last_err = err
                if GIGYA_UNAUTHORIZED_USER_ERROR_CODE not in str(err):
                    raise  # wrong password / rate-limit — no point probing further
                _LOGGER.debug("De'Longhi: pool %s -> 403005, probing next pool", pool)

        raise DeLonghiAuthError(f"all_pools: every Gigya pool rejected {email}") from last_err

    @staticmethod
    def _gigya_login(email: str, password: str, api_key: str) -> tuple[str, str | None]:
        payload = DeLonghiAPI._post_gigya(
            "/accounts.login", build_login_params(email=email, password=password, api_key=api_key)
        )
        try:
            return parse_login_response(payload)
        except GigyaAuthError as err:
            raise DeLonghiAuthError(str(err)) from err

    @staticmethod
    def _post_gigya(path: str, data: dict[str, str]) -> dict[str, Any]:
        try:
            resp = requests.post(f"{GIGYA_URL}{path}", data=data, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as err:
            raise DeLonghiApiError(f"Network error calling Gigya {path}: {err}") from err
        try:
            return resp.json()
        except ValueError as err:
            raise DeLonghiApiError(f"Invalid Gigya {path} response: {err}") from err

    def _ensure_jwt(self) -> None:
        if self._jwt and time.time() <= self._jwt_expiry:
            return
        _session_token, id_token = self._gigya_login(self.email, self._password, self._api_key)
        if not id_token:
            raise DeLonghiAuthError(
                "Gigya login succeeded but returned no id_token despite include=id_token"
            )
        self._jwt = id_token
        self._jwt_expiry = time.time() + GIGYA_JWT_CACHE_SECONDS

    def get_fresh_token(self) -> str:
        """Force a fresh id_token via a full password login.

        Always used right before opening a new MQTT connection so the
        Custom Authorizer never sees a stale token. Requires the stored
        password — see class docstring for why there's no cheaper,
        password-free rotation path for this Gigya site.
        """
        self._jwt = None
        self._ensure_jwt()
        assert self._jwt is not None  # _ensure_jwt raises rather than leaving this unset
        return self._jwt

    # -- AWS REST --------------------------------------------------------------

    def get_devices(self) -> dict:
        """Return the raw AWS REST /devices response for this account."""
        self._ensure_jwt()
        resp = self._get_devices_raw()
        if resp.status_code == 401:
            # JWT rejected — force a fresh one and retry once.
            self._jwt = None
            self._ensure_jwt()
            resp = self._get_devices_raw()

        if resp.status_code != 200:
            raise DeLonghiApiError(f"GET /devices returned HTTP {resp.status_code}")
        try:
            return resp.json()
        except ValueError as err:
            raise DeLonghiApiError(f"Invalid /devices response: {err}") from err

    def _get_devices_raw(self) -> requests.Response:
        try:
            return requests.get(
                f"{AWS_REST_URL}/devices",
                headers={"Authorization": f"Bearer {self._jwt}"},
                timeout=REQUEST_TIMEOUT,
            )
        except requests.RequestException as err:
            raise DeLonghiApiError(f"Network error fetching devices: {err}") from err
