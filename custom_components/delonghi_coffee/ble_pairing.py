"""Espressif BLE Security 1 provisioning client for De'Longhi ECAM ESP32 machines.

Implements the two-phase Security 1 BLE handshake that the De'Longhi
"My Coffee Lounge" app uses to pair a new user:

  Phase 0: Connect → SessionCmd0 → Machine shows 6-digit PIN → Disconnect
  Phase 1: Reconnect with user-entered PIN → SessionCmd1 → Verify → Done

After Phase 1 succeeds, the PIN is sent to the AWS backend as "pairingCode".
The PIN is simultaneously the AuthToken candidate for local LAN2LAN access.

Espressif BLE Provisioning proto references (session.proto / sec1.proto):
  https://github.com/espressif/esp-idf/tree/master/components/wifi_provisioning/proto

Security 1 key derivation (from Security1.java, verified at source):
  session_key = X25519(client_private, device_public) XOR SHA256(PIN)
  cipher0 (client→device): AES-CTR(session_key, IV=0)   — fresh per session
  cipher1 (device→client): AES-CTR(session_key, IV=0)   — fresh per session
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bleak.backends.device import BLEDevice

_LOGGER = logging.getLogger(__name__)

# Espressif provisioning service UUID (standard esp-idf default).
# The machine must advertise this UUID for the scanner-by-UUID fallback to work.
PROV_SERVICE_UUID = "021a9004-0382-4aea-bff4-6b3f1c5adfb4"
PROV_SESSION_UUID = "021aff51-0382-4aea-bff4-6b3f1c5adfb4"
PROV_CONFIG_UUID  = "021aff52-0382-4aea-bff4-6b3f1c5adfb4"

# De'Longhi BLE advertisement service data UUID.
# ALL De'Longhi ECAM ESP32 machines advertise service data under this UUID.
# (0xFEF3 = Bluetooth SIG member UUID, appears in service_data not service_uuids)
DELONGHI_ADV_UUID = "0000fef3-0000-1000-8000-00805f9b34fb"

# Name prefixes that De'Longhi / Espressif firmware may advertise.
# Extend this list if a different prefix is discovered.
_DELONGHI_NAME_PREFIXES = (
    "DLCOF",  # confirmed unprovisioned name: "DLCOF_250242ZZ26060850307" (MAC 84:1F:E8:3B:9A:96)
    "N02",    # confirmed: "N02T1"
    "AB02",   # seen: "AB02060020000001497"
    "PROV_",  # generic Espressif provisioning prefix
    "DeLon",
    "ECAM",
    "Prima",
)

_BLE_CONNECT_TIMEOUT = 20.0   # seconds — BLE connect + service discovery
_RESP_TIMEOUT        = 12.0   # seconds — wait for SessionResp after write


# ── Minimal protobuf codec ────────────────────────────────────────────────────

def _varint_encode(n: int) -> bytes:
    """Encode a non-negative integer as a protobuf base-128 varint."""
    out = []
    while n > 0x7F:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n & 0x7F)
    return bytes(out)


def _ld_field(field_num: int, payload: bytes) -> bytes:
    """Protobuf length-delimited field (wire type 2)."""
    tag = _varint_encode((field_num << 3) | 2)
    return tag + _varint_encode(len(payload)) + payload


def _varint_field(field_num: int, value: int) -> bytes:
    """Protobuf varint field (wire type 0)."""
    tag = _varint_encode((field_num << 3) | 0)
    return tag + _varint_encode(value)


def _proto_parse(data: bytes) -> dict:
    """
    Minimal, safe protobuf parser.  Returns {field_num: bytes | int}.

    Handles only wire types 0 (varint) and 2 (length-delimited), which
    covers all fields used by the Espressif Security 1 messages.
    """
    result: dict = {}
    pos = 0
    n = len(data)
    while pos < n:
        # Decode tag varint
        tag = 0
        shift = 0
        while pos < n:
            b = data[pos]; pos += 1
            tag |= (b & 0x7F) << shift
            shift += 7
            if not (b & 0x80):
                break

        wire_type = tag & 0x07
        field_num = tag >> 3

        if wire_type == 0:
            # Varint value
            val = 0; shift = 0
            while pos < n:
                b = data[pos]; pos += 1
                val |= (b & 0x7F) << shift
                shift += 7
                if not (b & 0x80):
                    break
            result[field_num] = val

        elif wire_type == 2:
            # Length-delimited
            length = 0; shift = 0
            while pos < n:
                b = data[pos]; pos += 1
                length |= (b & 0x7F) << shift
                shift += 7
                if not (b & 0x80):
                    break
            result[field_num] = data[pos: pos + length]
            pos += length

        else:
            _LOGGER.warning(
                "proto_parse: skipping unknown wire type %d at offset %d", wire_type, pos
            )
            break

    return result


# ── Cryptography helpers ──────────────────────────────────────────────────────

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _aes_ctr(key: bytes, data: bytes) -> bytes:
    """AES-CTR encryption/decryption starting at counter=0 (IV = 16 zero bytes).

    Each call creates a fresh cipher instance starting at block counter 0,
    mirroring Java's:
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(new byte[16]))
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher = Cipher(algorithms.AES(key), modes.CTR(b"\x00" * 16))
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def _aes_ctr_stream(session_key: bytes, device_random: bytes, offset_bytes: int, data: bytes) -> bytes:
    """Encrypt/decrypt `data` using AES-CTR with IV=device_random at `offset_bytes`.

    Matches Espressif Security 1 Java implementation (Security1.java lines 78-83).
    A single Cipher instance initialized with IvParameterSpec(device_random)
    processes all transmit and receive bytes continuously across Phase 1 and Phase 2.
    """
    if not data:
        return b""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher = Cipher(algorithms.AES(session_key), modes.CTR(device_random))
    enc = cipher.encryptor()
    if offset_bytes > 0:
        enc.update(b"\x00" * offset_bytes)
    return enc.update(data)


def compute_session_key(
    client_private_key_bytes: bytes,
    device_public_key_bytes: bytes,
    pin: str,
) -> bytes:
    """Derive the AES session key (Security1.java processStep0Response logic):

        shared = X25519(client_private, device_public)
        key    = shared XOR SHA256(PIN.encode("utf-8"))
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    priv = X25519PrivateKey.from_private_bytes(client_private_key_bytes)
    pub  = X25519PublicKey.from_public_bytes(device_public_key_bytes)
    shared = priv.exchange(pub)
    return _xor_bytes(shared, _sha256(pin.encode("utf-8")))


# ── Protobuf message builders & parsers ───────────────────────────────────────

def build_session_cmd0(client_pubkey: bytes) -> bytes:
    """Build SessionData containing SessionCmd0.

    Espressif standard sec1.proto / session.proto:
      SessionData {
        sec_ver = SecScheme1 (1)       [field 2, varint]
        sec1    = Sec1Payload           [field 11, length-delimited]
      }
      Sec1Payload {
        msg     = Session_Command0 (0) [field 1, varint]
        sc0     = SessionCmd0          [field 20, length-delimited]
      }
      SessionCmd0 {
        client_pubkey                  [field 1, bytes]
      }
    """
    sc0 = _ld_field(1, client_pubkey)
    sec1 = _varint_field(1, 0) + _ld_field(20, sc0)
    return _varint_field(2, 1) + _ld_field(11, sec1)


def parse_session_resp0(raw: bytes) -> tuple[bytes, bytes, int]:
    """Parse SessionData containing SessionResp0.

    Returns:
        device_pubkey (bytes, 32B)
        device_random (bytes, 16B)
        status        (int, 0 = OK)
    """
    _LOGGER.warning("parse_session_resp0: raw hex (%d bytes) = %s", len(raw), raw.hex())

    device_pubkey = b""
    device_random = b""
    status        = 0

    # ── Strategy 1: Direct pattern matching for Espressif Security 1 ─────────
    # In Espressif SessionResp0 protobuf:
    #   field 2 (device_pubkey) = tag 0x12, length 0x20 (32 bytes)
    #   field 3 (device_random) = tag 0x1a, length 0x10 (16 bytes)
    idx_pub = raw.find(b"\x12\x20")
    if idx_pub != -1 and len(raw) >= idx_pub + 2 + 32:
        device_pubkey = raw[idx_pub + 2 : idx_pub + 2 + 32]
        _LOGGER.warning("parse_session_resp0: extracted 32B pubkey via 0x1220 pattern: %s…", device_pubkey.hex()[:16])

    idx_rnd = raw.find(b"\x1a\x10")
    if idx_rnd != -1 and len(raw) >= idx_rnd + 2 + 16:
        device_random = raw[idx_rnd + 2 : idx_rnd + 2 + 16]
        _LOGGER.warning("parse_session_resp0: extracted 16B random via 0x1a10 pattern: %s…", device_random.hex()[:16])

    # ── Strategy 2: Structured Protobuf tree search ─────────────────────────
    if not device_pubkey:
        session = _proto_parse(raw)
        _LOGGER.warning("parse_session_resp0: parsed session dict = %s", session)

        def _scan_dict_for_bytes(d: dict, target_len: int) -> bytes:
            for k, v in d.items():
                if isinstance(v, bytes) and len(v) == target_len:
                    return v
                if isinstance(v, bytes):
                    sub = _proto_parse(v)
                    res = _scan_dict_for_bytes(sub, target_len)
                    if res:
                        return res
            return b""

        device_pubkey = _scan_dict_for_bytes(session, 32)
        if not device_random:
            device_random = _scan_dict_for_bytes(session, 16)

    # ── Strategy 3: Search raw bytes for any 32-byte block preceded by 0x20 ──
    if not device_pubkey:
        for i in range(len(raw) - 32):
            if raw[i] == 0x20:
                device_pubkey = raw[i + 1 : i + 1 + 32]
                _LOGGER.warning("parse_session_resp0: fallback extracted 32B pubkey after 0x20 tag: %s…", device_pubkey.hex()[:16])
                break

    _LOGGER.warning(
        "parse_session_resp0 final result: status=%d pubkey_len=%d random_len=%d",
        status, len(device_pubkey), len(device_random),
    )
    return device_pubkey, device_random, status


def build_session_cmd1(
    session_key: bytes,
    device_random: bytes,
    device_pubkey: bytes,
) -> bytes:
    """Build SessionData containing SessionCmd1.

    Matches Espressif Security 1 spec (Security1.java / Tink X25519.java):
      Tink X25519.computeSharedSecret mutates device_pubkey[31] &= 0x7F in-place
      before Security1.java calls encrypt(byteArray).
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    # Mask bit 255 of device_pubkey (Tink X25519 bArr2[31] &= 0x7f mutation)
    device_pubkey_masked = device_pubkey[:31] + bytes([device_pubkey[31] & 0x7F])

    cipher = Cipher(algorithms.AES(session_key), modes.CTR(device_random))
    enc = cipher.encryptor()
    client_verify = enc.update(device_pubkey_masked) + enc.finalize()

    sc1  = _ld_field(2, client_verify)
    sec1 = _varint_field(1, 2) + _ld_field(22, sc1)
    return _varint_field(2, 1) + _ld_field(11, sec1)


def parse_session_resp1(
    raw: bytes,
    session_key: bytes,
    device_random: bytes,
    client_pubkey: bytes,
) -> tuple[bool, int]:
    """Parse SessionData containing SessionResp1 and verify device identity.

    Matches Espressif Security 1 spec (Security1.java):
      device_verify = AES-CTR(key=session_key, IV=device_random, offset=32).decrypt(device_verify_enc)
      verified = (device_verify == client_pubkey)
    """
    _LOGGER.warning("parse_session_resp1: raw hex (%d bytes) = %s", len(raw), raw.hex())
    session = _proto_parse(raw)
    sec1_bytes = session.get(11, session.get(10, session.get(1, b"")))
    if isinstance(sec1_bytes, int):
        sec1_bytes = b""
    sec1 = _proto_parse(bytes(sec1_bytes))

    sr1_bytes = sec1.get(23, sec1.get(4, sec1.get(2, b"")))
    if isinstance(sr1_bytes, int):
        sr1_bytes = b""
    sr1 = _proto_parse(bytes(sr1_bytes))

    status            = int(sr1.get(1, 0))
    device_verify_enc = bytes(sr1.get(3, sr1.get(2, b"")))

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher = Cipher(algorithms.AES(session_key), modes.CTR(device_random))
    enc = cipher.encryptor()
    enc.update(b"\x00" * 32)  # advance keystream by 32 bytes (block counter offset)
    device_verify_dec = enc.update(device_verify_enc)

    client_pubkey_masked = client_pubkey[:31] + bytes([client_pubkey[31] & 0x7F])
    verified = (device_verify_dec == client_pubkey) or (device_verify_dec == client_pubkey_masked)

    if not verified:
        _LOGGER.warning(
            "BLE SessionResp1: verification failed\n"
            "  decrypted : %s\n"
            "  expected  : %s",
            device_verify_dec.hex(),
            client_pubkey.hex(),
        )
    return verified, status


# ── Session state (persisted between Phase 0 and Phase 1) ────────────────────

@dataclass
class EspSessionState:
    """All data needed to complete Phase 1 after the user enters the PIN."""

    client_private_key: bytes    # 32 B — ephemeral X25519 private key
    client_public_key: bytes     # 32 B — corresponding public key
    device_public_key: bytes     # 32 B — from SessionResp0
    device_random: bytes         # 16 B — from SessionResp0 (logged)
    ble_mac: str                 # BLE MAC address of the machine

    # Set by Phase 1 for use in Phase 2 (WiFi provisioning)
    session_key: bytes = b""

    # The live BleakClient is kept open between Phase 0 and Phase 1.
    # Stored here so Phase 1 can reuse the connection without a new SessionCmd0.
    # Type is Optional[bleak.BleakClient] — avoid hard import at module level.
    live_client: object = None
    char_uuid:   str    = ""
    enc_count:   int    = 0   # AES-CTR write counter (incremented per encrypt)
    dec_count:   int    = 0   # AES-CTR read  counter (incremented per decrypt)
    resp0_raw:   bytes  = b"" # Raw SessionResp0 bytes to detect cached GATT buffers


# ── BLE transport layer ───────────────────────────────────────────────────────

class DeLonghiBleProvisioner:
    """Two-phase Espressif Security 1 BLE client.

    Phase 0: triggers the PIN display on the machine.
    Phase 1: completes the handshake + AWS pairing with the user-entered PIN.
    """

    def __init__(self, ble_mac: str, hass=None) -> None:
        self._mac  = ble_mac.upper()
        self._hass = hass  # needed to use HA's Bluetooth scanner APIs

    # ── Phase 0 ────────────────────────────────────────────────────────────────

    async def async_phase0(self) -> EspSessionState:
        """Connect to the machine's BLE, send SessionCmd0, receive SessionResp0.

        After this call returns:
        - The machine's display shows the 6-digit PIN.
        - The BLE connection is kept alive inside the returned EspSessionState.
          Phase 1 MUST be called within ~60 s while the connection is open.
          If the connection drops, ble_pair_start must be called again.

        Raises RuntimeError with a human-readable message on any failure.
        """
        _LOGGER.info("BLE Phase 0: connecting to %s", self._mac)

        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat, PrivateFormat, NoEncryption,
        )
        from bleak import BleakClient

        priv_obj    = X25519PrivateKey.generate()
        pub_obj     = priv_obj.public_key()
        client_priv = priv_obj.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        client_pub  = pub_obj.public_bytes(Encoding.Raw, PublicFormat.Raw)

        cmd0 = build_session_cmd0(client_pub)

        # Use Home Assistant's official bleak_retry_connector to establish the connection
        # This handles GATT service discovery, MTU negotiation, and handle mapping properly on ESPHome proxies & BlueZ.
        from bleak_retry_connector import establish_connection

        device     = await self._get_ble_device()
        ble_client = await establish_connection(
            BleakClient,
            device,
            device.name or "DeLonghi",
            hass=self._hass,
            use_services_cache=False,
        )
        mtu = getattr(ble_client, "mtu_size", None)
        _LOGGER.warning("BLE: connected via bleak_retry_connector to %s  (MTU size = %s)", self._mac, mtu)

        session_char_uuid   = await self._find_session_char(ble_client)
        proto_ver_char_uuid = "021aff53-0382-4aea-bff4-6b3f1c5adfb4"

        # ── Step 1: Write "ESP" to proto-ver and read response to initialize ESP32 state machine ──
        # Matches BLETransport.java: app writes "ESP" to proto-ver, then reads proto-ver (JSON {"prov":{"ver":...}}),
        # which posts DeviceConnectionEvent(1) internally before sending SessionCmd0.
        _LOGGER.warning("BLE Phase 0: initializing ESP32 state machine by sending 'ESP' to proto-ver (%s)", proto_ver_char_uuid)
        try:
            await ble_client.write_gatt_char(proto_ver_char_uuid, b"ESP", response=False)
            _LOGGER.warning("BLE Phase 0: sent 'ESP' to proto-ver, reading version response...")
            ver_resp = await self._write_and_read(ble_client, proto_ver_char_uuid, b"", wait_delay=0.5)
            _LOGGER.warning("BLE Phase 0: proto-ver version response (%d B): %r", len(ver_resp), ver_resp.decode("utf-8", errors="ignore"))
        except Exception as exc:
            _LOGGER.debug("BLE: write/read 'ESP' to proto-ver failed: %s", exc)
        await asyncio.sleep(0.2)

        # ── Step 2: Send SessionCmd0 to prov-session ────────────────────────────
        _LOGGER.warning(
            "BLE Phase 0: sending SessionCmd0 (%d B) to resolved prov-session characteristic %s (immediate read)",
            len(cmd0), session_char_uuid,
        )

        resp0_raw = await self._write_and_read(ble_client, session_char_uuid, cmd0, wait_delay=1.0)

        if not resp0_raw:
            # Fallback 1: try prov-ctrl (021aff4f)
            ctrl_char_uuid = "021aff4f-0382-4aea-bff4-6b3f1c5adfb4"
            _LOGGER.warning(
                "BLE Phase 0: prov-session %s returned 0 bytes — falling back to prov-ctrl (%s)",
                session_char_uuid, ctrl_char_uuid,
            )
            resp0_raw = await self._write_and_read(ble_client, ctrl_char_uuid, cmd0, wait_delay=1.0)

        if not resp0_raw:
            # Fallback 2: try custom-data (021aff54)
            custom_char_uuid = "021aff54-0382-4aea-bff4-6b3f1c5adfb4"
            _LOGGER.warning(
                "BLE Phase 0: prov-session & prov-ctrl returned 0 bytes — falling back to custom-data (%s)",
                custom_char_uuid,
            )
            resp0_raw = await self._write_and_read(ble_client, custom_char_uuid, cmd0, wait_delay=1.0)

        if not resp0_raw:
            await ble_client.disconnect()
            raise RuntimeError(
                f"BLE Phase 0: prov-session ({session_char_uuid}), prov-ctrl, and custom-data on {self._mac} "
                "returned 0 bytes."
            )

        device_pubkey, device_random, status = parse_session_resp0(resp0_raw)

        if status != 0:
            await ble_client.disconnect()
            raise RuntimeError(
                f"BLE: SessionResp0 returned status {status} (expected 0 = OK). "
                "The machine might not be in provisioning mode.  "
                "Make sure the Wi-Fi reset is complete before calling this service."
            )
        if len(device_pubkey) != 32:
            await ble_client.disconnect()
            raise RuntimeError(
                f"BLE: device_pubkey has {len(device_pubkey)} bytes (expected 32).\n"
                f"Raw hex ({len(resp0_raw)} B): {resp0_raw.hex()}"
            )

        _LOGGER.info(
            "BLE Phase 0 complete \u2713 — device_pubkey=%s\u2026  "
            "PIN is now visible on the machine display.  "
            "You have ~60 s to call ble_pair_complete.",
            device_pubkey.hex()[:16],
        )

        return EspSessionState(
            client_private_key=client_priv,
            client_public_key=client_pub,
            device_public_key=device_pubkey,
            device_random=device_random,
            ble_mac=self._mac,
            live_client=ble_client,
            char_uuid=session_char_uuid,
            resp0_raw=resp0_raw,
        )

    # ── Phase 1 ────────────────────────────────────────────────────────────────

    async def async_phase1(
        self,
        state: EspSessionState,
        pin: str,
        ssid: str = "",
        password: str = "",
    ) -> None:
        """Send SessionCmd1 over the live connection from Phase 0, verify SessionResp1.

        If ssid and password are provided, Phase 2 (WiFi credential provisioning)
        runs automatically after the handshake is verified.

        Raises RuntimeError if the PIN is wrong or if the BLE connection has dropped.
        """
        client    = state.live_client
        char_uuid = state.char_uuid

        if client is None or not client.is_connected:
            raise RuntimeError(
                "The BLE connection to the machine has closed (it stays open ~60 s).  "
                "Call ble_pair_start again to trigger a new PIN, then call "
                "ble_pair_complete within 60 seconds."
            )

        _LOGGER.info(
            "BLE Phase 1: sending SessionCmd1 over live connection  mac=%s  pin=%s",
            self._mac, pin,
        )

        session_key = compute_session_key(
            state.client_private_key,
            state.device_public_key,
            pin,
        )
        cmd1      = build_session_cmd1(session_key, state.device_random, state.device_public_key)
        resp1_raw = await self._write_and_read(client, char_uuid, cmd1, prev_resp=state.resp0_raw)

        verified, status = parse_session_resp1(
            resp1_raw,
            session_key,
            state.device_random,
            state.client_public_key,
        )

        if not verified:
            await client.disconnect()
            raise RuntimeError(
                "BLE: device verification FAILED — the PIN was incorrect.  "
                "Re-read the PIN from the machine display and try again, or "
                "call ble_pair_start to generate a new PIN."
            )
        if status != 0:
            await client.disconnect()
            raise RuntimeError(
                f"BLE: The machine rejected the PIN (status {status}).  "
                "Double-check the 6-digit PIN shown on the machine display and try again."
            )

        state.session_key = session_key
        state.offset      = 64  # 32B clientVerify + 32B deviceVerify

        _LOGGER.info("BLE Phase 1 complete ✓ — BLE handshake verified.")

        # Read machine ID from custom-data endpoint (matches EspPairableAppliance.java)
        machine_id = await self.async_read_machine_id(state)
        if machine_id:
            state.machine_id = machine_id
            _LOGGER.info("BLE: retrieved machine_id from custom-data: %s", machine_id)

        if ssid:
            await self.async_phase2_wifi(state, ssid, password)
        else:
            await client.disconnect()

    async def async_pair_full(
        self,
        pin: str,
        ssid: str = "",
        password: str = "",
    ) -> str:
        """Perform complete BLE Security1 handshake, Machine ID read, and optional WiFi provisioning.

        Matches ESPProvisionManager / ESPDevice.java workflow in De'Longhi Android app:
        - The PIN is already on the coffee machine's screen.
        - Connects to BLE, performs Phase 0 (SessionCmd0), Phase 1 (SessionCmd1 with PIN),
          reads Machine ID via custom-data ('echo'), and provisions WiFi.
        """
        last_exc = None
        for attempt in range(1, 3):
            _LOGGER.info("BLE pair attempt %d/2 for MAC %s with PIN %r...", attempt, self._mac, pin)
            try:
                state = await self.async_phase0()
                await self.async_phase1(state, pin, ssid=ssid, password=password)
                _LOGGER.info("BLE pair SUCCESS with PIN %r", pin)
                return getattr(state, "machine_id", "")
            except Exception as exc:
                last_exc = exc
                _LOGGER.warning("BLE pair attempt %d failed: %s", attempt, exc)
                await asyncio.sleep(1.5)

        if last_exc:
            raise last_exc
        raise RuntimeError("BLE pair failed after attempts.")

    async def async_read_machine_id(self, state: EspSessionState) -> str:
        """Read Machine ID (serial number) from custom-data endpoint.

        Matches EspPairableAppliance.java lines 66-84:
        Sends encrypted "echo" to endpoint "custom-data" (021aff54) and decrypts the response.
        """
        import re
        custom_char_uuid = "021aff54-0382-4aea-bff4-6b3f1c5adfb4"
        client = state.live_client
        if client is None or not client.is_connected:
            return ""

        try:
            plain_echo = b"echo"
            enc_echo = _aes_ctr_stream(state.session_key, state.device_random, state.offset, plain_echo)
            state.offset += len(plain_echo)

            resp_enc = await self._write_and_read(client, custom_char_uuid, enc_echo, wait_delay=0.2)
            resp_dec = _aes_ctr_stream(state.session_key, state.device_random, state.offset, resp_enc)
            state.offset += len(resp_enc)

            raw_str = resp_dec.decode("utf-8", errors="ignore")
            clean_id = re.sub(r"[^a-zA-Z0-9]", "", raw_str)
            _LOGGER.info("BLE custom-data 'echo' decrypted response: raw=%r -> clean machine_id=%r", raw_str, clean_id)
            return clean_id
        except Exception as exc:
            _LOGGER.warning("Could not read machine_id via custom-data: %s", exc)
            return ""

    # ── Phase 2: WiFi credential provisioning ─────────────────────────────────

    async def async_phase2_wifi(
        self,
        state: EspSessionState,
        ssid: str,
        password: str,
    ) -> None:
        """Send WiFi credentials over the established encrypted BLE session.

        Encodes and encrypts the Espressif wifi_prov CmdSetConfig and
        CmdApplyConfig protobuf messages using AES-CTR with the session_key
        derived in Phase 1 (counters continue from where Phase 1 left off).

        Raises RuntimeError on any failure.
        """
        if not state.session_key:
            raise RuntimeError(
                "async_phase2_wifi called before phase 1 — session_key is empty."
            )
        client    = state.live_client
        char_uuid = state.char_uuid

        if client is None or not client.is_connected:
            raise RuntimeError(
                "BLE connection dropped before WiFi credentials could be sent. "
                "Please restart the provisioning flow."
            )

        _LOGGER.info(
            "BLE Phase 2: sending WiFi credentials  ssid=%r  mac=%s", ssid, self._mac
        )

        # WiFi config uses a second characteristic (Espressif standard: ...ff52).
        # We find it dynamically so custom UUID schemes are handled.
        wifi_char = await self._find_wifi_char(client, char_uuid)

        # ── CmdSetWifiConfig ────────────────────────────────────────────────
        # NetworkConfigPayload {
        #   msg [field 1] = TypeCmdSetWifiConfig (2)
        #   cmd_set_wifi_config [field 12] = CmdSetWifiConfig {
        #     ssid [field 1] = bytes, passphrase [field 2] = bytes
        #   }
        # }
        # Source: MessengeHelper.java:65, NetworkConfig.java:
        #   MSG_FIELD_NUMBER=1, CMD_SET_WIFI_CONFIG_FIELD_NUMBER=12,
        #   TypeCmdSetWifiConfig_VALUE=2, SSID_FIELD_NUMBER=1, PASSPHRASE_FIELD_NUMBER=2
        ssid_b = ssid.encode("utf-8")
        pass_b = password.encode("utf-8")
        inner_set_wifi = _ld_field(1, ssid_b) + _ld_field(2, pass_b)
        plain_set = _varint_field(1, 2) + _ld_field(12, inner_set_wifi)

        # AES-CTR keystream continues seamlessly from state.offset (which includes Phase 1 + custom-data echo).
        offset = getattr(state, "offset", 64)
        enc_set = _aes_ctr_stream(state.session_key, state.device_random, offset, plain_set)
        offset += len(plain_set)

        resp_set_enc = await self._write_and_read(client, wifi_char, enc_set)
        resp_set_dec = _aes_ctr_stream(state.session_key, state.device_random, offset, resp_set_enc)
        offset += len(resp_set_enc)

        # Parse RespSetWifiConfig:
        # NetworkConfigPayload {
        #   msg [field 1] = TypeRespSetWifiConfig (3)
        #   resp_set_wifi_config [field 13] = RespSetWifiConfig { status [field 1] }
        # }
        # Source: NetworkConfig.java: RESP_SET_WIFI_CONFIG_FIELD_NUMBER=13, STATUS_FIELD_NUMBER=1
        outer_set      = _proto_parse(resp_set_dec)
        inner_set_resp = _proto_parse(outer_set.get(13, b""))
        set_status = int(inner_set_resp.get(1, 0))  # Protobuf3: status=0 (Success) omitted on wire
        if set_status != 0:
            await client.disconnect()
            raise RuntimeError(
                f"BLE: WiFi CmdSetWifiConfig returned status {set_status}. "
                f"Check SSID spelling: {ssid!r}"
            )
        _LOGGER.info("BLE Phase 2: CmdSetWifiConfig accepted (ssid=%r)", ssid)

        # ── CmdApplyWifiConfig ──────────────────────────────────────────────
        # NetworkConfigPayload {
        #   msg [field 1] = TypeCmdApplyWifiConfig (4)
        #   cmd_apply_wifi_config [field 14] = CmdApplyWifiConfig {}  (empty message)
        # }
        # Source: MessengeHelper.java:29, NetworkConfig.java:
        #   CMD_APPLY_WIFI_CONFIG_FIELD_NUMBER=14, TypeCmdApplyWifiConfig_VALUE=4
        plain_apply = _varint_field(1, 4) + _ld_field(14, b"")
        enc_apply   = _aes_ctr_stream(state.session_key, state.device_random, offset, plain_apply)
        offset += len(plain_apply)

        resp_apply_enc = await self._write_and_read(client, wifi_char, enc_apply)
        resp_apply_dec = _aes_ctr_stream(state.session_key, state.device_random, offset, resp_apply_enc)
        offset += len(resp_apply_enc)

        # Parse RespApplyWifiConfig:
        # NetworkConfigPayload {
        #   msg [field 1] = TypeRespApplyWifiConfig (5)
        #   resp_apply_wifi_config [field 15] = RespApplyWifiConfig { status [field 1] }
        # }
        # Source: NetworkConfig.java: RESP_APPLY_WIFI_CONFIG_FIELD_NUMBER=15, STATUS_FIELD_NUMBER=1
        outer_apply      = _proto_parse(resp_apply_dec)
        inner_apply_resp = _proto_parse(outer_apply.get(15, b""))
        apply_status = int(inner_apply_resp.get(1, 0))  # Protobuf3: status=0 (Success) omitted
        if apply_status != 0:
            await client.disconnect()
            raise RuntimeError(
                f"BLE: WiFi CmdApplyWifiConfig returned status {apply_status}. "
                "The machine rejected the apply command."
            )

        _LOGGER.info("BLE Phase 2: CmdApplyWifiConfig accepted. Polling machine Wi-Fi connection status...")

        # ── CmdGetWifiStatus Polling ─────────────────────────────────────────
        # Source: ESPDevice.java line 528: pollForWifiConnectionStatus()
        # NetworkConfigPayload {
        #   msg [field 1] = TypeCmdGetWifiStatus (0)
        #   cmd_get_wifi_status [field 10] = CmdGetWifiStatus {} (empty)
        # }
        # Source: NetworkConfig.java: CMD_GET_WIFI_STATUS_FIELD_NUMBER=10, TypeCmdGetWifiStatus_VALUE=0
        plain_status_cmd = _varint_field(1, 0) + _ld_field(10, b"")
        wifi_connected = False

        for poll_step in range(1, 10):
            await asyncio.sleep(2.0)
            enc_status = _aes_ctr_stream(state.session_key, state.device_random, offset, plain_status_cmd)
            offset_resp = offset + len(plain_status_cmd)

            try:
                resp_status_enc = await self._write_and_read(client, wifi_char, enc_status)
                resp_status_dec = _aes_ctr_stream(state.session_key, state.device_random, offset_resp, resp_status_enc)
                offset = offset_resp + len(resp_status_enc)

                # RespGetWifiStatus:
                # NetworkConfigPayload {
                #   msg [field 1] = TypeRespGetWifiStatus (1)
                #   resp_get_wifi_status [field 11] = RespGetWifiStatus {
                #     status          [field 1]
                #     wifi_sta_state  [field 2] (0=Connected, 1=Connecting, 2=Disconnected)
                #     wifi_fail_reason[field 10]
                #   }
                # }
                # Source: NetworkConfig.java: RESP_GET_WIFI_STATUS_FIELD_NUMBER=11, WIFI_STA_STATE_FIELD_NUMBER=2
                outer_st = _proto_parse(resp_status_dec)
                inner_st = _proto_parse(outer_st.get(11, b""))
                sta_state = int(inner_st.get(2, 2))  # 0=Connected, 1=Connecting, 2=Disconnected
                _LOGGER.info("BLE Phase 2: Wi-Fi status poll #%d -> sta_state=%d", poll_step, sta_state)

                if sta_state == 0:  # WifiStationState.Connected
                    wifi_connected = True
                    _LOGGER.info("BLE Phase 2 complete ✓ — Machine successfully connected to Wi-Fi SSID %r!", ssid)
                    break
            except Exception as err:
                _LOGGER.debug("BLE Phase 2: Wi-Fi status poll #%d attempt error: %s", poll_step, err)
                offset = offset_resp

        if not wifi_connected:
            _LOGGER.info(
                "BLE Phase 2 complete — machine credentials submitted for SSID %r. "
                "Allow up to 30 seconds for the connection to finalize.",
                ssid,
            )

        await client.disconnect()

    # ── BLE helpers ────────────────────────────────────────────────────────────

    async def _get_ble_device(self):
        """Locate the machine's BLE device, waiting up to 20 s if needed.

        Search order:
        1. HA scanner cache by MAC (fast path).
        2. HA scanner callback — wait up to 20 s for the device to advertise.
        3. If MAC is unknown (all zeros or empty), scan for Espressif service
           UUID or known De'Longhi name prefix (handles ESP32 random-address
           devices where the BLE MAC differs from the Wi-Fi MAC).
        """
        import asyncio

        if self._hass is not None:
            try:
                from homeassistant.components.bluetooth import (
                    async_ble_device_from_address,
                    async_register_callback,
                    async_scanner_devices_by_address,
                    BluetoothCallbackMatcher,
                    BluetoothChange,
                    BluetoothServiceInfoBleak,
                )
                from homeassistant.core import callback

                # ── 1. Fast path: device already in scanner cache by MAC or offset ────
                if self._mac:
                    candidate_macs = [self._mac]
                    try:
                        parts = self._mac.split(":")
                        last_b = int(parts[-1], 16)
                        candidate_macs.append(":".join(parts[:-1] + [f"{(last_b + 2) & 0xFF:02X}"]))
                        candidate_macs.append(":".join(parts[:-1] + [f"{(last_b - 2) & 0xFF:02X}"]))
                    except Exception:
                        pass

                    for addr in candidate_macs:
                        device = async_ble_device_from_address(
                            self._hass, addr.upper(), connectable=True
                        )
                        if device is not None:
                            _LOGGER.warning("BLE: found target machine %s in scanner cache!", device.address)
                            return device

                # ── 2. Wait for specific MAC advertisement ──────────────────────
                if self._mac:
                    _LOGGER.info(
                        "BLE: %s not in cache — waiting up to 20 s for advertisement.",
                        self._mac,
                    )
                    found_evt = asyncio.Event()

                    @callback
                    def _on_adv(service_info: BluetoothServiceInfoBleak, change):
                        found_evt.set()

                    cancel = async_register_callback(
                        self._hass,
                        _on_adv,
                        BluetoothCallbackMatcher(address=self._mac),
                        BluetoothChange.ADVERTISEMENT,
                    )
                    try:
                        await asyncio.wait_for(found_evt.wait(), timeout=20.0)
                        device = async_ble_device_from_address(
                            self._hass, self._mac, connectable=True
                        )
                        if device is not None:
                            return device
                    except asyncio.TimeoutError:
                        _LOGGER.warning(
                            "BLE: %s not seen after 20 s — falling back to "
                            "Espressif service UUID / name scan.",
                            self._mac,
                        )
                    finally:
                        cancel()

                # ── 3. Scan by Espressif service UUID or De'Longhi name prefix ──
                # The ESP32's BLE MAC often differs from its Wi-Fi MAC.
                # We look for any device advertising the Espressif provisioning
                # service UUID or a known De'Longhi advertisement name.
                _LOGGER.info(
                    "BLE: scanning for Espressif provisioning service UUID or "
                    "De'Longhi name prefix (up to 20 s)"
                )
                found_evt2 = asyncio.Event()
                found_info = None

                @callback
                def _on_any_adv(service_info: BluetoothServiceInfoBleak, change):
                    nonlocal found_info
                    name = service_info.name or ""
                    uuids = [u.lower() for u in (service_info.service_uuids or [])]
                    target_macs = {self._mac} if self._mac else set()
                    if self._mac:
                        try:
                            parts = self._mac.split(":")
                            last_byte = int(parts[-1], 16)
                            mac_plus2 = ":".join(parts[:-1] + [f"{(last_byte + 2) & 0xFF:02X}"])
                            mac_minus2 = ":".join(parts[:-1] + [f"{(last_byte - 2) & 0xFF:02X}"])
                            target_macs.add(mac_plus2)
                            target_macs.add(mac_minus2)
                        except Exception:
                            pass

                    is_esp_uuid = PROV_SERVICE_UUID.lower() in uuids
                    is_named    = any(
                        name.upper().startswith(p.upper())
                        for p in _DELONGHI_NAME_PREFIXES
                    )

                    # If self._mac is set, strictly match target MACs only to avoid connecting to random ESP32 devices
                    if self._mac:
                        if service_info.address.upper() not in target_macs:
                            return
                    elif not (is_esp_uuid or is_named):
                        return

                    _LOGGER.info(
                        "BLE candidate: addr=%s  name=%r  "
                        "esp=%s  named=%s  rssi=%s",
                        service_info.address, name,
                        is_esp_uuid, is_named,
                        service_info.rssi,
                    )
                    # Prefer stronger signal if multiple candidates
                    if found_info is None or (
                        service_info.rssi is not None
                        and found_info.rssi is not None
                        and service_info.rssi > found_info.rssi
                    ):
                        found_info = service_info
                        found_evt2.set()

                cancel2 = async_register_callback(
                    self._hass,
                    _on_any_adv,
                    BluetoothCallbackMatcher(),   # match all
                    BluetoothChange.ADVERTISEMENT,
                )
                try:
                    await asyncio.wait_for(found_evt2.wait(), timeout=20.0)
                except asyncio.TimeoutError:
                    raise RuntimeError(
                        "No De'Longhi BLE device found after 20 s.  "
                        "Check that:\n"
                        "  1. The machine is powered on\n"
                        "  2. It is within Bluetooth range of the HA host\n"
                        "  3. The HA Bluetooth integration is enabled\n"
                        "If the machine uses a non-standard BLE name, pass its "
                        "exact BLE MAC via the ble_mac service parameter."
                    )
                finally:
                    cancel2()

                _LOGGER.info(
                    "BLE: found De'Longhi device via name/UUID scan: "
                    "addr=%s name=%r",
                    found_info.address,
                    found_info.name,
                )
                device = async_ble_device_from_address(
                    self._hass, found_info.address, connectable=True
                )
                if device is None:
                    raise RuntimeError(
                        f"Device {found_info.address} ({found_info.name}) was found "
                        "but is not connectable.  Try passing its MAC directly via "
                        "ble_mac in the service call."
                    )
                # Cache discovered MAC for Phase 1
                self._mac = found_info.address.upper()
                return device

            except ImportError:
                _LOGGER.debug(
                    "homeassistant.components.bluetooth not available — "
                    "falling back to direct BleakScanner"
                )

        # Fallback: direct BleakScanner (may conflict with HA's BT adapter).
        from bleak import BleakScanner
        _LOGGER.info(
            "BLE: scanning directly for %s (up to 20 s)",
            self._mac or "De'Longhi (any)",
        )
        if self._mac:
            device = await BleakScanner.find_device_by_address(self._mac, timeout=20.0)
        else:
            # Scan all and pick first matching service UUID or name
            device = None
            async with BleakScanner() as scanner:
                await asyncio.sleep(5.0)
            for d in scanner.discovered_devices:
                name = d.name or ""
                if any(name.upper().startswith(p.upper()) for p in _DELONGHI_NAME_PREFIXES):
                    device = d
                    _LOGGER.info("BLE direct scan found: %s (%s)", d.address, d.name)
                    break

        if device is None:
            raise RuntimeError(
                "BLE device not found.  "
                f"MAC={'not specified' if not self._mac else self._mac}"
            )
        if not self._mac:
            self._mac = device.address.upper()
        return device

    async def _open_client(self):
        """Return a connected BleakClient context manager."""
        from bleak import BleakClient
        device = await self._get_ble_device()
        return BleakClient(device, timeout=_BLE_CONNECT_TIMEOUT)

    async def _find_session_char(self, client) -> str:
        """Locate the prov-session characteristic by reading 0x2901 descriptors.

        Matches BLETransport.java in the De'Longhi Android app:
        The app reads GATT descriptor 0x2901 (User Description) on each characteristic.
        The descriptor string specifies the endpoint: "prov-session", "prov-config", "proto-ver".
        """
        _LOGGER.warning("BLE: resolving endpoint names via 0x2901 descriptors...")
        uuid_map = {}

        for service in client.services:
            for char in service.characteristics:
                _LOGGER.warning(
                    "BLE Char discovered: uuid=%s  props=%s  handle=%d",
                    char.uuid, char.properties, char.handle,
                )
                for desc in char.descriptors:
                    if "2901" in desc.uuid.lower():
                        try:
                            val_bytes = await client.read_gatt_descriptor(desc.handle)
                            name = val_bytes.decode("utf-8", errors="ignore").strip()
                            uuid_map[name] = char.uuid
                            _LOGGER.warning(
                                "BLE endpoint mapping: descriptor=%r -> char_uuid=%s (handle %d, props=%s)",
                                name, char.uuid, char.handle, char.properties,
                            )
                        except Exception as exc:
                            _LOGGER.debug("Could not read 0x2901 desc on %s: %s", char.uuid, exc)

        if "prov-session" in uuid_map:
            _LOGGER.warning("BLE: found prov-session via 0x2901 descriptor -> %s", uuid_map["prov-session"])
            return uuid_map["prov-session"]

        # Fallback if descriptors could not be read
        _LOGGER.warning("BLE: 0x2901 descriptor mapping incomplete (found: %s) — falling back to 021aff51", uuid_map)
        for service in client.services:
            for char in service.characteristics:
                if char.uuid.lower() == PROV_SESSION_UUID.lower():
                    return char.uuid

        raise RuntimeError(f"Could not resolve prov-session characteristic on {self._mac}.")

    async def _find_wifi_char(self, client, session_char_uuid: str) -> str:
        """Locate prov-config characteristic (021aff52) for WiFi provisioning."""
        for service in client.services:
            for char in service.characteristics:
                if char.uuid.lower() == PROV_CONFIG_UUID.lower():
                    return char.uuid
        return PROV_CONFIG_UUID

    async def _write_and_read(
        self,
        client,
        char_uuid: str,
        data: bytes,
        wait_delay: float = 2.0,
        prev_resp: bytes = b"",
    ) -> bytes:
        """Write `data` to `char_uuid` and return the machine's response.

        Espressif BLE provisioning endpoints use write-then-read with an ESP32
        processing delay (X25519 key generation takes ~1.5–2.0 seconds).
        """
        loop = asyncio.get_running_loop()
        response_fut: asyncio.Future = loop.create_future()

        def _on_notify(sender, recv_data: bytearray) -> None:
            if not response_fut.done():
                response_fut.set_result(bytes(recv_data))

        char_clean = char_uuid.lower()
        char = client.services.get_characteristic(char_clean)
        if char is None:
            for service in client.services:
                for c in service.characteristics:
                    if c.uuid.lower() == char_clean:
                        char = c
                        break
        target_char = char if char is not None else char_clean

        use_notify = False
        if char:
            try:
                await client.start_notify(target_char, _on_notify)
                use_notify = True
                _LOGGER.warning("BLE: enabled notifications on %s", char_uuid)
            except Exception as exc:
                _LOGGER.debug("start_notify failed on %s: %s", char_uuid, exc)

        # Determine MTU chunk size (default 512 or client.mtu_size - 3)
        mtu_val = getattr(client, "mtu_size", 512) or 512
        max_chunk = max(20, mtu_val - 3)

        if data:
            # Espressif BLE Provisioning (BLETransport.java line 203) sets setWriteType(2) (WRITE_TYPE_NO_RESPONSE)
            # Always use response=False to prevent Invalid PDU (0x04) errors on ESP32 protocomm endpoints.
            try:
                if len(data) > max_chunk:
                    _LOGGER.warning(
                        "BLE: payload (%d B) > max_chunk (%d B, MTU=%d) — chunking write (response=False)",
                        len(data), max_chunk, mtu_val,
                    )
                    for offset in range(0, len(data), max_chunk):
                        chunk = data[offset : offset + max_chunk]
                        await client.write_gatt_char(target_char, bytearray(chunk), response=False)
                        await asyncio.sleep(0.02)
                else:
                    await client.write_gatt_char(target_char, bytearray(data), response=False)
                _LOGGER.warning("BLE: wrote %d bytes (response=False) to %s", len(data), char_uuid)
            except Exception as exc:
                _LOGGER.warning("BLE: write with response=False failed on %s (%s) — retrying with response=True", char_uuid, exc)
                await client.write_gatt_char(target_char, bytearray(data), response=True)
                _LOGGER.warning("BLE: wrote %d bytes (response=True) to %s", len(data), char_uuid)

        if use_notify:
            try:
                resp = await asyncio.wait_for(asyncio.shield(response_fut), timeout=wait_delay)
                try:
                    await client.stop_notify(target_char)
                except Exception:
                    pass
                _LOGGER.warning("BLE: received %d bytes via notification from %s!", len(resp), char_uuid)
                return resp
            except asyncio.TimeoutError:
                pass

        # ESP32 protocomm_ble endpoints update quickly (or ~150-250ms for X25519).
        # Read immediately (0.1s) so fast characteristics like prov-config/custom-data are caught.
        resp = b""
        delays = [0.1, 0.3, 0.6, 1.0, 1.5]
        latest_resp = b""
        for attempt, delay in enumerate(delays, start=1):
            await asyncio.sleep(delay)
            try:
                r = bytes(await client.read_gatt_char(target_char))
                if len(r) > 0:
                    latest_resp = r
                    if prev_resp and r == prev_resp:
                        _LOGGER.warning(
                            "BLE: read returned cached previous response (%d B) on attempt %d — waiting for new response...",
                            len(r), attempt,
                        )
                        continue
                    _LOGGER.warning(
                        "BLE: read %d bytes directly from GATT char %s on attempt %d (hex: %s)",
                        len(r), char_uuid, attempt, r.hex(),
                    )
                    return r
            except Exception as exc:
                _LOGGER.debug("read_gatt_char attempt %d failed on %s: %s", attempt, char_uuid, exc)

        if latest_resp and (not prev_resp or latest_resp != prev_resp):
            return latest_resp
        _LOGGER.warning("BLE: read 0 bytes from GATT char %s after all attempts", char_uuid)
        return resp


# ── AWS pairing confirmation ──────────────────────────────────────────────────

def _find_token_like_fields(obj, path: str = "") -> dict:
    """Recursively scan a parsed JSON structure for keys that look like an
    auth token / secret / passcode.

    Returns {json_path: value} for every leaf whose key (case-insensitive)
    contains one of: token, auth, pass, secret, key, code, pin.
    """
    hits = {}
    needles = ("token", "auth", "pass", "secret", "lan2lan", "code", "pin")

    if isinstance(obj, dict):
        for k, v in obj.items():
            new_path = f"{path}.{k}" if path else k
            if isinstance(v, (dict, list)):
                hits.update(_find_token_like_fields(v, new_path))
            else:
                if any(n in k.lower() for n in needles) and v not in (None, "", False):
                    hits[new_path] = v
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hits.update(_find_token_like_fields(v, f"{path}[{i}]"))

    return hits


async def async_aws_confirm_pairing(
    hass,
    api,
    machine_id: str,
    pin: str,
) -> dict:
    """POST /devices/{machineID}/pair to complete the AWS-side pairing.

    Returns a dict:
      {
        "ok": bool,
        "status": int,
        "body": str,
        "token_candidates": {json_path: value},
      }
    """
    import json
    import aiohttp

    from .const import AWS_REST_URL

    token = await hass.async_add_executor_job(api.get_fresh_token)
    url     = f"{AWS_REST_URL}/devices/{machine_id}/pairing"
    headers = {
        "Authorization": f"Bearer {token}",
        "source":        "mycoffeelounge",
        "Content-Type":  "application/json",
    }
    payload = {"pairingCode": pin}

    _LOGGER.info("AWS pair: POST %s  body=%s", url, payload)
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                body = await resp.text()
                _LOGGER.info("AWS pair response: HTTP %d  %s", resp.status, body[:400])

                parsed_body = None
                try:
                    parsed_body = json.loads(body)
                except Exception:
                    pass

                token_candidates = {}
                if parsed_body is not None:
                    token_candidates = _find_token_like_fields(parsed_body)
                    if token_candidates:
                        _LOGGER.info("AWS pair response contained token-like field(s): %s", token_candidates)

                ok = resp.status in (200, 201, 202)
                return {
                    "ok": ok,
                    "status": resp.status,
                    "body": body,
                    "token_candidates": token_candidates,
                }
    except Exception as exc:  # noqa: BLE001
        _LOGGER.warning("AWS pair call failed: %s", exc)
        return {"ok": False, "status": 0, "body": str(exc), "token_candidates": {}}
