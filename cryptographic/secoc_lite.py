# `secoc_lite.py` — inline profile

#**Path:** `cryptographic/secoc_lite.py` (replace the existing file)

#The MAC primitive interface (`compute_mac`, `verify`, `set_primitive`)
#is unchanged so `benchmarktest/app.py` keeps working. Two new helpers
#(`build_secured_frame`, `parse_secured_frame`) handle the inline 8-byte
#layout. The old `mac_id_for` / `status_id_for` functions are removed
#since there are no separate MAC frames anymore.

"""
secoc_lite.py
-------------
Minimal SecOC-style message authentication helper (INLINE PROFILE).

This module implements the AUTOSAR SecOC "Authentic I-PDU" layout adapted
for classic CAN: the MAC and freshness counter are appended to the same
8-byte frame as the payload. No separate MAC frame is transmitted.

Frame layout (8 bytes total, classic CAN):

    | byte 0..3 | byte 4    | byte 5..7      |
    | payload   | freshness | truncated MAC  |

MAC input:    data_id (2 B) || freshness (1 B) || payload (4 B)  = 7 B
MAC output:   truncated to 3 B (24-bit MAC, AUTOSAR-compliant for CAN)

Selectable primitive (kept for the HMAC-vs-CMAC overhead benchmark):
  - "hmac" : HMAC-SHA256 truncated  (Python stdlib only)
  - "cmac" : AES-128 CMAC truncated (needs `cryptography`)

Limitations (stated up front for thesis transparency):
  - The shared key is hard-coded for the test-bed only. Real key
    management (provisioning, rotation, escrow) is out of scope and
    documented as future work.
  - Per-attempt forgery probability for the truncated MAC is ~2^-24,
    matching the AUTOSAR SecOC recommendation for classic CAN.
"""

import hmac
import hashlib

# ---- Test-bed shared keys (simulation only) -----------------------------
SHARED_KEY = b"thesis-testbed-shared-key-0001"
AES_KEY    = b"thesis-testbed16"        # 16 bytes -> AES-128

# ---- Inline frame layout (classic CAN, 8 bytes) -------------------------
PAYLOAD_BYTES       = 4                 # application payload
FRESHNESS_BYTES     = 1                 # 8-bit anti-replay counter
MAC_TRUNCATED_BYTES = 3                 # 24-bit truncated MAC
SECURED_FRAME_BYTES = PAYLOAD_BYTES + FRESHNESS_BYTES + MAC_TRUNCATED_BYTES   # 8

FRESHNESS_MODULO = 256                  # 1-byte freshness counter

# Selectable primitive: "hmac" or "cmac"
MAC_PRIMITIVE = "hmac"

"""Select the active MAC primitive: 'hmac' or 'cmac'."""
def set_primitive(name: str):
    global MAC_PRIMITIVE
    if name not in ("hmac", "cmac"):
        raise ValueError("primitive must be 'hmac' or 'cmac'")
    MAC_PRIMITIVE = name


def _auth_input(data_id: int, freshness: int, payload: bytes) -> bytes:
    return (
        data_id.to_bytes(2, "big")
        + bytes([freshness % FRESHNESS_MODULO])
        + bytes(payload)
    )


# ---- Primitive implementations ------------------------------------------
def _mac_hmac(msg: bytes) -> bytes:
    return hmac.new(SHARED_KEY, msg, hashlib.sha256).digest()[:MAC_TRUNCATED_BYTES]


def _mac_cmac(msg: bytes) -> bytes:
    # Imported lazily so the module loads in hmac-only mode without
    # the `cryptography` package installed.
    from cryptography.hazmat.primitives import cmac
    from cryptography.hazmat.primitives.ciphers import algorithms
    c = cmac.CMAC(algorithms.AES(AES_KEY))
    c.update(msg)
    return c.finalize()[:MAC_TRUNCATED_BYTES]

"""Truncated MAC over (data_id || freshness || payload)."""
def compute_mac(data_id: int, freshness: int, payload: bytes) -> bytes:
    msg = _auth_input(data_id, freshness, payload)
    if MAC_PRIMITIVE == "cmac":
        return _mac_cmac(msg)
    return _mac_hmac(msg)

"""Constant-time verification of a received truncated MAC."""
def verify(data_id: int, freshness: int, payload: bytes,
           mac_bytes: bytes) -> bool:
    expected = compute_mac(data_id, freshness, payload)
    return hmac.compare_digest(bytes(expected), bytes(mac_bytes))


# ---- Inline secured-frame construction & parsing ------------------------
"""Return the 8-byte secured frame as a list[int]: payload (4B) || freshness (1B) || truncated MAC (3B)."""
def build_secured_frame(data_id: int, freshness: int,
                        payload: bytes) -> list:
    if len(payload) != PAYLOAD_BYTES:
        raise ValueError(
            f"payload must be exactly {PAYLOAD_BYTES} bytes, "
            f"got {len(payload)}"
        )
    fresh = freshness % FRESHNESS_MODULO
    mac = compute_mac(data_id, fresh, payload)
    return list(payload) + [fresh] + list(mac)

"""Parses 8-byte secured frame into (payload, freshness, mac_bytes)."""
def parse_secured_frame(data: bytes):
    if len(data) < SECURED_FRAME_BYTES:
        raise ValueError(
            f"secured frame must be at least {SECURED_FRAME_BYTES} bytes, "
            f"got {len(data)}"
        )
    payload   = bytes(data[0:PAYLOAD_BYTES])
    freshness = data[PAYLOAD_BYTES]
    mac_bytes = bytes(
        data[PAYLOAD_BYTES + FRESHNESS_BYTES :
             PAYLOAD_BYTES + FRESHNESS_BYTES + MAC_TRUNCATED_BYTES]
    )
    return payload, freshness, mac_bytes

