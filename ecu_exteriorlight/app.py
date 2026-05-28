# Exterior Light ECU — inline SecOC

#**Path:** `ecu_exteriorlight/app.py` (replace the existing file)

#Key changes vs. the separate-frame version:
#- Removed `send_mac_frame()` helper. `send_exterior_light_status()` now
#  sends one 8-byte secured frame on `0x120`.
#- **NEW:** `handle_brake_status()` parses the inline secured frame on
#  `0x110`, verifies the MAC, checks freshness, and only then applies the
#  brake update. Previously the light ECU trusted the brake frame
#  unconditionally — this was a soft spot worth fixing.
#- Payload reduced from 5 to 4 bytes; `tx_counter` removed.
#- `last_brake_counter` now stores the **freshness** of the received brake
#  frame (lets the forensic component correlate which brake frame triggered
#  which lamp activation).

import can
import datetime as dt
from dataclasses import dataclass

import secoc_lite as secoc          # shared MAC helper (inline profile)

# =========================================================
# CAN IDs
# =========================================================
BRAKE_STATUS_ID          = 0x110
EXTERIOR_LIGHT_STATUS_ID = 0x120
FAULT_REPORT_ID          = 0x130

# =========================================================
# Configuration
# =========================================================
ECU_NAME = "Exterior Light ECU"
CHANNEL = "vcan0"
INTERFACE = "socketcan"

BRAKE_LIGHT_FORCE_THRESHOLD = 10

LIGHT_FAULT_INVALID_MESSAGE = 0
LIGHT_FAULT_MAC_VERIFY      = 1
LIGHT_FAULT_REPLAY          = 2


# =========================================================
# Data classes
# =========================================================
@dataclass
class ExteriorLightState:
    enabled: bool = True
    light_active: bool = False
    faults: int = 0
    last_brake_active: bool = False
    last_brake_force: int = 0
    last_brake_counter: int = 0   # echoes the brake frame's freshness


@dataclass
class BrakeStatusMessage:
    brake_active: int
    brake_force: int
    brake_enabled: int
    brake_faults: int

    @classmethod
    def from_payload(cls, payload: bytes):
        if len(payload) < secoc.PAYLOAD_BYTES:
            raise ValueError("Brake status payload too short")
        return cls(
            brake_active=int(payload[0]),
            brake_force=int(payload[1]),
            brake_enabled=int(payload[2]),
            brake_faults=int(payload[3]),
        )


# =========================================================
# Global state
# =========================================================
bus = can.interface.Bus(interface=INTERFACE, channel=CHANNEL)
light_state = ExteriorLightState()

# Outgoing freshness counters (per authenticated data ID we send)
freshness_counters = {}

# Incoming freshness tracker (last accepted per data ID we receive)
last_seen_freshness = {}


def next_freshness(data_id):
    val = freshness_counters.get(data_id, 0)
    freshness_counters[data_id] = (val + 1) % secoc.FRESHNESS_MODULO
    return val


def is_fresh(data_id, freshness, forward_window=16):
    """Anti-replay: accept only if freshness advances within a forward window
    (mod 256). Matches the forensic component's FreshnessTracker logic."""
    if data_id not in last_seen_freshness:
        last_seen_freshness[data_id] = freshness
        return True
    prev = last_seen_freshness[data_id]
    delta = (freshness - prev) % secoc.FRESHNESS_MODULO
    if 1 <= delta <= forward_window:
        last_seen_freshness[data_id] = freshness
        return True
    return False


# =========================================================
# Logging
# =========================================================
def log_action(event, description):
    time_frame = dt.datetime.now().isoformat(timespec="milliseconds")
    log_entry = {
        "Time": time_frame,
        "ECU": ECU_NAME,
        "event": event,
        "description": description,
        "state": {
            "enabled": light_state.enabled,
            "light_active": light_state.light_active,
            "faults": light_state.faults,
            "last_brake_active": light_state.last_brake_active,
            "last_brake_force": light_state.last_brake_force,
            "last_brake_counter": light_state.last_brake_counter,
        },
    }
    print(log_entry)
    return log_entry


# =========================================================
# Fault helpers
# =========================================================
def set_fault(fault_bit):
    light_state.faults |= (1 << fault_bit)


def clear_faults():
    light_state.faults = 0


# =========================================================
# CAN sending  (INLINE SecOC)
# =========================================================
def send_exterior_light_status():
    payload = bytes([
        int(light_state.light_active),
        int(light_state.enabled),
        int(light_state.faults),
        int(light_state.last_brake_counter),
    ])

    freshness = next_freshness(EXTERIOR_LIGHT_STATUS_ID)
    secured = secoc.build_secured_frame(
        EXTERIOR_LIGHT_STATUS_ID, freshness, payload
    )

    msg = can.Message(
        arbitration_id=EXTERIOR_LIGHT_STATUS_ID,
        data=secured,
        is_extended_id=False,
    )

    try:
        print(f"[Exterior Light ECU] Sending secured light status on {CHANNEL}: "
              f"payload={list(payload)} fresh={freshness} frame={secured}")
        bus.send(msg)
    except can.CanError as e:
        log_action("CAN_SEND_ERROR", f"Failed to send light status: {e}")


# =========================================================
# Light logic
# =========================================================
def update_exterior_light(brake_active, brake_force, brake_counter):
    if not light_state.enabled:
        return

    light_state.last_brake_active  = bool(brake_active)
    light_state.last_brake_force   = int(brake_force)
    light_state.last_brake_counter = int(brake_counter)

    if brake_active == 1 or brake_force > BRAKE_LIGHT_FORCE_THRESHOLD:
        light_state.light_active = True
        log_action("LIGHT_UPDATED", "Brake lights activated")
    else:
        light_state.light_active = False
        log_action("LIGHT_UPDATED", "Brake lights deactivated")

    send_exterior_light_status()


def handle_brake_status(msg):
    """Verify the inline MAC on 0x110, then apply the brake status.
    Frames that fail MAC verification or freshness are dropped and logged."""
    try:
        payload, freshness, mac_bytes = secoc.parse_secured_frame(bytes(msg.data))
    except ValueError as e:
        set_fault(LIGHT_FAULT_INVALID_MESSAGE)
        log_action("FAULT", f"Malformed brake status frame: {e}")
        return

    if not secoc.verify(BRAKE_STATUS_ID, freshness, payload, mac_bytes):
        set_fault(LIGHT_FAULT_MAC_VERIFY)
        log_action("FAULT", "Brake status MAC verification FAILED - frame ignored")
        return

    if not is_fresh(BRAKE_STATUS_ID, freshness):
        set_fault(LIGHT_FAULT_REPLAY)
        log_action("FAULT",
                   f"Brake status freshness=0x{freshness:02X} looks replayed - frame ignored")
        return

    try:
        brake_msg = BrakeStatusMessage.from_payload(payload)
    except ValueError as e:
        set_fault(LIGHT_FAULT_INVALID_MESSAGE)
        log_action("FAULT", f"Invalid brake status payload: {e}")
        return

    clear_faults()
    log_action(
        "BRAKE_STATUS_RECEIVED",
        f"Authentic brake status payload={list(payload)} fresh={freshness}",
    )

    update_exterior_light(
        brake_active=brake_msg.brake_active,
        brake_force=brake_msg.brake_force,
        brake_counter=freshness,    # echo the brake frame's freshness so
                                    # the forensic observer can correlate
    )


def handle_fault_report(msg):
    log_action("FAULT_REPORT_RECEIVED", f"Received fault report {list(msg.data)}")


# =========================================================
# Main loop
# =========================================================
def main():
    print("[Exterior Light ECU] Initializing (inline SecOC profile)...")
    while True:
        msg = bus.recv(timeout=0.1)
        if msg is None:
            continue
        if msg.arbitration_id == BRAKE_STATUS_ID:
            handle_brake_status(msg)
        elif msg.arbitration_id == FAULT_REPORT_ID:
            handle_fault_report(msg)


if __name__ == "__main__":
    main()

