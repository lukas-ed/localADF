import can
import datetime as dt
from dataclasses import dataclass

# =========================================================
# CAN IDs
# =========================================================
BRAKE_STATUS_ID = 0x110
EXTERIOR_LIGHT_STATUS_ID = 0x120
FAULT_REPORT_ID = 0x130

# =========================================================
# Configuration
# =========================================================
ECU_NAME = "Exterior Light ECU"
CHANNEL = "vcan0"
INTERFACE = "socketcan"

BRAKE_LIGHT_FORCE_THRESHOLD = 10

LIGHT_FAULT_INVALID_MESSAGE = 0


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
    last_brake_counter: int = 0
    tx_counter: int = 0


@dataclass
class BrakeStatusMessage:
    brake_active: int
    brake_force: int
    brake_enabled: int
    brake_faults: int
    brake_counter: int

    @classmethod
    def from_can_data(cls, data: bytes):
        if len(data) < 5:
            raise ValueError("Brake status payload too short")

        return cls(
            brake_active=int(data[0]),
            brake_force=int(data[1]),
            brake_enabled=int(data[2]),
            brake_faults=int(data[3]),
            brake_counter=int(data[4]),
        )


# =========================================================
# Global state
# =========================================================
bus = can.interface.Bus(interface=INTERFACE, channel=CHANNEL)
light_state = ExteriorLightState()


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
            "tx_counter": light_state.tx_counter,
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
# CAN sending
# =========================================================
def send_exterior_light_status():
    payload = [
        int(light_state.light_active),
        int(light_state.enabled),
        int(light_state.faults),
        int(light_state.last_brake_counter),
        int(light_state.tx_counter),
    ]

    msg = can.Message(
        arbitration_id=EXTERIOR_LIGHT_STATUS_ID,
        data=payload,
        is_extended_id=False
    )

    try:
        print(f"[Exterior Light ECU] Sending light status on {CHANNEL}: {payload}")
        bus.send(msg)
        light_state.tx_counter = (light_state.tx_counter + 1) % 256
    except can.CanError as e:
        log_action("CAN_SEND_ERROR", f"Failed to send light status: {e}")


# =========================================================
# Light logic
# =========================================================
def update_exterior_light(brake_active, brake_force, brake_counter):
    if not light_state.enabled:
        return

    light_state.last_brake_active = bool(brake_active)
    light_state.last_brake_force = int(brake_force)
    light_state.last_brake_counter = int(brake_counter)

    if brake_active == 1 or brake_force > BRAKE_LIGHT_FORCE_THRESHOLD:
        light_state.light_active = True
        log_action("LIGHT_UPDATED", "Brake lights activated")
    else:
        light_state.light_active = False
        log_action("LIGHT_UPDATED", "Brake lights deactivated")

    send_exterior_light_status()


def handle_brake_status(msg):
    try:
        brake_msg = BrakeStatusMessage.from_can_data(msg.data)
    except ValueError as e:
        set_fault(LIGHT_FAULT_INVALID_MESSAGE)
        log_action("FAULT", f"Invalid brake status message: {e}")
        return

    clear_faults()
    log_action("BRAKE_STATUS_RECEIVED", f"Received brake status {list(msg.data)}")

    update_exterior_light(
        brake_active=brake_msg.brake_active,
        brake_force=brake_msg.brake_force,
        brake_counter=brake_msg.brake_counter,
    )


def handle_fault_report(msg):
    log_action("FAULT_REPORT_RECEIVED", f"Received fault report {list(msg.data)}")


# =========================================================
# Main loop
# =========================================================
def main():
    print("[Exterior Light ECU] Initializing...")

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