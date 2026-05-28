import time
import can
import datetime as dt
from dataclasses import dataclass

# =========================================================
# CAN IDs
# =========================================================
BRAKE_INPUT_ID = 0x200
BRAKE_STATUS_ID = 0x110
FAULT_REPORT_ID = 0x130

# =========================================================
# Configuration
# =========================================================
ECU_NAME = "Brake ECU"
CHANNEL = "vcan0"
INTERFACE = "socketcan"

BRAKE_PEDAL_OVERRIDE_THRESHOLD = 95
GROUND_FAULT_THRESHOLD = 0
FAULT_HYSTERESIS = 3

BRAKE_FORCE_MIN = 0
BRAKE_FORCE_MAX = 100

BRAKE_FAULT_INVALID_SENSOR = 0
BRAKE_FAULT_OPERATOR_OVERRIDE = 1


# =========================================================
# Data classes
# =========================================================
@dataclass
class ConditionState:
    count: int = 0


@dataclass
class BrakePedalReading:
    high: int
    low: int


@dataclass
class BrakeECUState:
    enabled: bool = False
    faults: int = 0
    operator_override: bool = False
    brake_active: bool = False
    brake_force: int = 0
    tx_counter: int = 0


# =========================================================
# Global state
# =========================================================
bus = can.interface.Bus(interface=INTERFACE, channel=CHANNEL)

brake_state = BrakeECUState()
grounded_fault_state = ConditionState()
operator_override_state = ConditionState()


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
            "enabled": brake_state.enabled,
            "faults": brake_state.faults,
            "operator_override": brake_state.operator_override,
            "brake_active": brake_state.brake_active,
            "brake_force": brake_state.brake_force,
            "tx_counter": brake_state.tx_counter,
        },
    }
    print(log_entry)
    return log_entry


# =========================================================
# Fault helpers
# =========================================================
def set_fault(fault_bit):
    brake_state.faults |= (1 << fault_bit)


def clear_faults():
    brake_state.faults = 0


def condition_exceeded_duration(condition, hysteresis, state_obj):
    if condition:
        state_obj.count += 1
    else:
        state_obj.count = max(0, state_obj.count - 1)

    return state_obj.count >= hysteresis


def check_voltage_grounded(high, low, hysteresis, state_obj):
    condition = (high <= GROUND_FAULT_THRESHOLD and low <= GROUND_FAULT_THRESHOLD)
    return condition_exceeded_duration(condition, hysteresis, state_obj)


# =========================================================
# Sensor logic
# =========================================================
def read_brake_pedal_sensor(sensor_high, sensor_low):
    return BrakePedalReading(high=sensor_high, low=sensor_low)


# =========================================================
# Control state
# =========================================================
def enable_control():
    if not brake_state.enabled and not brake_state.operator_override:
        brake_state.enabled = True
        log_action("CONTROL_ENABLED", "Brake control enabled")


def disable_control():
    if brake_state.enabled:
        brake_state.enabled = False
        brake_state.brake_active = False
        brake_state.brake_force = 0
        log_action("CONTROL_DISABLED", "Brake control disabled")


# =========================================================
# CAN sending
# =========================================================
def send_brake_status():
    payload = [
        int(brake_state.brake_active),
        int(brake_state.brake_force),
        int(brake_state.enabled),
        int(brake_state.faults),
        int(brake_state.tx_counter),
    ]

    msg = can.Message(
        arbitration_id=BRAKE_STATUS_ID,
        data=payload,
        is_extended_id=False
    )

    try:
        print(f"[Brake ECU] Sending brake status on {CHANNEL}: {payload}")
        bus.send(msg)
        brake_state.tx_counter = (brake_state.tx_counter + 1) % 256
    except can.CanError as e:
        log_action("CAN_SEND_ERROR", f"Failed to send brake status: {e}")


def send_fault_report():
    payload = [
        1,  # source ECU code for Brake ECU
        int(brake_state.faults),
        int(brake_state.tx_counter),
        0,
        0,
    ]

    msg = can.Message(
        arbitration_id=FAULT_REPORT_ID,
        data=payload,
        is_extended_id=False
    )

    try:
        bus.send(msg)
        log_action("SEND_FAULT_REPORT", f"Sent fault report: {payload}")
    except can.CanError as e:
        log_action("CAN_SEND_ERROR", f"Failed to send fault report: {e}")


# =========================================================
# Brake logic
# =========================================================
def check_for_faults(sensor_high, sensor_low):
    if brake_state.enabled or brake_state.faults > 0:
        brake_reading = read_brake_pedal_sensor(sensor_high, sensor_low)
        brake_average = (brake_reading.high + brake_reading.low) // 2

        operator_overridden = condition_exceeded_duration(
            brake_average >= BRAKE_PEDAL_OVERRIDE_THRESHOLD,
            FAULT_HYSTERESIS,
            operator_override_state
        )

        inputs_grounded = check_voltage_grounded(
            brake_reading.high,
            brake_reading.low,
            FAULT_HYSTERESIS,
            grounded_fault_state
        )

        if inputs_grounded:
            disable_control()
            set_fault(BRAKE_FAULT_INVALID_SENSOR)
            send_fault_report()
            log_action("FAULT", "Invalid brake pedal sensor value")

        elif operator_overridden:
            disable_control()
            set_fault(BRAKE_FAULT_OPERATOR_OVERRIDE)
            brake_state.operator_override = True
            send_fault_report()
            log_action("FAULT", "Operator override detected")

        else:
            clear_faults()
            brake_state.operator_override = False


def update_brake(sensor_high, sensor_low):
    if brake_state.enabled:
        brake_high = max(BRAKE_FORCE_MIN, min(sensor_high, BRAKE_FORCE_MAX))
        brake_low = max(BRAKE_FORCE_MIN, min(sensor_low, BRAKE_FORCE_MAX))

        brake_average = (brake_high + brake_low) // 2
        brake_state.brake_force = brake_average
        brake_state.brake_active = brake_average > 10

        log_action(
            "BRAKE_UPDATED",
            f"Brake updated high={brake_high}, low={brake_low}, avg={brake_average}"
        )

        send_brake_status()


# =========================================================
# Input handling
# =========================================================
def handle_brake_input(msg):
    """
    Expected input payload:
    byte 0 = pressed (0 or 1)
    """
    if len(msg.data) < 1:
        log_action("INVALID_INPUT", "Brake input payload too short")
        return

    pressed = int(msg.data[0])

    if pressed == 1:
        sensor_high, sensor_low = 80, 40
    else:
        sensor_high, sensor_low = 0, 0 if False else (10, 5)

    # fix tuple issue explicitly
    if pressed == 1:
        sensor_high, sensor_low = 80, 40
    else:
        sensor_high, sensor_low = 10, 5

    log_action("BRAKE_INPUT_RECEIVED", f"Input pressed={pressed}")

    check_for_faults(sensor_high, sensor_low)

    if brake_state.enabled:
        update_brake(sensor_high, sensor_low)


# =========================================================
# Main loop
# =========================================================
def main():
    print("[Brake ECU] Initializing...")
    enable_control()

    while True:
        msg = bus.recv(timeout=0.1)

        if msg and msg.arbitration_id == BRAKE_INPUT_ID:
            handle_brake_input(msg)



if __name__ == "__main__":
    main()