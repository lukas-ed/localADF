"""
stimulus.py
-----------
Drives the test-bed's NORMAL flow by injecting brake-input events on the
production bus (vcan0). The brake ECU listens for these on BRAKE_INPUT_ID
(0x200); without this stimulus the system sits idle.

Payload convention (matches the brake ECU's handle_brake_input):
    byte 0 = pressed (1 = brake pressed, 0 = released)

Patterns
--------
  --pattern cycle    (default) alternate press/release at a fixed interval
  --pattern press    send a single press, then exit
  --pattern release  send a single release, then exit
  --pattern random   randomly press/release (rough "driving" profile)

Examples
--------
  python3 stimulus.py                              # press/release every 1.0s
  python3 stimulus.py --interval 0.5 --count 20    # 20 events, 0.5s apart
  python3 stimulus.py --pattern press              # one press
  python3 stimulus.py --pattern random --rate 50   # 50 events/s, random

This is part of the TEST HARNESS (it simulates the driver / pedal sensor),
not part of the proposed technique.
"""

import argparse
import random
import time
import can

BRAKE_INPUT_ID = 0x200
CHANNEL_DEFAULT = "vcan0"
INTERFACE_DEFAULT = "socketcan"


def send_brake(bus, pressed: int):
    msg = can.Message(
        arbitration_id=BRAKE_INPUT_ID,
        data=[int(bool(pressed))],
        is_extended_id=False,
    )
    bus.send(msg)
    state = "PRESS" if pressed else "release"
    print(f"[stimulus] brake {state}")


def run_cycle(bus, interval, count):
    pressed = 1
    sent = 0
    while count == 0 or sent < count:
        send_brake(bus, pressed)
        pressed ^= 1                     # toggle
        sent += 1
        time.sleep(interval)


def run_single(bus, pressed):
    send_brake(bus, pressed)


def run_random(bus, rate_hz, count):
    interval = 1.0 / max(0.1, rate_hz)
    sent = 0
    while count == 0 or sent < count:
        send_brake(bus, random.choice([0, 1]))
        sent += 1
        time.sleep(interval)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--channel", default=CHANNEL_DEFAULT)
    ap.add_argument("--interface", default=INTERFACE_DEFAULT)
    ap.add_argument("--pattern", choices=["cycle", "press", "release", "random"],
                    default="cycle")
    ap.add_argument("--interval", type=float, default=1.0,
                    help="seconds between events (cycle mode)")
    ap.add_argument("--rate", type=float, default=10.0,
                    help="events per second (random mode)")
    ap.add_argument("--count", type=int, default=0,
                    help="number of events to send (0 = run until Ctrl-C)")
    args = ap.parse_args()

    bus = can.interface.Bus(interface=args.interface, channel=args.channel)
    print(f"[stimulus] sending brake input on {args.channel} "
          f"(id=0x{BRAKE_INPUT_ID:X}), pattern={args.pattern}")

    try:
        if args.pattern == "cycle":
            run_cycle(bus, args.interval, args.count)
        elif args.pattern == "press":
            run_single(bus, 1)
        elif args.pattern == "release":
            run_single(bus, 0)
        elif args.pattern == "random":
            run_random(bus, args.rate, args.count)
    except KeyboardInterrupt:
        print("\n[stimulus] stopped.")


if __name__ == "__main__":
    main()
