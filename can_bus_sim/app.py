"""
mirror.py
---------
Mirrors every CAN frame from the production bus (vcan0) onto the forensic
bus (vcan1), so the passive, read-only forensic component listening on vcan1
observes exactly the traffic exchanged on vcan0.

Why a mirror exists in the test-bed
-----------------------------------
On a real vehicle, the forensic component would tap the segment in parallel
(an out-of-band read-only tap). A virtual CAN interface cannot be physically
tapped, so this mirror process emulates that tap by copying frames vcan0 ->
vcan1. It is part of the TEST HARNESS, not part of the proposed technique:
the component itself never reads vcan0 and never writes anywhere.

Two modes
---------
  --mode passthrough   (default) copy every vcan0 frame to vcan1 unchanged.
  --mode gateway       copy frames but allow selective SUPPRESSION of chosen
                       CAN IDs (used later to emulate a "drop" attack at the
                       gateway, since a frame already broadcast cannot be
                       un-sent on the bus itself).

Usage
-----
  python3 mirror.py
  python3 mirror.py --src vcan0 --dst vcan1
  python3 mirror.py --mode gateway --suppress 0x110      # drop brake status
  python3 mirror.py --mode gateway --suppress 0x110,0x510 # also its MAC frame

Note: an alternative to this script is the kernel's `cangw` tool:
  sudo modprobe can-gw
  sudo cangw -A -s vcan0 -d vcan1 -e
The Python mirror is used here because it also supports the gateway
suppression mode needed for the drop experiment, and because it lets the
mirror's behaviour be logged and varied programmatically.
"""

import argparse
import can


def parse_ids(s):
    if not s:
        return set()
    out = set()
    for part in s.split(","):
        part = part.strip()
        if part:
            out.add(int(part, 0))   # accepts 0x110 or decimal
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default="vcan0", help="source (production) bus")
    ap.add_argument("--dst", default="vcan1", help="destination (forensic) bus")
    ap.add_argument("--interface", default="socketcan")
    ap.add_argument("--mode", choices=["passthrough", "gateway"],
                    default="passthrough")
    ap.add_argument("--suppress", default="",
                    help="comma-separated CAN IDs to drop in gateway mode "
                         "(e.g. 0x110,0x510)")
    args = ap.parse_args()

    suppress = parse_ids(args.suppress)
    if args.mode == "gateway" and suppress:
        ids = ", ".join(hex(i) for i in sorted(suppress))
        print(f"[mirror] GATEWAY mode: suppressing IDs {ids}")
    else:
        print(f"[mirror] PASSTHROUGH mode")

    src_bus = can.interface.Bus(interface=args.interface, channel=args.src)
    dst_bus = can.interface.Bus(interface=args.interface, channel=args.dst)

    print(f"[mirror] forwarding {args.src} -> {args.dst}  (Ctrl-C to stop)")
    forwarded = 0
    dropped = 0
    try:
        while True:
            msg = src_bus.recv(timeout=1.0)
            if msg is None:
                continue

            if args.mode == "gateway" and msg.arbitration_id in suppress:
                dropped += 1
                # the frame still existed on vcan0 (it was broadcast); we only
                # decline to forward it to the forensic bus, emulating a
                # gateway that fails/withholds delivery of this evidence.
                continue

            # forward unchanged; preserve ID, data, and extended flag
            out = can.Message(
                arbitration_id=msg.arbitration_id,
                data=msg.data,
                is_extended_id=msg.is_extended_id,
            )
            try:
                dst_bus.send(out)
                forwarded += 1
            except can.CanError as e:
                print(f"[mirror] forward error: {e}")
    except KeyboardInterrupt:
        print(f"\n[mirror] stopped. forwarded={forwarded} dropped={dropped}")


if __name__ == "__main__":
    main()
