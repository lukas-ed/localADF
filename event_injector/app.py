# `event_injector.py` (new)
"""
The adversary, separate from `stimulus.py` (which drives normal input). Injects
the attacks for experiments 1–6: spoof (with or without a valid MAC), replay,
flood (mechanism-only on vcan), and fault-report spoofing. Frame *dropping* and
*modification* are gateway functions (see `gateway.py`), since a node on a
broadcast bus can add frames but not remove others'.
"""

"""
event_injector.py
-----------------
Adversary for the forensic test-bed.

Modes:
  spoof   --id 0x110 --data 1,60,1,0,5 [--mac]
            inject a status frame. With --mac, compute a VALID companion MAC
            using the shared key -> demonstrates the single-shared-key weakness
            (any key holder forges authentic frames). Without --mac, inject an
            unauthenticated status frame (cheapest spoof).
  replay  --id 0x110 [--delay 1.0]
            capture the next (status + companion MAC) pair and re-inject it
            verbatim after --delay seconds (valid MAC, stale freshness).
  flood   --id 0x000 --count 1000
            burst frames. NOTE: vcan has no arbitration/bit-rate, so this shows
            the *mechanism* only; real bus starvation must be argued analytically.
  fault   --source 1
            inject an (unauthenticated) 0x130 fault report -> tests the
            fault-indication trigger and the forgeability of fault reports.

Channel defaults to vcan0 (chassis). Use --channel vcan1 to attack the body bus.
"""

import time
import argparse
import can

import secoc_lite as secoc

DEFAULTS = {"channel": "vcan0", "interface": "socketcan"}


def _bus(channel):
    return can.interface.Bus(interface=DEFAULTS["interface"], channel=channel)


def _parse_data(s):
    return [int(x, 0) & 0xFF for x in s.split(",") if x.strip() != ""]


def do_spoof(args):
    bus = _bus(args.channel)
    data = _parse_data(args.data)
    bus.send(can.Message(arbitration_id=args.id, data=data, is_extended_id=False))
    print(f"[injector] spoofed 0x{args.id:X} data={data} on {args.channel}")
    if args.mac:
        # forge a valid companion MAC using the (shared) test-bed key
        freshness = args.freshness
        mac_payload = secoc.build_mac_payload(args.id, freshness, bytes(data))
        bus.send(can.Message(arbitration_id=secoc.mac_id_for(args.id),
                             data=mac_payload, is_extended_id=False))
        print(f"[injector] forged VALID MAC for 0x{args.id:X} (freshness={freshness})")


def do_replay(args):
    bus = _bus(args.channel)
    mac_id = secoc.mac_id_for(args.id)
    status = mac = None
    print(f"[injector] capturing 0x{args.id:X} (+0x{mac_id:X}) to replay...")
    while status is None or mac is None:
        msg = bus.recv(timeout=5.0)
        if msg is None:
            print("[injector] nothing captured; aborting replay")
            return
        if msg.arbitration_id == args.id:
            status = bytes(msg.data)
        elif msg.arbitration_id == mac_id:
            mac = bytes(msg.data)
    time.sleep(args.delay)
    bus.send(can.Message(arbitration_id=args.id, data=status, is_extended_id=False))
    bus.send(can.Message(arbitration_id=mac_id, data=mac, is_extended_id=False))
    print(f"[injector] replayed captured pair after {args.delay}s "
          f"(valid MAC, stale freshness)")


def do_flood(args):
    bus = _bus(args.channel)
    for _ in range(args.count):
        bus.send(can.Message(arbitration_id=args.id, data=[0] * 8, is_extended_id=False))
    print(f"[injector] flooded {args.count} x 0x{args.id:X} "
          f"(vcan: mechanism only -- no real arbitration/starvation)")


def do_fault(args):
    bus = _bus(args.channel)
    data = [args.source, 0x02, 0, 0, 0]   # forged fault report
    bus.send(can.Message(arbitration_id=0x130, data=data, is_extended_id=False))
    print(f"[injector] injected unauthenticated fault report 0x130 data={data}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--channel", default=DEFAULTS["channel"])
    sub = p.add_subparsers(dest="mode", required=True)

    s = sub.add_parser("spoof"); s.set_defaults(fn=do_spoof)
    s.add_argument("--id", type=lambda x: int(x, 0), default=0x110)
    s.add_argument("--data", default="1,60,1,0,5")
    s.add_argument("--mac", action="store_true")
    s.add_argument("--freshness", type=int, default=200)

    r = sub.add_parser("replay"); r.set_defaults(fn=do_replay)
    r.add_argument("--id", type=lambda x: int(x, 0), default=0x110)
    r.add_argument("--delay", type=float, default=1.0)

    f = sub.add_parser("flood"); f.set_defaults(fn=do_flood)
    f.add_argument("--id", type=lambda x: int(x, 0), default=0x000)
    f.add_argument("--count", type=int, default=1000)

    ft = sub.add_parser("fault"); ft.set_defaults(fn=do_fault)
    ft.add_argument("--source", type=int, default=1)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()

"""

**Maps to experiments:** `spoof --mac` (compromised-but-keyed ECU / shared-key
weakness), `spoof` no-MAC (cheapest spoof — note the light ECU acts on it but a
MAC-checking NS flags the missing/forged MAC), `replay` (anti-replay via
freshness), `fault` (fault-trigger + forgeable fault reports), `flood`
(mechanism only — pair with the analytical bus model for any load claim).
"""
