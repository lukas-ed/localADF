# `gateway.py` (new)

"""""
Bridges the two functional segments (vcan0 = chassis, vcan1 = body), forwarding
only the **routed** signals per a routing table. It is the single place an
inter-domain frame can be dropped or modified — the control point for the
gateway-tampering experiment that the cross-validation claim rests on.
"""
"""
gateway.py
----------
In-vehicle gateway between two CAN segments:
  vcan0 = chassis (brake ECU, optional wheel-speed ECU)
  vcan1 = body    (exterior-light ECU)

Forwards ONLY the signals in ROUTING (the routed/overlap set). Everything else
stays domain-local. Brake status (0x110) and its companion MAC (0x510) are
forwarded chassis->body so the light ECU can consume them and NS_body can
observe the post-gateway copy. NS_chassis observes the pre-gateway copy.

Attack hooks (env vars), used for experiment 4 (gateway tampering):
  GW_DROP_IDS   = "0x110"        -> drop these ids on forward (suppression)
  GW_MODIFY_IDS = "0x110"        -> corrupt payload of these ids on forward
  GW_ATTACK_AFTER = "20"         -> only start attacking after N forwards
Leave them unset for a faithful (non-tampering) gateway.
"""

import os
import time
import threading
import can

CHASSIS = os.getenv("GW_CHASSIS", "vcan0")
BODY = os.getenv("GW_BODY", "vcan1")
INTERFACE = "socketcan"

# id -> direction it is routed in: "c2b" (chassis->body) or "b2c"
ROUTING = {
    0x110: "c2b",   # brake status
    0x510: "c2b",   # brake status companion MAC
    0x130: "c2b",   # fault report
}


def _id_set(env):
    return {int(x, 16) for x in os.getenv(env, "").split(",") if x.strip()}


DROP_IDS = _id_set("GW_DROP_IDS")
MODIFY_IDS = _id_set("GW_MODIFY_IDS")
ATTACK_AFTER = int(os.getenv("GW_ATTACK_AFTER", "0"))

_forward_count = 0
_count_lock = threading.Lock()


def _attack_active():
    if ATTACK_AFTER <= 0:
        return True
    with _count_lock:
        return _forward_count >= ATTACK_AFTER


def _corrupt(data: bytes) -> bytes:
    b = bytearray(data)
    if b:
        b[0] ^= 0xFF      # flip the first byte; payload now fails MAC at the receiver
    return bytes(b)


def _forward_loop(src, dst, direction):
    global _forward_count
    while True:
        msg = src.recv(timeout=0.1)
        if msg is None:
            continue
        if ROUTING.get(msg.arbitration_id) != direction:
            continue  # not routed in this direction -> domain-local, ignore

        with _count_lock:
            _forward_count += 1

        aid = msg.arbitration_id
        if aid in DROP_IDS and _attack_active():
            print(f"[gateway][ATTACK] DROPPED 0x{aid:X} ({direction})")
            continue

        data = msg.data
        if aid in MODIFY_IDS and _attack_active():
            data = _corrupt(data)
            print(f"[gateway][ATTACK] MODIFIED 0x{aid:X} ({direction})")

        try:
            dst.send(can.Message(arbitration_id=aid, data=data, is_extended_id=False))
        except can.CanError as e:
            print(f"[gateway] forward error 0x{aid:X}: {e}")


def main():
    chassis = can.interface.Bus(interface=INTERFACE, channel=CHASSIS)
    body = can.interface.Bus(interface=INTERFACE, channel=BODY)
    print(f"[gateway] {CHASSIS}<->{BODY} routing="
          f"{ {hex(k): v for k, v in ROUTING.items()} } "
          f"drop={[hex(x) for x in DROP_IDS]} modify={[hex(x) for x in MODIFY_IDS]}")
    threads = [
        threading.Thread(target=_forward_loop, args=(chassis, body, "c2b"), daemon=True),
        threading.Thread(target=_forward_loop, args=(body, chassis, "b2c"), daemon=True),
    ]
    for t in threads:
        t.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[gateway] stopping")


if __name__ == "__main__":
    main()


#**Experiment use:**
#- Faithful run: leave the env vars unset.
#- Drop attack: `GW_DROP_IDS=0x110` → NS_chassis still sealed it pre-gateway; NS_body never sees it → L-SIEM cross-validation flags an omission.
#- Modify attack: `GW_MODIFY_IDS=0x110` (0x510 forwarded unchanged) → NS_body's MAC verify fails **and** the payload differs from NS_chassis → flagged two ways.
