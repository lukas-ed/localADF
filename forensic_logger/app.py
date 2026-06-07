
"""
forensic_logger/app.py  (INLINE PROFILE: embedded MAC, rolling buffer + context window)
-------------------------------------------------------------------------------------
Passive bus-segment monitor.

Behavior:
- Every observed CAN frame is appended to a bounded rolling buffer.
- Normal authenticated brake/light status frames update internal state only.
- Normal frames are NOT permanently logged as events.
- When an HS or NS event is detected, one event record is logged.
- In extended mode, the monitor seals PRE_N frames before and POST_N frames after
  the event into a hash-chained contextual capsule.
"""

import os
import can
import time
import json
import hashlib
import datetime as dt
import collections
from dataclasses import dataclass, asdict

import secoc_lite as secoc


# ============================ configuration ============================
CHANNEL = os.getenv("NS_CHANNEL", "vcan1")
INTERFACE = os.getenv("NS_INTERFACE", "socketcan")
MONITOR_ID = os.getenv("NS_ID", "NS_chassis")

MODE = os.getenv("NS_MODE", "extended")        # "limited" | "extended"

PRE_N = int(os.getenv("NS_PRE_N", "12"))
POST_N = int(os.getenv("NS_POST_N", "12"))
BUFFER_SIZE = int(os.getenv("NS_BUFFER", "256"))

BRAKE_STATUS_ID = 0x110
EXTERIOR_LIGHT_STATUS_ID = 0x120
FAULT_REPORT_ID = 0x130
HS_EVENT_ID = 0x160

BRAKE_TO_LAMP_WINDOW_S = 0.20
SWEEP_INTERVAL_S = 0.05

LOG_PATH = os.getenv("LOG_PATH", os.getenv("NS_LOG", "forensic_log.jsonl"))


# ============================ reconstructed state ============================
@dataclass
class ObservedBrake:
    brake_active: int = 0
    brake_force: int = 0
    enabled: int = 0
    faults: int = 0
    counter: int = 0          # SecOC freshness
    observed_at: float = 0.0
    resolved: bool = False


@dataclass
class ObservedLight:
    light_active: int = 0
    enabled: int = 0
    faults: int = 0
    last_brake_counter: int = 0
    counter: int = 0          # SecOC freshness
    observed_at: float = 0.0


# ============================ freshness / replay ============================
class FreshnessTracker:
    def __init__(self, forward_window: int = 16):
        self.last = {}
        self.forward_window = forward_window

    def is_fresh(self, data_id: int, freshness: int) -> bool:
        if data_id not in self.last:
            self.last[data_id] = freshness
            return True

        prev = self.last[data_id]
        delta = (freshness - prev) % secoc.FRESHNESS_MODULO

        if 1 <= delta <= self.forward_window:
            self.last[data_id] = freshness
            return True

        return False


# ============================ hash-chained log ============================
class HashChainLog:
    GENESIS = "0" * 64

    def __init__(self, path: str):
        self.path = path
        self.prev_hash = self.GENESIS
        self.count = 0
        open(self.path, "w").close()

    def append(self, record: dict) -> dict:
        record["seq"] = self.count
        record["prev_hash"] = self.prev_hash

        body = json.dumps(record, sort_keys=True, separators=(",", ":"))
        entry_hash = hashlib.sha256((self.prev_hash + body).encode()).hexdigest()

        record["entry_hash"] = entry_hash

        with open(self.path, "a") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")

        self.prev_hash = entry_hash
        self.count += 1

        return record

    def verify_file(self) -> bool:
        prev = self.GENESIS

        with open(self.path) as fh:
            for line in fh:
                rec = json.loads(line)
                stored = rec.pop("entry_hash")

                body = json.dumps(rec, sort_keys=True, separators=(",", ":"))
                expected = hashlib.sha256((prev + body).encode()).hexdigest()

                if expected != stored or rec["prev_hash"] != prev:
                    return False

                prev = stored

        return True


# ============================ forensic component ============================
class ForensicComponent:
    def __init__(self):
        self.bus = can.interface.Bus(channel=CHANNEL, interface=INTERFACE)

        self.brake = ObservedBrake()
        self.light = ObservedLight()
        self.freshness = FreshnessTracker()
        self.log = HashChainLog(LOG_PATH)

        # Rolling buffer and context-capture state
        self.buffer = collections.deque(maxlen=BUFFER_SIZE)
        self.cap_seq = 0
        self.pending_capsules = []
        self.capsule_counter = 0

        self.metrics = {
            "frames_observed": 0,
            "mac_verified_ok": 0,
            "mac_failed": 0,
            "replays": 0,
            "drops": 0,
            "spec_violations": 0,
            "hs_events": 0,
            "capsules_sealed": 0,
        }

    # ============================ permanent event log ============================
    def record(self, event, detail, anomaly=False, source="NS", extra=None):
        rec = {
            "capture_time": dt.datetime.now().isoformat(timespec="microseconds"),
            "record_type": "event",
            "monitor_id": MONITOR_ID,
            "source": source,
            "event": event,
            "detail": detail,
            "anomaly": bool(anomaly),
            "observed_brake": asdict(self.brake),
            "observed_light": asdict(self.light),
        }

        if extra:
            rec.update(extra)

        written = self.log.append(rec)

        tag = "ANOMALY" if anomaly else "ok"
        print(f"[{MONITOR_ID}][{tag}] {source}:{event}: {detail}", flush=True)

        return written

    # ============================ rolling buffer ============================
    def _buffer_frame(self, msg):
        """Store every observed frame temporarily.

        This is not permanent logging. Entries are overwritten when the rolling
        buffer reaches BUFFER_SIZE. They are only written to the forensic log if
        a later HS/NS event causes a context capsule to be sealed.
        """
        self.cap_seq += 1

        entry = {
            "cap_seq": self.cap_seq,
            "ts": dt.datetime.now().isoformat(timespec="microseconds"),
            "can_id": msg.arbitration_id,
            "dlc": len(msg.data),
            "payload_hex": bytes(msg.data).hex(),
        }

        self.buffer.append(entry)

        finished = []

        for cap in self.pending_capsules:
            if cap["need"] > 0:
                cap["post"].append(entry)
                cap["need"] -= 1

                if cap["need"] == 0:
                    self._finalize_capsule(cap)
                    finished.append(cap)

        for cap in finished:
            self.pending_capsules.remove(cap)

    def _trigger_context(self, trigger_seq, label):
        """Start a PRE_N/POST_N context capsule after a detected event."""
        if MODE != "extended":
            return

        self.capsule_counter += 1
        capsule_id = f"cap_{MONITOR_ID}_{self.capsule_counter}"

        # This includes the triggering frame if it has already been buffered.
        pre = list(self.buffer)[-PRE_N:]

        self.pending_capsules.append({
            "capsule_id": capsule_id,
            "trigger_seq": trigger_seq,
            "label": label,
            "pre": pre,
            "post": [],
            "need": POST_N,
        })

        print(
            f"[{MONITOR_ID}] trigger '{label}' -> context {capsule_id} "
            f"({len(pre)} pre, collecting {POST_N} post)",
            flush=True,
        )

    def _finalize_capsule(self, cap):
        """Write the contextual window into the hash-chained forensic log."""
        capsule_id = cap["capsule_id"]
        member_hashes = []

        for fr in cap["pre"] + cap["post"]:
            payload_bytes = bytes.fromhex(fr["payload_hex"])

            rec = self.log.append({
                "capture_time": fr["ts"],
                "record_type": "observed_frame",
                "monitor_id": MONITOR_ID,
                "capsule_id": capsule_id,
                "relates_to": cap["trigger_seq"],
                "can_id": f"0x{fr['can_id']:X}",
                "dlc": fr["dlc"],
                "payload_repr": "raw",
                "payload_hex": fr["payload_hex"],
                "payload_hash": hashlib.sha256(payload_bytes).hexdigest(),
                "cap_seq": fr["cap_seq"],
            })

            member_hashes.append(rec["entry_hash"])

        self.log.append({
            "capture_time": dt.datetime.now().isoformat(timespec="microseconds"),
            "record_type": "manifest",
            "monitor_id": MONITOR_ID,
            "capsule_id": capsule_id,
            "trigger_seq": cap["trigger_seq"],
            "trigger_label": cap["label"],
            "member_count": len(member_hashes),
            "member_root": hashlib.sha256(
                json.dumps(member_hashes, sort_keys=True).encode()
            ).hexdigest(),
        })

        self.metrics["capsules_sealed"] += 1

        print(
            f"[{MONITOR_ID}] sealed {capsule_id}: "
            f"{len(cap['pre'])} pre + {len(cap['post'])} post frames",
            flush=True,
        )

    # ============================ authenticated status handling ============================
    def _accept_authenticated(self, data_id, payload, freshness):
        """Update reconstructed state after successful MAC/freshness verification.

        Important:
        Normal brake/light status frames are NOT written as permanent event records.
        They remain in the rolling buffer and are only persisted if an HS/NS event
        causes a context capsule to be sealed.
        """
        now = time.time()

        if data_id == BRAKE_STATUS_ID:
            self.brake = ObservedBrake(
                brake_active=payload[0],
                brake_force=payload[1],
                enabled=payload[2],
                faults=payload[3],
                counter=freshness,
                observed_at=now,
                resolved=False,
            )
            return

        if data_id == EXTERIOR_LIGHT_STATUS_ID:
            self.light = ObservedLight(
                light_active=payload[0],
                enabled=payload[1],
                faults=payload[2],
                last_brake_counter=payload[3],
                counter=freshness,
                observed_at=now,
            )

            # Only log if this normal frame reveals an anomaly.
            self._check_causality_on_light()
            return

    # ============================ NS causality checks ============================
    def _brake_demands_light(self) -> bool:
        return self.brake.brake_active == 1 or self.brake.brake_force > 10

    def _check_causality_on_light(self):
        if self._brake_demands_light():
            if self.light.light_active == 1:
                self.brake.resolved = True
            else:
                self.metrics["spec_violations"] += 1

                r = self.record(
                    "SPEC_VIOLATION_LAMP_OFF",
                    "brake active but lamp not activated",
                    anomaly=True,
                )

                self._trigger_context(r["seq"], "SPEC_VIOLATION_LAMP_OFF")
        else:
            if self.light.light_active == 1:
                self.metrics["spec_violations"] += 1

                r = self.record(
                    "SPEC_VIOLATION_LAMP_WITHOUT_BRAKE",
                    "lamp active without brake demand",
                    anomaly=True,
                )

                self._trigger_context(r["seq"], "SPEC_VIOLATION_LAMP_WITHOUT_BRAKE")

    def _sweep_timeouts(self):
        if (
            self._brake_demands_light()
            and not self.brake.resolved
            and self.brake.observed_at > 0
            and (time.time() - self.brake.observed_at) > BRAKE_TO_LAMP_WINDOW_S
        ):
            self.metrics["drops"] += 1

            r = self.record(
                "DROP_DETECTED",
                "expected lamp activation not observed",
                anomaly=True,
                extra={"window_s": BRAKE_TO_LAMP_WINDOW_S},
            )

            self._trigger_context(r["seq"], "DROP_DETECTED")
            self.brake.resolved = True

    # ============================ frame dispatch ============================
    def on_frame(self, msg):
        self.metrics["frames_observed"] += 1

        # Continuous temporary capture happens first.
        self._buffer_frame(msg)

        aid = msg.arbitration_id
        data = bytes(msg.data)

        # Inline secured status frames: [payload 4B | freshness 1B | MAC 3B]
        if aid in (BRAKE_STATUS_ID, EXTERIOR_LIGHT_STATUS_ID):
            try:
                payload, freshness, mac_bytes = secoc.parse_secured_frame(data)
            except ValueError:
                return

            if not secoc.verify(aid, freshness, payload, mac_bytes):
                self.metrics["mac_failed"] += 1

                r = self.record(
                    "MAC_VERIFY_FAILED",
                    f"authenticity failed id=0x{aid:X}",
                    anomaly=True,
                    extra={
                        "freshness": freshness,
                        "payload": list(payload),
                    },
                )

                self._trigger_context(r["seq"], "MAC_VERIFY_FAILED")
                return

            if not self.freshness.is_fresh(aid, freshness):
                self.metrics["replays"] += 1

                r = self.record(
                    "REPLAY_DETECTED",
                    f"stale freshness id=0x{aid:X}",
                    anomaly=True,
                    extra={"freshness": freshness},
                )

                self._trigger_context(r["seq"], "REPLAY_DETECTED")
                return

            self.metrics["mac_verified_ok"] += 1
            self._accept_authenticated(aid, payload, freshness)
            return

        # HS events observed on the bus -> permanent event + context trigger.
        if aid == FAULT_REPORT_ID:
            self.metrics["hs_events"] += 1

            r = self.record(
                "HS_FAULT_REPORT_SEEN",
                f"fault report {list(data)}",
                anomaly=True,
                source="HS",
            )

            self._trigger_context(r["seq"], "HS_FAULT_REPORT")
            return

        if aid == HS_EVENT_ID:
            self.metrics["hs_events"] += 1
            code = data[1] if len(data) > 1 else None

            r = self.record(
                "HS_EVENT_SEEN",
                f"HS event {list(data)}",
                anomaly=True,
                source="HS",
                extra={"event_code": code},
            )

            self._trigger_context(r["seq"], "HS_EVENT")
            return

    # ============================ runtime ============================
    def run(self):
        print(
            f"[{MONITOR_ID}] listening (read-only) on {CHANNEL} | "
            f"mode={MODE} | inline MAC | window={PRE_N}pre/{POST_N}post frames",
            flush=True,
        )

        last_sweep = time.time()

        try:
            while True:
                msg = self.bus.recv(timeout=SWEEP_INTERVAL_S)

                if msg is not None:
                    self.on_frame(msg)

                if time.time() - last_sweep >= SWEEP_INTERVAL_S:
                    self._sweep_timeouts()
                    last_sweep = time.time()

        except KeyboardInterrupt:
            self._shutdown()

    def _shutdown(self):
        # Finalize any pending capsules with whatever post-window has been collected.
        # This avoids losing a triggered capsule if the test run stops before POST_N frames.
        for cap in list(self.pending_capsules):
            self._finalize_capsule(cap)
            self.pending_capsules.remove(cap)

        print(f"\n[{MONITOR_ID}] shutting down. Metrics:", flush=True)
        print(json.dumps(self.metrics, indent=2), flush=True)
        print(
            f"[{MONITOR_ID}] hash-chain integrity verified: {self.log.verify_file()}",
            flush=True,
        )


if __name__ == "__main__":
    ForensicComponent().run()
