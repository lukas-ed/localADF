# Forensic component — inline SecOC

#**Path:** `forensic_logger/app.py` (replace the existing file)

#Key changes vs. the separate-frame version:
#- **Deleted** `pending_mac` and `pending_payload` buffers and the
#  `_try_authenticate()` pairing helper entirely.
#- **NEW** `_authenticate()` that parses the inline secured frame and
#  performs MAC + freshness checks directly on each observed frame.
#- `on_frame()` simplified — no longer has a separate code path for MAC
#  companion frames; every authenticated status frame is self-contained.
#- `ObservedBrake.counter` / `ObservedLight.counter` renamed to
#  `freshness` to reflect what they actually hold now.
#- All detection logic (causality, drop timeout, hash-chained log) is
#  byte-for-byte unchanged — this is deliberate; the **forensic
#  contribution does not depend on the SecOC layout**.

"""
forensic_component.py
---------------------
Passive, out-of-band SSU/FSAC-style forensic acquisition component.

INLINE SecOC variant: each authenticated status frame carries its MAC
inline (payload || freshness || truncated MAC) in a single 8-byte CAN
frame. No companion MAC frame, no pairing buffers.

Placement & behaviour:
  - Listens READ-ONLY on the mirrored forensic bus (vcan1). Never
    transmits, never a chokepoint.
  - For every authenticated status frame:
        (1) verifies the SecOC truncated MAC,
        (2) checks the freshness counter for replay,
        (3) updates the reconstructed brake/lamp state,
        (4) runs the brake -> lamp causality specification check,
        (5) appends a hash-chained, tamper-evident record.
  - Causality timeout sweep detects DROP attacks (expected lamp never
    observed within BRAKE_TO_LAMP_WINDOW_S).
"""

import can
import time
import json
import hashlib
import datetime as dt
from dataclasses import dataclass, asdict

import secoc_lite as secoc

# =========================================================
# Configuration
# =========================================================
CHANNEL = "vcan1"           # FORENSIC bus (mirror of vcan0). Read-only.
INTERFACE = "socketcan"

BRAKE_STATUS_ID          = 0x110
EXTERIOR_LIGHT_STATUS_ID = 0x120
FAULT_REPORT_ID          = 0x130

BRAKE_TO_LAMP_WINDOW_S = 0.20
SWEEP_INTERVAL_S       = 0.05

LOG_PATH = "forensic_log.jsonl"


# =========================================================
# Observed state
# =========================================================
@dataclass
class ObservedBrake:
    brake_active: int = 0
    brake_force: int = 0
    enabled: int = 0
    faults: int = 0
    freshness: int = 0
    observed_at: float = 0.0
    resolved: bool = False    # True once a matching lamp activation is seen


@dataclass
class ObservedLight:
    light_active: int = 0
    enabled: int = 0
    faults: int = 0
    last_brake_counter: int = 0
    freshness: int = 0
    observed_at: float = 0.0


# =========================================================
# Freshness / replay tracker
# =========================================================
class FreshnessTracker:
    """Tracks the last accepted 8-bit freshness per data_id with modulo-256
    wrap. A freshness is 'fresh' iff it advances within a forward window."""

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


# =========================================================
# Tamper-evident hash-chained log
# =========================================================
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
        entry_hash = hashlib.sha256(
            (self.prev_hash + body).encode("utf-8")
        ).hexdigest()
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
                recomputed = hashlib.sha256((prev + body).encode()).hexdigest()
                if recomputed != stored or rec["prev_hash"] != prev:
                    return False
                prev = stored
        return True


# =========================================================
# The forensic component
# =========================================================
class ForensicComponent:
    def __init__(self):
        # listen_only flag is the kernel-level read-only guarantee on real
        # SocketCAN; on vcan it's accepted but not enforced. We never call
        # bus.send() ourselves either way.
        self.bus = can.interface.Bus(interface=INTERFACE, channel=CHANNEL)
        self.brake = ObservedBrake()
        self.light = ObservedLight()
        self.freshness = FreshnessTracker()
        self.log = HashChainLog(LOG_PATH)
        self.metrics = {
            "frames_observed": 0,
            "mac_verified_ok": 0,
            "mac_failed": 0,
            "replays": 0,
            "drops": 0,
            "spec_violations": 0,
            "verify_time_total_s": 0.0,
        }

    # ---- capture-time forensic record (hashed by the log) -------------
    def record(self, event, detail, anomaly=False, extra=None):
        rec = {
            "capture_time": dt.datetime.now().isoformat(timespec="microseconds"),
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
        print(f"[forensic][{tag}] {event}: {detail}")
        return written

    # ---- inline MAC + freshness verification --------------------------
    def _authenticate(self, data_id: int, frame_bytes: bytes):
        """Parse, verify MAC, and check freshness on one inline secured
        frame. Returns (payload, freshness) on success, or None on any
        failure (and records the anomaly)."""
        try:
            payload, freshness, mac_bytes = secoc.parse_secured_frame(frame_bytes)
        except ValueError as e:
            self.metrics["mac_failed"] += 1
            self.record(
                "MALFORMED_FRAME",
                f"could not parse secured frame on id=0x{data_id:X}: {e}",
                anomaly=True,
            )
            return None

        t0 = time.perf_counter()
        ok = secoc.verify(data_id, freshness, payload, mac_bytes)
        self.metrics["verify_time_total_s"] += time.perf_counter() - t0

        if not ok:
            self.metrics["mac_failed"] += 1
            self.record(
                "MAC_VERIFY_FAILED",
                f"authenticity check failed for id=0x{data_id:X}",
                anomaly=True,
                extra={"freshness": freshness, "payload": list(payload)},
            )
            return None

        if not self.freshness.is_fresh(data_id, freshness):
            self.metrics["replays"] += 1
            self.record(
                "REPLAY_DETECTED",
                f"stale/replayed freshness for id=0x{data_id:X}",
                anomaly=True,
                extra={"freshness": freshness},
            )
            return None

        self.metrics["mac_verified_ok"] += 1
        return payload, freshness

    # ---- state acceptance + causality ---------------------------------
    def _accept_brake(self, payload: bytes, freshness: int):
        self.brake = ObservedBrake(
            brake_active=payload[0], brake_force=payload[1],
            enabled=payload[2], faults=payload[3],
            freshness=freshness, observed_at=time.time(), resolved=False,
        )
        self.record(
            "BRAKE_STATUS",
            f"authentic brake status payload={list(payload)} fresh={freshness}",
        )

    def _accept_light(self, payload: bytes, freshness: int):
        self.light = ObservedLight(
            light_active=payload[0], enabled=payload[1], faults=payload[2],
            last_brake_counter=payload[3], freshness=freshness,
            observed_at=time.time(),
        )
        self.record(
            "LIGHT_STATUS",
            f"authentic light status payload={list(payload)} fresh={freshness}",
        )
        self._check_causality_on_light()

    def _brake_demands_light(self) -> bool:
        return self.brake.brake_active == 1 or self.brake.brake_force > 10

    def _check_causality_on_light(self):
        if self._brake_demands_light():
            if self.light.light_active == 1:
                self.brake.resolved = True
            else:
                self.metrics["spec_violations"] += 1
                self.record(
                    "SPEC_VIOLATION_LAMP_OFF",
                    "brake active but lamp not activated",
                    anomaly=True,
                )
        else:
            if self.light.light_active == 1:
                self.metrics["spec_violations"] += 1
                self.record(
                    "SPEC_VIOLATION_LAMP_WITHOUT_BRAKE",
                    "lamp active without a corresponding brake demand",
                    anomaly=True,
                )

    def _sweep_timeouts(self):
        """Detect dropped lamp frames: brake demanded a lamp activation
        but none was observed within the causality window."""
        if (self._brake_demands_light()
                and not self.brake.resolved
                and self.brake.observed_at > 0
                and (time.time() - self.brake.observed_at) > BRAKE_TO_LAMP_WINDOW_S):
            self.metrics["drops"] += 1
            self.record(
                "DROP_DETECTED",
                "expected lamp activation not observed within window",
                anomaly=True,
                extra={"window_s": BRAKE_TO_LAMP_WINDOW_S},
            )
            self.brake.resolved = True   # report once per brake event

    # ---- frame dispatch -----------------------------------------------
    def on_frame(self, msg):
        self.metrics["frames_observed"] += 1
        aid = msg.arbitration_id
        data = bytes(msg.data)

        if aid == BRAKE_STATUS_ID:
            res = self._authenticate(BRAKE_STATUS_ID, data)
            if res is not None:
                self._accept_brake(*res)
            return

        if aid == EXTERIOR_LIGHT_STATUS_ID:
            res = self._authenticate(EXTERIOR_LIGHT_STATUS_ID, data)
            if res is not None:
                self._accept_light(*res)
            return

        if aid == FAULT_REPORT_ID:
            self.record("FAULT_REPORT_SEEN", f"fault report {list(data)}")
            return

    # ---- main loop ----------------------------------------------------
    def run(self):
        print(f"[forensic] listening (read-only) on {CHANNEL} (inline SecOC profile)")
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
        print("\n[forensic] shutting down. Metrics:")
        n = max(1, self.metrics["mac_verified_ok"] + self.metrics["mac_failed"])
        avg_us = (self.metrics["verify_time_total_s"] / n) * 1e6
        self.metrics["avg_mac_verify_us"] = round(avg_us, 2)
        print(json.dumps(self.metrics, indent=2))
        intact = self.log.verify_file()
        print(f"[forensic] hash-chain integrity verified: {intact}")


if __name__ == "__main__":
    ForensicComponent().run()
