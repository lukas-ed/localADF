"""
mac_benchmark.py
----------------
Standalone micro-benchmark comparing the overhead of the two MAC primitives
(HMAC-SHA256 vs AES-128 CMAC) used by secoc_lite.

It reports, per primitive:
  - mean / median / p95 time to COMPUTE a MAC (sign side, on the ECU)
  - mean / median / p95 time to VERIFY a MAC (forensic-component side)
  - MAC + companion-frame size (bytes on the wire)

This is a software micro-benchmark on the host CPU; it is NOT a measurement
on automotive ECU hardware. Results are indicative of relative overhead and
should be interpreted as such (see thesis limitations). To contextualise the
numbers, you can scale them against a published ECU clock (e.g. compute the
result as a fraction of a per-message time budget).
"""

import time
import statistics as stats
import secoc_lite as secoc

ITERATIONS = 50_000
WARMUP = 2_000

# representative status payload (5 bytes, as the ECUs send)
DATA_ID = 0x110
PAYLOAD = bytes([1, 80, 1, 0, 7])


def _percentile(xs, p):
    xs = sorted(xs)
    k = int(round((p / 100.0) * (len(xs) - 1)))
    return xs[k]


def bench_primitive(name: str):
    secoc.set_primitive(name)

    # warmup (let any lazy imports / caches settle)
    for i in range(WARMUP):
        secoc.compute_mac(DATA_ID, i % 256, PAYLOAD)

    # ---- compute (sign) ----
    compute_times = []
    for i in range(ITERATIONS):
        t0 = time.perf_counter()
        mac = secoc.compute_mac(DATA_ID, i % 256, PAYLOAD)
        compute_times.append((time.perf_counter() - t0) * 1e6)  # microseconds

    # ---- verify ----
    ref_mac = secoc.compute_mac(DATA_ID, 0, PAYLOAD)
    verify_times = []
    for i in range(ITERATIONS):
        t0 = time.perf_counter()
        secoc.verify(DATA_ID, 0, PAYLOAD, ref_mac)
        verify_times.append((time.perf_counter() - t0) * 1e6)

    mac_payload = secoc.build_mac_payload(DATA_ID, 0, PAYLOAD)

    return {
        "primitive": name,
        "compute_us_mean": round(stats.mean(compute_times), 3),
        "compute_us_median": round(stats.median(compute_times), 3),
        "compute_us_p95": round(_percentile(compute_times, 95), 3),
        "verify_us_mean": round(stats.mean(verify_times), 3),
        "verify_us_median": round(stats.median(verify_times), 3),
        "verify_us_p95": round(_percentile(verify_times, 95), 3),
        "mac_bytes": secoc.MAC_TRUNCATED_BYTES,
        "mac_frame_bytes": len(mac_payload),   # freshness + truncated MAC
    }


def main():
    print(f"Iterations: {ITERATIONS} (warmup {WARMUP})")
    print(f"Payload: {list(PAYLOAD)}  data_id: 0x{DATA_ID:X}\n")

    rows = [bench_primitive("hmac"), bench_primitive("cmac")]

    # pretty table
    cols = ["primitive", "compute_us_mean", "compute_us_median", "compute_us_p95",
            "verify_us_mean", "verify_us_median", "verify_us_p95",
            "mac_bytes", "mac_frame_bytes"]
    hdr = ["primitive", "comp.mean", "comp.med", "comp.p95",
           "ver.mean", "ver.med", "ver.p95", "macB", "frameB"]
    widths = [10, 10, 9, 9, 9, 8, 8, 5, 7]

    print("  ".join(h.ljust(w) for h, w in zip(hdr, widths)))
    print("-" * (sum(widths) + 2 * len(widths)))
    for r in rows:
        print("  ".join(str(r[c]).ljust(w) for c, w in zip(cols, widths)))

    print("\n(times in microseconds; software micro-benchmark on host CPU, "
          "indicative only)")


if __name__ == "__main__":
    main()
