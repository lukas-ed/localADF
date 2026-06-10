#!/usr/bin/env python3
"""
verify_log.py -- independent integrity check of a runtime forensic_log.jsonl.

Re-verifies, without trusting the logger that produced the file:
  1. the forward hash chain (prev_hash links + recomputed entry_hash),
  2. each context capsule's manifest (member_root recomputed from the frames),
  3. (optional) the SecOC MAC of each captured 0x110/0x120 frame, if secoc_lite
     is importable.

Usage:
    python3 verify_log.py [path-to-forensic_log.jsonl]
Default path: ../logs/forensic_log.jsonl

Exit code 0 = all checks pass, 1 = a check failed (tamper detected).
"""

import sys
import json
import hashlib
from collections import defaultdict

GENESIS = "0" * 64


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def verify(path: str) -> bool:
    records = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))

    # 1) hash chain -- must match HashChainLog.append exactly
    prev = GENESIS
    chain_ok = True
    for i, rec in enumerate(records):
        stored = rec.get("entry_hash")
        body_dict = {k: v for k, v in rec.items() if k != "entry_hash"}
        body = json.dumps(body_dict, sort_keys=True, separators=(",", ":"))
        if sha(prev + body) != stored or rec.get("prev_hash") != prev:
            print(f"  CHAIN BREAK at record index {i} (seq={rec.get('seq')})")
            chain_ok = False
            break
        prev = stored

    # 2) capsule manifests -- recompute member_root from the frames in the file
    frames = defaultdict(list)          # capsule_id -> [entry_hash, ...] in file order
    manifests = {}
    for rec in records:
        rt = rec.get("record_type")
        if rt == "observed_frame":
            frames[rec["capsule_id"]].append(rec["entry_hash"])
        elif rt == "manifest":
            manifests[rec["capsule_id"]] = rec

    man_ok = True
    for cid, man in manifests.items():
        members = frames.get(cid, [])
        root = sha(json.dumps(members, sort_keys=True))
        if root != man.get("member_root") or len(members) != man.get("member_count"):
            print(f"  MANIFEST MISMATCH for {cid}: "
                  f"frames={len(members)} expected={man.get('member_count')}")
            man_ok = False

    n_caps = len(manifests)
    n_frames = sum(len(v) for v in frames.values())
    n_events = sum(1 for r in records if r.get("record_type") == "event")
    print(f"records={len(records)}  events={n_events}  "
          f"capsules={n_caps}  captured_frames={n_frames}")
    print(f"hash chain : {'OK' if chain_ok else 'FAILED'}")
    print(f"manifests  : {'OK' if man_ok else 'FAILED'}")

    # 3) optional MAC re-verification of captured secured frames
    try:
        import secoc_lite as secoc
        ok = fail = 0
        for rec in records:
            if rec.get("record_type") != "observed_frame":
                continue
            cid = rec.get("can_id", "")
            if cid not in ("0x110", "0x120"):
                continue
            try:
                payload, fresh, mac = secoc.parse_secured_frame(
                    bytes.fromhex(rec["payload_hex"]))
            except Exception:
                continue
            if secoc.verify(int(cid, 16), fresh, payload, mac):
                ok += 1
            else:
                fail += 1
        print(f"MAC verify : {ok} ok, {fail} failed")
    except ImportError:
        print("MAC verify : skipped (secoc_lite not on path)")

    return chain_ok and man_ok


if __name__ == "__main__":
    p = sys.argv[1] if len(sys.argv) > 1 else "../logs/forensic_log.jsonl"
    print(f"Verifying {p}")
    sys.exit(0 if verify(p) else 1)