#!/usr/bin/env python3
"""cycles-to-root timing analyzer for rr_loop_czg1.log (root-speed backlog).

Usage: cycle_timing.py [log]   — prints per-cycle phase durations and totals.
"""
import re, sys, datetime

log = sys.argv[1] if len(sys.argv) > 1 else \
    "/Users/arno/Documents/workdir/apple-cve-researcher/a17-research/" \
    "ghostlock-a17/scripts/rr_loop_czg1.log"

ev = []  # (ts, cycle, event)
pat = re.compile(r"\[(\d+):(\d+):(\d+)\] cycle (\d+): (.*)")
for line in open(log, errors="replace"):
    m = pat.match(line)
    if not m:
        m2 = re.match(r"\[(\d+):(\d+):(\d+)\] (ROOTED.*)", line)
        if m2:
            ts = int(m2[1]) * 3600 + int(m2[2]) * 60 + int(m2[3])
            ev.append((ts, None, m2[4]))
        continue
    ts = int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))
    ev.append((ts, int(m.group(4)), m.group(5).strip()))

t0 = ev[0][0] if ev else 0
cycles = {}
cur = None
for ts, cyc, what in ev:
    if cyc is None:
        print(f"*** {what} at +{ts - t0}s")
        continue
    d = cycles.setdefault(cyc, {})
    if "warming" in what and "warm0" not in d:
        d["warm0"] = ts
    if "wq-umh run" in what:
        d["umh0"] = ts
        if "warm0" in d:
            d["warm_dur"] = ts - d["warm0"]
    if "done" in what or "rerolling" in what or "still enforcing" in what:
        d["end"] = ts
        if "umh0" in d:
            d["umh_dur"] = ts - d["umh0"]

print(f"{'cyc':>4} {'warm_s':>7} {'umh_s':>7} {'total_s':>8}  note")
for c in sorted(cycles):
    d = cycles[c]
    warm = d.get("warm_dur")
    umh = d.get("umh_dur")
    end = d.get("end")
    tot = (end - d["warm0"]) if (end and "warm0" in d) else None
    print(f"{c:>4} {warm if warm is not None else '-':>7} "
          f"{umh if umh is not None else '-':>7} "
          f"{tot if tot is not None else '-':>8}")
print(f"\nelapsed since loop start: {ev[-1][0] - t0}s over {len(cycles)} cycles")
