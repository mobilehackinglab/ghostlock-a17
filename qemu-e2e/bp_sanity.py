#!/usr/bin/env python3
"""lldb sanity trace: confirm breakpoints fire at all (getpid = hot, called by
the exploit constantly) plus the PI walk entry points."""
import lldb, sys, time

BPS = {
    0xFFFFFFC0800F3718: "getpid",          # sanity: very hot
    0xFFFFFFC0811EB78C: "rt_mutex_adjust_pi",
    0xFFFFFFC0811EBD00: "chain->rb_erase_cached site",
    0xFFFFFFC080149C60: "sys_sched_setattr",
}

dbg = lldb.SBDebugger.Create()
dbg.SetAsync(True)
err = lldb.SBError()
target = dbg.CreateTarget(None, "aarch64-unknown-linux-android", None, True, err)
process = target.ConnectRemote(dbg.GetListener(), "connect://localhost:1234",
                               None, err)
if not err.Success():
    print("connect failed:", err); sys.exit(1)

bps = {}
for addr, name in BPS.items():
    bp = target.BreakpointCreateByAddress(addr)
    bps[bp.GetID()] = name
    print("bp %d %s @ %#x valid=%d" % (bp.GetID(), name, addr, bp.IsValid()),
          flush=True)
process.Continue()

counts = {v: 0 for v in BPS.values()}
t_end = time.time() + 60
while time.time() < t_end:
    st = process.GetState()
    if st == lldb.eStateStopped:
        for th in process:
            if th.GetStopReason() == lldb.eStopReasonBreakpoint:
                name = bps.get(th.GetStopReasonDataAtIndex(0), "?")
                counts[name] += 1
        process.Continue()
    else:
        time.sleep(0.05)
print("COUNTS", counts, flush=True)
process.Kill()
