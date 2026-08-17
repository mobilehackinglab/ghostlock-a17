#!/usr/bin/env python3
"""lldb script (nokaslr BZA5 guest): trace the PI-chain erase path.
BP1 = rt_mutex_adjust_pi entry        (walk starts)
BP2 = rt_mutex_adjust_prio_chain+0x498 (bl rb_erase_cached — the landing store)
"""
import lldb, sys, time

BP_ADJUST_PI = 0xFFFFFFC0811EB78C
BP_ERASE_SITE = 0xFFFFFFC0811EBD00

dbg = lldb.SBDebugger.Create()
dbg.SetAsync(True)   # Continue() must not block — we poll state in the loop
err = lldb.SBError()
target = dbg.CreateTarget(None, "aarch64-unknown-linux-android", None, True, err)
process = target.ConnectRemote(dbg.GetListener(), "connect://localhost:1234",
                               None, err)
if not err.Success():
    print("connect failed:", err); sys.exit(1)

bp1 = target.BreakpointCreateByAddress(BP_ADJUST_PI)
bp2 = target.BreakpointCreateByAddress(BP_ERASE_SITE)
process.Continue()   # qemu -S: VM starts suspended

def reg(f, n):
    return f.FindRegister(n).GetValueAsUnsigned()

t_end = time.time() + float(sys.argv[1] if len(sys.argv) > 1 else 100)
walks = erases = 0
while time.time() < t_end:
    if process.GetState() == lldb.eStateStopped:
        for th in process:
            if th.GetStopReason() != lldb.eStopReasonBreakpoint:
                continue
            bpno = th.GetStopReasonDataAtIndex(0)
            f0 = th.GetFrameAtIndex(0)
            if bpno == bp1.GetID():
                walks += 1
                print("WALK task=%#x pi_blocked_on=? lr=%#x" %
                      (reg(f0, "x0"), reg(f0, "x30")), flush=True)
            elif bpno == bp2.GetID():
                erases += 1
                x0 = reg(f0, "x0")
                e = lldb.SBError()
                mem = process.ReadMemory(x0, 24, e)
                flds = [hex(int.from_bytes(mem[i:i+8], "little"))
                        for i in range(0, 24, 8)] if e.Success() else ["?"]*3
                print("ERASE node=%#x root=%#x pc=%s right=%s left=%s "
                      "task(x19)=%#x waiter(x26)=%#x" %
                      (x0, reg(f0, "x1"), flds[0], flds[1], flds[2],
                       reg(f0, "x19"), reg(f0, "x26")), flush=True)
        process.Continue()
    else:
        time.sleep(0.1)
print("TOTAL walks=%d erases=%d" % (walks, erases), flush=True)
process.Kill()
