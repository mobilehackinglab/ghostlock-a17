#!/usr/bin/env python3
"""Build Image.trace = Image.nokdp + two printk trace stubs (nokaslr only):

  A) rt_mutex_adjust_prio_chain+0x498 (the `bl rb_erase_cached` landing-store
     site): printk(node, root, task) before the original call.
  B) rt_mutex_adjust_pi entry: printk(task, pi_blocked_on) but only when the
     caller is __sched_setscheduler (i.e. the exploit's sched_setattr punch).

Stubs live in the dead prepare_ro_creds tail (never called with kdp_enable=0).
Format strings are REUSED existing rodata (3x %px / 2x %px) — no rodata writes.
"""

BASE = 0xFFFFFFC080000000
VM_SEC_OFF = 0x1C0

def I(words):
    return b"".join(w.to_bytes(4, "little") for w in words)

def adrp(rd, pc, target):
    imm = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
    imm &= 0x1FFFFF
    return 0x90000000 | ((imm & 3) << 29) | ((imm >> 2) << 5) | rd

def bl(src, dst):
    off = (dst - src) // 4
    return 0x94000000 | (off & 0x3FFFFFF)

def b(src, dst):
    off = (dst - src) // 4
    return 0x14000000 | (off & 0x3FFFFFF)

# --- constants (nokaslr, static) ---
_PRINTK      = 0xFFFFFFC0800148C8
RB_ERASE_CACHED = 0xFFFFFFC08016A6AC
FMT3 = 0xFFFFFFC08178326A   # "list_del corruption. next->prev should be %px, but was %px. (next=%px)\n"
FMT2 = 0xFFFFFFC0817DDFE9   # "0x%px-0x%px"
SCHED_LO = 0xFFFFFFC0801488BC
SCHED_HI = SCHED_LO + 0xB94

CAVE_A = 0xE3DF30           # stub A file offset (vaddr = BASE + off); 108B
CAVE_B = 0xE3DFC0           # stub B (starts after stub A)

SITE_A = 0x11EBD00          # rt_mutex_adjust_prio_chain+0x498  (bl rb_erase_cached)
SITE_B = 0x11EB78C          # rt_mutex_adjust_pi entry (paciasp)

def stub_a(va):
    # pre:  printk(FMT3, node, node->pc, node->rb_right)
    # call rb_erase_cached
    # post: printk(FMT3, node, [parent+8], [parent+0x10])   (parent = pc & ~3)
    words = [
        0xD100C3FF,                    #  0 sub sp, sp, #0x30
        0xA90007E0,                    #  1 stp x0, x1, [sp]
        0xA9010FE2,                    #  2 stp x2, x3, [sp, #0x10]
        0xF90013FE,                    #  3 str x30, [sp, #0x20]
        0xF9400403,                    #  4 ldr x3, [x0, #8]
        0xF9400002,                    #  5 ldr x2, [x0]
        0xAA0003E1,                    #  6 mov x1, x0
        adrp(0, va + 0x1c, FMT3),      #  7
        0x91000000 | ((FMT3 & 0xFFF) << 10),   #  8 add x0, x0, #fmt_lo
        bl(va + 0x24, _PRINTK),        #  9
        0xA94007E0,                    # 10 ldp x0, x1, [sp]
        bl(va + 0x2C, RB_ERASE_CACHED),          # 11
        0xF94003E0,                    # 12 ldr x0, [sp]
        0xF9400002,                    # 13 ldr x2, [x0]        (pc)
        0x92800063,                    # 14 movn x3, #3         (~3)
        0x8A030042,                    # 15 and x2, x2, x3      (parent)
        0xF9400443,                    # 16 ldr x3, [x2, #8]
        0xF9400842,                    # 17 ldr x2, [x2, #0x10]
        0xAA0003E1,                    # 18 mov x1, x0
        adrp(0, va + 0x4C, FMT3),      # 19
        0x91000000 | ((FMT3 & 0xFFF) << 10),   # 20
        bl(va + 0x54, _PRINTK),        # 21
        0xA94007E0,                    # 22 ldp x0, x1, [sp]
        0xA9410FE2,                    # 23 ldp x2, x3, [sp, #0x10]
        0xF94013FE,                    # 24 ldr x30, [sp, #0x20]
        0x9100C3FF,                    # 25 add sp, sp, #0x30
        0,                             # 26 b SITE_A+4 (patched below)
    ]
    back_va = va + 4 * (len(words) - 1)
    off = ((BASE + SITE_A + 4) - back_va) // 4
    words[-1] = 0x14000000 | (off & 0x3FFFFFF)
    return I(words)

def stub_b(va):
    words = []
    words += [
        0xD100C3FF,                    # sub sp, sp, #0x30
        0xA90007E0,                    # stp x0, x1, [sp]
        0xA9010FE2,                    # stp x2, x3, [sp, #0x10]
        0xA9027BF0,                    # stp x16, x30, [sp, #0x20]
    ]
    # x16 = SCHED_LO
    lo = SCHED_LO
    words += [
        0xD2800000 | (((lo >>  0) & 0xFFFF) << 5) | 16,   # mov  x16, #lo0
        0xF2A00000 | (((lo >> 16) & 0xFFFF) << 5) | 16,   # movk x16, #lo1, lsl 16
        0xF2C00000 | (((lo >> 32) & 0xFFFF) << 5) | 16,   # movk x16, #lo2, lsl 32
        0xF2E00000 | (((lo >> 48) & 0xFFFF) << 5) | 16,   # movk x16, #lo3, lsl 48
        0xEB10029F,                    # cmp x30, x16
        0x54000000 | 0x3,              # b.lo skip (patched below)
    ]
    # x16 = SCHED_HI
    hi = SCHED_HI
    idx_blo = len(words) - 1
    words += [
        0xD2800000 | (((hi >>  0) & 0xFFFF) << 5) | 16,
        0xF2A00000 | (((hi >> 16) & 0xFFFF) << 5) | 16,
        0xF2C00000 | (((hi >> 32) & 0xFFFF) << 5) | 16,
        0xF2E00000 | (((hi >> 48) & 0xFFFF) << 5) | 16,
        0xEB10029F,                    # cmp x30, x16
        0x54000000 | 0x2,              # b.hs skip (patched below)
    ]
    idx_bhs = len(words) - 1
    # print: printk(FMT2, task, pi_blocked_on)
    pc_adrp = va + 4 * len(words)
    words += [
        0xF9450C02,                    # ldr x2, [x0, #0xa18]  pi_blocked_on
        0xAA0003E1,                    # mov x1, x0            task
        adrp(0, pc_adrp, FMT2),
        0x91000000 | ((FMT2 & 0xFFF) << 10) | 0,
        bl(pc_adrp + 8, _PRINTK),
    ]
    # skip:
    skip_va = va + 4 * len(words)
    # patch the two conditional branches (offset in instrs from their pc)
    for idx in (idx_blo, idx_bhs):
        instr_va = va + 4 * idx
        off = (skip_va - instr_va) // 4
        words[idx] = (words[idx] & 0xFF00001F) | ((off & 0x7FFFF) << 5)
    words += [
        0xA94007E0,                    # ldp x0, x1, [sp]
        0xA9410FE2,                    # ldp x2, x3, [sp, #0x10]
        0xA9427BF0,                    # ldp x16, x30, [sp, #0x20]
        0x9100C3FF,                    # add sp, sp, #0x30
        0xD503233F,                    # paciasp (original instruction)
        0,                             # b SITE_B+4 (patched below)
    ]
    # final branch back into rt_mutex_adjust_pi+4 (NOT ret: x30 is signed now)
    back_va = va + 4 * (len(words) - 1)
    off = ((BASE + SITE_B + 4) - back_va) // 4
    words[-1] = 0x14000000 | (off & 0x3FFFFFF)
    return I(words)

def main():
    import pathlib
    here = pathlib.Path(__file__).parent
    img = bytearray((here / "Image.nokdp").read_bytes())

    stubA = stub_a(BASE + CAVE_A)
    stubB = stub_b(BASE + CAVE_B)
    assert CAVE_A + len(stubA) <= CAVE_B, "stub A overruns B"
    assert CAVE_B + len(stubB) <= 0xE3E128, "stub B overruns cave"
    img[CAVE_A:CAVE_A + len(stubA)] = stubA
    img[CAVE_B:CAVE_B + len(stubB)] = stubB
    # trampolines: plain B (never clobber x30 — these are mid-function detours)
    img[SITE_A:SITE_A + 4] = b(BASE + SITE_A, BASE + CAVE_A).to_bytes(4, "little")
    img[SITE_B:SITE_B + 4] = b(BASE + SITE_B, BASE + CAVE_B).to_bytes(4, "little")

    out = here / "Image.trace"
    out.write_bytes(img)
    print(f"wrote {out} ({len(img)} bytes)")
    print(f"  stubA @{BASE+CAVE_A:#x} ({len(stubA)}B)  siteA {BASE+SITE_A:#x}")
    print(f"  stubB @{BASE+CAVE_B:#x} ({len(stubB)}B)  siteB {BASE+SITE_B:#x}")

if __name__ == "__main__":
    main()
