# qemu-e2e — QEMU end-to-end validation of the rebuilt ghostlock A17 exploit

**Setup:** this harness needs the kernel `Image` extracted from your own
device firmware (not included here — it is Samsung's copyrighted binary).
Unpack the AP firmware tar, extract `boot.img`, unpack the kernel Image,
then run `patch_image.py` to produce `Image.nokdp`, `mkinitramfs.sh` to
build the initramfs, and `./run.sh` to boot.  `boot47.log` and `boot61.log`
are real captured runs showing the complete in-guest chain.

Boots the **real device kernel** (`../extract/Image`,
6.12.23-android16-5-abA175FXXS3BZA5-4k) in QEMU virt on Apple Silicon (HVF,
native execution) and runs the rebuilt exploit in-guest:

    GL_WQ_UMH=1 RWF_DEBUG=1 KPHYS=0x40200000 GL_NOKASLR=1 GL_RWF_SLOTS=128 \
        PSELECT_ROUTE_DELAY_USEC=100000 /data/local/tmp/a/g4 --rwforge

## Result (boot47/boot48)

The wq-umh root stage completes end-to-end in-guest:

    [+] wq-umh: queued on system_wq BOUND pool (pwq=... pool=...)
    [*] wq-umh: triggering via ptmx storm
    [*] wq-umh: wake=1 complete=1 retval=0
    [+] wq-umh: helper ran with init creds
    [+] ROOTED via wq-umh (init-creds helper)
    ...
    [init] marker check:
    rooted
    uid=0(root) gid=0(root) euid=0 egid=0 caps=unknown
    fake_sh ran

## Files

- `run.sh` — boots `KERNEL` (default `Image.nokdp`) with HVF (`ACCEL`) and
  `nokaslr` (default; `EXTRA_APPEND=` overrides), optional `GDBSTUB=1` (-s -S).
- `patch_image.py` — writes `Image.nokdp` from `../extract/Image` (never
  touches the original).  Two minimal patches that emulate a no-hypervisor,
  unlocked-device environment:
  1. `start_kernel+0x198`: NOP the `kdp_enable = 1` store — without an EL2
     hypervisor, KDP's prepare_ro_creds panics ("KDP Call failed") and the
     KDP slab caches corrupt.  Equivalent to a non-KDP kernel build.
  2. `is_boot_state_unlocked` → `return 1` — DEFEX otherwise panics on the
     missing signed rules file ("Signature mismatch").  This is exactly the
     "device unlocked, DEFEX disabled" state.
- `patch_trace.py` — writes `Image.trace` = `Image.nokdp` + two printk trace
  stubs in the dead `prepare_ro_creds` tail (used to prove the PI-chain
  erase executes with the forged node values; format strings are reused
  existing rodata).  Diagnostic only.
- `init_e2e.c` — static `/init`: mknod fallbacks (no devtmpfs in this
  config), /proc/misc-driven ashmem node, devpts, RLIMIT_NOFILE=32768,
  panic_on_oops/panic_on_warn=0, optional DIAG phase (`/boot/diag` present;
  digits inside set PSELECT_ROUTE_DELAY_USEC), then the exploit, then marker
  dump and poweroff.
- `fake_sh.c` — static `/system/bin/sh` (and `/bin/sh`): writes
  `.umh_rooted` ("rooted") and `/data/local/tmp/cap/id.txt` with the real
  uid, plus a `fake_sh_ran` marker.  This is the helper the forged
  subprocess_info execs.
- `mkinitramfs.sh` — packs `rootfs/` into `initramfs.cpio.gz`.
- `dl_stub.c` — dlopen/dlsym stubs so the rebuilt tree links `-static`
  (miniadb's libselinux path is unused by --rwforge).
- `btf_audit.py` — workqueue_struct/pool_workqueue/worker_pool/
  subprocess_info/work_struct layout extraction from `../extract/vmlinux.elf`
  BTF (ground truth used by the fixes below).
- `rb_trace.py`, `bp_sanity.py` — lldb gdbstub tracers.  NOTE: qemu's
  gdbstub breakpoints do NOT fire under HVF (nor did they under TCG within a
  practical boot window) — `patch_trace.py` printk stubs were the working
  kernel-observability route.

## Guest environment deltas vs device (and why)

| knob | value | reason |
|---|---|---|
| KDP | patched off | no EL2 hypervisor in QEMU |
| DEFEX | patched off | no signed rules file on initramfs |
| KASLR | `nokaslr` | slide=0 by construction; exploit's physmap aliases are slide-independent |
| `KPHYS=0x40200000` | phys base | **QEMU places the kernel image at phys 0x40200000, not 0x40000000** (proven by swapper pgdir phys 0x42278000 - swapper_pg_dir@image+0x2078000, stable across boots).  Without this, every physmap-alias write misses by 0x200000 — the "conn but never lands" failure. |
| `GL_NOKASLR=1` | skip slide detour | boot_id oracle is a device tool; slide is known (0) |
| `GL_RWF_SLOTS=128` | forge budget | the 31-slot budget assumes device multi-boot grinding; the guest runs the whole stage in one boot |
| `PSELECT_ROUTE_DELAY_USEC=100000` | route timing | gives the waiter time to reach the PI-blocked window on 4 vCPUs |

`/dev/ashmem`, `/dev/ptmx`, `/dev/pts` are created by init (the kernel has
no devtmpfs here; ashmem's misc minor is resolved via /proc/misc).

## Tree fixes this E2E produced (ghostlock-a17-rebuilt)

All validated in-guest on the real kernel; all device-relevant:

1. `bootid_oracle_read8` / field scanner: restore value was
   `data_addr(SLIDE_SYSCTL_BOOTID)` — a **double physmap-alias** of an
   already-aliased constant (garbage 0xffffffbf... address, deterministic
   kernel oops in `rb_erase` when the restore route's erase ran).  Now
   `data_addr(SLIDE_SYSCTL_BOOTID_IMAGE)` (image VA → runtime alias).
2. `bootid_oracle_restore_verified`: full-UUID compare could never pass —
   the mode-3 route's post-store (`*cval = pc`) clobbers uuid bytes 0-7 on a
   successful restore.  Compares only uuid text chars 19+ (bytes 8-15).
3. wq-umh cpu_pwq discovery: new primary path — walk `system_wq.pwqs`
   (first link = cpu0 pwq, `pwqs_node` at pwq+0x88, back-check
   `pwq->wq == wq`).  The old seed/cursor scan mis-read the `cpu_pwq`
   field's storage form.  Seed scan kept as fallback; discovery failure now
   falls back to the unbound `pool_walk` instead of `stage_failed`.
4. subprocess_info blob: `path`/`argv`/`envp` were raw offsets (0x1818 etc.)
   — e's page-base-prefixed add was dead code.  E2E: worker ran the forged
   work and faulted in `getname_kernel(0x1818)`.  Now full page-relative
   pointers; the fake `completion` layout fixed (wait.lock@8 must be 0;
   task_list self-links at +0x10/+0x18 — the old blob overlapped the lock,
   crashing `complete()` after a successful exec).
5. `GL_NOKASLR` (skip slide detours) and `GL_RWF_SLOTS` (forge budget) knobs.

Note: the uuid buffer's first 8 bytes stay corrupted after an oracle round
(write(2) collateral) — cosmetic; visible in the trailing boot_id dump.

## Hardening round (boot50)

After the device test panicked mid-wait (fuse collateral is fatal on device:
panic_on_oops=1/PANIC_ON_BUG), `wq_umh_root` gained: verify-after-queue
(pool head + func readback, one re-forge/re-link on mismatch), pre-trigger
struct-page flag repair via the armed configfs attr
(`rwf_repair_flags_wq_umh`, which tracks the fake-work page and uses e's
self-testing `rwf_repair_flags`; the pipe channel cannot address vmemmap —
its write gate rejects 0xfffffffec... addresses), and a 5-round
re-queue loop (link check → ~10s ptmx storm → marker).  In-guest the flow
completes identically (boot50: link verified, helper ran with init creds,
uid=0); the flag repair self-test correctly reports "configfs write NOT
live" in-guest (the fuse arm found no file candidates in the idle guest)
and the stage proceeds — on device the armed attr makes it real.

## Post-root kernel noise

`BUG: Bad page state ... anon_pipe_buf_release ...` at exploit exit is the
known fuse collateral (flags-corrupted spray pages being freed).  Harmless
here (panic_on_warn=0); on device the one-round-per-process + pin rules
apply.
