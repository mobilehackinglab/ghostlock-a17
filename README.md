# GhostLock on the Samsung Galaxy A17 (SM-A175F)

Full user-to-root exploit chain for **CVE-2026-43499** on the Samsung
Galaxy A17 (mt6789, Mali-G57), kernel
`6.12.23-android16-5-abA175FXXS3BZA5-4k` — ending in a usermode helper
running as **`uid=0(root) gid=0(root) groups=0(root)
context=u:r:kernel:s0`**, the strongest execution context the device
offers.

| | |
| --- | --- |
| **CVE** | CVE-2026-43499 ("ghostlock") |
| **Device** | Samsung Galaxy A17 (SM-A175F, mt6789) |
| **Kernel** | `6.12.23-android16-5-abA175FXXS3BZA5-4k` (GKI 6.12) |
| **Result** | usermode helper as `uid=0(root)`, `u:r:kernel:s0` |
| **Key mitigations defeated** | Samsung KDP (EL2), DEFEX, SELinux, PANIC_ON_OOPS, large-slide arm64 KASLR |

> **Note:** We did not discover this vulnerability.  All credit goes to
> NebuSec, who published CVE-2026-43499 as part of their
> [CyberMeowfia/IonStack](https://github.com/NebuSec/CyberMeowfia/tree/main/IonStack)
> research.  This repository contains our port to the Samsung
> Galaxy A17, including a new final stage, and the engineering record of
> what a Samsung retail build changes. The exploit base is the public
> [ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus) tree
> (JoinChang).

> **For authorized security research and educational purposes only.**
> Developed and tested on a dedicated research device we own.

## Related work — and why a new port was needed

**IonStack part 3 ([NebuSec](https://nebusec.ai/research/ionstack-part-3/))**
roots a Pixel 10 / Android 17 GKI with a *data-only cred-patch* endgame:
pselect reclaim → `boot_id` sysctl `.data` repoint to leak the slide →
ashmem fops swapped for same-CFI-signature configfs handlers → constrained
RW → `pipe_buffer.page` overwrite for full RW → walk the task list, patch
`cred` (uids/caps/securebits/seccomp), flip `selinux_enforcing`.  Their own
writeup names the assumption that breaks on Samsung: KNOX/RKP keeps `cred`
and the SELinux state read-only to the EL1 kernel.

That endgame is dead on the A17's BZA5 build — KDP drops task-slab writes
at EL2 (proven: 20+ clean runs, verified-correct candidates, zero cred
lands).  So instead of *writing* root, this chain gets the kernel to
*execute* it: forge a workqueue work item on a bound `system_wq` pool
whose function is the usermode-helper exec path, trigger it with a ptmx
storm, and the helper runs with full init creds — no cred write ever
happens.  (This is the RKP-era technique NebuSec's blog itself cites from
BH2017, and the natural answer to `STATIC_USERMODEHELPER`.)  Slide handling
differs too: arm64 KASLR is virtual-only, so the channel's physical reads
are slide-independent, and the slide comes from the `boot_id` ctl_table
*triplet* — three slid pointers on one page, cross-validated — because this
device's slides (~187 GB class) fall outside every small-window validator.

**Root-My-Galaxy-Payloads ([PR #188](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads/pull/188))**
targets a *different phone*: the A17 5G (**SM-A176B**) on kernel
**5.15.189** — this tree targets the SM-A175F on **6.12.23-android16 GKI**.
Different kernel generation, different physical base (`0x80000000` vs
`0x40000000`), different struct layouts (its commits bounce between
LEGACY/DEFAULT `rt_mutex_waiter` layouts), and the PR is still open,
fighting offset panics and KernelSnitch timing-leak flakiness on the A17's
weaker cores.  Even working perfectly, none of its constants transfer to a
6.12 GKI kernel — and it still ends in the cred-patch endgame that KDP
blocks here.

One line: *same bug, same entry primitives — but a different kernel
generation, EL2 data protection killing the cred-patch endgame, and KASLR
slides an order of magnitude larger than expected forced a different final
stage: forged workqueue execution instead of credential patching,
validated end-to-end in QEMU against the real extracted kernel before
spending device cycles.*

## What changed vs the ghostlock-oneplus base

The entry primitives are upstream's (pselect stack reclaim, fake
`rt_mutex_waiter`, constrained rb-erase pointer write).  Almost everything
after the write primitive is new or reworked for this target:

- **New endgame.**  The base's final stage assumes a task/cred write lands;
  on KDP that store is silently dropped.  Replaced with a forged
  workqueue work item on a bound `system_wq` pool → ptmx-storm trigger →
  kernel runs our usermode helper with init creds (`STATIC_USERMODEHELPER`
  compatible, KDP-proof, no cred write at all).
- **New slide oracle.**  Perf-event page anchoring never worked on this
  device.  The slide now comes from the `boot_id` ctl_table *triplet*
  (procname/data/proc_handler — three slid pointers on one page,
  cross-validated), read through the physmap alias so it works regardless
  of KASLR; validator widened for ~187 GB-class slides.
- **Dynamic structure discovery.**  `cpu_pwq` is found by walking
  `wq->pwqs` at runtime instead of trusting a fixed offset; the p0 profile
  table itself was validated 12/12 against the extracted firmware kernel
  (`docs/OFFSETS.md`).
- **Fuse (struct-page flag dirt) handling.**  The channel's collateral is
  fatal at process teardown under PANIC_ON_OOPS, so the chain repairs the
  dirtied struct-page flags pre-trigger via an fdtable walk
  (`channel_own_task()` — the perf-based `perf_find_task` never returns on
  this busy 8-core target).
- **Reliability engineering.**  Bound-pool forge with busy guard,
  verify-after-queue with requeue rounds, boot-quality warming probe
  (`--write1`), one-round-per-process fuse hygiene, and a reboot-aware
  grind loop (`scripts/rr_loop4.sh`).
- **Bug fixes to the original device binary's logic** (present in the tree
  we started from): the boot_id oracle was missing its restore write
  (dangling pointer → UUID written into kernel .data → deterministic
  panic), and the SELinux-off write's retry cap produced fake "dead boots".
- **QEMU E2E harness** (`qemu-e2e/`): boots the real extracted kernel and
  runs the full chain in-guest — this is how the device-fatal bugs above
  were found before burning device cycles.

## Why this target is hard

Samsung stacks several layers on top of GKI 6.12, and each one killed a
"standard" technique:

- **KDP (Kernel Data Protection, EL2).**  Creds live in hypervisor-watched
  read-only slab caches.  The classic task→cred write path is *dead* on
  this build: the write primitive's store to a task-slab page is silently
  dropped (20+ clean runs, candidates proven correct by the comm-pointer
  partner rule, zero cred lands).  Static `.data` writes (e.g.
  `selinux_enforcing`) land fine.
- **Pointer-only write primitive.**  The rb-tree write can only deliver
  aligned pointer values — `core_pattern`/`modprobe_path` text writes are
  structurally impossible (the walk dereferences the value; ASCII values
  correlate with panics).
- **PANIC_ON_OOPS / PANIC_ON_BUG.**  Every speculative kernel oops is a
  device reset.  The channel's own collateral (dirtied struct-page flags,
  the "fuse" problem) is fatal at process teardown — the chain has to
  repair struct-page flags *before* triggering the final stage.
- **Huge arm64 KASLR slides.**  Observed per-boot slides up to ~187 GB
  (`0x2eae400000`) — far outside the small windows typical slide finders
  assume.  But arm64 KASLR is *virtual-only*: physical placement is fixed,
  so any read channel that works on physical (physmap-alias) addresses is
  slide-independent, while text pointers read back with the slide baked in.
- **DEFEX** (Samsung's exec/file integrity LSM) and SELinux on top.

## The chain

```
 userspace (shell, uid 2000)
   │  pselect/PI-futex constrained write (one aligned qword per round)
   ▼
 rwforge physrw channel — forged pipe_buffer slots give
 arbitrary physical read/write through a pipe we own
   │
   ├─ slide oracle: the boot_id ctl_table entry carries THREE slid
   │   pointers (procname / data / proc_handler); cross-validate →
   │   the real per-boot KASLR slide, no perf anchors needed
   │
   ├─ cpu_pwq discovery: walk system_wq.pwqs (cpu0's pool_workqueue is
   │   the first link − offsetof(pwqs_node)), verify via pwq->wq
   │
   ├─ flag repair: struct-page flags dirtied by the route rounds are
   │   restored through a configfs virtual write (armed ashmem attr),
   │   BEFORE anything can trip BUG: Bad page state on a locked device
   │
   ▼
 forged work_struct on system_wq's bound cpu0 pool:
   work.func = call_usermodehelper_exec_work,
   work's subprocess_info = { path: "/system/bin/sh",
                              argv: { sh, /data/local/tmp/a/umh.sh } }
   │
   ▼  ptmx alloc/free storm wakes the pool (forged links get no
      wake_up_worker — real work landing on the pool drains our item)
 usermode helper → kernel thread context → init creds
   ▼
 /system/bin/sh /data/local/tmp/a/umh.sh   running as
 uid=0(root) gid=0(root) context=u:r:kernel:s0
```

Notable engineering details:

- The boot_id sysctl `data` pointer doubles as an arbitrary-read oracle
  (retarget it, read `/proc/sys/kernel/random/boot_id`, restore — with
  byte-range-verified restore, since the route's post-store clobbers the
  uuid's first 8 bytes).
- The forged `subprocess_info` must carry full page-relative pointers;
  the original binary's page-base add was dead code, and the raw-offset
  variant faults in `getname_kernel` the moment the worker actually runs
  the work (proven in QEMU first, then on-device).
- `call_usermodehelper` helpers inherit the queueing context's fds on
  this kernel — the helper's stdout/stderr land in the exploit's own log
  file, which makes on-device debugging of the helper almost pleasant.

## Build

Requires the Android NDK (r30 used; any recent clang with an
aarch64-linux-android target works):

```
make            # produces ./ghostlock  (aarch64 PIE)
```

The build is byte-reproducible against our on-device binary
(md5 `a8698e7f3a841d06edb26fc882b617c9`).

## Run (device)

```
adb push ghostlock /data/local/tmp/a/g4
adb shell 'chmod 755 /data/local/tmp/a/g4'
adb shell 'GL_WQ_UMH=1 GL_RWF_SLOTS=64 RWF_DEBUG=1 /data/local/tmp/a/g4 --rwforge'
```

The primitive is probabilistic (write-land rate varies hugely per boot —
~1/3 on a good boot to ~1/20 on a cold one), so a grind loop helps:
`scripts/rr_loop4.sh` warms each boot with `--write1` until SELinux reads
permissive, then runs the channel+wq-umh stage, reboot-aware, exiting on
success.

Success markers:

- exploit log: `wq-umh: link verified` → `wq-umh: triggering via ptmx
  storm` → `wq-umh: helper ran with init creds` → `ROOTED via wq-umh`
- `/data/local/tmp/a/.umh_rooted`, `/data/local/tmp/cap/id.txt`
  (`uid=0(root) ... context=u:r:kernel:s0`), and the capture set under
  `/data/local/tmp/cap/` + `/data/local/tmp/a/*.txt` (dmesg, last_kmsg,
  kallsyms, pstore, dropbox SYSTEM_LAST_KMSG/SYSTEM_BOOT entries).

**Expected device behavior:** the kernel panics when the exploit process
exits (the forged-pipe teardown trips `BUG: Bad page state` —
panic_on_oops=1 on this build).  Everything the helper wrote is synced to
disk before that; the device comes back ~60–90 s later.  This is a
research-device trade-off, not a stability claim.

## QEMU end-to-end validation

The `qemu-e2e/` harness (included) boots the **real extracted BZA5 kernel
Image** in QEMU virt on Apple Silicon (HVF, native-speed) with two minimal,
well-understood patches on a copy (`Image.nokdp`): the `kdp_enable=1` store
in `start_kernel` is NOP'd (no EL2 hypervisor exists in QEMU), and
`is_boot_state_unlocked()` is forced true (DEFEX otherwise panics on the
missing signed rules file).  An initramfs init runs the exploit in-guest.

**Setup:** extract the kernel `Image` from your own device firmware (not
included — it is Samsung's copyrighted binary), then run
`patch_image.py` to produce `Image.nokdp`, `mkinitramfs.sh` to build the
initramfs, and `run.sh` to boot.  `boot47.log` / `boot61.log` are real
captured runs showing the complete in-guest chain.

In-guest the *entire* chain completes against the real kernel: channel up
→ slide oracle → queue → trigger → helper runs → `uid=0(root)` markers
(boots 47/48/50/51/52/57/58/59/60/61).  QEMU differences that mattered:
the kernel image loads at phys 0x40200000 there (not 0x40000000 — the
`KPHYS` env knob exists for exactly this), and `nokaslr` + guest-only
knobs (`GL_NOKASLR`, `GL_RWF_SLOTS`) are used because the slide is known
and the forge budget can be spent freely in a throwaway VM.

The E2E harness caught four device-fatal bugs before they cost weeks of
on-device grinding (see the QEMU section above).

## Proof of root

`examples/` holds artifacts from a real rooted run on the device
(2026-08-17, cycle 88 of that grind session):

- `examples/rooted-run-cycle88.log` — the trimmed run log: slide anchors →
  pool forge → trigger → `helper ran with init creds` → `ROOTED`.
- `examples/id.txt` — the helper's own `id` output, written as root:
  `uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0`.
- `examples/cmdline.txt`, `examples/pstore_ls.txt`,
  `examples/capture-file-listing.txt` — sample capture output (the helper
  also pulls `dmesg`, full `kallsyms` (17 MB), `iomem`, `last_kmsg`, and
  the newest Samsung dropbox `SYSTEM_LAST_KMSG@*` entries as root before
  the process exits).

The chain rooted the device four times in one day (18:23, 18:59, 20:04,
20:24) with the same binary — see below for what that does and does not
mean.

## Success rate — set expectations honestly

Per-cycle success is a few percent and **boot-quality dominated**: the
observed write-land rate ranges from ~1/3 on a "hot" boot to ~1/20 on a
cold one.  In a day of grinding: one 10.5-hour dry spell, then three roots
in 90 minutes, then another >1-hour dry spell.  Of ~150 cycles, the physrw
channel came up ~10 times; every time the full chain ran, it rooted.

Practical reading: **median time-to-root ≈ 1 hour per boot, worst case
several hours**, with the loop riding through panic-reboots on its own.
Fine for research and forensics; not a "root 30 seconds after boot"
experience.

Known levers to raise the rate (understood, not yet implemented):
restructure the wq-umh discovery reads onto the cheap boot_id-oracle path
(fewer channel rounds → fewer panic chances), and fix the fdtable own-task
lookup so the pre-trigger struct-page flag repair actually engages (this
would also remove the panic-on-exit).

## Persistence

This exploit is deliberately **root-per-boot**: re-run `scripts/rr_loop4.sh`
(or wrap it in an app with a boot receiver) and root lands hands-free after
every reboot — no bootloader unlock, no Knox trip, no data wipe, device
stays stock for reporting.  Install-style persistence (Magisk/KernelSU in
the boot image) requires flashing, which on a locked Samsung means
bootloader unlock → warranty trip → wipe; we chose not to do that on the
research device.

## Repository layout

```
Makefile            NDK build (make → ./ghostlock)
src/                full exploit source (core + device offset tables)
docs/OFFSETS.md     the validated BZA5 offset table + how it was verified
examples/           proof-of-root artifacts from a real device run
scripts/rr_loop4.sh the on-device grind loop (warm boot → wq-umh → capture)
qemu-e2e/           QEMU harness: boot the real kernel in-guest, run the
                    exploit end-to-end (bring your own extracted Image)
```

## Disclaimer

This proof of concept is provided for **educational and authorized security
research purposes only**.  Only use it on devices and environments you own
or have explicit permission to test.  The authors are not responsible for
any misuse.  All findings were developed on a dedicated research device we
own.
