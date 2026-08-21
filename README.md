# GhostLock — CVE-2026-43499 on Samsung Galaxy A17

Full user-to-root exploit chain for **CVE-2026-43499 ("GhostLock")** on the Samsung Galaxy A17 **SM-A175F**, running Android 16 / GKI 6.12.

The chain starts from the public GhostLock primitives and ends with a usermode helper executing as:

```text
uid=0(root) gid=0(root) groups=0(root)
context=u:r:kernel:s0
```

It also starts a persistent per-boot root shell through `g4d` / `g4sh` and exits without a kernel panic.

📖 **Full technical write-up:**  
https://www.mobilehackinglab.com/blog/cve-2026-43499-ghostlock-a17-root-shell

> **Research note**
>
> We did not discover CVE-2026-43499. Credit for the original vulnerability and IonStack research goes to Nebula Security.
>
> This repository documents our independent port to the Samsung Galaxy A17, the changes required for Samsung's kernel protections, and a new final exploitation stage.
>
> For authorized security research and educational purposes only.

---

## Target

| | |
|---|---|
| **CVE** | CVE-2026-43499 — "ghostlock" |
| **Device** | Samsung Galaxy A17 (SM-A175F, mt6789) |
| **GPU** | Mali-G57 |
| **Kernel** | `6.12.23-android16-5-abA175FXXS3BZA5-4k` |
| **Result** | `uid=0(root)` / `u:r:kernel:s0` |
| **Root shell** | `g4d` daemon + `g4sh` client |
| **Persistence** | Per-boot |
| **Exploit exit** | Clean, no kernel panic |
| **Mitigations encountered** | Samsung KDP, DEFEX, SELinux, PANIC_ON_OOPS, arm64 KASLR |
| **Supported firmware** | `A175FXXS3BZA5` (kernel 6.12.23) and `A175FXXS6CZG1` (kernel 6.12.38, SPL 2026-07-05) — both device-verified, same chain |

---

## What makes this port different?

The original ghostlock research provides the entry primitives:

```text
pselect reclaim
      ↓
fake rt_mutex_waiter
      ↓
constrained rb-tree pointer write
```

On the Galaxy A17, however, the standard credential-patching endgame does not work.

### Samsung KDP blocks the usual cred write

KDP protects credential-related kernel data at EL2.

On this build, attempts to modify task credentials were silently dropped even when the target addresses were correct.

So instead of **writing root credentials**, this port makes the kernel **execute with existing privileged credentials**.

### New endgame: forged workqueue execution

The final stage:

```text
constrained kernel write
        ↓
physical read/write channel
        ↓
KASLR slide recovery
        ↓
discover system_wq / cpu_pwq
        ↓
forge work_struct
        ↓
call_usermodehelper_exec_work
        ↓
/system/bin/sh
        ↓
uid=0(root), u:r:kernel:s0
```

A forged work item is placed on a bound `system_wq` pool and triggered with a `ptmx` allocation/free storm.

The resulting usermode helper executes with init credentials.

No task credential overwrite is required.

---

## Exploit chain

```text
userspace shell (uid 2000)
        │
        ▼
pselect / PI-futex primitive
        │
        ▼
constrained aligned kernel pointer write
        │
        ▼
forged pipe_buffer channel
        │
        ▼
arbitrary physical read/write
        │
        ├── recover KASLR slide
        │
        ├── locate system_wq / cpu_pwq
        │
        └── prepare forged work_struct
        │
        ▼
queue usermode-helper work
        │
        ▼
ptmx storm wakes worker
        │
        ▼
/system/bin/sh runs with init creds
        │
        ▼
uid=0(root)
        │
        ▼
g4d → @ghostlockd → g4sh
```

---

## Key engineering changes

Compared with the public OnePlus port, most stages after the initial write primitive were reworked.

### 1. New KDP-compatible root stage

The credential-patching endgame was replaced with a forged workqueue item targeting the usermode-helper execution path.

This avoids writing protected `cred` structures entirely.

### 2. New KASLR slide oracle

The previous perf-event anchoring approach was unreliable on this device.

Instead, the exploit uses three slid pointers from the `boot_id` `ctl_table` entry:

```text
procname
data
proc_handler
```

All three are cross-validated before accepting the slide.

### 3. Runtime workqueue discovery

`cpu_pwq` is discovered by walking:

```text
system_wq → pwqs
```

rather than relying on a fixed device-specific offset.

### 4. Clean exploit exit

The original channel leaves collateral changes to `struct page` state that can trigger `PANIC_ON_OOPS` during teardown.

The current chain avoids the teardown crash and has been demonstrated exiting cleanly after root.

### 5. Root shell

The usermode helper starts:

```text
g4d
```

which listens on the abstract Unix socket:

```text
@ghostlockd
```

`g4sh` connects to it and provides either an interactive root shell or one-shot command execution.

```bash
/data/local/tmp/a/g4sh
/data/local/tmp/a/g4sh -c "id"
```

---

## Why the Galaxy A17 is interesting

This target combines several protections that break common Android kernel exploitation techniques:

- **Samsung KDP** — protects credential-related kernel data at EL2
- **DEFEX** — restricts privileged execution from untrusted paths
- **SELinux**
- **PANIC_ON_OOPS / PANIC_ON_BUG**
- **Large arm64 KASLR slides**
- **Pointer-only constrained write primitive**

This forced a different exploit strategy from the usual:

```text
arbitrary RW → patch cred → disable SELinux
```

Instead:

```text
arbitrary RW → recover runtime state → forge kernel work → execute usermode helper
```

---

## Build

Requires a recent Android NDK.

```bash
make        # BZA5 firmware (kernel 6.12.23)
make czg1   # CZG1 firmware (kernel 6.12.38): per-target slide anchors,
            # offsets are uname-keyed at runtime
```

Produces:

```text
ghostlock   # exploit (ghostlock-czg1 for the CZG1 build)
g4d         # static root-shell daemon
g4sh        # root-shell client
```

---

## Run

Push the binaries:

```bash
adb push ghostlock /data/local/tmp/a/g4
adb push g4d /data/local/tmp/a/g4d
adb push g4sh /data/local/tmp/a/g4sh

adb shell 'chmod 755 /data/local/tmp/a/g4 /data/local/tmp/a/g4d /data/local/tmp/a/g4sh'
```

Run the reboot-aware exploit loop:

```bash
./scripts/rr_loop4.sh
```

After `ROOTED`:

```bash
adb shell /data/local/tmp/a/g4sh
```

Or execute a single command:

```bash
adb shell '/data/local/tmp/a/g4sh -c "id"'
```

Expected result:

```text
uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
```

---

## Reliability

The primitive is probabilistic and strongly dependent on boot conditions.

Successful exploitation may require repeated attempts. The included `rr_loop4.sh` script handles retries and reboot cycles automatically.

This is a research exploit, not an instant one-shot rooting tool.

---

## QEMU validation

`qemu-e2e/` contains an end-to-end validation harness using the extracted Samsung kernel.

The harness was used to test:

- exploit-chain changes
- KASLR handling
- workqueue forging
- usermode-helper execution
- clean exploit teardown
- `g4d` / `g4sh` round trips

The Samsung kernel image itself is **not included**.

See:

```text
qemu-e2e/
```

for setup instructions.

---

## Repository layout

```text
Makefile
src/                  exploit source and device profiles
src/daemon/           g4d root daemon + g4sh client
docs/OFFSETS.md       validated device offsets
docs/PORTING.md       porting notes
examples/             proof-of-root artifacts
scripts/rr_loop4.sh   reboot-aware exploit loop
qemu-e2e/             end-to-end QEMU validation
```

---

## Related research

### Original GhostLock / IonStack research

NebuSec:

https://nebusec.ai/research/ionstack-part-3/

https://github.com/NebuSec/CyberMeowfia/tree/main/IonStack

### OnePlus port

https://github.com/JoinChang/ghostlock-oneplus

### Mobile Hacking Lab write-up

A deeper look at the Samsung Galaxy A17 port, KDP limitations, KASLR recovery, workqueue-based final stage, and root-shell implementation:

https://www.mobilehackinglab.com/blog/cve-2026-43499-ghostlock-a17-root-shell

---

## Proof of root

Real-device artifacts are available under:

```text
examples/
```

including exploit logs and root-context verification.

Example:

```text
uid=0(root)
gid=0(root)
groups=0(root)
context=u:r:kernel:s0
```

---

## Disclaimer

This proof of concept is provided for **educational and authorized security research purposes only**.

Only use it on devices and environments you own or have explicit permission to test.