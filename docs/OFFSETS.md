# Kernel offset table — Samsung Galaxy A17 (BZA5 firmware)

The exploit needs no KASLR leak to *find* most of its targets: the kernel
image loads at a fixed physical address on this device (phys 0x40000000,
RAM start), so every static kernel object is reachable through its
**physmap alias** `0xffffff8000000000 + (image_offset + phys_delta)`,
independent of the (huge, virtual-only) KASLR slide.  The table below is
the image offsets (VA − 0xffffffc080000000) of everything the chain uses.

All values were verified 12/12 against the real firmware kernel
(`extract/vmlinux.elf`, 136,422 kallsyms symbols, recovered from
`firmware/AP_A175FXXS3BZA5_..._OS16.tar.md5`; plus BTF for the struct
layouts).

## Symbol offsets (BZA5, kernel 6.12.23-android16-5-abA175FXXS3BZA5-4k)

| name | image offset | role |
|---|---|---|
| `init_task` | 0x024FCF40 | task list anchor |
| `init_cred` | 0x02512B08 | reference creds |
| `init_uts_ns` | 0x02685A88 | uts namespace (kernel release string) |
| `empty_zero_page` | 0x02726000 | — |
| `root_task_group` | 0x0272ED80 | sched group anchor |
| `selinux_enforcing` | 0x0277E560 | W1 write target (→ permissive) |
| `kptr_restrict` | 0x024FB678 | — |
| `selinux_blob_sizes` | 0x018A10E8 | — |
| `kmalloc_caches` | 0x018974C0 | slab cache array |
| `anon_pipe_buf_ops` | 0x0126EF88 | pipe slot forge: ops pointer |
| `ashmem_fops` | 0x013FB018 | fdtable arm: f_op identity check |
| `ashmem_ioctl` | 0x00DD8FA0 | payload fops table |
| `ashmem_compat_ioctl` | 0x00DD9588 | " |
| `ashmem_mmap` | 0x00DD9604 | " |
| `ashmem_open` | 0x00DD9660 | " |
| `ashmem_release` | 0x00DD9060 | replaced by a noop gadget in the armed table |
| `ashmem_show_fdinfo` | 0x00DD9560 | " |
| `configfs_read_iter` | 0x00512CE4 | configfs virtual-read gadget |
| `configfs_bin_write_iter` | 0x00512F18 | configfs virtual-write gadget (vmemmap writes) |
| `copy_splice_read` | 0x0048E7D4 | payload fops table |
| `noop_llseek` | 0x0043BB44 | " |
| `system_wq` / `system_unbound_wq` (globals) | 0x01897238 / 0x01897250 | workqueue pointers |
| `call_usermodehelper_exec_work` | 0x000F75EC | forged work's func |
| `__per_cpu_offset` | 0x024EB810 | per-cpu base table |
| `runqueues` | 0x024CF3C0 | per-cpu runqueue (own-task find) |
| boot_id ctl_table entry | 0x0261B918 | slide oracle: 3 slid pointers |
| `random_table` boot_id uuid buffer | 0x028204F0 | boot_id oracle data |

## Struct offsets (BTF-verified against the BZA5 vmlinux)

- `task_struct` (0x1440): pid 0x708, tgid 0x70c, real_cred 0x8f8,
  cred 0x900, comm 0x910, files 0x940, stack 0x38 (runtime content
  unreliable at runtime), active_mm 0x690, tasks 0x638,
  pi_waiters 0xa00, pi_blocked_on 0xa18.
- `workqueue_struct` (320): pwqs 0x0, max_active 0xa4, dfl_pwq 0xc0,
  cpu_pwq 0x108.
- `pool_workqueue` (512): pool 0x0, wq 0x8, work_color 0x10, refcnt 0x18,
  nr_in_flight 0x1c, nr_active 0x60, pwqs_node 0x88.
- `worker_pool` (792): cpu 0x4, nr_running 0x24, worklist 0x28,
  nr_workers 0x38, nr_idle 0x3c.
- `work_struct` (32): data 0x0, entry 0x8, func 0x18.
- `subprocess_info` (96): work 0x0, complete 0x20, path 0x28, argv 0x30,
  envp 0x38, wait 0x40, retval 0x44, init 0x48, cleanup 0x50, data 0x58.
- `file` (0xd8): f_mode 0xc, f_op 0x10, private_data 0x20.
- `files_struct`: fdt 0x20, fdtab 0x28; `fdtable`: max_fds 0x0, fd 0x8.
- `ctl_table`: procname 0x0, data 0x8, proc_handler 0x18.
- runqueue: `curr` 0xd10.

## Verification method

1. Symbol offsets: extracted from the shipped binary's `known_offsets[]`
   table, then re-verified byte-exact against the firmware vmlinux's
   kallsyms (136k symbols) — 12/12 target symbols match.
2. Struct offsets: parsed from the vmlinux's embedded BTF
   (`qemu-e2e/btf_audit.py` in the research tree).
3. Runtime: the QEMU E2E harness boots the real kernel and the full chain
   runs against these values (see README's E2E section).
