/* g4d.c — ghostlock root daemon: abstract-socket root shell server.
 *
 * Started by the wq-umh helper (init creds) after a successful root:
 *   /data/local/tmp/a/g4d          (device; self-daemonizes)
 *   /boot/g4d                      (QEMU guest, via fake_sh hook)
 *
 * Listens on the abstract unix socket @ghostlockd.  Per connection:
 * SO_PEERCRED gate (uid 0 or 2000/shell only), then /system/bin/sh on a
 * fresh pty, bridged to the socket.  Multi-session (one child per
 * connection).  Duplicate starts self-terminate (EADDRINUSE on bind).
 *
 * Static, no dependencies.  Builds for device and guest with the same file.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#define G4D_NAME   "ghostlockd"          /* abstract socket: @ghostlockd */
#define G4D_PIDF   "/data/local/tmp/a/g4d.pid"
#define G4D_SHELL  "/system/bin/sh"

static int peer_ok(int fd) {
  struct ucred cr;
  socklen_t len = sizeof(cr);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &len) != 0)
    return 0;
  return cr.uid == 0 || cr.uid == 2000;   /* root or shell */
}

/* Bridge socket <-> pty master until either side closes or the shell
 * exits.  Runs in the per-connection child. */
static void bridge(int cfd, int master, pid_t shell) {
  struct pollfd pf[2] = {
    { .fd = cfd,    .events = POLLIN },
    { .fd = master, .events = POLLIN },
  };
  unsigned char buf[4096];
  for (;;) {
    int pr = poll(pf, 2, 1000);
    if (pr < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    if (waitpid(shell, NULL, WNOHANG) == shell)
      break;
    if (pr == 0)
      continue;
    if (pf[0].revents & POLLIN) {
      ssize_t n = read(cfd, buf, sizeof(buf));
      if (n <= 0)
        break;
      if (write(master, buf, n) != n)
        break;
    }
    if (pf[1].revents & POLLIN) {
      ssize_t n = read(master, buf, sizeof(buf));
      if (n <= 0)
        break;
      if (write(cfd, buf, n) != n)
        break;
    }
    if ((pf[0].revents | pf[1].revents) & (POLLHUP | POLLERR))
      break;
  }
}

/* One shell session on its own pty.  Never returns. */
static void session(int cfd) {
  int master = posix_openpt(O_RDWR | O_NOCTTY);
  if (master < 0)
    _exit(1);
  if (grantpt(master) != 0 || unlockpt(master) != 0)
    _exit(1);
  char slave[128];
  if (ptsname_r(master, slave, sizeof(slave)) != 0)
    _exit(1);
  pid_t pid = fork();
  if (pid == 0) {
    setsid();
    int sfd = open(slave, O_RDWR);   /* becomes the controlling tty */
    if (sfd < 0)
      _exit(127);
    dup2(sfd, 0);
    dup2(sfd, 1);
    dup2(sfd, 2);
    if (sfd > 2)
      close(sfd);
    close(master);
    close(cfd);
    char *const argv[] = { (char *)"sh", NULL };
    execv(G4D_SHELL, argv);
    _exit(127);
  }
  if (pid < 0)
    _exit(1);
  bridge(cfd, master, pid);
  close(master);
  close(cfd);
  _exit(0);
}

int main(void) {
  /* daemonize: parent returns at once so the caller (umh helper) never
   * blocks; the real daemon is the child */
  pid_t p = fork();
  if (p < 0)
    return 1;
  if (p > 0) {
    int pf = open(G4D_PIDF, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (pf >= 0) {
      dprintf(pf, "%d\n", p);
      close(pf);
    }
    return 0;
  }
  setsid();
  /* the umh helper launches g4d through a bind-mount shadow
   * (/system/bin/lmkd) to pass DEFEX safeplace — the kernel then sets
   * comm from the shadow's name, so fix it for ps/pgrep */
  prctl(PR_SET_NAME, "g4d", 0, 0, 0);

  int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (lfd < 0) {
    fprintf(stderr, "g4d: socket: %s\n", strerror(errno));
    _exit(1);
  }
  struct sockaddr_un un;
  memset(&un, 0, sizeof(un));
  un.sun_family = AF_UNIX;
  strcpy(un.sun_path + 1, G4D_NAME);   /* abstract namespace */
  socklen_t alen = sizeof(sa_family_t) + 1 + strlen(G4D_NAME);
  if (bind(lfd, (struct sockaddr *)&un, alen) != 0) {
    /* EADDRINUSE: already running (or a stale shell-creds instance holds
     * the socket — kill it before the root cycle) */
    fprintf(stderr, "g4d: bind @%s: %s\n", G4D_NAME, strerror(errno));
    _exit(1);
  }
  if (listen(lfd, 4) != 0) {
    fprintf(stderr, "g4d: listen: %s\n", strerror(errno));
    _exit(1);
  }

  /* auto-reap session children */
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_DFL;
  sa.sa_flags = SA_NOCLDWAIT;
  sigaction(SIGCHLD, &sa, NULL);

  for (;;) {
    int cfd = accept(lfd, NULL, NULL);
    if (cfd < 0) {
      if (errno == EINTR)
        continue;
      _exit(1);
    }
    if (!peer_ok(cfd)) {
      close(cfd);
      continue;
    }
    pid_t s = fork();
    if (s == 0) {
      close(lfd);
      session(cfd);   /* never returns */
    }
    close(cfd);
  }
}
