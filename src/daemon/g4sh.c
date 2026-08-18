/* g4sh.c — client for the ghostlock root daemon (g4d).
 *
 *   g4sh              interactive root shell (raw tty bridge)
 *   g4sh -c "id"      run one command, print its output, exit
 *
 * Connects to the abstract unix socket @ghostlockd.  The daemon side forks
 * /system/bin/sh with the wq-umh helper's init creds on a pty.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <termios.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#define G4D_NAME "ghostlockd"

static int g4d_connect(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;
  struct sockaddr_un un;
  memset(&un, 0, sizeof(un));
  un.sun_family = AF_UNIX;
  strcpy(un.sun_path + 1, G4D_NAME);
  socklen_t alen = sizeof(sa_family_t) + 1 + strlen(G4D_NAME);
  /* the daemon may still be starting when the harness calls — brief retry */
  for (int t = 0; t < 10; t++) {
    if (connect(fd, (struct sockaddr *)&un, alen) == 0)
      return fd;
    usleep(200000);
  }
  close(fd);
  return -1;
}

int main(int argc, char **argv) {
  int fd = g4d_connect();
  if (fd < 0) {
    fprintf(stderr, "g4sh: g4d not reachable (@%s): %s\n", G4D_NAME,
            strerror(errno));
    return 1;
  }

  if (argc >= 3 && strcmp(argv[1], "-c") == 0) {
    /* one-shot: command, then exit so the shell terminates and the daemon
     * closes the connection (EOF ends the stream below) */
    dprintf(fd, "%s\nexit\n", argv[2]);
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0)
      if (write(1, buf, n) != n)
        break;
    close(fd);
    return 0;
  }

  /* interactive: raw local tty, bridge stdin/stdout <-> socket */
  struct termios orig;
  int raw = isatty(0) && tcgetattr(0, &orig) == 0;
  if (raw) {
    struct termios t = orig;
    cfmakeraw(&t);
    tcsetattr(0, TCSANOW, &t);
  }
  struct pollfd pf[2] = {
    { .fd = 0,  .events = POLLIN },
    { .fd = fd, .events = POLLIN },
  };
  char buf[4096];
  int done = 0;
  while (!done) {
    if (poll(pf, 2, -1) < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    if (pf[0].revents & POLLIN) {
      ssize_t n = read(0, buf, sizeof(buf));
      if (n <= 0)
        shutdown(fd, SHUT_WR);
      else if (write(fd, buf, n) != n)
        break;
    }
    if (pf[1].revents & (POLLIN | POLLHUP | POLLERR)) {
      ssize_t n = read(fd, buf, sizeof(buf));
      if (n <= 0)
        done = 1;
      else if (write(1, buf, n) != n)
        done = 1;
    }
  }
  if (raw)
    tcsetattr(0, TCSANOW, &orig);
  close(fd);
  return 0;
}
