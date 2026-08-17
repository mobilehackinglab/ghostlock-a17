/* fake_sh.c — minimal static "shell" for the QEMU guest.
 *
 * The wq-umh helper exec's /system/bin/sh with the script as an argument.
 * This fake shell doesn't interpret the script; it performs the capture
 * semantics directly (the proof we need: the forged work ran a program
 * with init creds):
 *   - touch /data/local/tmp/a/.umh_rooted
 *   - write uid/gid/caps to /data/local/tmp/cap/id.txt
 *   - print a banner on the console
 * It also works as /bin/sh for `sh -c "id"` style invocations from the
 * exploit's finish path (prints the id line).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>

static void wfile(const char *path, const char *data) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd >= 0) {
    write(fd, data, strlen(data));
    close(fd);
  }
}

int main(int argc, char **argv) {
  char idbuf[256];
  snprintf(idbuf, sizeof(idbuf),
           "uid=%u(%s) gid=%u(%s) euid=%u egid=%u caps=unknown\n",
           getuid(), getuid() == 0 ? "root" : "?", getgid(),
           getgid() == 0 ? "root" : "?", geteuid(), getegid());
  if (argc >= 3 && !strcmp(argv[1], "-c")) {
    /* sh -c "..." — only "id" matters for the exploit's su probes */
    if (strstr(argv[2], "id")) {
      printf("%s", idbuf);
      fflush(stdout);
      return 0;
    }
    return 0;
  }
  printf("[fake_sh] helper running pid=%d %s", getpid(), idbuf);
  fflush(stdout);
  wfile("/data/local/tmp/a/.umh_rooted", "rooted\n");
  mkdir("/data/local/tmp/cap", 0755);
  wfile("/data/local/tmp/cap/id.txt", idbuf);
  wfile("/data/local/tmp/cap/fake_sh_ran.txt", "fake_sh ran\n");
  printf("[fake_sh] HELPER-RAN marker written\n");
  fflush(stdout);
  return 0;
}
