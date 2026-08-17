/* Static-link stubs for the guest build of the rebuilt ghostlock tree.
 * miniadb.c's dlopen(libselinux) path is only used by the interactive
 * mini-adb shell, which the --rwforge E2E route never enters; make the
 * symbols resolve to graceful failure so the tree links with -static.
 */
void *dlopen(const char *f, int fl) { (void)f; (void)fl; return 0; }
void *dlsym(void *h, const char *s) { (void)h; (void)s; return 0; }
int dlclose(void *h) { (void)h; return 0; }
char *dlerror(void) { return "static build: dlopen unsupported"; }
