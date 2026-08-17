#!/system/bin/sh
echo UMH-ALIVE
while IFS= read -r L; do case "$L" in Uid:*|Gid:*|Cap*:|NoNewPrivs:*|Seccomp:*) echo "PS: $L";; esac; done < /proc/self/status
echo UMH-STATUS-DONE
id; echo "ID-RC=$?"
id >&2; echo "ID2-RC=$?" >&2
id > /data/local/tmp/a/umh_id.txt 2>&1; echo "W-ID-RC=$?"; sync
touch /data/local/tmp/a/.umh_rooted; echo "W-MARK-RC=$?"; sync
cat /proc/last_kmsg > /data/local/tmp/a/last_kmsg.txt 2>/dev/null; sync
dmesg > /data/local/tmp/a/dmesg.txt 2>/dev/null; sync
cat /proc/iomem > /data/local/tmp/a/iomem.txt 2>/dev/null; sync
cat /proc/cmdline > /data/local/tmp/a/cmdline.txt 2>/dev/null; sync
cat /proc/kallsyms > /data/local/tmp/a/kallsyms.txt 2>/dev/null; sync
id > /data/local/tmp/a/id.txt 2>&1; sync
ls -la /sys/fs/pstore/ > /data/local/tmp/a/pstore_ls.txt 2>/dev/null; sync
for f in /sys/fs/pstore/*; do cp $f /data/local/tmp/a/ 2>/dev/null; done; sync
ls -la /data/system/dropbox/ > /data/local/tmp/a/dropbox_ls.txt 2>&1; sync
for f in $(ls -t /data/system/dropbox/SYSTEM_LAST_KMSG@* 2>/dev/null | head -3); do cp $f /data/local/tmp/a/ 2>/dev/null; cp $f /data/local/tmp/cap/ 2>/dev/null; done; sync
for f in $(ls -t /data/system/dropbox/SYSTEM_BOOT@* 2>/dev/null | head -3); do cp $f /data/local/tmp/a/ 2>/dev/null; cp $f /data/local/tmp/cap/ 2>/dev/null; done; sync
mkdir -p /data/local/tmp/cap && chmod 755 /data/local/tmp/cap; cat /proc/last_kmsg > /data/local/tmp/cap/last_kmsg.txt 2>/dev/null; dmesg > /data/local/tmp/cap/dmesg.txt 2>/dev/null; cat /proc/iomem > /data/local/tmp/cap/iomem.txt 2>/dev/null; cat /proc/cmdline > /data/local/tmp/cap/cmdline.txt 2>/dev/null; cat /proc/kallsyms > /data/local/tmp/cap/kallsyms.txt 2>/dev/null; id > /data/local/tmp/cap/id.txt 2>&1; ls -la /sys/fs/pstore/ > /data/local/tmp/cap/pstore_ls.txt 2>/dev/null; for f in /sys/fs/pstore/*; do cp $f /data/local/tmp/cap/ 2>/dev/null; done; chmod 644 /data/local/tmp/cap/* /data/local/tmp/a/*.txt 2>/dev/null; echo CAPTURES-DONE
