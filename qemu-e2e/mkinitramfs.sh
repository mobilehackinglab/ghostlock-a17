#!/bin/bash
# Build the guest initramfs (cpio newc, gzipped) from rootfs/.
set -e
cd "$(dirname "$0")/rootfs"
find . | LC_ALL=C sort | cpio --quiet -o -H newc > ../initramfs.cpio
gzip -9 -f -c ../initramfs.cpio > ../initramfs.cpio.gz
cd ..
ls -la initramfs.cpio.gz
