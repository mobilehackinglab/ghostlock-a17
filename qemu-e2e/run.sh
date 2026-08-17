#!/bin/bash
# Boot the real A17 (BZA5) kernel Image in QEMU virt and run the wq-umh E2E.
set -e
cd "$(dirname "$0")"
./mkinitramfs.sh
exec qemu-system-aarch64 \
  -accel "${ACCEL:-hvf}" \
  -M virt -cpu "${CPU:-host}" -smp 4 -m 2G \
  -kernel "${KERNEL:-Image.nokdp}" \
  -initrd initramfs.cpio.gz \
  -append "console=ttyAMA0 earlycon panic=-1 loglevel=7 ${EXTRA_APPEND:-nokaslr}" \
  -display none -serial stdio -monitor none \
  ${GDBSTUB:+-s -S} \
  -no-reboot
