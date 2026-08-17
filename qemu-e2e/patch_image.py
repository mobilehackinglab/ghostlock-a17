#!/usr/bin/env python3
"""Patch a COPY of the BZA5 kernel Image so it boots on QEMU virt (no EL2 hypervisor).

Patch 1 — KDP off:
start_kernel+0x198 unconditionally sets kdp_enable=1 right after rkp_init
(whose _uh_call hypervisor handshake silently fails on QEMU).  With KDP on but
no hypervisor, prepare_ro_creds() panics ("KDP Call failed") and the KDP slab
caches corrupt.  kdp_enable==0 makes every consumer (copy_creds, put_cred,
kdp_cred_init, RKP slab paths, ...) take the normal non-KDP code path.
So: NOP the `strb w8, [x19, #0x3b0]` that sets kdp_enable.

Patch 2 — DEFEX off:
defex_load_rules() panics ("Signature mismatch") when the /system rules file is
absent, unless is_boot_state_unlocked() reports an unlocked device (bootconfig
androidboot.verifiedbootstate=orange — absent on QEMU).  Force
is_boot_state_unlocked() to return 1: the exact "device unlocked, DEFEX
disabled" state, which also makes defex_lsm_load() skip rule loading.

Never touches ../extract/Image — writes Image.nokdp.
"""

BASE = 0xFFFFFFC080000000          # vmlinux _text / Image file offset 0
VM_SEC_OFF = 0x1C0                 # .kernel file offset in vmlinux.elf

NOP = bytes.fromhex("1f2003d5")

PATCHES = {
    0x2080650: NOP,   # start_kernel: strb w8, [x19, #0x3b0]  (kdp_enable = 1)
    0x735EB0: (0x52800020).to_bytes(4, "little"),  # is_boot_state_unlocked: mov w0, #1
    0x735EB4: (0xD65F03C0).to_bytes(4, "little"),  #                        ret
}

def main():
    import pathlib
    here = pathlib.Path(__file__).parent
    vm = (here / "../extract/vmlinux.elf").read_bytes()
    img = bytearray((here / "../extract/Image").read_bytes())

    # sanity: Image file offset == vaddr - BASE (arm64 header, text_offset=0)
    for off in PATCHES:
        vm_off = VM_SEC_OFF + off
        assert vm[vm_off:vm_off + 4] == bytes(img[off:off + 4]), \
            f"Image/vmlinux diverge at {BASE + off:#x}"
    for off, data in PATCHES.items():
        old = bytes(img[off:off + 4])
        img[off:off + 4] = data
        print(f"patched {BASE + off:#010x}: {int.from_bytes(old, 'little'):#010x} -> "
              f"{int.from_bytes(data, 'little'):#010x}")

    out = here / "Image.nokdp"
    out.write_bytes(img)
    print(f"wrote {out} ({len(img)} bytes)")

if __name__ == "__main__":
    main()
