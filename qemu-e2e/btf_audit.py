#!/usr/bin/env python3
"""Audit wq-umh struct offsets against the BZA5 kernel BTF.
Usage: btf_audit.py /path/to/vmlinux.elf [/path/to/extract_btf_dir]
extract_btf.py comes from the ghostlock-oneplus tools/ directory."""
import sys, struct
sys.path.insert(0, sys.argv[2] if len(sys.argv) > 2 else ".")
import extract_btf

data = open(sys.argv[1] if len(sys.argv) > 1 else "vmlinux.elf", 'rb').read()
btf_off = extract_btf.find_btf(data)
hdr_len = struct.unpack_from('<I', data, btf_off+4)[0]
type_len = struct.unpack_from('<I', data, btf_off+12)[0]
type_data = data[btf_off+hdr_len:btf_off+hdr_len+type_len]
str_data = data[btf_off+hdr_len+type_len:]

for name in ["workqueue_struct", "pool_workqueue", "worker_pool", "subprocess_info", "work_struct"]:
    res = extract_btf.find_struct_in_btf(type_data, str_data, name)
    for size, members in res:
        print(f"=== {name} (size={size}):")
        for mname, moff in members:
            print(f"  {mname:32s} 0x{moff:x}")
