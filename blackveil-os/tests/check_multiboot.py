"""Verifies the Multiboot v1 header: 4-byte aligned, in the first 8 KiB, valid checksum."""
import struct
import sys

MAGIC = 0x1BADB002

data = open(sys.argv[1], "rb").read(8192)
for off in range(0, len(data) - 11, 4):
    magic, flags, checksum = struct.unpack_from("<III", data, off)
    if magic == MAGIC:
        if (magic + flags + checksum) & 0xFFFFFFFF != 0:
            sys.exit(f"bad checksum at offset {off:#x}")
        print(f"  multiboot header at file offset {off:#x}, flags {flags:#x}")
        sys.exit(0)
sys.exit("multiboot header not found in first 8 KiB")
