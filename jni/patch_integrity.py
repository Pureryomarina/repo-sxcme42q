#!/usr/bin/env python3
"""
Post-build integrity patcher for safe_bypass (64-byte nested verification tail).

Tail format (64 bytes):
  [0..7]   magic          DEADBEEF12345678
  [8..11]  crc_file       CRC32 of full file payload (before tail)
  [12..43] hmac_file      HMAC-SHA256(key, full file payload)
  [44..47] crc_text       CRC32 of loaded .text ELF segment
  [48..51] crc_helpers    reserved (0)
  [52..63] reserved       0-padding

Usage: python3 patch_integrity.py <path_to_safe_bypass>
"""

import sys
import struct
import hashlib
import hmac

MAGIC = b"\xde\xad\xbe\xef\x12\x34\x56\x78"
TAIL_SIZE = 64

HMAC_KEY = bytes([
    0x4B, 0x8E, 0x2D, 0x7F, 0x1A, 0x6C, 0x93, 0xE4,
    0xB5, 0x0F, 0x38, 0xD2, 0x66, 0xC9, 0x5A, 0x81,
    0xFD, 0x3E, 0x47, 0x9B, 0x0C, 0x78, 0xA5, 0xD3,
    0x2E, 0x6F, 0x14, 0x89, 0xBB, 0xCC, 0xDD, 0xEE
])


def crc32(data: bytes) -> int:
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            if c & 1:
                c = 0xEDB88320 ^ (c >> 1)
            else:
                c >>= 1
        table.append(c)
    crc = 0
    for b in data:
        crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def find_text_section(data: bytes) -> tuple:
    """从 64-bit ELF 中提取第一个 PT_LOAD PF_X 段（≈ .text 在内存中的映射）"""
    if data[:4] != b"\x7fELF" or data[4] != 2:  # 64-bit little-endian only
        return None
    e_phoff,   = struct.unpack_from('<Q', data, 0x20)
    e_phentsz, = struct.unpack_from('<H', data, 0x36)
    e_phnum,   = struct.unpack_from('<H', data, 0x38)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsz
        p_type, = struct.unpack_from('<I', data, off)
        if p_type != 1:  # PT_LOAD
            continue
        p_flags, = struct.unpack_from('<I', data, off + 4)
        if not (p_flags & 1):  # PF_X
            continue
        p_offset, = struct.unpack_from('<Q', data, off + 8)
        p_filesz, = struct.unpack_from('<Q', data, off + 0x20)
        if p_offset >= len(data) or p_offset + p_filesz > len(data):
            continue
        return (p_offset, int(p_filesz))
    return None


def patch_binary(path: str):
    with open(path, "rb") as f:
        data = f.read()
    if not data:
        print(f"ERROR: {path} is empty"); sys.exit(1)

    # 移除旧尾部（支持 44/48/64 字节旧格式）
    old_sizes = [44, 48, 64]
    for ts in old_sizes:
        if len(data) >= ts and data[-ts:-ts + 8] == MAGIC:
            data = data[:-ts]
            print(f"[INFO] Removed old {ts}-byte integrity tail")
            break

    payload = data

    # 计算 CRC32 和 HMAC
    crc_val  = crc32(payload)
    hmac_val = hmac.new(HMAC_KEY, payload, hashlib.sha256).digest()

    # 计算 ELF .text 段 CRC（只取前 90%，避开 PLT/GOT）
    text_info = find_text_section(data)
    if text_info:
        text_off, text_sz = text_info
        text_check_len = (text_sz * 90) // 100
        text_crc = crc32(data[text_off:text_off + text_check_len])
    else:
        text_crc = 0

    # helpers_crc 预留 (0)
    helpers_crc = 0

    print(f"  File size   : {len(data)} bytes")
    print(f"  CRC(file)   : 0x{crc_val:08X}")
    print(f"  HMAC-SHA256 : {hmac_val.hex().upper()}")
    if text_info:
        print(f"  CRC(.text)  : 0x{text_crc:08X}  (offset={text_off:#x}, size={text_sz})")

    # 拼装尾部
    tail = MAGIC \
         + struct.pack(">I", crc_val) \
         + hmac_val \
         + struct.pack(">I", text_crc) \
         + struct.pack(">I", helpers_crc) \
         + b"\x00" * 12   # reserved

    with open(path, "wb") as f:
        f.write(data)
        f.write(tail)

    print(f"[OK] Patched {path}  (+{len(tail)} bytes integrity tail)")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path_to_safe_bypass>"); sys.exit(1)
    patch_binary(sys.argv[1])
