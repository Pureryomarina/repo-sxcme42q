#ifndef DEEP_INTEGRITY_H
#define DEEP_INTEGRITY_H

// ============================================================================
//  DeepIntegrity —— 整 ELF 嵌套互锁完整性校验
//
//  覆盖整个文件每一字节，采用「分块 HMAC + 嵌套哈希链(Merkle 风格)」：
//    1. 整文件 payload(去掉 128 字节尾部)切成 N 个块
//    2. 每块算 bd_i = HMAC(K1, block_i)
//    3. 嵌套链:  c = HMAC(K2, "DEEP_INIT");  c = HMAC(K2, c ‖ bd_i)  逐块推进
//    4. 最终 c 即 merkle 根，与尾部存储的期望根比对
//    5. 子密钥 K1/K2 从主 HMAC key 派生，不单独存储
//    6. 结构互锁: 解析全部 program header，校验所有 PT_LOAD 段落在文件内，
//       且块数量与文件长度自洽
//
//  纯文件校验，不依赖运行环境 → root 设备不会误报。
//  任意一字节改动(任何段/任何 section/ELF 头) → 根不同 → 检出。
// ============================================================================

#include <cstdint>
#include <cstring>
#include <cstdlib>
#include "IntegrityCheck.h"

namespace DeepIntegrity {

static const uint32_t DEEP_BLOCK_SIZE = 65536;  // 64KB / 块

// 尾部(128 字节)布局，merkle 字段相对 magic 起点的偏移:
//   [0..7]    magic
//   [8..11]   crc_file
//   [12..43]  hmac_file
//   [44..47]  crc_text
//   [48..51]  crc_helpers
//   [52..83]  merkle_root   <-- 本模块校验对象
//   [84..87]  block_size    (大端)
//   [88..91]  block_count   (大端)
//   [92..127] reserved
static const size_t DEEP_TAIL_SIZE   = 128;
static const size_t OFF_MERKLE_ROOT  = 52;
static const size_t OFF_BLOCK_SIZE   = 84;
static const size_t OFF_BLOCK_COUNT  = 88;

// 子密钥派生: out = HMAC(master, ctx)
static inline void derive_key(const uint8_t *master, size_t mlen,
                              const char *ctx, uint8_t out[32]) {
    IntegrityCheck::hmac_sha256(master, mlen,
                                ctx, strlen(ctx), out);
}

// 计算整 payload 的嵌套 merkle 根
static inline void compute_root(const uint8_t *payload, size_t plen,
                                const uint8_t *key, size_t klen,
                                uint8_t root_out[32]) {
    uint8_t k1[32], k2[32];
    derive_key(key, klen, "BLOCK_KEY_V1", k1);
    derive_key(key, klen, "CHAIN_KEY_V1", k2);

    uint8_t chain[32];
    IntegrityCheck::hmac_sha256(k2, 32, "DEEP_INIT", 9, chain);

    uint8_t bd[32];
    uint8_t step[64];
    size_t off = 0;
    while (off < plen) {
        size_t bs = plen - off;
        if (bs > DEEP_BLOCK_SIZE) bs = DEEP_BLOCK_SIZE;
        IntegrityCheck::hmac_sha256(k1, 32, payload + off, bs, bd);
        memcpy(step, chain, 32);
        memcpy(step + 32, bd, 32);
        IntegrityCheck::hmac_sha256(k2, 32, step, 64, chain);
        off += bs;
    }
    memcpy(root_out, chain, 32);
}

// 结构互锁: 校验所有 PT_LOAD 段落在文件内
static inline bool verify_elf_structure(const uint8_t *data, size_t fsz) {
    if (fsz < 64) return false;
    if (memcmp(data, "\x7f""ELF", 4) != 0) return false;
    if (data[4] != 2) return false;  // 64-bit only

    uint64_t e_phoff;   memcpy(&e_phoff,   data + 0x20, 8);
    uint16_t e_phentsz; memcpy(&e_phentsz, data + 0x36, 2);
    uint16_t e_phnum;   memcpy(&e_phnum,   data + 0x38, 2);
    if (e_phentsz < 56) return false;
    if (e_phoff == 0 || e_phoff + (uint64_t)e_phnum * e_phentsz > fsz) return false;

    bool seen_exec = false;
    for (uint16_t i = 0; i < e_phnum; i++) {
        const uint8_t *ph = data + e_phoff + (size_t)i * e_phentsz;
        uint32_t p_type;   memcpy(&p_type,   ph + 0, 4);
        uint32_t p_flags;  memcpy(&p_flags,  ph + 4, 4);
        uint64_t p_offset; memcpy(&p_offset, ph + 8, 8);
        uint64_t p_filesz; memcpy(&p_filesz, ph + 0x20, 8);
        if (p_type != 1) continue;  // PT_LOAD
        if (p_offset + p_filesz > fsz) return false;
        if (p_flags & 1) seen_exec = true;  // PF_X
    }
    return seen_exec;
}

// 顶层校验: 返回 true=通过, false=被篡改/无尾部
static inline bool verify(const uint8_t *key, size_t klen) {
    uint8_t *data = nullptr;
    size_t fsz = IntegrityCheck::read_self_file(&data);
    if (!data || fsz < DEEP_TAIL_SIZE) { if (data) free(data); return false; }

    // 1. 尾部 magic
    const uint8_t *tail = data + fsz - DEEP_TAIL_SIZE;
    if (memcmp(tail, IntegrityCheck::INTEGRITY_MAGIC, 8) != 0) { free(data); return false; }

    size_t payload_sz = fsz - DEEP_TAIL_SIZE;

    // 2. 结构互锁
    if (!verify_elf_structure(data, fsz)) { free(data); return false; }

    // 3. 块数量自洽
    uint32_t blk_size  = ((uint32_t)tail[OFF_BLOCK_SIZE]  << 24) |
                         ((uint32_t)tail[OFF_BLOCK_SIZE+1] << 16) |
                         ((uint32_t)tail[OFF_BLOCK_SIZE+2] << 8)  |
                          (uint32_t)tail[OFF_BLOCK_SIZE+3];
    uint32_t blk_count = ((uint32_t)tail[OFF_BLOCK_COUNT]  << 24) |
                         ((uint32_t)tail[OFF_BLOCK_COUNT+1] << 16) |
                         ((uint32_t)tail[OFF_BLOCK_COUNT+2] << 8)  |
                          (uint32_t)tail[OFF_BLOCK_COUNT+3];
    if (blk_size == 0) { free(data); return false; }
    uint32_t expect_count = (uint32_t)((payload_sz + blk_size - 1) / blk_size);
    if (blk_count != expect_count) { free(data); return false; }

    // 4. 嵌套 merkle 根
    uint8_t root[32];
    compute_root(data, payload_sz, key, klen, root);

    int diff = 0;
    const uint8_t *exp = tail + OFF_MERKLE_ROOT;
    for (int i = 0; i < 32; i++) diff |= (root[i] ^ exp[i]);  // 常量时间

    free(data);
    return diff == 0;
}

}  // namespace DeepIntegrity

#endif  // DEEP_INTEGRITY_H
