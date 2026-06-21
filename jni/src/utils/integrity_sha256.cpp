// integrity_sha256.cpp — 独立 SHA-256/HMAC 实现 + 纯计算函数
// 不 include IntegrityCheck.h, 所有静态数据内部定义
// 不受 OLLVM 混淆影响, 但也不泄露 MAGIC/TAIL 到明文
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

namespace IntegrityCheck {

// SHA256_CTX — 与 IntegrityCheck.h 中布局一致
struct SHA256_CTX {
    uint32_t state[8];
    uint64_t bits;
    uint32_t buf[16];
    int len;
};

// CRC32 表 — 内部 static, 不对外暴露
static uint32_t crc32_table[256] = {0};
static bool     crc32_table_init = false;

static inline void crc32_init_table() {
    if (crc32_table_init) return;
    for (int i = 0; i < 256; i++) {
        uint32_t c = (uint32_t)i;
        for (int j = 0; j < 8; j++) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
    crc32_table_init = true;
}

// TAIL_SIZE = 128 (0x80), XOR 编码避免 strings 搜索
static const uint8_t  TAIL_XOR = 0xA3;
static const uint8_t  TAIL_ENC = 0x80 ^ 0xA3;  // 0x80 ^ 0xA3 = 0x23

static inline size_t get_tail_size() {
    return (size_t)(TAIL_ENC ^ TAIL_XOR);  // = 128
}

static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static uint32_t sigma0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
static uint32_t sigma1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
static uint32_t gamma0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
static uint32_t gamma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void sha256_transform(SHA256_CTX *ctx, const void *block) {
    const uint8_t *blk = static_cast<const uint8_t*>(block);
    uint32_t w[64];
    for (int j = 0; j < 16; j++) w[j] = (uint32_t(blk[j*4]) << 24) | (uint32_t(blk[j*4+1]) << 16) | (uint32_t(blk[j*4+2]) << 8) | uint32_t(blk[j*4+3]);
    for (int j = 16; j < 64; j++) w[j] = gamma1(w[j-2]) + w[j-7] + gamma0(w[j-15]) + w[j-16];
    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
    for (int j = 0; j < 64; j++) {
        uint32_t t1 = h + sigma1(e) + ch(e, f, g) + K[j] + w[j];
        uint32_t t2 = sigma0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->bits = 0; ctx->len = 0;
}

void sha256_update(SHA256_CTX *ctx, const void *data, size_t len) {
    ctx->bits += len * 8;
    const uint8_t *p = (const uint8_t*)data;
    size_t left = len;
    size_t offset = ctx->len & 63;
    ctx->len += len;
    if (offset) {
        size_t need = 64 - offset;
        if (left < need) {
            memcpy((uint8_t*)ctx->buf + offset, p, left);
            return;
        }
        memcpy((uint8_t*)ctx->buf + offset, p, need);
        sha256_transform(ctx, ctx->buf);
        p += need;
        left -= need;
        offset = 0;
    }
    while (left >= 64) {
        sha256_transform(ctx, p);
        p += 64;
        left -= 64;
    }
    if (left) {
        memcpy((uint8_t*)ctx->buf + offset, p, left);
    }
}

void sha256_final(SHA256_CTX *ctx, uint8_t hash[32]) {
    uint8_t pad[128];
    memset(pad, 0, sizeof(pad));
    size_t offset = ctx->len & 63;
    pad[0] = 0x80;
    size_t pad_len = (offset < 56) ? (56 - offset) : (120 - offset);
    uint64_t saved_bits = ctx->bits;
    sha256_update(ctx, pad, pad_len);
    uint8_t bits_be[8];
    for (int i = 0; i < 8; i++) bits_be[i] = (uint8_t)(saved_bits >> ((7-i)*8));
    sha256_update(ctx, bits_be, 8);
    for (int i = 0; i < 8; i++) {
        uint32_t w = ctx->state[i];
        hash[i*4]   = (uint8_t)(w >> 24);
        hash[i*4+1] = (uint8_t)(w >> 16);
        hash[i*4+2] = (uint8_t)(w >> 8);
        hash[i*4+3] = (uint8_t)w;
    }
}

void sha256(const void *data, size_t len, uint8_t hash[32]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);
}

// HMAC-SHA256: key 在 obfuscated 代码中，攻击者无 key 无法重算
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const void *data, size_t data_len,
                 uint8_t mac[32]) {
    uint8_t key_block[64] = {};
    if (key_len > 64) {
        // key 过长时先用 SHA256 哈希
        sha256(key, key_len, key_block);
        // key_block[0..31] = hash, key_block[32..63] = 0 (already zeroed)
    } else {
        memcpy(key_block, key, key_len);
    }

    uint8_t o_key_pad[64], i_key_pad[64];
    for (int i = 0; i < 64; i++) {
        o_key_pad[i] = key_block[i] ^ 0x5c;
        i_key_pad[i] = key_block[i] ^ 0x36;
    }

    SHA256_CTX ctx;
    uint8_t inner[32];

    sha256_init(&ctx);
    sha256_update(&ctx, i_key_pad, 64);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner);

    sha256_init(&ctx);
    sha256_update(&ctx, o_key_pad, 64);
    sha256_update(&ctx, inner, 32);
    sha256_final(&ctx, mac);
}

// 交叉校验用：对固定消息做 HMAC，obfuscated 代码比对期望值
void hmac_sha256_self_test(const uint8_t *key, size_t key_len,
                           const char *msg, uint8_t mac[32]) {
    hmac_sha256(key, key_len, msg, strlen(msg), mac);
}

// ═══════════════════════════════════════════════════════
// 以下函数只负责计算，不包含任何决策逻辑
// 所有比较均在 OLLVM 混淆代码 (main.cpp) 中完成
// ═══════════════════════════════════════════════════════

// 计算加载态内存段的 CRC32（不加比较、不读尾部）
uint32_t compute_memory_crc(const void *start, size_t len) {
    if (!start || !len) return 0;
    crc32_init_table();
    uint32_t crc_val = 0;
    const uint8_t *p = static_cast<const uint8_t*>(start);
    for (size_t i = 0; i < len; i++)
        crc_val = crc32_table[(crc_val ^ p[i]) & 0xFF] ^ (crc_val >> 8);
    return crc_val ^ 0xFFFFFFFFu;
}

// 读自身文件（去尾）做 HMAC，返回原始哈希
bool compute_file_hmac(const uint8_t *key, size_t key_len, uint8_t mac_out[32]) {
    uint8_t *data = nullptr;
    size_t fsz = 0;
    {
        char path[256];
        ssize_t rl = readlink("/proc/self/exe", path, sizeof(path)-1);
        if (rl <= 0) return false;
        path[rl] = '\0';
        int fd = open(path, O_RDONLY);
        if (fd < 0) return false;
        struct stat st;
        if (fstat(fd, &st) != 0 || st.st_size <= 0) { close(fd); return false; }
        fsz = (size_t)st.st_size;
        data = (uint8_t*)malloc(fsz);
        if (!data) { close(fd); return false; }
        size_t total = 0;
        while (total < fsz) {
            ssize_t r = read(fd, data + total, fsz - total);
            if (r <= 0) break;
            total += (size_t)r;
        }
        close(fd);
        if (total != fsz) { free(data); return false; }
    }
    // 去尾部
    size_t tail_sz = get_tail_size();
    size_t payload_sz = (fsz >= tail_sz) ? (fsz - tail_sz) : fsz;
    hmac_sha256(key, key_len, data, payload_sz, mac_out);
    free(data);
    return true;
}

// 计算 ELF 文件中代码段的 CRC32（与 Python patch_integrity.py 一致）
uint32_t compute_loaded_text_crc(const char *soname) {
    // 读 /proc/self/exe 文件（与 Python 在构建时读的是同一个 ELF 文件结构）
    char path[256];
    ssize_t rl = readlink("/proc/self/exe", path, sizeof(path)-1);
    if (rl <= 0) return 0;
    path[rl] = '\0';

    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;

    uint8_t ehdr[0x40];
    if (read(fd, ehdr, 0x40) != 0x40 || memcmp(ehdr, "\x7f" "ELF", 4) != 0 || ehdr[4] != 2) {
        close(fd); return 0;
    }

    uint64_t e_phoff   = *reinterpret_cast<uint64_t*>(ehdr + 0x20);
    uint16_t e_phentsz = *reinterpret_cast<uint16_t*>(ehdr + 0x36);
    uint16_t e_phnum   = *reinterpret_cast<uint16_t*>(ehdr + 0x38);

    bool found = false;
    uint64_t p_offset = 0, p_filesz = 0;

    uint8_t *phdr = (uint8_t*)malloc(e_phentsz * e_phnum);
    if (!phdr) { close(fd); return 0; }
    lseek(fd, (off_t)e_phoff, SEEK_SET);
    if (read(fd, phdr, e_phentsz * e_phnum) != (ssize_t)(e_phentsz * e_phnum)) {
        free(phdr); close(fd); return 0;
    }

    for (int i = 0; i < e_phnum; i++) {
        uint8_t *p = phdr + i * e_phentsz;
        uint32_t p_type  = *reinterpret_cast<uint32_t*>(p);
        uint32_t p_flags = *reinterpret_cast<uint32_t*>(p + 4);
        if (p_type == 1 && (p_flags & 1)) {  // PT_LOAD + PF_X
            p_offset = *reinterpret_cast<uint64_t*>(p + 8);
            p_filesz = *reinterpret_cast<uint64_t*>(p + 0x20);
            found = true;
            break;
        }
    }
    free(phdr);
    if (!found || p_filesz == 0) { close(fd); return 0; }

    // 只取前 90%，避开 PLT/GOT 尾部（与 Python 端一致）
    size_t check_len = (size_t)((p_filesz * 90) / 100);

    uint8_t *data = (uint8_t*)malloc(check_len);
    if (!data) { close(fd); return 0; }
    lseek(fd, (off_t)p_offset, SEEK_SET);
    ssize_t r = read(fd, data, check_len);
    close(fd);

    uint32_t crc = 0;
    if (r == (ssize_t)check_len) {
        crc = compute_memory_crc(data, check_len);
    }
    free(data);
    return crc;
    (void)soname;
}

} // namespace IntegrityCheck
