#ifndef INTEGRITY_CHECK_H
#define INTEGRITY_CHECK_H

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <vector>
#include "ProtectCommon.h"

namespace IntegrityCheck {

static uint32_t crc32_table[256] = {0};
static bool crc32_table_init = false;

static inline void crc32_init_table() {
    if (crc32_table_init) return;
    for (int i = 0; i < 256; i++) {
        uint32_t c = (uint32_t)i;
        for (int j = 0; j < 8; j++) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
    crc32_table_init = true;
}

static inline uint32_t crc32_update(uint32_t crc, const void *buf, size_t len) {
    crc32_init_table();
    const uint8_t *p = static_cast<const uint8_t*>(buf);
    uint32_t val = crc ^ 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) val = crc32_table[(val ^ p[i]) & 0xFF] ^ (val >> 8);
    return val ^ 0xFFFFFFFFu;
}

static inline uint32_t crc32(const void *buf, size_t len) {
    return crc32_update(0xFFFFFFFFu, buf, len);
}

struct SHA256_CTX {
    uint32_t state[8];
    uint64_t bits;
    uint32_t buf[16];
    int len;
};

void sha256_transform(SHA256_CTX *ctx, const void *block);
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const void *data, size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t hash[32]);
void sha256(const void *data, size_t len, uint8_t hash[32]);
void hmac_sha256(const uint8_t *key, size_t key_len, const void *data, size_t data_len, uint8_t mac[32]);
void hmac_sha256_self_test(const uint8_t *key, size_t key_len, const char *msg, uint8_t mac[32]);
uint32_t compute_memory_crc(const void *start, size_t len);
bool compute_file_hmac(const uint8_t *key, size_t key_len, uint8_t mac_out[32]);
uint32_t compute_loaded_text_crc(const char *soname);

static const uint8_t INTEGRITY_MAGIC[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78};
static const size_t  TAIL_SIZE = 128; // 8 magic+4 crc+32 hmac+4 text_crc+4 helpers_crc+32 merkle_root+4 blk_size+4 blk_count+36 reserved

static inline bool get_self_path(char *out, size_t out_sz) {
    ssize_t len = readlink("/proc/self/exe", out, out_sz - 1);
    if (len <= 0) return false;
    out[len] = '\0';
    return true;
}

static inline size_t read_self_file(uint8_t **out_data) {
    *out_data = nullptr;
    char path[256];
    if (!get_self_path(path, sizeof(path))) return 0;

    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return 0; }
    size_t fsz = (size_t)st.st_size;
    if (fsz == 0) { close(fd); return 0; }

    uint8_t *buf = (uint8_t*)malloc(fsz);
    if (!buf) { close(fd); return 0; }

    size_t total = 0;
    while (total < fsz) {
        ssize_t r = read(fd, buf + total, fsz - total);
        if (r <= 0) break;
        total += (size_t)r;
    }
    close(fd);

    if (total != fsz) { free(buf); return 0; }
    *out_data = buf;
    return fsz;
}

static inline bool verify_self_integrity(const char *soname,
                                          const uint8_t *hmac_key, size_t hmac_key_len,
                                          uint32_t *out_actual_crc, uint8_t out_actual_sha[32],
                                          bool *crc_ok, bool *sha_ok) {
    (void)soname;
    *crc_ok = true;
    *sha_ok = true;

    uint8_t *data = nullptr;
    size_t fsz = read_self_file(&data);
    if (!data || fsz == 0) return false;

    size_t payload_sz = fsz;
    bool has_tail = false;
    uint32_t exp_crc = 0;
    uint8_t  exp_sha[32] = {0};
    uint32_t exp_text_crc = 0;  // 48-byte tail: bytes 44-47

    if (fsz >= TAIL_SIZE && memcmp(data + fsz - TAIL_SIZE, INTEGRITY_MAGIC, 8) == 0) {
        has_tail = true;
        payload_sz = fsz - TAIL_SIZE;
        const uint8_t *t = data + payload_sz + 8;
        exp_crc = ((uint32_t)t[0] << 24) | ((uint32_t)t[1] << 16) |
                  ((uint32_t)t[2] << 8)  |  (uint32_t)t[3];
        memcpy(exp_sha, t + 4, 32);
        // text_crc at offset 44 (=8+4+32)
        const uint8_t *tc = t + 4 + 32;  // = data + payload_sz + 44
        exp_text_crc = ((uint32_t)tc[0] << 24) | ((uint32_t)tc[1] << 16) |
                       ((uint32_t)tc[2] << 8)  |  (uint32_t)tc[3];
    }

    size_t to_hash = payload_sz;

    crc32_init_table();
    uint32_t crc_val = 0;
    for (size_t i = 0; i < to_hash; i++)
        crc_val = crc32_table[(crc_val ^ data[i]) & 0xFF] ^ (crc_val >> 8);
    uint32_t actual_crc = (crc_val ^ 0xFFFFFFFFu);

    // HMAC-SHA256 替代纯 SHA256：攻击者无 HMAC key 无法重算
    uint8_t actual_sha[32];
    if (hmac_key && hmac_key_len > 0) {
        hmac_sha256(hmac_key, hmac_key_len, data, to_hash, actual_sha);
    } else {
        // 降级：无 key 时用纯 SHA256（向后兼容）
        sha256(data, to_hash, actual_sha);
    }

    if (out_actual_crc) *out_actual_crc = actual_crc;
    if (out_actual_sha) memcpy(out_actual_sha, actual_sha, 32);

    if (has_tail) {
        *crc_ok = (actual_crc == exp_crc);
        *sha_ok = (memcmp(actual_sha, exp_sha, 32) == 0);
    }

    free(data);
    return true;
}

struct IntegrityCheckConfig {
    uint8_t expected_text_hash[32];
    uint32_t expected_crc;
    bool enable_periodic_check;
    int check_interval_ms;
    bool panic_on_mismatch;
    std::vector<uintptr_t> watched_funcs;
    std::vector<uint32_t> watched_func_crcs;
    std::vector<const char*> watched_func_names;
    const char *target_soname;
    bool enable_crc;
    bool enable_sha256;
    const uint8_t *hmac_key;
    size_t hmac_key_len;
};

inline struct IntegrityCheckConfig default_config() {
    struct IntegrityCheckConfig cfg = {};
    memset(cfg.expected_text_hash, 0, 32);
    cfg.expected_crc = 0;
    cfg.enable_periodic_check = false;
    cfg.check_interval_ms = 10000;
    cfg.panic_on_mismatch = true;
    cfg.target_soname = nullptr;
    cfg.enable_crc = true;
    cfg.enable_sha256 = true;
    cfg.hmac_key = nullptr;
    cfg.hmac_key_len = 0;
    return cfg;
}

static inline bool get_text_range(const char *soname, uintptr_t *out_start, size_t *out_size) {
    char line[512] = {0};
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, soname)) continue;
        if (strstr(line, "r-xp")) {
            uintptr_t start = 0, end = 0;
            if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                *out_start = start;
                *out_size = end - start;
                fclose(fp);
                return true;
            }
        }
    }
    fclose(fp);
    return false;
}

static inline uint32_t calc_text_crc(const char *soname) {
    uintptr_t start = 0; size_t size = 0;
    if (!get_text_range(soname, &start, &size)) return 0;
    size_t check_len = (size * 90) / 100;
    if (check_len > 0x200000) check_len = 0x200000;
    return crc32(reinterpret_cast<void*>(start), check_len);
}

static inline void calc_text_sha256(const char *soname, uint8_t hash[32]) {
    uintptr_t start = 0; size_t size = 0;
    if (!get_text_range(soname, &start, &size)) {
        memset(hash, 0, 32); return;
    }
    size_t check_len = (size * 90) / 100;
    if (check_len > 0x200000) check_len = 0x200000;
    sha256(reinterpret_cast<void*>(start), check_len, hash);
}

static bool get_func_addr_from_name(const char *func_name, uintptr_t *out_addr) {
    void *h = dlopen(nullptr, RTLD_NOLOAD);
    if (!h) h = dlopen("libc.so", RTLD_NOLOAD);
    if (!h) return false;
    void *addr = dlsym(h, func_name);
    if (!addr) return false;
    *out_addr = reinterpret_cast<uintptr_t>(addr);
    return true;
}

static uint32_t crc32_func_by_name(const char *func_name, size_t check_size) {
    uintptr_t addr = 0;
    if (!get_func_addr_from_name(func_name, &addr)) return 0;
    return crc32(reinterpret_cast<void*>(addr), check_size);
}

struct CheckResult {
    bool crc_ok;
    bool sha256_ok;
    uint32_t actual_crc;
    uint8_t actual_sha256[32];
    std::vector<bool> func_checks;
};

static inline CheckResult verify(const IntegrityCheckConfig &cfg, const char *soname) {
    struct CheckResult res = {};
    bool ok = verify_self_integrity(soname, cfg.hmac_key, cfg.hmac_key_len,
                                     &res.actual_crc, res.actual_sha256,
                                     &res.crc_ok, &res.sha256_ok);

    if (!ok) {
        res.crc_ok = true;
        res.sha256_ok = true;
    }

    if (cfg.enable_crc && cfg.target_soname) {
        uint8_t *data = nullptr;
        size_t fsz = read_self_file(&data);
        bool has_tail = (data && fsz >= TAIL_SIZE && memcmp(data + fsz - TAIL_SIZE, INTEGRITY_MAGIC, 8) == 0);
        if (data) free(data);

        if (!has_tail) {
            if (cfg.panic_on_mismatch) {
                res.crc_ok = false;
                res.sha256_ok = false;
            } else {
                res.crc_ok = true;
                res.sha256_ok = true;
            }
        }
    } else {
        if (!cfg.enable_crc) res.crc_ok = true;
        if (!cfg.enable_sha256) res.sha256_ok = true;
    }

    for (size_t i = 0; i < cfg.watched_funcs.size(); i++) {
        uint32_t actual = crc32(reinterpret_cast<void*>(cfg.watched_funcs[i]), 256);
        bool ok = cfg.watched_func_crcs.size() > i ? (actual == cfg.watched_func_crcs[i]) : true;
        res.func_checks.push_back(ok);
    }
    for (size_t i = 0; i < cfg.watched_func_names.size(); i++) {
        uint32_t actual = crc32_func_by_name(cfg.watched_func_names[i], 256);
        size_t idx = cfg.watched_funcs.size() + i;
        bool ok = cfg.watched_func_crcs.size() > idx ? (actual == cfg.watched_func_crcs[idx]) : true;
        res.func_checks.push_back(ok);
    }
    return res;
}

static bool check_func_integrity_batch(
    const std::vector<const char*> &func_names,
    const std::vector<uint32_t> &expected_crcs,
    std::vector<bool> *results) {
    if (func_names.size() != expected_crcs.size()) return false;
    results->clear();
    for (size_t i = 0; i < func_names.size(); i++) {
        uint32_t actual = crc32_func_by_name(func_names[i], 256);
        results->push_back(actual == expected_crcs[i]);
    }
    return true;
}

} // namespace IntegrityCheck

#endif
