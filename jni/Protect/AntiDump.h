#ifndef ANTI_DUMP_H
#define ANTI_DUMP_H

#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <pthread.h>
#include <dlfcn.h>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <vector>
#include "ProtectCommon.h"

#ifndef PR_SET_DUMPABLE
#define PR_SET_DUMPABLE 4
#endif
#ifndef PR_GET_DUMPABLE
#define PR_GET_DUMPABLE 3
#endif

namespace AntiDump {

struct AntiDumpConfig {
    bool prevent_ptrace_dump;
    bool detect_memory_read;
    bool encrypt_code_section;
    bool anti_unlink;
    bool check_fake_so;
    bool check_pagemap;
    bool check_maps_modify;
    bool detect_ptrace_bypass;
    bool check_dumpable;
    bool check_maps_injection;
    bool check_anonymous_exec;
    bool check_suspicious_fd;
    int  monitor_interval_ms;
};

struct AntiDumpConfig default_config() {
    struct AntiDumpConfig cfg = {};
    cfg.prevent_ptrace_dump = true;
    cfg.detect_memory_read = false;
    cfg.encrypt_code_section = false;
    cfg.anti_unlink = true;
    cfg.check_fake_so = true;
    cfg.check_pagemap = true;
    cfg.check_maps_modify = true;
    cfg.detect_ptrace_bypass = true;
    cfg.check_dumpable = true;
    cfg.check_maps_injection = true;
    cfg.check_anonymous_exec = true;
    cfg.check_suspicious_fd = true;
    cfg.monitor_interval_ms = 5000;
    return cfg;
}

static inline void *get_module_base(const char *soname) {
    char line[512] = {0};
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return nullptr;
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, soname)) continue;
        uintptr_t start = 0;
        if (sscanf(line, "%lx", &start) == 1 && start != 0) {
            fclose(fp);
            return reinterpret_cast<void*>(start);
        }
    }
    fclose(fp);
    return nullptr;
}

static inline void disable_core_dump() {
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}

static inline bool is_dumpable() {
    return prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 1;
}

static inline bool detect_mem_file_open() {
    char path[256] = {0};
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) return false;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "/proc/self/fd/%s", entry->d_name);
        char link[512] = {0};
        ssize_t len = readlink(path, link, sizeof(link) - 1);
        if (len > 0) {
            link[len] = '\0';
            if (strstr(link, "/mem") != nullptr) {
                closedir(dir);
                return true;
            }
        }
    }
    closedir(dir);
    return false;
}

static inline bool detect_suspicious_mmap() {
    char line[512] = {0};
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    while (fgets(line, sizeof(line), fp)) {
        char perms[8] = {0};
        uintptr_t start = 0, end = 0;
        if (sscanf(line, "%lx-%lx %s", &start, &end, perms) == 3) {
            if (perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x') {
                char *path_start = strchr(line, '/');
                if (!path_start) {
                    size_t size = end - start;
                    if (size >= 0x1000) {
                        fclose(fp);
                        return true;
                    }
                }
            }
        }
    }
    fclose(fp);
    return false;
}

static bool check_so_integrity(const char *so_path) {
    struct stat st;
    if (stat(so_path, &st) != 0) return false;
    if (st.st_size < 1024) return false;
    return true;
}

static bool detect_maps_injection() {
    char line[512] = {0};
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    int inject_count = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "/data/local/tmp/") ||
            strstr(line, "/data/user_de/0/")) {
            inject_count++;
            if (inject_count >= 2) {
                fclose(fp);
                return true;
            }
        }
        if (strstr(line, ".so") && strstr(line, "r-xp")) {
            uintptr_t start = 0, end = 0;
            char perms[8] = {0};
            if (sscanf(line, "%lx-%lx %s", &start, &end, perms) == 3) {
                if (perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x') {
                    fclose(fp);
                    return true;
                }
            }
        }
    }
    fclose(fp);
    return false;
}

static uint32_t maps_crc32(const void *buf, size_t len) {
    static uint32_t table[256] = {0};
    static bool init = false;
    if (!init) {
        for (int i = 0; i < 256; i++) {
            uint32_t c = (uint32_t)i;
            for (int j = 0; j < 8; j++) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        init = true;
    }
    const uint8_t *p = (const uint8_t*)buf;
    uint32_t val = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) val = table[(val ^ p[i]) & 0xFF] ^ (val >> 8);
    return val ^ 0xFFFFFFFFu;
}

// 初始化 maps 基线 CRC（第一次调用时记录，后续调用才比对）
static uint32_t g_maps_baseline_crc = 0;
static bool g_maps_baseline_initialized = false;

static inline void init_maps_baseline() {
    char line[512] = {0};
    uint32_t crc = 0xFFFFFFFF;
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return;
    while (fgets(line, sizeof(line), fp)) {
        // 只对含有 .so 和权限相关行做哈希，忽略动态地址变化
        if (strstr(line, ".so") || strstr(line, "[")) {
            const char *perms_start = strchr(line, ' ');
            if (perms_start) {
                crc ^= maps_crc32(perms_start, strlen(perms_start));
            }
        }
    }
    fclose(fp);
    g_maps_baseline_crc = crc;
    g_maps_baseline_initialized = true;
}

static bool detect_maps_modify() {
    if (!g_maps_baseline_initialized) {
        init_maps_baseline();
        return false;  // 首次初始化不报警
    }
    char line[512] = {0};
    uint32_t crc = 0xFFFFFFFF;
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return true;  // 无法读取视为异常
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, ".so") || strstr(line, "[")) {
            const char *perms_start = strchr(line, ' ');
            if (perms_start) {
                crc ^= maps_crc32(perms_start, strlen(perms_start));
            }
        }
    }
    fclose(fp);
    return (crc != g_maps_baseline_crc);
}

static bool detect_text_section_modified() {
    char line[512] = {0};
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    while (fgets(line, sizeof(line), fp)) {
        uintptr_t start = 0, end = 0;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %s", &start, &end, perms) == 3) {
            if (perms[0] == 'r' && perms[2] == 'x') {
                char *path = strchr(line, '/');
                if (!path) {
                    size_t sz = end - start;
                    if (sz > 0x100000) {
                        fclose(fp);
                        return true;
                    }
                }
            }
            if (perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x') {
                fclose(fp);
                return true;
            }
        }
    }
    fclose(fp);
    return false;
}

// ═══════════════════════════════════════════
// 匿名可执行内存检测
// ═══════════════════════════════════════════
static bool detect_anonymous_exec() {
    char line[512];
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    while (fgets(line, sizeof(line), fp)) {
        uintptr_t start = 0, end = 0;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) != 3) continue;
        if (perms[2] == 'x' && !strchr(line, '/')) {
            if (!strstr(line, "[stack") && !strstr(line, "[heap") &&
                !strstr(line, "[vdso") && !strstr(line, "[vsyscall") &&
                !strstr(line, "[vvar") && !strstr(line, "[sigpage")) {
                fclose(fp); return true;
            }
        }
    }
    fclose(fp);
    return false;
}

// ═══════════════════════════════════════════
// FD 分析
// ═══════════════════════════════════════════
static bool detect_suspicious_fd() {
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) return false;
    struct dirent *entry;
    char link[512];
    int mem_count = 0;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        char fd_path[64];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%s", entry->d_name);
        ssize_t len = readlink(fd_path, link, sizeof(link) - 1);
        if (len <= 0) continue;
        link[len] = '\0';
        if (strstr(link, "/proc/") && strstr(link, "/mem")) {
            mem_count++;
            if (mem_count >= 2) { closedir(dir); return true; }
        }
        if (strstr(link, "/dev/mem") || strstr(link, "/dev/kmem")) {
            closedir(dir); return true;
        }
    }
    closedir(dir);
    return false;
}

static inline bool check_all(const AntiDumpConfig &cfg, const char *main_so_path = nullptr) {
    if (cfg.prevent_ptrace_dump) {
        disable_core_dump();
        if (detect_mem_file_open()) return true;
    }
    if (cfg.check_maps_modify && detect_maps_modify()) return true;
    if (cfg.check_maps_injection && detect_maps_injection()) return true;
    if (cfg.check_anonymous_exec && detect_anonymous_exec()) return true;
    if (cfg.check_suspicious_fd && detect_suspicious_fd()) return true;
    if (cfg.check_fake_so && main_so_path) {
        if (!check_so_integrity(main_so_path)) return true;
    }
    return false;
}

} // namespace AntiDump

#endif
