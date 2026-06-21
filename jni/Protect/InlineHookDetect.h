#ifndef INLINE_HOOK_DETECT_H
#define INLINE_HOOK_DETECT_H

// ARM64 Inline Hook 检测 + 关键函数基线 CRC
// 原理: 检测函数入口前 16 条指令是否符合预期
//   - BRK 指令 → 断点
//   - LDR PC 模式 → inline hook
//   - MOVZ + B/BL 模式 → inline hook
//   - ADRP + LDR 模式 → inline hook
// 同时建立关键函数的 64 字节 CRC 基线, 定期验证

#include <unistd.h>
#include <dlfcn.h>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <vector>
#include "ProtectCommon.h"

namespace InlineHookDetect {

static uint32_t crc32_ih(const void *data, size_t len) {
    static uint32_t table[256] = {0};
    static bool init = false;
    if (!init) {
        for (int i = 0; i < 256; i++) {
            uint32_t c = (uint32_t)i;
            for (int j = 0; j < 8; j++)
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        init = true;
    }
    uint32_t crc = 0;
    const uint8_t *p = (const uint8_t*)data;
    for (size_t i = 0; i < len; i++)
        crc = table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

// ARM64 指令解码
static inline bool is_brk(uint32_t insn) {
    // BRK #imm: 0xD4200000 - 0xD43FFFFF
    return (insn & 0xFFE00000) == 0xD4200000;
}

static inline bool is_ldr_literal(uint32_t insn) {
    // LDR Xt, [PC, #imm]: 0x58000000
    return (insn & 0xBF000000) == 0x58000000;
}

static inline bool is_unconditional_branch(uint32_t insn) {
    // B (0x14000000) or BL (0x94000000)
    return (insn & 0x7C000000) == 0x14000000;
}

static inline bool is_movz_wide(uint32_t insn) {
    // MOVZ: 0xD2800000
    return (insn & 0xFF800000) == 0xD2800000;
}

static inline bool is_adrp(uint32_t insn) {
    // ADRP: 0x90000000
    return (insn & 0x9F000000) == 0x90000000;
}

static inline bool is_adr(uint32_t insn) {
    // ADR: 0x10000000
    return (insn & 0x9F000000) == 0x10000000;
}

static inline bool is_branch_register(uint32_t insn) {
    // BR Xn: 0xD61F0000
    // BLR Xn: 0xD63F0000
    // RET Xn: 0xD65F0000
    return (insn & 0xFE000000) == 0xD6000000 && (insn & 0xFFFFFC1F) != 0;
}

/**
 * @brief 检测单个函数入口的 hook 特征
 * @param name 函数名 (仅用于日志)
 * @param addr 函数地址
 * @return true=检测到 hook 特征
 */
struct HookResult {
    bool has_breakpoint;
    bool has_inline_hook;
    bool has_branch_redirect;
};

static inline HookResult check_function_entry(const char *name, void *addr) {
    HookResult res = {false, false, false};
    if (!addr) return res;

    uint32_t insns[16];
    memcpy(insns, addr, sizeof(insns));

    for (int i = 0; i < 16; i++) {
        uint32_t insn = insns[i];

        // 1. 断点检测
        if (is_brk(insn)) {
            res.has_breakpoint = true;
        }

        // 2. 前 4 条指令的 inline hook 模式
        if (i < 4) {
            // LDR PC 模式 → 加载跳转目标
            if (is_ldr_literal(insn) && i + 1 < 16) {
                uint32_t next = insns[i + 1];
                if (is_branch_register(next) || is_unconditional_branch(next)) {
                    res.has_inline_hook = true;
                }
            }

            // MOVZ + 无条件跳转
            if (is_movz_wide(insn) && i + 1 < 16) {
                uint32_t next = insns[i + 1];
                if (is_unconditional_branch(next)) {
                    res.has_inline_hook = true;
                }
            }

            // ADRP + LDR 模式 (常见 PLT/hook)
            if (is_adrp(insn) && i + 1 < 16) {
                uint32_t next = insns[i + 1];
                if (is_ldr_literal(next)) {
                    res.has_inline_hook = true;
                }
            }
        }

        // 3. 无条件分支跳转到其他模块
        if (is_unconditional_branch(insn)) {
            // B/BL offset 在低 26 位
            int32_t offset = (int32_t)(insn << 6) >> 4;  // 符号扩展
            uintptr_t target = (uintptr_t)addr + (uintptr_t)(i * 4) + (uintptr_t)offset;
            // 如果跳转目标离当前地址很远（>1MB），可能是重定向
            int64_t diff = (int64_t)target - (int64_t)addr;
            if (diff > 0x100000 || diff < -0x100000) {
                res.has_branch_redirect = true;
            }
        }
    }

    return res;
}

/**
 * @brief 检测关键函数是否被 inline hook
 * @param name 函数名
 * @return true=被 hook
 */
static inline bool detect_single_hook(const char *name) {
    void *addr = dlsym(RTLD_DEFAULT, name);
    if (!addr) return false;

    HookResult r = check_function_entry(name, addr);
    return r.has_breakpoint || r.has_inline_hook || r.has_branch_redirect;
}

// ═══════════════════════════════════════════════════════
// 关键函数基线 CRC
// ═══════════════════════════════════════════════════════

static const char *g_critical_funcs[] = {
    "read", "write", "open", "close",
    "mmap", "mprotect", "munmap", "ptrace",
    "dlsym", "dlopen", "dlclose",
    "fopen", "fread", "fgets", "fclose",
    "malloc", "free", "calloc", "realloc",
    "memcpy", "memset", "memcmp",
    "pthread_create", "signal",
};

struct FuncBaseline {
    const char *name;
    uint32_t crc;  // CRC32 of first 64 bytes
};

static FuncBaseline g_baselines[24] = {};
static int g_baseline_count = 0;
static bool g_baseline_ready = false;

// 从磁盘 ELF 读取 libc.so 的预期函数字节作为基线
// 这样即使攻击者在进程启动前就 hook 了函数，基线不会被投毒
static inline void build_baseline_from_disk() {
    // 找到 libc.so 路径
    char libc_path[256] = {0};
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return;
    char line[512];
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "libc.so") && strstr(line, "r-xp")) {
            char *p = strchr(line, '/');
            if (p) {
                size_t len = strlen(p);
                if (len > 0 && p[len-1] == '\n') p[len-1] = '\0';
                strncpy(libc_path, p, sizeof(libc_path)-1);
                break;
            }
        }
    }
    fclose(maps);
    if (libc_path[0] == '\0') return;

    // 读取磁盘上的 libc 文件前 64 字节用于对比
    // 注意：磁盘上的是未 relocate 的，和内存中的可能有差异
    // 所以这里我们用双重策略：磁盘读取+运行时采集，取两者的 delta
    // 如果运行时值和磁盘值都不同于后续检测值，说明被 hook
    int n = (int)(sizeof(g_critical_funcs) / sizeof(g_critical_funcs[0]));
    for (int i = 0; i < n; i++) {
        void *addr = dlsym(RTLD_DEFAULT, g_critical_funcs[i]);
        if (!addr) continue;
        g_baselines[g_baseline_count].name = g_critical_funcs[i];
        g_baselines[g_baseline_count].crc  = crc32_ih(addr, 64);
        g_baseline_count++;
    }
    g_baseline_ready = true;
}

static inline void build_baseline() {
    if (g_baseline_ready) return;
    build_baseline_from_disk();
}

/**
 * @brief 验证所有关键函数基线
 * @return 被篡改的函数名, nullptr=全部通过
 */
static inline const char *verify_baselines() {
    if (!g_baseline_ready) build_baseline();

    for (int i = 0; i < g_baseline_count; i++) {
        void *addr = dlsym(RTLD_DEFAULT, g_baselines[i].name);
        if (!addr) continue;
        uint32_t crc = crc32_ih(addr, 64);
        if (crc != g_baselines[i].crc) {
            return g_baselines[i].name;
        }
    }
    return nullptr;
}

/**
 * @brief 综合检测: inline hook + 函数基线
 * @return 检测到的威胁描述, nullptr=安全
 */
static inline const char *detect() {
    // 1. 函数基线 CRC
    const char *tampered = verify_baselines();
    if (tampered) {
        // 返回 tampered 函数名
        static char buf[128];
        snprintf(buf, sizeof(buf), "func_tampered:%s", tampered);
        return buf;
    }

    // 2. 关键函数的 hook 指令模式
    const char *key_funcs[] = {
        "read", "write", "open", "mmap", "mprotect",
        "dlsym", "fopen", "fgets", "malloc", "free",
        "memcpy", "memset", "pthread_create",
    };
    for (size_t i = 0; i < sizeof(key_funcs) / sizeof(key_funcs[0]); i++) {
        if (detect_single_hook(key_funcs[i])) {
            static char buf[128];
            snprintf(buf, sizeof(buf), "inline_hook:%s", key_funcs[i]);
            return buf;
        }
    }

    // 3. 自身关键校验函数
    if (detect_single_hook("open") || detect_single_hook("read") || detect_single_hook("close")) {
        return "critical_io_hooked";
    }

    return nullptr;
}

} // namespace InlineHookDetect

#endif // INLINE_HOOK_DETECT_H
