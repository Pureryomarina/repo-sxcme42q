#ifndef ANTI_HOOK_H
#define ANTI_HOOK_H

#include <unistd.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <pthread.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <atomic>
#include <vector>
#include <string>
#include "ProtectCommon.h"

namespace AntiHook {

struct AntiHookConfig {
    bool check_got;
    bool check_inline;
    bool check_shadowpage;
    bool check_memory_write;
    bool check_ld_preload;
    bool check_suspicious_so;
    bool check_plt_hooks;
    bool check_rwxp_pages;
    int  scan_interval_ms;
    int  max_violations;
};

struct AntiHookConfig default_config() {
    struct AntiHookConfig cfg = {};
    cfg.check_got = true;
    cfg.check_inline = false;
    cfg.check_shadowpage = true;
    cfg.check_memory_write = true;
    cfg.check_ld_preload = true;
    cfg.check_suspicious_so = true;
    cfg.check_plt_hooks = true;
    cfg.check_rwxp_pages = false;
    cfg.scan_interval_ms = 3000;
    cfg.max_violations = 3;
    return cfg;
}

static inline uintptr_t get_page_start(uintptr_t addr) {
    return addr & ~(uintptr_t(getpagesize() - 1));
}

static void* get_module_base_range(const char *soname, uintptr_t *out_start, uintptr_t *out_end) {
    char line[512] = {0};
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return nullptr;
    void *base = nullptr;
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, soname)) continue;
        uintptr_t s = 0, e = 0;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %s", &s, &e, perms) != 3) continue;
        if (s == 0) continue;
        if (base == nullptr) {
            base = reinterpret_cast<void*>(s);
            *out_start = s;
        }
        *out_end = e;
    }
    fclose(fp);
    return base;
}

static inline void get_libc_range(uintptr_t *out_start, uintptr_t *out_end) {
    get_module_base_range("libc.so", out_start, out_end);
}

static void* get_func_addr_from_plt(const char *sym) {
    void *h = dlopen("libc.so", RTLD_NOLOAD);
    if (!h) h = dlopen("libstdc++.so", RTLD_NOLOAD);
    if (!h) return nullptr;
    return dlsym(h, sym);
}

static uint32_t read_memory_word(void *addr) {
    return *(volatile uint32_t*)addr;
}

static bool detect_bvc_trap(void *addr) {
    uint32_t insn = read_memory_word(addr);
    if (insn == 0xd4200000) return true;
    return false;
}

static bool detect_bcc_jump_outside(void *addr, uintptr_t mod_start, uintptr_t mod_end, int range) {
    uint32_t *insns = reinterpret_cast<uint32_t*>(addr);
    for (int i = 0; i < range; i++) {
        uint32_t insn = read_memory_word(&insns[i]);
        if ((insn & 0xFF000000u) == 0x54000000u) {
            int32_t imm = ((insn >> 5) & 0x7FFFFF);
            if (imm > 0x400000) imm |= ~0x7FFFFF;
            int bit_pos = insn & 0x1F;
            intptr_t target = reinterpret_cast<intptr_t>(addr) + ((int64_t)imm << 2) + bit_pos;
            if (target < 0 || (uintptr_t)target < mod_start || (uintptr_t)target >= mod_end) return true;
        }
        if ((insn & 0xFC000000u) == 0x14000000u) {
            int32_t offset = (insn & 0x3FFFFFFu) * 4;
            intptr_t target = reinterpret_cast<intptr_t>(addr) + offset;
            if ((uintptr_t)target < mod_start || (uintptr_t)target >= mod_end) return true;
        }
        if ((insn & 0xFC000000u) == 0x94000000u) {
            int32_t offset = (insn & 0x3FFFFFFu) * 4;
            intptr_t target = reinterpret_cast<intptr_t>(addr) + offset;
            if ((uintptr_t)target < mod_start || (uintptr_t)target >= mod_end) return true;
        }
    }
    return false;
}

static bool detect_indirect_branch(void *addr) {
    uint32_t insn = read_memory_word(addr);
    if ((insn & 0x9F000000u) == 0x10000000u) {
        uint32_t next = read_memory_word(reinterpret_cast<uint32_t*>(addr) + 1);
        if ((next & 0xFFFFFC1Fu) == 0xD61F0000u) return true;
    }
    if ((insn & 0xF8000000u) == 0xD8000000u) {
        uint32_t rd = (insn >> 0) & 0x1F;
        uint32_t rn = (insn >> 5) & 0x1F;
        if (rd != 16 && rn != 16) return true;
    }
    return false;
}

static bool detect_inline_hook_inner(void *func_addr, uintptr_t mod_start, uintptr_t mod_end) {
    if (!func_addr) return false;
    if (detect_bvc_trap(func_addr)) return true;
    if (detect_indirect_branch(func_addr)) return true;
    if (detect_bcc_jump_outside(func_addr, mod_start, mod_end, 6)) return true;
    return false;
}

static bool check_plt_hook_common(const char *sym, uintptr_t libc_start, uintptr_t libc_end) {
    void *orig = get_func_addr_from_plt(sym);
    if (!orig) return false;
    uintptr_t addr = reinterpret_cast<uintptr_t>(orig);
    if (detect_bvc_trap(reinterpret_cast<void*>(addr))) return true;
    if (detect_bcc_jump_outside(reinterpret_cast<void*>(addr), libc_start, libc_end, 3)) return true;
    return false;
}

static bool check_read_hook() {
    uintptr_t s = 0, e = 0;
    get_libc_range(&s, &e);
    if (s == 0) return false;
    return check_plt_hook_common("read", s, e);
}

static bool check_fgets_hook() {
    uintptr_t s = 0, e = 0;
    get_libc_range(&s, &e);
    if (s == 0) return false;
    return check_plt_hook_common("fgets", s, e);
}

static bool check_write_hook() {
    uintptr_t s = 0, e = 0;
    get_libc_range(&s, &e);
    if (s == 0) return false;
    return check_plt_hook_common("write", s, e);
}

static bool check_open_hook() {
    uintptr_t s = 0, e = 0;
    get_libc_range(&s, &e);
    if (s == 0) return false;
    return check_plt_hook_common("open", s, e);
}

static bool check_fopen_hook() {
    uintptr_t s = 0, e = 0;
    get_libc_range(&s, &e);
    if (s == 0) return false;
    return check_plt_hook_common("fopen", s, e);
}

static bool check_mprotect_hook() {
    uintptr_t s = 0, e = 0;
    get_libc_range(&s, &e);
    if (s == 0) return false;
    return check_plt_hook_common("mprotect", s, e);
}

static bool check_clone_hook() {
    uintptr_t s = 0, e = 0;
    get_libc_range(&s, &e);
    if (s == 0) return false;
    return check_plt_hook_common("clone", s, e);
}

static bool check_fork_hook() {
    uintptr_t s = 0, e = 0;
    get_libc_range(&s, &e);
    if (s == 0) return false;
    return check_plt_hook_common("fork", s, e);
}

static bool check_pthread_create_hook() {
    uintptr_t s = 0, e = 0;
    get_libc_range(&s, &e);
    if (s == 0) return false;
    void *handle = dlopen("libc.so", RTLD_NOLOAD);
    if (!handle) return false;
    void *addr = dlsym(handle, "pthread_create");
    if (!addr) return false;
    return detect_inline_hook_inner(addr, s, e);
}

static bool check_dlopen_hook() {
    uintptr_t s = 0, e = 0;
    get_module_base_range("libdl.so", &s, &e);
    if (s == 0) {
        void *h = dlopen("libdl.so", RTLD_NOLOAD);
        if (h) dlclose(h);
        get_module_base_range("libdl.so", &s, &e);
    }
    if (s == 0) get_libc_range(&s, &e);
    if (s == 0) return false;
    void *handle = dlopen("libdl.so", RTLD_NOLOAD);
    if (!handle) handle = dlopen("libc.so", RTLD_NOLOAD);
    if (!handle) return false;
    void *addr = dlsym(handle, "dlopen");
    if (!addr) return false;
    return detect_inline_hook_inner(addr, s, e);
}

static bool check_dlsym_hook() {
    uintptr_t s = 0, e = 0;
    get_module_base_range("libdl.so", &s, &e);
    if (s == 0) {
        void *h = dlopen("libdl.so", RTLD_NOLOAD);
        if (h) dlclose(h);
        get_module_base_range("libdl.so", &s, &e);
    }
    if (s == 0) get_libc_range(&s, &e);
    if (s == 0) return false;
    void *handle = dlopen("libdl.so", RTLD_NOLOAD);
    if (!handle) handle = dlopen("libc.so", RTLD_NOLOAD);
    if (!handle) return false;
    void *addr = dlsym(handle, "dlsym");
    if (!addr) return false;
    return detect_inline_hook_inner(addr, s, e);
}

static bool check_so_inline_hook(const char *soname, const char *func_name) {
    uintptr_t mod_start = 0, mod_end = 0;
    get_module_base_range(soname, &mod_start, &mod_end);
    if (mod_start == 0) return false;
    void *handle = dlopen(soname, RTLD_NOLOAD);
    if (!handle) return false;
    void *addr = dlsym(handle, func_name);
    if (!addr) return false;
    return detect_inline_hook_inner(addr, mod_start, mod_end);
}

static bool detect_inline_hooks_batch() {
    const char *funcs[] = {
        "read", "write", "open", "fopen", "mprotect", "dlopen", "dlsym",
        "pthread_create", "fork", "clone", "exit", "_exit"
    };
    uintptr_t mod_start = 0, mod_end = 0;
    get_libc_range(&mod_start, &mod_end);
    if (mod_start == 0) return false;
    void *handle = dlopen("libc.so", RTLD_NOLOAD);
    if (!handle) return false;
    for (size_t i = 0; i < sizeof(funcs)/sizeof(funcs[0]); i++) {
        void *addr = dlsym(handle, funcs[i]);
        if (addr && detect_inline_hook_inner(addr, mod_start, mod_end)) {
            dlclose(handle);
            return true;
        }
    }
    dlclose(handle);
    return false;
}

static bool check_so_hooked_funcs_all() {
    bool hooked = false;
    hooked |= check_so_inline_hook("libc.so", "read");
    hooked |= check_so_inline_hook("libc.so", "write");
    hooked |= check_so_inline_hook("libc.so", "open");
    hooked |= check_so_inline_hook("libc.so", "fopen");
    hooked |= check_so_inline_hook("libc.so", "mprotect");
    hooked |= check_so_inline_hook("libc.so", "clone");
    hooked |= check_so_inline_hook("libc.so", "pthread_create");
    hooked |= check_so_inline_hook("libdl.so", "dlopen") || check_so_inline_hook("libc.so", "dlopen");
    hooked |= check_so_inline_hook("libdl.so", "dlsym") || check_so_inline_hook("libc.so", "dlsym");
    hooked |= detect_inline_hooks_batch();
    return hooked;
}

static bool detect_shadowpage_memfd() {
    char line[512] = {0};
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "shadow") || strstr(line, "gadget")) {
            char perms[8] = {0};
            uintptr_t start = 0, end = 0;
            if (sscanf(line, "%lx-%lx %s", &start, &end, perms) == 3) {
                if (perms[0] == 'r' && perms[2] == 'x') {
                    size_t size = end - start;
                    if (size >= 0x100000) {
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

static bool detect_ld_preload_env() {
    const char *env = getenv("LD_PRELOAD");
    if (!env) return false;
    const char *suspicious[] = {
        "local_activate", "liblocal", "activate", "hook", "inline",
        "frida", "xhook", "substrate", "sandhook", "android_hook",
        "LibInject", "hookzz", "whale", "epic", "Cydia"
    };
    for (size_t i = 0; i < sizeof(suspicious)/sizeof(suspicious[0]); i++) {
        if (strstr(env, suspicious[i])) return true;
    }
    return false;
}

static bool detect_suspicious_injected_so() {
    char line[512] = {0};
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "/data/local/tmp/") ||
            strstr(line, "/data/user_de/")) {
            char perms[8] = {0};
            uintptr_t start = 0, end = 0;
            if (sscanf(line, "%lx-%lx %s", &start, &end, perms) == 3) {
                if (perms[0] == 'r' && perms[2] == 'x' && (end - start) < 0x200000) {
                    fclose(fp);
                    return true;
                }
            }
        }
    }
    fclose(fp);
    return false;
}

static bool detect_memory_page_rwxp() {
    char line[512] = {0};
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    while (fgets(line, sizeof(line), fp)) {
        char perms[8] = {0};
        uintptr_t start = 0, end = 0;
        if (sscanf(line, "%lx-%lx %s", &start, &end, perms) == 3) {
            if (perms[0] == 'r' && perms[2] == 'x' && perms[1] == 'w') {
                fclose(fp);
                return true;
            }
        }
    }
    fclose(fp);
    return false;
}

static inline bool check_all(const AntiHookConfig &cfg) {
    if (cfg.check_ld_preload && detect_ld_preload_env()) return true;
    if (cfg.check_suspicious_so && detect_suspicious_injected_so()) return true;
    if (cfg.check_memory_write && detect_memory_page_rwxp()) return true;
    if (cfg.check_got) {
        if (check_dlopen_hook()) return true;
        if (check_dlsym_hook()) return true;
        if (check_pthread_create_hook()) return true;
    }
    if (cfg.check_plt_hooks) {
        if (check_read_hook()) return true;
        if (check_fgets_hook()) return true;
        if (check_write_hook()) return true;
        if (check_open_hook()) return true;
        if (check_fopen_hook()) return true;
        if (check_mprotect_hook()) return true;
        if (check_clone_hook()) return true;
        if (check_fork_hook()) return true;
        if (check_dlopen_hook()) return true;
        if (check_dlsym_hook()) return true;
        if (check_pthread_create_hook()) return true;
    }
    if (cfg.check_shadowpage && detect_shadowpage_memfd()) return true;
    return false;
}

} // namespace AntiHook

#endif
