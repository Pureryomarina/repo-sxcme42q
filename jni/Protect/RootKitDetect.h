#ifndef ROOTKIT_DETECT_H
#define ROOTKIT_DETECT_H

#include <unistd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <vector>
#include <dlfcn.h>
#include <link.h>
#include <signal.h>
#include "ProtectCommon.h"

#ifndef PR_GET_SECCOMP
#define PR_GET_SECCOMP 21
#endif
#ifndef PR_SET_SECCOMP
#define PR_SET_SECCOMP 22
#endif
#ifndef SECCOMP_MODE_STRICT
#define SECCOMP_MODE_STRICT 1
#endif
#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2
#endif

namespace RootKitDetect {

struct RootKitConfig {
    bool check_tracer_pid;
    bool check_vm_writev;
    bool check_code_section_perms;
    bool check_seccomp;
    bool check_address_leak;
    bool check_sigstop;
    bool check_task_injection;
    bool check_ptrace_scope;
    bool check_kernel_modules;
    int monitor_interval_ms;
};

struct RootKitConfig default_config() {
    struct RootKitConfig cfg = {};
    cfg.check_tracer_pid = true;
    cfg.check_vm_writev = true;
    cfg.check_code_section_perms = true;
    cfg.check_seccomp = true;
    cfg.check_address_leak = true;
    cfg.check_sigstop = true;
    cfg.check_task_injection = true;
    cfg.check_ptrace_scope = true;
    cfg.check_kernel_modules = true;
    cfg.monitor_interval_ms = 3000;
    return cfg;
}

static inline bool read_status_field(const char *field, int *out_value) {
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) return false;
    char line[256] = {0};
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, field, strlen(field)) == 0) {
            char *p = strchr(line, ':');
            if (p) {
                *out_value = atoi(p + 1);
                fclose(fp);
                return true;
            }
        }
    }
    fclose(fp);
    return false;
}

static bool detect_tracer_pid() {
    int tracer = 0;
    if (!read_status_field("TracerPid", &tracer)) return false;
    return tracer != 0;
}

static bool detect_sigstop_handler_removed() {
    struct sigaction sa_current;
    if (sigaction(SIGSTOP, nullptr, &sa_current) != 0) return false;
    return sa_current.sa_handler == SIG_DFL;
}

static bool detect_vm_writev_available() {
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) return false;
    struct dirent *entry;
    char path[256] = {0};
    int found = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "/proc/self/fd/%s", entry->d_name);
        char link[512] = {0};
        ssize_t len = readlink(path, link, sizeof(link) - 1);
        if (len > 0) {
            if (strstr(link, "/proc/") && strstr(link, "/mem")) {
                found++;
            }
        }
    }
    closedir(dir);
    return found > 0;
}

static bool detect_task_directory_injection() {
    DIR *dir = opendir("/proc/self/task");
    if (!dir) return false;
    struct dirent *entry;
    int thread_count = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.' && entry->d_name[1] == '\0') continue;
        if (entry->d_name[0] == '.' && entry->d_name[1] == '.' && entry->d_name[2] == '\0') continue;
        thread_count++;
    }
    closedir(dir);
    return thread_count > 128;
}

static void get_text_range(uintptr_t *out_start, uintptr_t *out_end) {
    char line[512] = {0};
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return;
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, ".text")) continue;
        uintptr_t s = 0, e = 0;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %s", &s, &e, perms) == 3) {
            if (perms[0] == 'r' && perms[2] == 'x') {
                *out_start = s;
                *out_end = e;
                fclose(fp);
                return;
            }
        }
    }
    fclose(fp);
}

static bool detect_code_section_writable() {
    char line[512] = {0};
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    while (fgets(line, sizeof(line), fp)) {
        uintptr_t s = 0, e = 0;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %s", &s, &e, perms) == 3) {
            if (perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x') {
                size_t sz = e - s;
                if (sz > 0x100000) {
                    fclose(fp);
                    return true;
                }
            }
        }
    }
    fclose(fp);
    return false;
}

static bool detect_seccomp_disabled() {
    int mode = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    return mode == 0;
}

static bool detect_suspicious_linker_so() {
    char line[512] = {0};
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    int count = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, ".so") && strstr(line, "r-xp")) {
            char *path = strchr(line, '/');
            if (!path) {
                count++;
                if (count > 10) {
                    fclose(fp);
                    return true;
                }
            }
        }
    }
    fclose(fp);
    return false;
}

static bool detect_libc_readable_text() {
    void *handle = dlopen("libc.so", RTLD_NOLOAD);
    if (!handle) return false;
    void *text_addr = dlsym(handle, "read");
    if (!text_addr) {
        dlclose(handle);
        return false;
    }
    uintptr_t page_start = reinterpret_cast<uintptr_t>(text_addr) & ~(uintptr_t(getpagesize() - 1));
    int ret = mprotect(reinterpret_cast<void*>(page_start), getpagesize(), PROT_READ | PROT_WRITE);
    if (ret == 0) {
        mprotect(reinterpret_cast<void*>(page_start), getpagesize(), PROT_READ | PROT_EXEC);
        dlclose(handle);
        return true;
    }
    dlclose(handle);
    return false;
}

// maps 中可疑路径检测
static bool detect_suspicious_maps_paths() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    char line[512];
    const char *patterns[] = {"frida", "gadget", "substrate", "re.frida", "xposed"};
    int hit_count = 0;
    while (fgets(line, sizeof(line), fp)) {
        for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
            if (strstr(line, patterns[i])) {
                hit_count++;
                if (hit_count >= 2) { fclose(fp); return true; }
            }
        }
    }
    fclose(fp);
    return false;
}

// 内核模块 rootkit 字符串检测
static bool detect_kernel_module_strings() {
    FILE *fp = fopen("/proc/modules", "r");
    if (!fp) return false;
    char line[512];
    // 只匹配已知恶意 rootkit 框架，不含 magisk/gg 等合法工具
    const char *patterns[] = {
        "shadowhooks", "diamorphine", "suterusu", "reptile",
        "mokes", "azazel", "brootkit", "adore-ng",
        "knark", "hide_lkm",
    };
    while (fgets(line, sizeof(line), fp)) {
        for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
            if (strstr(line, patterns[i])) { fclose(fp); return true; }
        }
    }
    fclose(fp);
    return false;
}

static inline bool check_all(const RootKitConfig &cfg) {
    if (cfg.check_tracer_pid && detect_tracer_pid()) return true;
    if (cfg.check_sigstop && detect_sigstop_handler_removed()) return true;
    if (cfg.check_vm_writev && detect_vm_writev_available()) return true;
    if (cfg.check_task_injection && detect_task_directory_injection()) return true;
    if (cfg.check_code_section_perms && detect_code_section_writable()) return true;
    if (cfg.check_kernel_modules && detect_kernel_module_strings()) return true;
    if (cfg.check_kernel_modules && detect_suspicious_maps_paths()) return true;
    return false;
}

static inline const char* check_once_detailed(const RootKitConfig &cfg) {
    if (cfg.check_tracer_pid && detect_tracer_pid()) return "tracer_pid_nonzero";
    if (cfg.check_sigstop && detect_sigstop_handler_removed()) return "sigstop_handler_removed";
    if (cfg.check_vm_writev && detect_vm_writev_available()) return "vm_writev_available";
    if (cfg.check_task_injection && detect_task_directory_injection()) return "task_injection";
    if (cfg.check_code_section_perms && detect_code_section_writable()) return "code_section_writable";
    if (cfg.check_kernel_modules && detect_kernel_module_strings()) return "kernel_rootkit_module";
    if (cfg.check_kernel_modules && detect_suspicious_maps_paths()) return "suspicious_path_in_maps";
    return "";
}

} // namespace RootKitDetect

#endif
