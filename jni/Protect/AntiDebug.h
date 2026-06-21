#ifndef ANTI_DEBUG_H
#define ANTI_DEBUG_H

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <dirent.h>
#include <dlfcn.h>
#include <pthread.h>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "ProtectCommon.h"

namespace AntiDebug {

struct AntiDebugConfig {
    bool check_ptrace;
    bool check_frida;
    bool check_debugger;
    bool check_emulator;
    bool check_proc_files;
    bool check_thumb_threads;
    int  scan_interval_ms;
    int  max_violations;
};

struct AntiDebugConfig default_config() {
    struct AntiDebugConfig cfg = {};
    cfg.check_ptrace = true;
    cfg.check_frida = true;
    cfg.check_debugger = true;
    cfg.check_emulator = true;
    cfg.check_proc_files = true;
    cfg.check_thumb_threads = true;
    cfg.scan_interval_ms = 2000;
    cfg.max_violations = 3;
    return cfg;
}

static inline bool detect_ptrace() {
    char buf[256] = {0};
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) return true;  // 无法读取 status 视为异常
    while (fgets(buf, sizeof(buf), fp)) {
        if (strncmp(buf, "TracerPid:", 10) == 0) {  // 修复: 10 而非 11
            int tracer = atoi(buf + 10);
            fclose(fp);
            return tracer != 0;
        }
    }
    fclose(fp);
    return false;
}

// PTRACE_TRACEME 占坑：先自己 trace 自己，阻止外部附加
static inline bool occupy_ptrace() {
    return (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == 0);
}

// 通过 syscall 直接调用避免 libc ptrace hook
static inline bool detect_ptrace_syscall() {
    char buf[256] = {0};
    // 使用 syscall 直接 openat 而非 fopen，防止 fopen 被 hook
    int fd = (int)syscall(__NR_openat, AT_FDCWD, "/proc/self/status", O_RDONLY);
    if (fd < 0) return true;
    ssize_t n = syscall(__NR_read, fd, buf, sizeof(buf) - 1);
    syscall(__NR_close, fd);
    if (n <= 0) return true;
    buf[n] = '\0';
    const char *p = strstr(buf, "TracerPid:");
    if (!p) {
        // 继续读取直到找到
        fd = (int)syscall(__NR_openat, AT_FDCWD, "/proc/self/status", O_RDONLY);
        if (fd < 0) return true;
        char fullbuf[4096] = {0};
        ssize_t total = 0;
        while (total < (ssize_t)sizeof(fullbuf) - 1) {
            ssize_t r = syscall(__NR_read, fd, fullbuf + total, sizeof(fullbuf) - 1 - total);
            if (r <= 0) break;
            total += r;
        }
        syscall(__NR_close, fd);
        fullbuf[total] = '\0';
        p = strstr(fullbuf, "TracerPid:");
        if (!p) return false;
        int tracer = atoi(p + 10);
        return tracer != 0;
    }
    int tracer = atoi(p + 10);
    return tracer != 0;
}

static inline bool detect_frida_ports() {
    const short frida_ports[] = {27042, 27043, 27046, 27047};
    for (int i = 0; i < 4; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(frida_ports[i]);
        addr.sin_addr.s_addr = htonl(0x7F000001);
        int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        close(fd);
        if (ret == 0) return true;
    }
    return false;
}

static inline bool detect_frida_files() {
    const char *frida_markers[] = {
        "frida",
        "linjector",
        "agent.so",
        "re.frida.server",
    };
    char line[512] = {0};
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    while (fgets(line, sizeof(line), fp)) {
        for (int i = 0; i < 4; i++) {
            if (strstr(line, frida_markers[i])) {
                fclose(fp);
                return true;
            }
        }
    }
    fclose(fp);
    return false;
}

static inline bool detect_frida_threads() {
    DIR *dir = opendir("/proc/self/task");
    if (!dir) return false;
    char path[256] = {0};
    struct dirent *entry = NULL;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "/proc/self/task/%s/comm", entry->d_name);
        FILE *cfp = fopen(path, "r");
        if (!cfp) continue;
        char comm[256] = {0};
        if (fgets(comm, sizeof(comm), cfp)) {
            if (strstr(comm, "gum-js-loop") ||
                strstr(comm, "gum-backend") ||
                strstr(comm, "pool-frida")) {
                fclose(cfp);
                closedir(dir);
                return true;
            }
        }
        fclose(cfp);
    }
    closedir(dir);
    return false;
}

static inline bool detect_emulator() {
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[512] = {0};
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "Goldfish") ||
                strstr(line, "HWC composer") ||
                strstr(line, "ranchu") ||
                strstr(line, "emulator") ||
                strstr(line, "Qt coupled")) {
                fclose(fp);
                return true;
            }
        }
        fclose(fp);
    }
    return false;
}

static inline bool detect_ida_agent() {
    char line[512] = {0};
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "android_server") ||
            strstr(line, "linux_server") ||
            strstr(line, "idaq") ||
            strstr(line, "idaq64") ||
            strstr(line, "frida-server") ||
            strstr(line, "xposed")) {
            fclose(fp);
            return true;
        }
    }
    fclose(fp);
    return false;
}

static inline bool detect_xposed() {
    char line[512] = {0};
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "XposedBridge") ||
            strstr(line, "de.robv.android.xposed")) {
            fclose(fp);
            return true;
        }
    }
    fclose(fp);
    return false;
}

static inline bool check_all(const AntiDebugConfig &cfg) {
    if (cfg.check_ptrace && detect_ptrace()) return true;
    if (cfg.check_debugger && detect_ptrace()) return true;
    if (cfg.check_frida) {
        if (detect_frida_ports()) return true;
        if (detect_frida_files()) return true;
        if (detect_frida_threads()) return true;
    }
    if (cfg.check_emulator && detect_emulator()) return true;
    if (cfg.check_proc_files) {
        if (detect_ida_agent()) return true;
        if (detect_xposed()) return true;
    }
    return false;
}

} // namespace AntiDebug

#endif
