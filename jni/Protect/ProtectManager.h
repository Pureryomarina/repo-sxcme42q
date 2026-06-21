#ifndef PROTECT_MANAGER_H
#define PROTECT_MANAGER_H

#include "AntiDebug.h"
#include "AntiHook.h"
#include "AntiDump.h"
#include "IntegrityCheck.h"
#include "RootKitDetect.h"
#include "SeccompGuard.h"
#include "InlineHookDetect.h"
#include <pthread.h>
#include <unistd.h>
#include <atomic>
#include <functional>

namespace ProtectManager {

enum ViolationAction {
    LOG_ONLY = 0,
    TERMINATE = 1,
    OBFUSCATE = 2,
    CUSTOM = 3,
};

struct OnViolation {
    ViolationAction action;
    std::function<void(const char*)> custom_callback;
};

struct ProtectConfig {
    AntiDebug::AntiDebugConfig anti_debug;
    AntiHook::AntiHookConfig anti_hook;
    AntiDump::AntiDumpConfig anti_dump;
    IntegrityCheck::IntegrityCheckConfig integrity_check;
    RootKitDetect::RootKitConfig rootkit;
    ViolationAction on_violation;
    bool enable_periodic_monitor;
    int monitor_interval_ms;
    int max_violations;
    bool quiet_mode;
    const char *target_soname;
    bool check_maps_modify;
    bool check_suspicious_so;
};

inline struct ProtectConfig default_config() {
    struct ProtectConfig cfg = {};
    cfg.anti_debug = AntiDebug::default_config();
    cfg.anti_hook = AntiHook::default_config();
    cfg.anti_dump = AntiDump::default_config();
    cfg.integrity_check = IntegrityCheck::default_config();
    cfg.rootkit = RootKitDetect::default_config();
    cfg.on_violation = TERMINATE;
    cfg.enable_periodic_monitor = true;
    cfg.monitor_interval_ms = 2000;
    cfg.max_violations = 3;
    cfg.quiet_mode = false;
    cfg.target_soname = nullptr;
    cfg.check_maps_modify = false;
    cfg.check_suspicious_so = false;
    return cfg;
}

inline const char* check_once(const ProtectConfig &cfg) {
    // Anti-Debug: 双重检测 (libc + syscall 直调)
    if (cfg.anti_debug.check_debugger) {
        if (AntiDebug::detect_ptrace()) return "ptrace_attached";
        if (AntiDebug::detect_ptrace_syscall()) return "ptrace_syscall_detected";
    }
    if (cfg.anti_debug.check_frida) {
        if (AntiDebug::detect_frida_ports()) return "frida_port";
        if (AntiDebug::detect_frida_files()) return "frida_file";
        if (AntiDebug::detect_frida_threads()) return "frida_thread";
    }
    if (cfg.anti_debug.check_emulator && AntiDebug::detect_emulator()) return "emulator";
    if (cfg.anti_debug.check_proc_files) {
        if (AntiDebug::detect_ida_agent()) return "ida_agent";
        if (AntiDebug::detect_xposed()) return "xposed";
    }

    // RootKit: TracerPid + vm_writev + task injection (之前未接入)
    if (cfg.rootkit.check_tracer_pid && RootKitDetect::detect_tracer_pid()) return "rootkit_tracer";
    if (cfg.rootkit.check_vm_writev && RootKitDetect::detect_vm_writev_available()) return "rootkit_vm_writev";
    if (cfg.rootkit.check_task_injection && RootKitDetect::detect_task_directory_injection()) return "rootkit_task_injection";

    if (AntiHook::detect_ld_preload_env()) return "ld_preload_env";
    if (cfg.anti_hook.check_suspicious_so && AntiHook::detect_suspicious_injected_so()) return "suspicious_so_injection";

    if (cfg.anti_hook.check_got) {
        if (AntiHook::check_dlopen_hook()) return "dlopen_hooked";
        if (AntiHook::check_dlsym_hook()) return "dlsym_hooked";
        if (AntiHook::check_pthread_create_hook()) return "pthread_create_hooked";
    }

    if (cfg.anti_hook.check_plt_hooks) {
        if (AntiHook::check_read_hook()) return "read_plt_hooked";
        if (AntiHook::check_fgets_hook()) return "fgets_plt_hooked";
        if (AntiHook::check_write_hook()) return "write_plt_hooked";
        if (AntiHook::check_open_hook()) return "open_plt_hooked";
        if (AntiHook::check_fopen_hook()) return "fopen_plt_hooked";
        if (AntiHook::check_mprotect_hook()) return "mprotect_plt_hooked";
        if (AntiHook::check_clone_hook()) return "clone_plt_hooked";
        if (AntiHook::check_fork_hook()) return "fork_plt_hooked";
    }

    if (cfg.anti_hook.check_shadowpage && AntiHook::detect_shadowpage_memfd()) return "shadowpage_detected";
    if (cfg.anti_hook.check_rwxp_pages && AntiHook::detect_memory_page_rwxp()) return "rwxp_page_detected";

    if (cfg.anti_dump.check_maps_modify && AntiDump::detect_maps_modify()) return "maps_crc_changed";
    if (cfg.anti_dump.check_maps_injection && AntiDump::detect_maps_injection()) return "maps_so_injection";

    if (cfg.anti_dump.prevent_ptrace_dump) {
        if (AntiDump::detect_mem_file_open()) return "mem_file_open";
    }

    if (cfg.anti_dump.check_fake_so && cfg.target_soname) {
        if (!AntiDump::check_so_integrity(cfg.target_soname)) return "so_tampered";
    }
    if (cfg.anti_dump.check_anonymous_exec && AntiDump::detect_anonymous_exec()) return "anonymous_exec_mem";
    if (cfg.anti_dump.check_suspicious_fd && AntiDump::detect_suspicious_fd()) return "suspicious_fd";

    if (cfg.target_soname) {
        auto res = IntegrityCheck::verify(cfg.integrity_check, cfg.target_soname);
        if (!res.crc_ok) return "text_crc_mismatch";
        if (!res.sha256_ok) return "text_sha256_mismatch";

        // 内存级 .text CRC 检测（检测运行时 patch/hook）
        uint32_t mem_crc = IntegrityCheck::calc_text_crc(cfg.target_soname);
        if (mem_crc != 0 && res.actual_crc != 0 && mem_crc != res.actual_crc) {
            return "memory_text_patched";
        }
    }

    if (cfg.rootkit.check_code_section_perms && RootKitDetect::detect_code_section_writable()) return "code_section_writable";
    if (cfg.rootkit.check_kernel_modules && RootKitDetect::detect_kernel_module_strings()) return "kernel_rootkit";
    if (cfg.rootkit.check_kernel_modules && RootKitDetect::detect_suspicious_maps_paths()) return "suspicious_maps_path";

    // 7. Inline Hook 指令检测 + 函数基线 CRC
    {
        const char *r = InlineHookDetect::detect();
        if (r) return r;
    }

    // 8. 时序异常检测
    if (TimingGuard::detect_timing_anomaly()) return "timing_anomaly";

    return "";
}

inline void handle_violation(const ProtectConfig &cfg, const char *detection_name, int *violation_count) {
    if (!cfg.quiet_mode) {
        ALOGE("[Protect] 检测到威胁: %s", detection_name);
    }
    if (*violation_count >= cfg.max_violations) {
        if (cfg.on_violation == TERMINATE) {
            _exit(0);
        }
    }
    (*violation_count)++;
}

struct MonitorContext {
    ProtectConfig config;
    std::atomic<bool> running;
    pthread_t thread;
    int violation_count;
};

inline void* monitor_thread_func(void *arg) {
    struct MonitorContext *ctx = static_cast<struct MonitorContext*>(arg);
    ctx->running = true;
    ctx->violation_count = 0;
    while (ctx->running.load()) {
        const char *threat = check_once(ctx->config);
        if (threat && threat[0] != '\0') {
            handle_violation(ctx->config, threat, &ctx->violation_count);
        }
        usleep(ctx->config.monitor_interval_ms * 1000);
    }
    return nullptr;
}

struct Manager {
    struct MonitorContext *ctx;
    bool started;
    Manager() : ctx(nullptr), started(false) {}

    void start(const ProtectConfig &cfg) {
        if (started) return;
        ctx = new MonitorContext();
        ctx->config = cfg;
        ctx->violation_count = 0;
        const char *threat = check_once(cfg);
        if (threat && threat[0] != '\0') {
            handle_violation(const_cast<ProtectConfig&>(cfg), threat, &ctx->violation_count);
        }
        if (cfg.enable_periodic_monitor) {
            ctx->running = false;
            pthread_create(&ctx->thread, nullptr, monitor_thread_func, ctx);
        }
        started = true;
    }

    const char* detect() {
        return check_once(ctx ? ctx->config : default_config());
    }

    void stop() {
        if (!started || !ctx) return;
        ctx->running = false;
        pthread_join(ctx->thread, nullptr);
        started = false;
    }

    ~Manager() {
        if (started) stop();
        if (ctx) delete ctx;
    }
};

} // namespace ProtectManager

#endif
