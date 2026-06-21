#ifndef SECCOMP_GUARD_H
#define SECCOMP_GUARD_H

// seccomp BPF + 时序检测 — 内核级 syscall 阻断
// 原理: 在进程启动早期安装 BPF 过滤器, 内核拒绝危险 syscall
// 攻击者无法在用户态绕过 (即使 hook libc 也没用)

#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include "ProtectCommon.h"

#ifndef PR_SET_SECCOMP
#define PR_SET_SECCOMP 22
#endif
#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2
#endif
#ifndef SECCOMP_RET_KILL
#define SECCOMP_RET_KILL 0x00000000U
#endif
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW 0x7FFF0000U
#endif
#ifndef __NR_seccomp
#define __NR_seccomp 277
#endif

// ARM64 syscall numbers (may not be defined on all NDK versions)
#ifndef __NR_process_vm_readv
#define __NR_process_vm_readv 270
#endif
#ifndef __NR_process_vm_writev
#define __NR_process_vm_writev 271
#endif
#ifndef __NR_memfd_create
#define __NR_memfd_create 279
#endif
#ifndef __NR_userfaultfd
#define __NR_userfaultfd 282
#endif
#ifndef __NR_perf_event_open
#define __NR_perf_event_open 241
#endif

namespace SeccompGuard {

static volatile bool g_seccomp_active = false;

// BPF 指令编码 — 使用标准的 sock_filter 兼容结构
// code=opcode, jt/jf=jump offsets, k=constant
struct bpf_insn {
    uint16_t code;
    uint8_t  jt;
    uint8_t  jf;
    uint32_t k;
};

// 注意: seccomp 只过滤本进程自己的 syscall，不能阻止外部进程的 ptrace/vm_readv。
// 它的真正作用：(1) 防止本进程被注入的恶意代码利用这些 syscall，
// (2) 防止 fork 出的子进程 escalation。
// 真正的 anti-debug 由 PTRACE_TRACEME + 周期检测 TracerPid 完成。
static inline bool install() {
    if (g_seccomp_active) return true;

    // 必须设置 NO_NEW_PRIVS 才能在非 root 下安装 seccomp filter
    // 以 root 运行时也建议设置，增强安全性
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    // BPF 指令: 先验证 arch 是 ARM64 (0xC00000B7)
    // 格式: {opcode, jt, jf, constant}
    // 0x20=LD_W_ABS, 0x15=JMP_JEQ_K, 0x06=RET_K
    struct bpf_insn filter[] = {
        // Load architecture from seccomp_data.arch (offset 4)
        {0x20, 0, 0, 4},
        // Verify arch == AUDIT_ARCH_AARCH64 (0xC00000B7), otherwise KILL
        // (防止 32 位 compat syscall 绕过)
        {0x15, 1, 0, 0xC00000B7},
        {0x06, 0, 0, SECCOMP_RET_KILL},

        // Load syscall number from seccomp_data.nr (offset 0)
        {0x20, 0, 0, 0},

        // ptrace(117) -> KILL
        {0x15, 0, 1, 117},
        {0x06, 0, 0, SECCOMP_RET_KILL},

        // process_vm_readv(270) -> KILL
        {0x15, 0, 1, 270},
        {0x06, 0, 0, SECCOMP_RET_KILL},

        // process_vm_writev(271) -> KILL
        {0x15, 0, 1, 271},
        {0x06, 0, 0, SECCOMP_RET_KILL},

        // memfd_create(279) -> KILL
        {0x15, 0, 1, 279},
        {0x06, 0, 0, SECCOMP_RET_KILL},

        // userfaultfd(282) -> KILL
        {0x15, 0, 1, 282},
        {0x06, 0, 0, SECCOMP_RET_KILL},

        // perf_event_open(241) -> KILL
        {0x15, 0, 1, 241},
        {0x06, 0, 0, SECCOMP_RET_KILL},

        // Allow all other syscalls
        {0x06, 0, 0, SECCOMP_RET_ALLOW},
    };

    struct {
        uint16_t len;
        struct bpf_insn *filter;
    } prog = {
        .len    = (uint16_t)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    int ret = (int)syscall(__NR_seccomp, SECCOMP_MODE_FILTER, 0, &prog);
    if (ret != 0) {
        return false;
    }

    g_seccomp_active = true;
    return true;
}

static inline bool is_active() { return g_seccomp_active; }

} // namespace SeccompGuard


// ═══════════════════════════════════════════════════════════
// 时序检测器 — 检测调试器单步/hook 导致的异常延迟
// ═══════════════════════════════════════════════════════════
namespace TimingGuard {

struct TimingDetector {
    uint64_t last_ns;
    const char *last_checkpoint;
    int anomaly_count;
    bool detected;
    int checkpoint_count;  // 追踪 checkpoint 调用次数

    void reset() {
        last_ns = 0;
        last_checkpoint = nullptr;
        anomaly_count = 0;
        detected = false;
        checkpoint_count = 0;
    }

    // 在关键函数入口/出口调用 — 需要在多处调用才有意义
    void checkpoint(const char *name) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t now = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
        checkpoint_count++;

        if (last_ns == 0) {
            last_ns = now;
            last_checkpoint = name;
            return;
        }

        uint64_t delta = now - last_ns;

        // 超过 3s → 可疑。启动阶段需多次读取/HMAC 整个 16MB 文件，
        // 单层就可能耗时数百 ms，阈值过低必然误报；而真正的单步调试/
        // 断点暂停是人为操作，间隔在秒级以上，3s 阈值仍能可靠捕获。
        if (delta > 3000000000ULL) {
            anomaly_count++;
            if (anomaly_count >= 2) {
                detected = true;
            }
        }

        last_ns = now;
        last_checkpoint = name;
    }

    bool is_anomaly() const { return detected; }
    int get_count() const { return anomaly_count; }
};

// 全局实例
static TimingDetector g_timing;

static inline void timing_checkpoint(const char *name) {
    g_timing.checkpoint(name);
}

static inline bool detect_timing_anomaly() {
    return g_timing.is_anomaly();
}

} // namespace TimingGuard

#endif // SECCOMP_GUARD_H
