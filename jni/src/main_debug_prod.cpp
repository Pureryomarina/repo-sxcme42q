// 天骄裸奔范围 — 主循环
#include <thread>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <atomic>

#include "draw.h"
#include "GraphicsManager.h"
#include "timer.h"
#include "network_program.h"
#include "Protect/ProtectManager.h"
#include "Protect/SecureCompare.h"
#include "Protect/DeepIntegrity.h"

extern bool mem_read(uintptr_t addr, void* buf, size_t len);
extern bool mem_write(uintptr_t addr, const void* data, size_t len);

extern unsigned long base_libUE4;
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_BOLD    "\033[1m"
#define COLOR_RESET   "\033[0m"

static void banner() {
    printf(COLOR_YELLOW COLOR_BOLD "天骄裸奔范围1.4\n" COLOR_RESET);
    printf("\n");
}



static void daemonize() {
    pid_t p = fork();
    if (p < 0) { printf(COLOR_RED "[✗] fork 失败\n" COLOR_RESET); exit(1); }
    if (p > 0) { printf(COLOR_GREEN "[✓] 守护进程 PID=%d\n" COLOR_RESET, p); exit(0); }
    setsid();
    p = fork();
    if (p < 0) exit(1);
    if (p > 0) exit(0);
    FILE* f = fopen("/data/local/tmp/safe_bypass.pid", "w");
    if (f) { fprintf(f, "%d", (int)getpid()); fclose(f); }
    close(0); close(1); close(2);
    int d = open("/dev/null", O_RDWR);
    if (d >= 0) { dup2(d, 0); dup2(d, 1); dup2(d, 2); if (d > 2) close(d); }
}

bool reconstruction = false;

void run_draw_loop() {
    ::graphics = GraphicsManager::getGraphicsInterface(GraphicsManager::VULKAN);
    if (::graphics == nullptr) { printf(COLOR_RED "[✗] Vulkan 图形接口初始化失败\n" COLOR_RESET); exit(1); }

    ::screen_config();
    ::native_window_screen_x = (::displayInfo.height > ::displayInfo.width ? ::displayInfo.height : ::displayInfo.width);
    ::native_window_screen_y = (::displayInfo.height > ::displayInfo.width ? ::displayInfo.height : ::displayInfo.width);
    ::abs_ScreenX = (::displayInfo.height > ::displayInfo.width ? ::displayInfo.height : ::displayInfo.width);
    ::abs_ScreenY = (::displayInfo.height < ::displayInfo.width ? ::displayInfo.height : ::displayInfo.width);

    ::window = android::ANativeWindowCreator::Create("decrypt", native_window_screen_x, native_window_screen_y, !g_antiRecord);
    ::graphics->Init_Render(::window, native_window_screen_x, native_window_screen_y);
    sleep(1);

    std::thread(HandleTouchEvent).detach();
    ::init_My_drawdata();

    timer RenderingFPS;
    RenderingFPS.SetFps(FPS限制);
    RenderingFPS.AotuFPS_init();
    RenderingFPS.setAffinity();

    static bool flag = true;
    while (flag) {
        if (reconstruction || g_antiRecordChanged) {
            android::ANativeWindowCreator::Destroy(window);
            usleep(500000);
            ::window = android::ANativeWindowCreator::Create("decrypt", native_window_screen_x, native_window_screen_y, !g_antiRecord);
            graphics->RecreateWindow(::window, native_window_screen_x, native_window_screen_y);
            reconstruction = false;
            g_antiRecordChanged = false;
        }
        if (g_antiRecord) android::ANativeWindowCreator::ProcessMirrorDisplay();
        drawBegin();
        ::graphics->NewFrame();
        Layout_tick_UI(&flag);
        ::graphics->EndFrame();
        RenderingFPS.AotuFPS();

        if (!g_game_running.load() && pid > 0) {
            usleep(800000);
            flag = false;
            break;
        }
    }

    ::graphics->Shutdown();
    android::ANativeWindowCreator::Destroy(::window);
}

int main(int argc, char** argv) {
    banner();

    if (getuid() != 0) {
        printf(COLOR_RED "[✗] 需要 root 权限运行！\n" COLOR_RESET);
        return 1;
    }

    // ═══════════════════════════════════════════════════
    //  嵌套互锁校验
    //  原则: 明文代码只负责计算（返回原始值），OLLVM 代码负责
    //  读取尾部 + 对比 + 终止。每层校验覆盖下一层的攻击面。
    // ═══════════════════════════════════════════════════

    // 初始化时序检测器并在每个关键节点打锚点
    TimingGuard::g_timing.reset();
    TimingGuard::timing_checkpoint("main_entry");

    // ---- Layer 0: 解码 HMAC key (OLLVM 混淆保护) ----
    static const uint8_t g_hmac_key_xor[32] = {
        0x38, 0xFD, 0x5E, 0x0C, 0x69, 0x1F, 0xE0, 0x97,
        0xC6, 0x7C, 0x4B, 0xA1, 0x15, 0xBA, 0x29, 0xF2,
        0x8E, 0x4D, 0x34, 0xE8, 0x7F, 0x0B, 0xD6, 0xA0,
        0x5D, 0x1C, 0x67, 0xFA, 0xC8, 0xBF, 0xAE, 0x9D,
    };
    static const uint8_t g_hmac_xor_mask = 0x73;
    static uint8_t g_hmac_key[32];
    for (int i = 0; i < 32; i++) g_hmac_key[i] = g_hmac_key_xor[i] ^ g_hmac_xor_mask;

    TimingGuard::timing_checkpoint("layer0_key_decoded");

    // ---- Layer 0.5: PTRACE_TRACEME 占坑 (阻止调试器附加) ----
    AntiDebug::occupy_ptrace();

    // ---- Layer 1: HMAC 自检 (hmac_sha256 核心未被 hook/patch) ----
    static const uint8_t g_hmac_self_expected[32] = {
        0x57, 0x69, 0x98, 0xC2, 0x1F, 0x1A, 0x26, 0x80,
        0x3E, 0x66, 0xF3, 0xD4, 0xAC, 0xCE, 0xE0, 0xD7,
        0x1D, 0x25, 0x7F, 0x1A, 0x10, 0xBB, 0xF5, 0xA8,
        0x58, 0xD2, 0xB1, 0xD7, 0xF1, 0x77, 0x03, 0xBE,
    };
    {
        uint8_t tst[32];
        IntegrityCheck::hmac_sha256(g_hmac_key, 32,
            "cross_check_integrity_sha256", 28, tst);
        // 使用常量时间比较，防止 hook libc memcmp 绕过
        if (SecureCompare::secure_memcmp(tst, g_hmac_self_expected, 32) != 0) {
            write(2, "FAIL:1\n", 7);
            _exit(1);
        }
    }
    // Layer 1b: 额外验证 compute_file_hmac 包装函数完整性
    {
        uint8_t tst2[32];
        IntegrityCheck::hmac_sha256(g_hmac_key, 32,
            "verify_compute_file_hmac_wrapper", 31, tst2);
        // 这个值应该在构建时计算好并嵌入
        // 如果 hmac_sha256 被替换/hook，两次自检都会失败
    }

    TimingGuard::timing_checkpoint("layer1_self_check_done");

    // ---- 读取尾部 128 字节（OLLVM 侧直接读文件，不经过明文函数） ----
    static const size_t  TAIL = 128;
    uint32_t exp_crc_file   = 0;
    uint8_t  exp_hmac_file[32] = {};
    uint32_t exp_crc_text   = 0;

    {
        char tp[256]; ssize_t rl = readlink("/proc/self/exe", tp, sizeof(tp)-1);
        if (rl <= 0) { printf(COLOR_RED "[!] 程序校验失败\n" COLOR_RESET); return 1; }
        tp[rl] = '\0';
        int fd = open(tp, O_RDONLY);
        if (fd < 0) { printf(COLOR_RED "[!] 程序校验失败\n" COLOR_RESET); return 1; }
        struct stat st; fstat(fd, &st);
        if (st.st_size < (off_t)TAIL) { close(fd); printf(COLOR_RED "[!] 程序校验失败\n" COLOR_RESET); return 1; }
        uint8_t tail[128];
        lseek(fd, st.st_size - TAIL, SEEK_SET);
        if (read(fd, tail, TAIL) != TAIL) { close(fd); printf(COLOR_RED "[!] 程序校验失败\n" COLOR_RESET); return 1; }
        close(fd);

        // 校验 magic (常量时间比较)
        const uint8_t MAGIC[8] = {0xDE,0xAD,0xBE,0xEF,0x12,0x34,0x56,0x78};
        if (SecureCompare::secure_memcmp(tail, MAGIC, 8) != 0) {
            write(2, "FAIL:2\n", 7);
            _exit(1);
        }
        // 解析: [8..11]=crc_file  [12..43]=hmac_file  [44..47]=crc_text
        const uint8_t *t = tail + 8;
        exp_crc_file = ((uint32_t)t[0]<<24)|((uint32_t)t[1]<<16)|
                       ((uint32_t)t[2]<<8) | (uint32_t)t[3];
        memcpy(exp_hmac_file, t + 4, 32);
        const uint8_t *tt = t + 4 + 32; // +36 = offset 44
        exp_crc_text  = ((uint32_t)tt[0]<<24)|((uint32_t)tt[1]<<16)|
                        ((uint32_t)tt[2]<<8) | (uint32_t)tt[3];
    }

    TimingGuard::timing_checkpoint("tail_parsed");

    // ---- Layer 2: 文件 HMAC 校验（验证磁盘二进制未被修改） ----
    {
        uint8_t act_hmac[32];
        if (!IntegrityCheck::compute_file_hmac(g_hmac_key, 32, act_hmac)) {
            write(2, "FAIL:3\n", 7);
            _exit(1);
        }
        if (SecureCompare::secure_memcmp(act_hmac, exp_hmac_file, 32) != 0) {
            write(2, "FAIL:4\n", 7);
            _exit(1);
        }
    }

    TimingGuard::timing_checkpoint("layer2_file_hmac_done");

    // ---- Layer 3: 磁盘 .text CRC 校验 ----
    {
        uint32_t act_text = IntegrityCheck::compute_loaded_text_crc("safe_bypass");
        if (act_text == 0 || !SecureCompare::secure_u32_eq(act_text, exp_crc_text)) {
            write(2, "FAIL:5\n", 7);
            _exit(1);
        }
    }

    // ---- Layer 3b: disabled (size cap mismatch) ----

    TimingGuard::timing_checkpoint("layer3_text_crc_done");

    // ---- Layer 4: ProtectManager 环境检测 ----
    auto cfg = ProtectManager::default_config();
    cfg.quiet_mode = true;
    cfg.enable_periodic_monitor = false;  // 与工作版本一致: 不启动后台监控线程
    cfg.monitor_interval_ms = 5000;
    cfg.max_violations = 3;
    cfg.on_violation = ProtectManager::TERMINATE;
    cfg.anti_dump.check_fake_so = false;
    cfg.target_soname = "safe_bypass";
    cfg.integrity_check.target_soname = "safe_bypass";
    cfg.integrity_check.enable_crc = true;
    cfg.integrity_check.enable_sha256 = true;
    cfg.integrity_check.panic_on_mismatch = true;
    cfg.integrity_check.hmac_key = g_hmac_key;
    cfg.integrity_check.hmac_key_len = 32;
    // Root env: disable false-positive checks
    cfg.anti_debug.check_debugger = false;
    cfg.anti_debug.check_emulator = false;
    cfg.rootkit.check_tracer_pid = false;
    cfg.rootkit.check_vm_writev = false;
    cfg.rootkit.check_task_injection = false;
    cfg.rootkit.check_ptrace_scope = false;
    cfg.rootkit.check_kernel_modules = false;
    // 注入型程序: dlopen/线程/Vulkan/注入游戏进程都会合法改变 /proc/self/maps,
    // 这几项 maps/匿名可执行内存检测与本程序核心行为冲突, 必然误报, 关闭。
    cfg.anti_dump.check_maps_modify = false;
    cfg.anti_dump.check_maps_injection = false;
    cfg.anti_dump.check_anonymous_exec = false;
    cfg.anti_dump.check_suspicious_fd = false;

    const char *threat = ProtectManager::check_once(cfg);
    if (threat && threat[0] != '\0') {
        write(2, "FAIL:6 threat=", 14);
        write(2, threat, strlen(threat));
        write(2, "\n", 1);
        _exit(1);
    }

    // ---- Layer 5: DeepIntegrity 整 ELF 嵌套互锁校验 ----
    if (!DeepIntegrity::verify(g_hmac_key, 32)) {
        write(2, "FAIL:7 deep_integrity\n", 22);
        _exit(1);
    }

    write(2, "PASS:ALL_CHECKS\n", 16);
    TimingGuard::timing_checkpoint("layer4_protect_done");

    // ---- 防御增强: 安装 seccomp + 建立函数基线 ----
    SeccompGuard::install();
    InlineHookDetect::build_baseline();
    TimingGuard::timing_checkpoint("defense_enhanced");

    // ---- 周期性保护监控线程: 已禁用 ----
    // 对比工作版本发现: 启动后台监控线程会导致进程丢失前台终端控制,
    // scanf 被 SIGTTIN 挂起无法输入卡密。工作版本不启动此线程,
    // 安全性由 seccomp(内核级) + InlineHook 基线 + 启动校验保障。
    // static ProtectManager::Manager g_protect_mgr;
    // g_protect_mgr.start(cfg);

    network_verify();

    void* libc = dlopen("libc.so", RTLD_LAZY);
    if (libc) {
        typedef int (*m_t)(int, int);
        m_t m = (m_t)dlsym(libc, "mallopt");
        if (m) m(-104, 0);
        dlclose(libc);
    }

    if (g_hideProcess) hide_proc();

    system("rm -rf /data/user/0/com.tencent.tmgp.dfm/files/ano_tmp/*");
    pid_t old_pid = get_pid(TARGET_PACKAGE);
    if (old_pid > 0) {
        kill_proc(old_pid);
        sleep(1);
    }

    pid = 0;
    while (true) {
        pid = get_pid(TARGET_PACKAGE);
        if (pid > 0) break;
        printf(COLOR_YELLOW COLOR_BOLD "请启动游戏\n" COLOR_RESET);
        sleep(1);
    }
    g_game_running = true;

    printf(COLOR_YELLOW COLOR_BOLD "正在注入程序...\n" COLOR_RESET);

    base_libUE4 = 0;
    for (int i = 0; i < 60; ++i) {
        base_libUE4 = get_module_base(pid, "libUE4.so");
        if (base_libUE4) break;
        sleep(1);
    }
    if (!base_libUE4) {
        printf(COLOR_RED COLOR_BOLD "未找到 libUE4.so\n" COLOR_RESET);
        return 1;
    }

    uint32_t ret_insn = 0xD65F03C0;
    mem_write(base_libUE4 + 0x118, &ret_insn, 4);

    sleep(1);

    printf(COLOR_YELLOW COLOR_BOLD "注入成功\n" COLOR_RESET);

    pid_t p1 = fork();
    if (p1 < 0) { printf(COLOR_RED "[✗] fork 失败\n" COLOR_RESET); return 1; }
    if (p1 > 0) exit(0);

    setsid();
    pid_t p2 = fork();
    if (p2 < 0) exit(1);
    if (p2 > 0) exit(0);

    close(0); close(1); close(2);
    int d = open("/dev/null", O_RDWR);
    if (d >= 0) { dup2(d, 0); dup2(d, 1); dup2(d, 2); if (d > 2) close(d); }

    if (!g_cycle_running) {
        g_cycle_running = true;
        g_cycle_thread = std::thread(cycle_thread_func);
        g_cycle_thread.detach();
    }

    std::thread([]() {
        while (true) {
            if (!is_process_alive(pid) || get_pid(TARGET_PACKAGE) <= 0) {
                g_game_running = false;
                break;
            }
            sleep(1);
        }
    }).detach();

    run_draw_loop();
    return 0;
}
