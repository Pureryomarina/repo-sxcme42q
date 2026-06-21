#include <chrono>
#include <cmath>
#include <thread>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <signal.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <sys/wait.h>
#include <random>

#include "Font.h"
#include "draw.h"
#include "inject_bin.h"
#include "libsjz_bin.h"
#include "libzrf.h"

// ========== 全局变量定义 (extern in draw.h) ==========
std::unique_ptr<AndroidImgui> graphics;
ANativeWindow* window = nullptr;
android::ANativeWindowCreator::DisplayInfo displayInfo;
float abs_ScreenX = 0.0f, abs_ScreenY = 0.0f;
int native_window_screen_x = 0, native_window_screen_y = 0;
int FPS限制 = 120;
bool Getth = false;
bool permeate_record = false;
pid_t pid = 0;

// ========== 防录屏/隐藏进程全局标志 ==========
bool g_antiRecord = false;
bool g_antiRecordChanged = false;
bool g_hideProcess = true;

// ========== 工具函数 ==========
std::string random_str(int length) {
    static const char chars[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::string s; s.reserve(length);
    std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<> dist(0, sizeof(chars) - 2);
    for (int i = 0; i < length; ++i) s += chars[dist(gen)];
    return s;
}

unsigned long base_libUE4 = 0;

std::atomic<bool> g_feature_head{false};
std::atomic<bool> g_feature_body{false};
std::atomic<bool> g_feature_leg{false};
std::atomic<bool> g_feature_thirdperson{false};

std::atomic<float> g_head_val{50.0f};
std::atomic<float> g_body_val{80.0f};
std::atomic<float> g_leg_val{99.0f};

std::atomic<bool> g_cycle_running{false};
std::thread g_cycle_thread;

std::atomic<bool> g_game_ready{false};
std::atomic<bool> g_game_running{false};

static char g_logBuf[4096] = "";

void log_add(const char* fmt, ...) {
    char t[1024]; va_list a; va_start(a, fmt); vsnprintf(t, 1024, fmt, a); va_end(a);
    size_t c = strlen(g_logBuf), r = sizeof(g_logBuf) - c - 1;
    if (r > 0) snprintf(g_logBuf + c, r, "%s\n", t);
}

bool run_cmd(const std::string& cmd) {
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return false;
    char buf[512];
    while (fgets(buf, sizeof(buf), pipe)) {}
    int ret = pclose(pipe);
    return WIFEXITED(ret) && WEXITSTATUS(ret) == 0;
}

bool is_process_alive(pid_t _pid) {
    if (_pid <= 0) return false;
    return (kill(_pid, 0) == 0);
}

pid_t get_pid(const char* pkg) {
    DIR* dir = opendir("/proc");
    if (!dir) return -1;
    struct dirent* e;
    pid_t _pid = -1;
    while ((e = readdir(dir))) {
        if (e->d_type != DT_DIR) continue;
        pid_t id = atoi(e->d_name);
        if (id == 0) continue;
        char path[64], cmd[256];
        snprintf(path, sizeof(path), "/proc/%d/cmdline", id);
        FILE* fp = fopen(path, "r");
        if (fp) {
            if (fgets(cmd, sizeof(cmd), fp) && strcmp(cmd, pkg) == 0) {
                _pid = id; fclose(fp); break;
            }
            fclose(fp);
        }
    }
    closedir(dir);
    return _pid;
}

uintptr_t get_module_base(pid_t _pid, const char* mod) {
    char path[64], line[512];
    snprintf(path, sizeof(path), "/proc/%d/maps", _pid);
    FILE* fp = fopen(path, "r");
    if (!fp) return 0;
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, mod)) { base = strtoul(line, nullptr, 16); break; }
    }
    fclose(fp);
    return base;
}

bool mem_read(uintptr_t addr, void* buf, size_t len) {
    if (!is_process_alive(pid)) return false;
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    int fd = open(mem_path, O_RDONLY);
    if (fd < 0) return false;
    bool ok = (lseek(fd, addr, SEEK_SET) != (off_t)-1) && (read(fd, buf, len) == (ssize_t)len);
    close(fd);
    return ok;
}

bool mem_write(uintptr_t addr, const void* data, size_t len) {
    if (!is_process_alive(pid)) return false;
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    int fd = open(mem_path, O_RDWR);
    if (fd < 0) return false;
    bool ok = (lseek(fd, addr, SEEK_SET) != (off_t)-1) && (write(fd, data, len) == (ssize_t)len);
    close(fd);
    return ok;
}

void kill_proc(pid_t _pid) { if (_pid > 0) kill(_pid, SIGKILL); }

// ========== 注入函数 ==========
bool 执行注入() {
    std::string baseDir = "/data/local/tmp/";
    std::string randDir = random_str(10);
    std::string tmpDir = baseDir + randDir + "/";
    run_cmd("rm -rf " + tmpDir);
    if (mkdir(tmpDir.c_str(), 0755) != 0) return false;

    std::string injName = random_str(8);
    std::string soName  = random_str(8);
    std::string injPath = tmpDir + injName;
    std::string soPath  = tmpDir + soName;

    std::ofstream f_inj(injPath, std::ios::binary);
    if (!f_inj) { run_cmd("rm -rf " + tmpDir); return false; }
    f_inj.write(reinterpret_cast<const char*>(inject), inject_len);
    f_inj.close();

    std::ofstream f_so(soPath, std::ios::binary);
    if (!f_so) { run_cmd("rm -rf " + tmpDir); return false; }
    f_so.write(reinterpret_cast<const char*>(libsjz_so), libsjz_so_len);
    f_so.close();

    chmod(injPath.c_str(), 0755);
    chmod(soPath.c_str(), 0644);

    std::string cmd = injPath + " -n " + TARGET_PACKAGE + " -so " + soPath;
    int ret = system(cmd.c_str());
    usleep(500000);
    run_cmd("rm -rf " + tmpDir);
    return (ret == 0);
}

bool 注入libzrf() {
    std::string baseDir = "/data/data/com.tencent.tmgp.dfm/";
    std::string randDir = random_str(10);
    std::string tmpDir = baseDir + randDir + "/";
    run_cmd("rm -rf " + tmpDir);
    if (mkdir(tmpDir.c_str(), 0755) != 0) return false;

    std::string injName = random_str(8);
    std::string soName  = random_str(8);
    std::string injPath = tmpDir + injName;
    std::string soPath  = tmpDir + soName;

    std::ofstream f_inj(injPath, std::ios::binary);
    if (!f_inj) { run_cmd("rm -rf " + tmpDir); return false; }
    f_inj.write(reinterpret_cast<const char*>(inject), inject_len);
    f_inj.close();

    std::ofstream f_so(soPath, std::ios::binary);
    if (!f_so) { run_cmd("rm -rf " + tmpDir); return false; }
    f_so.write(reinterpret_cast<const char*>(libzrf_so), libzrf_so_len);
    f_so.close();

    chmod(injPath.c_str(), 0755);
    chmod(soPath.c_str(), 0644);

    std::string cmd = injPath + " -n " + TARGET_PACKAGE + " -so " + soPath;
    int ret = system(cmd.c_str());
    usleep(500000);
    run_cmd("rm -rf " + tmpDir);
    return (ret == 0);
}

// ========== 注入按钮函数 ==========
static bool 注入libzrf_按钮() {
    if (注入libzrf()) {
        log_add("[√] libzrf 注入成功");
        g_game_ready = true;
        if (!g_cycle_running) {
            g_cycle_running = true;
            g_cycle_thread = std::thread(cycle_thread_func);
            g_cycle_thread.detach();
        }
        return true;
    }
    log_add("[-] libzrf 注入失败");
    return false;
}

// ========== 循环写入线程 ==========
void cycle_thread_func() {
    static int cycle_check_counter = 0;
    while (g_cycle_running) {
        if (!is_process_alive(pid)) {
            g_game_running = false;
            g_game_ready = false;
            g_cycle_running = false;
            break;
        }
        g_game_running = true;

        // 每 50 次循环做一次快速反调试检测（防止晚附加）
        if (++cycle_check_counter >= 50) {
            cycle_check_counter = 0;
            // 直接 syscall 检查 TracerPid，不经过 libc
            char status_buf[512] = {0};
            int sfd = (int)syscall(__NR_openat, AT_FDCWD, "/proc/self/status", O_RDONLY);
            if (sfd >= 0) {
                syscall(__NR_read, sfd, status_buf, sizeof(status_buf) - 1);
                syscall(__NR_close, sfd);
                const char *tp = strstr(status_buf, "TracerPid:");
                if (tp && atoi(tp + 10) != 0) _exit(0);
            }
        }

        if (g_feature_head && base_libUE4) {
            uintptr_t addr = 0;
            if (mem_read(base_libUE4 + 0x1B2CC688, &addr, 8) && addr &&
                mem_read(addr + 0x8, &addr, 8) && addr &&
                mem_read(addr + 0x250, &addr, 8) && addr &&
                mem_read(addr + 0x40, &addr, 8) && addr &&
                mem_read(addr + 0x90, &addr, 8) && addr &&
                mem_read(addr + 0x48, &addr, 8) && addr) {
                addr += 0x48;
                float cur = 0; mem_read(addr, &cur, 4);
                float target = g_head_val.load();
                if (cur != target) mem_write(addr, &target, 4);
            }
        }

        if (g_feature_body && base_libUE4) {
            uintptr_t addr = 0;
            if (mem_read(base_libUE4 + 0x1B2CC688, &addr, 8) && addr &&
                mem_read(addr + 0x8, &addr, 8) && addr &&
                mem_read(addr + 0x250, &addr, 8) && addr &&
                mem_read(addr + 0x40, &addr, 8) && addr &&
                mem_read(addr + 0x0, &addr, 8) && addr &&
                mem_read(addr + 0x48, &addr, 8) && addr) {
                addr += 0x48;
                float cur = 0; mem_read(addr, &cur, 4);
                float target = g_body_val.load();
                if (cur != target) mem_write(addr, &target, 4);
            }
        }

        if (g_feature_leg && base_libUE4) {
            uintptr_t addr = 0;
            if (mem_read(base_libUE4 + 0x1B2CC688, &addr, 8) && addr &&
                mem_read(addr + 0x8, &addr, 8) && addr &&
                mem_read(addr + 0x250, &addr, 8) && addr &&
                mem_read(addr + 0x40, &addr, 8) && addr &&
                mem_read(addr + 0x18, &addr, 8) && addr &&
                mem_read(addr + 0x48, &addr, 8) && addr) {
                addr += 0x48;
                float cur = 0; mem_read(addr, &cur, 4);
                float target = g_leg_val.load();
                if (cur != 0 && cur != target) mem_write(addr, &target, 4);
            }
        }

        if (g_feature_thirdperson && base_libUE4) {
            uint32_t val = 1384120352;
            mem_write(base_libUE4 + 0x9443F34, &val, 4);
        }
        usleep(30000);
    }
}

bool 大厅开启初始化() {
    注入libzrf_按钮();
    return true;
}

// ========== 注入全局内透 ==========
static void inject_sjz() {
    if (getuid() != 0) { log_add("[-] need root"); return; }
    pid_t running = get_pid(TARGET_PACKAGE);
    if (running <= 0) { log_add("[-] 游戏未运行，请先启动游戏"); return; }
    log_add("[+] 目标 PID: %d", (int)running);
    if (执行注入()) log_add("[√] 全局内透注入完成");
    else log_add("[-] 全局内透注入失败");
}

// ========== 隐藏进程 ==========
void hide_proc() {
    std::thread([]() {
        run_cmd("mkdir -p /data/local/tmp/empty");
        char c[256];
        snprintf(c, 256, "mount --bind /data/local/tmp/empty /proc/%d 2>/dev/null", (int)getpid());
        run_cmd(c);
    }).detach();
}

// ========== UI ==========
static void SetupCustomStyle() {
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding = s.FrameRounding = s.ScrollbarRounding = s.GrabRounding = 0;
    s.WindowPadding = ImVec2(16, 16); s.FramePadding = ImVec2(10, 8);
    s.ItemSpacing = ImVec2(12, 12); s.ItemInnerSpacing = ImVec2(8, 4);
    ImVec4* c = s.Colors;
    c[ImGuiCol_WindowBg] = ImVec4(.05, .05, .05, .95);
    c[ImGuiCol_ChildBg] = ImVec4(.08, .08, .08, .85);
    c[ImGuiCol_TitleBg] = ImVec4(.1, .1, .1, .9);
    c[ImGuiCol_TitleBgActive] = ImVec4(.12, .12, .12, .95);
    c[ImGuiCol_FrameBg] = ImVec4(.12, .12, .12, .6);
    c[ImGuiCol_FrameBgHovered] = ImVec4(.18, .18, .18, .7);
    c[ImGuiCol_FrameBgActive] = ImVec4(.22, .22, .22, .8);
    c[ImGuiCol_Button] = ImVec4(.15, .15, .15, .7);
    c[ImGuiCol_ButtonHovered] = ImVec4(.25, .25, .25, .8);
    c[ImGuiCol_ButtonActive] = ImVec4(.35, .35, .35, .9);
    c[ImGuiCol_Text] = ImVec4(.85, .85, .85, .95);
    c[ImGuiCol_Border] = ImVec4(.2, .2, .2, .5);
    c[ImGuiCol_Header] = ImVec4(.15, .15, .15, .7);
    c[ImGuiCol_HeaderHovered] = ImVec4(.22, .22, .22, .8);
    c[ImGuiCol_HeaderActive] = ImVec4(.3, .3, .3, .9);
    c[ImGuiCol_CheckMark] = ImVec4(1, 1, 1, .9);
}

void init_My_drawdata() {
    SetupCustomStyle();
    ImGuiIO& io = ImGui::GetIO();
    ImFontConfig cfg; cfg.SizePixels = 26;
    ImFont* f = io.Fonts->AddFontFromMemoryTTF((void*)OPPOSans_H, OPPOSans_H_size, 26, &cfg, io.Fonts->GetGlyphRangesChineseFull());
    if (f) io.FontDefault = f;
    io.Fonts->Build();
}

void screen_config() {
    ::displayInfo = android::ANativeWindowCreator::GetDisplayInfo();
}

void drawBegin() { screen_config(); }

void Layout_tick_UI(bool* flag) {
    bool moduleReady = (base_libUE4 != 0);
    bool gameRunning = g_game_running.load();

    ImGui::SetNextWindowSize(ImVec2(420, 520), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(ImVec2(20, 60), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("天骄", flag, 0)) { ImGui::End(); return; }

    ImGui::TextColored(ImVec4(.4, 1, .4, 1), "天骄裸奔范围");
    ImGui::SameLine(250);
    ImGui::Text("PID: %d", (int)pid);
    ImGui::Separator();

    // === 设置 ===
    if (ImGui::CollapsingHeader("设置", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (ImGui::Checkbox("关闭防录屏", &g_antiRecord)) {
            g_antiRecordChanged = true;
        }
        if (ImGui::Checkbox("隐藏本进程", &g_hideProcess)) {
            if (g_hideProcess) hide_proc();
        }
    }
    ImGui::Separator();

    // === 注入按钮 ===
    if (!g_game_ready) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(.1, .35, .15, .85));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(.15, .45, .2, .9));
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, 1));
        if (ImGui::Button("大厅开启初始化", ImVec2(-1, 50))) {
            std::thread([]() { 大厅开启初始化(); }).detach();
        }
        ImGui::PopStyleColor(3);
    } else {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(.1, .45, .1, .85));
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(.5, 1, .5, 1));
        if (ImGui::Button("大厅运行中", ImVec2(-1, 50))) {
            std::thread([]() { 大厅开启初始化(); }).detach();
        }
        ImGui::PopStyleColor(2);
    }

    // === 全局内透 ===
    if (g_game_ready) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(.1, .15, .45, .85));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(.15, .2, .55, .9));
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1, 1, 1, 1));
        if (ImGui::Button("注入全局内透",ImVec2(-1, 50))) {
            std::thread([]() { inject_sjz(); }).detach();
        }
        ImGui::PopStyleColor(3);
    }

    // === 命中范围调整 ===
    if (g_game_ready && ImGui::CollapsingHeader("命中范围调整", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::BeginDisabled(!moduleReady);

        bool h = g_feature_head.load();
        if (ImGui::Checkbox("头部范围", &h)) g_feature_head.store(h);
        if (h) {
            ImGui::SameLine();
            int v = (int)g_head_val.load();
            ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x);
            if (ImGui::SliderInt("##head", &v, 30, 200, "%d")) g_head_val.store((float)v);
        }

        bool b = g_feature_body.load();
        if (ImGui::Checkbox("胸部范围", &b)) g_feature_body.store(b);
        if (b) {
            ImGui::SameLine();
            int v = (int)g_body_val.load();
            ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x);
            if (ImGui::SliderInt("##body", &v, 30, 200, "%d")) g_body_val.store((float)v);
        }

        bool l = g_feature_leg.load();
        if (ImGui::Checkbox("腿部范围", &l)) g_feature_leg.store(l);
        if (l) {
            ImGui::SameLine();
            int v = (int)g_leg_val.load();
            ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x);
            if (ImGui::SliderInt("##leg", &v, 30, 200, "%d")) g_leg_val.store((float)v);
        }

        bool t = g_feature_thirdperson.load();
        if (ImGui::Checkbox("第三人称", &t)) g_feature_thirdperson.store(t);

        ImGui::EndDisabled();
    }
    ImGui::Separator();

    // === 日志 ===
    if (ImGui::CollapsingHeader("日志", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(.03, .03, .05, 1));
        ImGui::BeginChild("log", ImVec2(0, 220), true);
        ImGui::TextUnformatted(g_logBuf);
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 5) ImGui::SetScrollHereY(1);
        ImGui::EndChild();
        ImGui::PopStyleColor();
        if (ImGui::Button("清空")) g_logBuf[0] = 0;
    }
    ImGui::Separator();
    ImGui::TextColored(ImVec4(.35, .35, .35, .6), "TG:@TXTinaY");
    ImGui::End();
}
