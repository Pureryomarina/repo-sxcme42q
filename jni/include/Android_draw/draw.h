#ifndef NATIVESURFACE_DRAW_H
#define NATIVESURFACE_DRAW_H

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <atomic>
#include <cstdint>
#include <thread>
#include "ImGui/imgui.h"
#include "ImGui/imgui_internal.h"
#include "native_surface/ANativeWindowCreator.h"
#include "AndroidImgui.h"

extern std::unique_ptr<AndroidImgui> graphics;
extern ANativeWindow* window;
extern android::ANativeWindowCreator::DisplayInfo displayInfo;
extern float abs_ScreenX, abs_ScreenY;
extern int native_window_screen_x, native_window_screen_y;
extern int FPS限制;
extern bool Getth;
extern bool permeate_record;
extern pid_t pid;

extern void screen_config();
extern void drawBegin();
extern void Layout_tick_UI(bool* main_thread_flag);
extern void init_My_drawdata();
extern void HandleTouchEvent();
extern bool g_antiRecord;
extern bool g_antiRecordChanged;
extern bool g_hideProcess;
extern void hide_proc();

#define TARGET_PACKAGE "com.tencent.tmgp.dfm"

extern pid_t get_pid(const char* pkg);
extern void kill_proc(pid_t _pid);
extern bool 大厅开启初始化();
extern std::atomic<bool> g_game_ready;
extern std::atomic<bool> g_game_running;
extern std::atomic<bool> g_cycle_running;
extern std::thread g_cycle_thread;
extern void log_add(const char* fmt, ...);
extern bool is_process_alive(pid_t _pid);
extern uintptr_t get_module_base(pid_t _pid, const char* mod);
extern unsigned long base_libUE4;
extern bool 注入libzrf();
extern void cycle_thread_func();

#endif //NATIVESURFACE_DRAW_H
