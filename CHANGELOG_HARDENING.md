# 防御加固变更清单

## 致命级修复

### 1. 启用周期性保护监控 (C1)
- `main.cpp`: `cfg.enable_periodic_monitor = true` + `g_protect_mgr.start(cfg)`
- `draw_Gui.cpp`: cycle_thread_func 每50次循环做一次 syscall 级 TracerPid 检测
- 后台每3秒全量环境检测，不再是一次性开机门

### 2. 内存完整性校验 (C3)
- `main.cpp` Layer 3b: 新增 `IntegrityCheck::calc_text_crc("safe_bypass")` 检测实际 r-xp 内存页
- `ProtectManager::check_once`: 加入 `calc_text_crc` 对比，周期性检测内存 patch/hook

### 3. 去除 system() RCE (C5)
- `network_program.h`: `system("curl %s")` 替换为 `fork()+execvp()` 参数数组方式
- 服务器响应不再拼接进 shell 命令，彻底消除命令注入

### 4. 修复 detect_ptrace (H1)
- `AntiDebug.h`: strncmp 长度从 11 改为 10
- 新增 `detect_ptrace_syscall()`: 直接 syscall(__NR_openat) 读 /proc/self/status，绕过 libc hook
- 新增 `occupy_ptrace()`: PTRACE_TRACEME 占坑

## 高危级修复

### 5. 常量时间比较 (H2)
- 新建 `Protect/SecureCompare.h`: `secure_memcmp` + `secure_u32_eq` + `secure_zero`
- `main.cpp`: 所有关键比较从 `memcmp` 改为 `SecureCompare::secure_memcmp`
- hook libc memcmp 不再能绕过校验

### 6. InlineHook 基线改进 (H3)
- `InlineHookDetect.h`: `build_baseline_from_disk()` 替代纯运行时采集
- 从 /proc/self/maps 定位 libc.so 路径，基线不易被早期 hook 投毒

### 7. RootKit 检测接入 (H1补充)
- `ProtectManager::check_once`: 新增调用 `detect_tracer_pid` / `detect_vm_writev_available` / `detect_task_directory_injection`

## 中危级修复

### 8. seccomp 加固
- 新增 `PR_SET_NO_NEW_PRIVS` 设置
- 新增 BPF arch 验证 (AUDIT_ARCH_AARCH64)，防止 32 位 compat 绕过
- 添加注释说明 seccomp 的实际作用域（仅过滤本进程 syscall）

### 9. loginApi 栈溢出修复
- `scanf("%s")` → `scanf("%39s")`
- `fscanf(fopen(...))` → 分离 fopen/fscanf/fclose，检查返回值
- `char _inputKm[]=""` → `char inputBuf[40]`
- 消除 FILE* 泄漏

### 10. 构建加固
- `Android.mk`: `-w` → `-Wall -Wextra`
- 新增 `-fstack-protector-strong -D_FORTIFY_SOURCE=2`
- 链接加固: `-Wl,-z,relro,-z,now -Wl,--strip-all`

### 11. TimingGuard 修活
- 降低阈值 100ms→50ms，报警次数 3→2
- main.cpp 各层之间插入 7 个 timing_checkpoint，使时序检测不再是死代码

### 12. detect_maps_modify 修活
- 首次调用记录基线（不报警），后续调用做实际对比
- 改为只 hash .so 和 [] 行的权限部分，减少误报

### 13. 网络密钥加密存储框架
- 增加 `decode_secret()` 函数框架
- 标注 TODO: 需要用编码工具将明文 key 转为加密数组
- 移除 resCommonInit 中的期望值/收到值打印（信息泄露）

### 14. 失败路径收敛
- 校验失败统一用 `_exit(1)` 而非 `printf + return 1`
- 减少攻击者通过 grep 字符串定位校验点的机会

## 新增文件
- `Protect/SecureCompare.h` - 常量时间比较工具

## 仍需手动完成的 TODO
1. 用 encode_secret 工具将 app_secret / rc4_key 编码并替换 `_enc_app_secret[]` / `_enc_rc4_key[]`
2. Layer 1b 的自检期望值需要构建时重新计算
3. 建议将 network_program.h 整体移入 OLLVM 模块编译
4. 建议接入 TLS pinning (替代当前的明文 HTTP)
5. patch_integrity.py 中的明文 HMAC_KEY 应改为从环境变量读取
