# safe_bypass 防御体系文档

## 概览

项目采用 **5 层嵌套互锁** + **5 类环境检测** 的纵深防御架构。核心设计原则：

> **明文代码只负责计算原始值，OLLVM 混淆代码负责读取期望值 + 对比 + 终止决策。**
> 每一层既保护自身，又锁定下一层，形成闭合的互锁链。

---

## 一、编译分工

| 编译单元 | 文件 | OLLVM | 职责 |
|----------|------|-------|------|
| `obfuscated` (静态库) | `main.cpp`, `draw_Gui.cpp` | ✅ indbr / icall / indgv / cff / cse | 校验决策、控制流 |
| `safe_bypass` (可执行) | 其余全部 `.cpp` | ❌ | 图形渲染、明文计算 |

```
Android.mk:

obfuscated 库:
  -mllvm -irobf -mllvm -irobf-indbr          ← 间接跳转
  -mllvm -irobf-icall=1 -mllvm -level-icall=50000  ← 间接调用
  -mllvm -irobf-indgv=1 -mllvm -level-indgv=30000  ← 全局变量混淆
  -mllvm -irobf-cff -mllvm -irobf-cse              ← 控制流平坦化 + 不透明谓词

safe_bypass 可执行:
  无 OLLVM 标志，明文编译
```

核心校验代码全部在 `obfuscated` 库中，攻击者即使拿到可执行文件也无法直接看懂校验逻辑。

---

## 二、5 层嵌套互锁校验

### Layer 0 — HMAC Key 解码

**位置**: `src/main.cpp`（OLLVM 混淆）

```cpp
static const uint8_t g_hmac_key_xor[32] = {0x38, 0xFD, ...};  // XOR 编码
static const uint8_t g_hmac_xor_mask = 0x73;
static uint8_t g_hmac_key[32];  // 运行时解码
for (int i = 0; i < 32; i++)
    g_hmac_key[i] = g_hmac_key_xor[i] ^ g_hmac_xor_mask;
```

- 32 字节 HMAC key 以 XOR 形式静态存储
- OLLVM 混淆 (`-irobf-cse -irobf-indbr`) 掩护解码循环
- 攻击者必须逆向 OLLVM 还原后才能提取 key
- **无此 key 则 Layer 1/2 全部失败**

---

### Layer 1 — HMAC 自检

**位置**: `src/main.cpp`（OLLVM 混淆）

```cpp
static const uint8_t g_hmac_self_expected[32] = {0x57, 0x69, ...};
uint8_t tst[32];
IntegrityCheck::hmac_sha256(g_hmac_key, 32,
    "cross_check_integrity_sha256", 28, tst);
if (memcmp(tst, g_hmac_self_expected, 32) != 0)
    → 终止: "hash核心被篡改"
```

**检测能力**:
- 明文代码 `integrity_sha256.cpp` 中的 `sha256` / `hmac_sha256` 函数体是否被 hook/patch
- 攻击者即使替换了明文侧的 hash 函数也会立即暴露
- `g_hmac_self_expected` 嵌在 OLLVM 代码中，无法静态替换

---

### Layer 2 — OLLVM 侧读取尾部

**位置**: `src/main.cpp`（OLLVM 混淆）

```cpp
// OLLVM 直接 open/read /proc/self/exe 尾部 64 字节
char tp[256]; readlink("/proc/self/exe", tp, ...);
int fd = open(tp, O_RDONLY);
uint8_t tail[64];
lseek(fd, st.st_size - 64, SEEK_SET);
read(fd, tail, 64);

// 校验 magic
const uint8_t MAGIC[8] = {0xDE,0xAD,0xBE,0xEF,0x12,0x34,0x56,0x78};
if (memcmp(tail, MAGIC, 8) != 0) → 终止: "尾部magic缺失"

// 解析期望值
exp_crc_file = big_endian_u32(tail + 8);
exp_hmac_file = tail[12..43];   // 32 bytes
exp_crc_text = big_endian_u32(tail + 44);
```

**关键设计**: 尾部读取不经过任何明文函数，全在 OLLVM 侧独立完成。攻击者无法通过修改明文函数来返回假期望值。

---

### Layer 3 — 文件 HMAC 校验

**位置**: `src/main.cpp` 调 `integrity_sha256.cpp::compute_file_hmac`

```
明文侧 (integrity_sha256.cpp):
  read /proc/self/exe → 去尾 64 字节 → hmac_sha256(key, payload) → mac_out[32]

OLLVM 侧 (main.cpp):
  memcmp(act_hmac, exp_hmac_file) != 0 → 终止: "二进制文件被篡改"
```

**检测能力**:
- 磁盘上的二进制文件是否被修改（包括尾部本身）
- 攻击者无 HMAC key 无法重算正确 HMAC
- 覆盖整个文件（~16MB），无盲区

**尾部 64 字节格式**:

```
偏移    长度    内容
[0..7]   8      magic          DE AD BE EF 12 34 56 78
[8..11]  4      crc_file       CRC32 全文件（去尾）, 大端
[12..43] 32     hmac_file      HMAC-SHA256(key, 全文件去尾)
[44..47] 4      crc_text       CRC32 代码段（前 90%）, 大端
[48..51] 4      crc_helpers    预留
[52..63] 12     reserved       全零
```

---

### Layer 4 — 代码段 CRC 校验

**位置**: `src/main.cpp` 调 `integrity_sha256.cpp::compute_loaded_text_crc`

```
compute_loaded_text_crc:
  read /proc/self/exe → 解析 64-bit ELF header
  → 找到 PT_LOAD + PF_X 段
  → 取前 90% (避开 PLT/GOT, 动态链接器会修改)
  → CRC32 → 返回 uint32_t

OLLVM 侧:
  act_text != exp_crc_text → 终止: "内存代码段被篡改"
```

**检测能力**:
- 代码段是否在磁盘上被修改
- 覆盖 `main.cpp` 和 `integrity_sha256.cpp` 所在的 ELF 段
- 取 90% 是平衡检测率和误报（PLT/GOT 内联 stub 会在加载时变化）

---

### Layer 5 — ProtectManager 环境检测

**位置**: `Protect/ProtectManager.h` → 组合调用各子模块

```cpp
auto cfg = ProtectManager::default_config();
cfg.on_violation = TERMINATE;
cfg.max_violations = 1;
cfg.target_soname = "safe_bypass";
cfg.integrity_check.hmac_key = g_hmac_key;
cfg.integrity_check.hmac_key_len = 32;

const char *threat = ProtectManager::check_once(cfg);
if (threat) → 终止
```

内部的 `check_once()` 串联 5 套检测引擎：

---

## 三、5 类环境检测引擎

### 3.1 AntiDebug (`Protect/AntiDebug.h`)

| 检测项 | 方法 |
|--------|------|
| ptrace 附加 | 读取 `/proc/self/status` 的 `TracerPid` |
| Frida Android Server | 检查 27042/27043 端口 |
| Frida 文件残留 | 扫描 `/data/local/tmp/` 下的 frida-server |
| Frida 线程 | 扫描 `/proc/self/task/*/comm` |
| IDA Pro Android Server | 检查 `/data/local/tmp/` 下 android_server |
| Xposed | 检查 `/data/data/de.robv.android.xposed.installer/` |
| 模拟器 | 检测 QEMU/Genymotion 特征文件 |

### 3.2 AntiHook (`Protect/AntiHook.h`)

| 检测项 | 方法 |
|--------|------|
| LD_PRELOAD | 检查 `getenv("LD_PRELOAD")` |
| 可疑注入 SO | 扫描 `/proc/self/maps` 中非系统 SO |
| GOT 表 hook | 检查 `dlopen`/`dlsym`/`pthread_create` 的 GOT 项是否指向预期地址 |
| PLT hook | 检查 `read`/`fgets`/`write`/`open`/`fopen`/`mprotect`/`clone`/`fork` 的前几条指令 |
| ShadowPage (memfd) | 检查 `/proc/self/maps` 中 memfd 匿名映射 |
| RWXP 页面 | 检查代码段是否有同时可读+可写+可执行页面 |

### 3.3 AntiDump (`Protect/AntiDump.h`)

| 检测项 | 方法 |
|--------|------|
| /proc/self/maps 篡改 | 对比 maps 的 CRC |
| maps 注入 | 检查 maps 中出现不合规路径 |
| /proc/self/mem 被打开 | 检查其他进程是否打开了本进程的 mem 文件 |
| SO 文件完整性 | 检查磁盘上自身 SO 是否被篡改 |

### 3.4 IntegrityCheck (`Protect/IntegrityCheck.h`)

在 ProtectManager 中做第 6 层附加校验（双重验证）：

```cpp
cfg.integrity_check.target_soname = "safe_bypass";
cfg.integrity_check.enable_crc = true;
cfg.integrity_check.enable_sha256 = true;
cfg.integrity_check.panic_on_mismatch = true;
cfg.integrity_check.hmac_key = g_hmac_key;
```

- 再次验证文件 CRC + HMAC
- `panic_on_mismatch` → 无尾部则直接终止

### 3.5 RootKitDetect (`Protect/RootKitDetect.h`)

| 检测项 | 方法 |
|--------|------|
| 代码段可写 | 检查 `/proc/self/maps` 代码段权限是否异常可写 |

---

## 四、互锁关系图

```
┌─────────────────────────────────────────────────────┐
│ OLLVM 混淆侧 (obfuscated 静态库)                       │
│                                                       │
│  Layer 0  XOR解码 HMAC key ──────────────────────────┐│
│  Layer 1  HMAC 自检 (sha256核心完整) ────────────────┐││
│  Layer 2  读 /proc/self/exe 尾部 64B → 提取期望值 ───┐│││
│  Layer 3  compute_file_hmac → 比对文件 HMAC ←──────┐││││
│  Layer 4  compute_loaded_text_crc → 比对代码段 CRC ←┐││││
│  Layer 5  ProtectManager 环境检测 ←────────────┐   ││││││
│                                                   │   ││││││
├───────────────────────────────────────────────── │ ──│││││││
│ 明文计算侧 (safe_bypass 可执行, 无 OLLVM)           │   ││││││
│                                                   │   ││││││
│  hmac_sha256(key, data) → mac[32]  ← Layer1锁 ←──┘   ││││││
│  compute_file_hmac(key, key_len, mac_out) ← Layer3  ←┘││││
│  compute_loaded_text_crc(name) → uint32_t  ← Layer4 ←─┘│││
│  compute_memory_crc(addr, len) → uint32_t              │││
│                                                         │││
│  ← Layer4 的代码段 CRC 覆盖 main.cpp 所在段 ────────────┘││
│  ← Layer3 的 HMAC 覆盖整个文件 (含 Layer4 的代码) ────────┘│
│  ← Layer1 锁定 Layer3/4 的 sha256/hmac 核心完整性─────────┘
│  ← Layer0 的 HMAC key 是 Layer1/2/3/5 的前提─────────────┘
└─────────────────────────────────────────────────────┘
```

| 层 | 保护目标 | 被哪层保护 |
|----|---------|-----------|
| L0 | HMAC key 本身 | OLLVM 混淆 |
| L1 | hash 核心完整 | L0 (key), 自身 (期望值在 OLLVM) |
| L2 | 尾部读取 | L0 (读取 /proc/self/exe 不走明文), L4 (代码段覆盖) |
| L3 | 文件完整性 | L0 (key), L1 (hash 核心), L4 (compute_file_hmac 所在段) |
| L4 | 代码段完整性 | L3 (整个文件 HMAC 覆盖所有代码), L1 (hash 核心) |
| L5 | 运行环境 | L4 (ProtectManager 所在段被代码段 CRC 覆盖) |

---

## 五、构建流水线

```
ndk-build -j16
  ├─ obfuscated   : main.cpp + draw_Gui.cpp  → OLLVM 混淆
  └─ safe_bypass  : 其余全部 .cpp            → 明文编译
       ↓
patch_integrity.py
  ├─ 读 ELF, 找 PT_LOAD PF_X 段
  ├─ CRC32(全文件去尾)
  ├─ HMAC-SHA256(key, 全文件去尾)
  ├─ CRC32(代码段前 90%)
  └─ 追加 64 字节尾部
       ↓
safe_bypass (含尾部) → adb push → 设备
```

---

## 六、攻击者绕过成本分析

| 攻击手法 | 需同时击穿的层 | 难度 |
|----------|--------------|------|
| 静态修改二进制 | L2(magic) + L3(HMAC) → 无 key 无法重算 | 极高 |
| 修改 ELF 代码段 | L4(.text CRC) + L3(HMAC) | 极高 |
| Hook sha256 返回假值 | L1(自检) → 期望值在 OLLVM 中 | 高 |
| 替换整个 compute_file_hmac | L1(自检) → sha256 被改即暴露 | 高 |
| 读取/proc/pid/mem 写内存 | L5(AntiDump.mem_file_open) | 中高 |
| Frida 注入 | L5(AntiDebug.frida_*) + L5(AntiHook) | 中高 |
| ptrace 调试 | L5(AntiDebug.ptrace) + L5(AntiHook) | 中高 |
| LD_PRELOAD 注入 | L5(AntiHook.ld_preload) | 中 |
| ROOT + 内核级 hook | 全层 | 高 (需内核访问) |

**核心要点**: 攻击者无法单点突破。修改任意一处必然触发另一层。HMAC key 是整条链的基石，key 在 OLLVM 混淆的 `main.cpp` 中 XOR 存储，逆向提取 key 本身就需要先击穿 Layer 4 的代码段保护。

---

## 七、文件索引

| 文件 | 职责 |
|------|------|
| `src/main.cpp` | Layer 0-4 决策、协调调用 (OLLVM) |
| `Protect/IntegrityCheck.h` | CRC32 / 尾部定义 / verify_self_integrity / CheckResult |
| `src/utils/integrity_sha256.cpp` | SHA-256 / HMAC-SHA256 / compute_* 纯计算 (明文) |
| `Protect/ProtectManager.h` | Layer 5 统一管理、check_once |
| `Protect/AntiDebug.h` | 反调试 (ptrace/Frida/IDA/模拟器/Xposed) |
| `Protect/AntiHook.h` | 反 Hook (GOT/PLT/SO/ShadowPage/RWXP) |
| `Protect/AntiDump.h` | 反 Dump (maps/mem/SO 文件) |
| `Protect/RootKitDetect.h` | 权限异常检测 |
| `patch_integrity.py` | 构建后补尾部 (CRC + HMAC + .text CRC) |
| `do_build.ps1` | 一键构建 + 补尾部 |
| `Android.mk` | 编译单元划分 (obfuscated / safe_bypass) |
