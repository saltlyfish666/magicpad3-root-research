# ppgroot（一键提权 v3.8）逆向分析报告

> 逆向工具：jadx 1.5.6（GitHub 最流行的 APK 反编译工具）+ 手工字符串/资产分析
> 目标：`com.dsh.ppgroot` v3.8（APK 22.5MB，本机拉取于 2026-10-16 01:00）
> 分析纪律：观察 / 推断 / 未知 三态分离（每节标注）
> 状态：**进行中**（01:15 首轮；自动任务持续到 08:00）

---

## 1. 目标身份（观察）

| 项 | 值 |
|---|---|
| 包名/版本 | `com.dsh.ppgroot` v3.8（首装时间 2026-10-16 00:53） |
| APK | `ppgroot_v3.8.apk`（22,486,310 B，sha256 见文件） |
| 结构 | 单 dex + 99 条目；assets 58 个（多设备载荷） |
| 反编译 | jadx 1.5.6 → `decompiled/`（Java 源码级） |

## 2. 路由架构（观察 — 来自 RouteKit.java）

App 是多设备提权框架，共 **4 条路线**：

| 路线 | 设备 | 机型码 | 描述（原文） | 入口脚本 |
|---|---|---|---|---|
| **KIT** | 荣耀 MagicPad3 | **CGA-W00（=本机）** | "CVE-2026-43499 + KernelSU · 套件日志" | dc_ksu_run.sh |
| M6 | 荣耀 Magic6 Pro | BVL-AN16 | "selx11 路线 · ⚠ 成功率低，失败需重启" | dc_ksu_run.sh |
| M8 | 荣耀 Magic8 Pro | BKQ-AN90 | "WorkBuddy mk2 路线 · ghostlock_v128 + KSU late-load" | m8_run.sh |
| MEP | 荣耀 500 Pro | MEP-AN00 | "使用其脚本自带流程与日志" | mep_run.sh |

**设备识别**：`RouteKit.byModel(机型码)`（MainActivity:3962 调用）。
**部署方式**：assets → /data/local/tmp/route/<key>/，`kaslr_leak` 额外软链到 /data/local/tmp/。

## 3. 关键对比：KIT 路线 vs 我们的方案（观察 + 推断）

### 3.1 文件级对比（观察）
- `assets/route/kit/cve-2026-43499-bin-dc14-sig`：**与我们在用文件字节级相同**（sha256 0c99f8b4… 双方一致，md5 6914a30e）
- `dc_ksu_run.sh`（6637B）、`kernelsu_cga.ko`（5540360B）、`ksu_loader.sh`（48171B）等全部相同
- **推断**：本机赞助版 kit 与 ppgroot 的 KIT 路线是同一套文件（同源）

### 3.2 流程级对比（观察 — MainActivity fireRoute43499 / watchRoute43499）
| 维度 | ppgroot（KIT 路线） | 我们的方案 |
|---|---|---|
| 每 boot 发数 | 1 发（run.lock 纪律，"原地重试会 panic"） | **8 次 attempt/发**（二进制补丁）+ 3 发/boot |
| 失败处理 | 提示用户**手动重启** | **自动循环**（重启→等 boot→自动开火） |
| 命中检测 | 5s 轮询 × 96 次（8 分钟） | 5s 轮询 + 早杀优化 + 黄金样本自动收档 |
| 多 boot 自动化 | 无（人工） | 有（12 boot 上限 + 熔断保护） |
| 声称命中率 | "约 1/3~1/2"（原文，待验证） | 实测：补丁后多 attempt 已命中（23:40） |

### 3.3 结论（推断）
**对本机（CGA-W00）而言，ppgroot 的 KIT 路线没有超出我们现役方案的任何东西**——
同套件、单发纪律、人工重启。我们后加的「8 次 attempt 二进制补丁 + 自动循环 + 早杀」是严格增量。
其声称的"1/3~1/2 命中率"与我们的实测（单发 ~5-7%、补丁后多 attempt 显著提升）**口径可能不同**（待 08:00 前核实其是否含额外机制）。
> **【定稿 [04:35]】** 命中率文案已核实（§10）；本节的 KIT 结论维持**"无超越"**，并已扩展为全路线最终对比表 —— 见 §17。修正一处：KIT 的 run.lock 单发纪律在套件里本有 `ALLOW_MULTISHOT` 开关（默认关；我们已开），细节见 §13.5 与 §17.2。

## 4. 新情报：M8 路线的下一代技术（观察 — 来自 ghostlock_m8 字符串）

`ghostlock_m8`（2,514,088 B，clang 构建，2026-09-22/24 版本痕迹，引用 6.6.140 / 6.12.38/80/86）：
**同 CVE（CVE-2026-43499）但下一代实现（"mk2 路线"），CLI 多阶段化。** 关键新技术：

| 技术 | 证据（字符串） | 意义 |
|---|---|---|
| **purgerec 可控页伪锁** | `--purge-page`、`--purgerec-lock-allbase`、"purgerec: open(/proc/slabinfo)"、`prim_lock = base+0x4000` 满足 rtmutex.c:842 | 不依赖 res-encode 的替代路径：清页→重占→伪锁 |
| **alias-oracle 零重启标定** | `alias-oracle ✅ init_task.comm 读回 "swapper/"`、`--kimg-delta`、`--phys-load`、`--slide-sweep` | 写别名→安全读回验证；**猜错只静默写坏别的物理页，零重启可反复调参** |
| **stage5 子系统** | `--stage5-bridge/-self/-pageprobe/-hex`、`uinput_misc=…`、`[uinput+0x60]=0 避免 fortify_panic` | uinput_misc 劫持 + 页内布局核对 |
| **selbox** | `selbox: sid %u -> %u (exec_sid=%u)`、"init_cred 校验没过退回 pid 1 域" | SELinux SID 精细操控 |
| **多阶段 CLI** | `--stage a/b/c/e/all`、`--attempts`、`--spray-mode 3/4/5`、`--spray 8`、`--prim-iov 1..8`、`--pselect-geo-probe` 等 | 全部参数运行时可调 |
| **tracefs 泄露** | `--leak-tracefs --leak-tracefs-seconds`、`GL_TRACEFS_NO_STIR/NO_ARM`、perf_paranoid 检查 | 与 170 包 kaslr_leak 同源思路 |

**未知**：ghostlock_m8 是否含 6.1.x 支持（字符串只见 6.6/6.12）→ 推断**不直接可移植到本机 6.1.157**。
**推断**：其"零重启重试"哲学（安全 miss 设计）是方向性启示；若未来 6.1 分支出现同款构建，值得优先评估。

## 5. 结论与建议（推断）

1. **不用换**：ppgroot 对本机无增量（同套件+更保守流程）；我们的补丁+自动循环是超集。
2. **可借鉴**：M8 的「alias-oracle 零重启标定」思想 → 或可启发我们解决"pipe gate 失败后僵死"问题（用安全读回验证替代盲目重试）。
3. **待深挖（今晚自动化任务）**：
   - [ ] MainActivity 其余 4400 行的完整逻辑（配额、三重轮、缓存校验重试段）
   - [ ] KoUpdater.java（模块更新机制——是否有我们能用的热更新）
   - [ ] m6 route 的 window_chain.sh / phone_fire.sh / next_sym_addr.txt（selx11 技术细节）
   - [ ] mep route（preload.so 机制）
   - [ ] device-registry.json 全表（多机型知识）
   - [ ] ghostlock_m8 的完整 --help 文本（UTF-8 解码）
   - [ ] 核实其"1/3~1/2 命中率"的来源

## 6. 约束与安全（贯穿整个任务）
- **绝不操作平板**（用户明令）：只做 PC 侧静态分析；不 adb 推文件/重启/开火
- 分析产物全部落在 `.workbuddy/community/ppgroot/` 目录


---

## 7. 【重大】CVE-2026-64560 第二漏洞线（01:30 发现）

### 7.1 观察
App 有**两条漏洞线**（registry `defaultRouteDoc`）：
- `"43499:<route>"` = GhostLock 套件（assets/route/*）
- `"64560"` = **自带载荷**（`pl_*_fanout` / `pl_*_rotate` 系列，97-99KB ELF）

`/data/local/tmp/cve64560/` 工作目录 + `fanout --preflight|--probe-task|--run` CLI + **stdin 脚本驱动**。

### 7.2 我们设备相关的关键事实
| 事实 | 证据 |
|---|---|
| **`pl_mtn-an80_fanout` / `pl_mtn-an80_rotate` 的编译目标是 `6.1.157-android14-11-g19a495a97bff` —— 与本机内核构建完全相同** | 二进制内嵌串（md5 b628f4a9 / 151efd63） |
| 我们设备是"**首次适配这套方案的原始设备**"（CGA-W00，route=43499:kit） | registry cga-w00 条目 |
| 我们设备的**旧 64560 载荷已被移除**（理由："与套件内核重复"）——但 MTN-AN80（同内核构建）的载荷仍留在 APK 里 | registry kernelsNote |
| MTN-AN80 的 64560 载荷"**首次适配（离线完成），尚未真机验证**" | registry mtn 条目 |
| 64560 = posix-cpu-timers UAF（影响 6.1.128~6.1.180 ⇒ 本机 6.1.157 在范围内） | 载荷内 `posix_timers_cache` 串 + knowlily 文档 |

### 7.3 64560 载荷的技术特征（观察 — 来自字符串）
- **全链 gate 化**：STAGE0（bootid 写）/ CROSSCACHE / PIPE_*（含 `PIPE_CACHE_GATE`、`PIPE_RECLAIM_PASS`、`ORDER1_RECLAIM_GATE`）/ MISC_BRIDGE + MISC_LIST（misc 设备链表操控，带 head/backlink/prev_pointer 全套 restore gate）/ STAGE8（cred 提权 + SELinux）/ REAPER（回收线程）
- **自愈式设计**：每个 gate 失败都有 `*_FAIL`/`*_MISS_CLEAN` 分支 + `KERNEL_STATE_RESTORE_NOT_PROVEN` 判据——**失败时主动恢复内核状态**（而非放任挂起）
- **成功日程常量**：`DADA_SUCCESS_SCHEDULE stage0=two-rounds-of-1-16 bridge=13,32,21,1-twice-then-full-coverage`
- CPU 管控：`RACE_CPU_PIN_GATE` / `RACE_CPU_LIMIT_GATE`（读回校验 CPU 绑定）
- 调用方式：`{ 脚本; sleep 7200; } | fanout --run` —— root 子进程从 stdin 读命令以 root 执行（KSU 加载脚本由 app 现场生成）

### 7.4 推断
- **这是一条我们从未拥有的备选 root 路径**（CVE-2026-64560，与 43499 完全不同的 bug 类），且**有针对我们内核构建的现成载荷**（两个变体 fanout/rotate）
- 其"gate 化 + 自愈恢复"设计与 43499 套件（一次写坏 PI 树即废）不同——**理论上对重复尝试更友好**
- **未知**：两个载荷在真机的实际成功率（未验证）；fanout vs rotate 的具体差异（需反汇编对比）

### 7.5 后续（待用户批准后）
- [ ] 反汇编对比 fanout vs rotate 的差异
- [ ] 若用户允许：在本机平板做 `--preflight`（只读环境检查）验证兼容性
- [ ] 评估作为 43499 之外的备选路径（不改现有方案的前提下并行储备）

## 9. T6 完成：ghostlock_m8 全量 CLI 分析（[01:21] 第二批）

### 9.1 身份确认（观察）
- 二进制内嵌标识（0x252c2）：`GhostLock / CVE-2026-43499 — Linux rtmutex remove_waiter() UAF`
- **与 KIT 路线是同一个 CVE（43499）**——第 4 节"同 CVE 但下一代实现（mk2）"的推断，现为直接证据
- 主 usage 行（0x21589）：`用法: ghostlock [--info] [--selftest] [--leak] [--leak-dev] [--scan] [--leak-perf] [--leak-tracefs] [--stage a|b|c|all] [--attempts N]`
- 散见用法示例：`ghostlock --purgerec-lock-allbase --spray-mode 4 \`、`ghostlock --stage all --prim-lock <hex> --selinux`、`ghostlock --purgerec-lock --stage b --attempts 20`、`ghostlock --stage all --slide-only`、`ghostlock --purge-page --oracle-readback --attempts 20`

### 9.2 内核版本覆盖（观察 — 关键结论）
| 证据串 | 位置 | 含义 |
|---|---|---|
| `6.12.38-android16-5-gfde7767f6ef6-abogki481467632-4k` | 0x1c740 | M8 目标机（Magic8 Pro）完整构建串 |
| `6.6.140` | 多处 | 6.6 线版本号 |
| `6.12.80` / `6.12.86` | 多处 | 修复版/判据版 |
| `一次 -EDEADLK 都没有 -> 核对内核是否已修 (>= 6.12.86 / 6.6.140)` | 0x16d66 | **修复门槛**：此 CVE 在 6.12.86 / 6.6.140 已修 |
| `目标 6.12.38 < 修复版 6.12.80, perf_sample_regs_intr() 不查 exclude_kernel` | 0x1d759 | 泄漏渠道的版本差异（6.12.38 还能用 perf 采样） |
| `本机 KASLR 未启用 (bootargs 里有 nokaslr)` | 0x241ed | 某测试环境判据（非通用路径） |

- **覆盖范围 = {6.6.x（< 6.6.140）, 6.12.x（< 6.12.86）}；全二进制无任何 6.1.x 痕迹**
- ⇒ 结论：**不适用于本机 CGA-W00（6.1.157-android14）**。无 6.1 分支；其内核结构假设（perf/kstack/fd 布局）均为 6.6/6.12 代际。

### 9.3 参数表（观察）
106 个参数（全清单：`extracted/m8/strings_ascii.txt`）。相对首轮新增的主要家族：
- pselect 族（15+）：`--pselect-form/-nfds/-read/-read-at/-self/-resenc/-resencode/-geo-probe/-write/-write-val/-write-valrel`
- pstack 族：`--pstack-cmsg/-cmsg-auto/-cmsg-off/-drift/-drift-n/-lock/-name/-name-off/-self/-task`
- s5-cfs 族：`--s5-cfs/-cfs-at/-cfs-data/-cfs-hex/-cfs-len/-hold/-kaddr`
- purge 族：`--purge-only/-recv-check/-reclaim-cpu/-purgerec-lock-only`
- slide 族：`--slide/-candidates/-end/-only/-start/-step/-sweep`
- 其他：`--forge-cred/-sec`、`--hold-victim`、`--linger`、`--nice-range`、`--pr-lock-sweep`、`--tp`、`--trigger`

### 9.4 实际调用方式（观察 — m8_run.sh，03:xx 内核 6.12.38）
1. `--leak-tracefs --leak-tracefs-seconds 5` → 解出 slide（实录 `slide=0x29d6400000`，2MiB 对齐）
2. `GL_LEAK_ADDR=… GL_LEAK_SYM=_text GL_S5_FOPS=1 GL_PSEL_E2=1 GL_GATE_PC=1 ghostlock_m8 --stage b --spray-mode 5 --spray 8 --purge-page` → 每 boot 一发
3. `su -c id` 验证 → `insmod kernelsu_m8.ko` late-load
- 环境变量族：`GL_LEAK_ADDR/SYM/LINK/LOOSE`、`GL_TRACEFS_NO_ARM/NO_STIR`、`GL_FAKETAB_UNSAFE`、`GL_EVIDENCE_NONCE`、`GL_SPRAY_ROUNDS`、`GL_CPU_VICTIM`、`GL_VICTIM_TIMEOUT_MS`

### 9.5 零重启重试 / alias-oracle / purgerec 细节（观察）
- **alias-oracle 判据**：`alias-oracle ✅ init_task.comm 读回 "swapper/" => 别名公式 / phys_load / 线性映射未随机化(P1) 三者同时成立`；`扫描判据 = alias_verify_comm 的读回（不再依赖崩溃与否）；猜错只静默写坏别的物理页（第 69 轮结论）`；`零重启, 可反复调参重试`——**但**：`⚠ 每个错误候选都会按别名写坏两处内核内存(随机 qword)，且每个候选都要打一发 UAF。这是有代价的操作，不是免费试探`（0x5054）
- **purgerec**：`open(/proc/slabinfo)` 持久化 fd（缓冲预热）；fork 填充子进程 `⇒ 空闲池归零, 下次分配从崭新页页首开始`；`[pg] [pin] 父进程(回收侧) -> cpu%d（= 释放侧核, 才能捞到 P）`；`⑨ 泄漏子进程保活（占住 P 的第 25 个对象, P3 时才 kill）`；MTE 顶字节归一化
- **读通道演进**：`faketab: [3/3] 读通道已升级为非破坏性 (proc_dostring)——不再触发 generate_random_uuid`；boot_id 表项可恢复（`gl_faketab_restore`）
- **stage5 执行通道**：`/system/bin/sh /data/local/tmp/g3.sh`（root shell）；
- **fd 几何实录**：`task@fds128..191 / lock@fds192..255 / ws@fds256..319`
- **KASLR 粒度**：slide 2MiB 对齐；`CONFIG_RANDOMIZE_KSTACK_OFFSET` 6 位熵（0~0x3F0）判据
- **工具链**：`python tools/dump_symbols.py build/vmlinux.elf --search <symbol>` / `--slide-candidates 0x…`（从 vmlinux 取符号与候选）

### 9.6 产物
- `extracted/m8/ghostlock_m8`（2.51MB ELF）
- `extracted/m8/ghostlock_m8_help_dump.txt`（2446 片段 / 236KB 全量帮助+日志文本，含中文）
- `extracted/m8/strings_ascii.txt`（17142 条 ASCII 串）

### 9.7 未知
- help 逐参数说明未能 100% 重建（编译器 4 字节对齐拆散 + 需实机执行 `--help` 确认）
- m8 内含大量调试轮次痕迹（"第 55/58/69/71/79/81 轮"），当前构建是否收敛未知

## 10. T7 完成：命中率"约 1/3~1/2"来源核实（[01:21]）

- **来源（观察）**：`MainActivity.java:4055`，`fireRoute43499`（43499 套件族 KIT/M6 共用的发射函数）启动后的提示文案：
  ```java
  appendLog("[43499] 已在后台启动（最长 8 分钟，命中率约 1/3~1/2）");
  ```
- 上下文：先查 boot_id==run.lock（本 boot 已打则拒绝："原地重试会 panic"）；启动入口脚本；watchRoute43499 轮询 5s×96（8 分钟）
- **推断**：这是**写给用户的声称值**，App 内无统计代码/数据导出支撑；口径很可能是开发期多 boot 累计经验。与我们实测（单发 ~5-7%）的差异属口径不同。**不构成 ppgroot 优于我们方案的技术证据**（其内部同样没有自动多 boot 机制）。
- 结论：该文案可作"期望值"参考（与我们补丁后多 attempt 的观测不矛盾），但不可当精确命中率引用。
- **【06:55 补注 —— §24.3 发现内部统计】**：kit 版 `dc_ksu_run.sh` 批注载有破解方一手普查数据：**26 轮 miss 普查 46% 死于 plant 竞速 + 19% 死于 gate 单试**（⇒ 单发 ≈ 35%）、configfs misc_fops 写 37% 阵亡 ⇒ "1/3~1/2" 与内部统计"单发 ≈35%"互证，来源从"无统计支撑"更新为"有内部普查支撑（26 轮）"。

## 11. T1（核心）完成：自动化设计梳理（[01:21]）

> 原问题："配额系统、重跑 3 轮、缓存校验重试是否包含可借鉴的自动化设计？"——结论：**是，且集中在 64560 路线**（App 自研的完整重跑系统）；43499 路线反而保守（人工重启）。

### 11.1 64560 路线自动重跑系统（观察 — `runExploit()` @3477）
- 结构：`runExploit()` 最多 **3 轮**循环 → `runExploitOnce(i)` 单轮 → 监控循环增量读 `app-run.log`（`tail -c +N`）
- **重跑条件精确限定**：仅当 `cacheDeadRestart==true`（页回收自检失败）才自动重跑；其他失败（stop/abort/额度尽/dirty）直接退出
- 页回收自检失败判据（@3649）：`PIPE_CACHE_GATE ok=0` 后 **20s（CACHE_DEAD_MS）** 无新记录 → 判定载荷已停 → 自动重跑
- 启动判据：**90s（STARTUP_MS）** 无任何输出 → "载荷没启动或启动即失败"（列原因，不重跑）
- 回合重置：`prepareRestartRound` = `pkill -9 fanout/run.sh` + 删日志 + 状态清零
- 3 轮仍失败 → 提示"建议重启手机后再试"（复位决定权留给用户）

### 11.2 配额/熔断（观察）
- 从日志 marker 解析：`maxAttempts` / `controlledMaxAttempts` / `parseBridgeBudget`（正则 `attempt=(\d+)\s*/\s*(\d+)`）
- 额度用尽 → `budgetExhausted` → 自动暂停 + 失败分类提示

### 11.3 状态机与失败分类（观察 — `noteProgress`/`classify`）
- marker 驱动 UI：`BOOTID_WRITE_PASS→CROSSCACHE_KS→MISC_BRIDGE_STAGE_BEGIN/READ_PASS/RW_PASS→PHYS_READ_PASS/LAYOUT_PASS→STAGE8_CHILD_USERLAND_PASS/ROOT_CHILD_HOLD_PASS`
- `classify()` 三分类：`dirty`（内核状态脏：MISC_BRIDGE_MISS_PRESERVE/KERNEL_STATE_* 等）/ `early`（未进竞态，无 CROSSCACHE_ALLOC）/ `in-race`（竞态中 miss）

### 11.4 环境门控（观察）
- `runPreflight`：`fanout --preflight` 只读预检（输出 `SLAB_BASELINE active=N` + `PREFLIGHT_PASS`）；slab >560 → "成功率低、易搞脏，建议重启"；**预检失败不拦路（诊断而非门禁）**
- 事前提示（@3020）：`posix_timers_cache` >558 判不利（"成功案例参考 310"）；温度（读 `/sys/class/thermal/thermal_zone0/temp`）：≤36°C 最佳 / 36~40°C 约 33% / >40°C "基本进不了桥接 0%"
- 43499 路线（对照）：run.lock 单发纪律 + 失败"建议立即重启"强提示（保守）

### 11.5 推送校验（观察 — `pushLocalFile`）
本地 → `.stage` 暂存 → 设备 `.new` → `cp+chmod+mv -f` 原子替换 → `stat -c %s` 尺寸核对；不符抛"推送校验失败"。与 KoUpdater 同一哲学（见 §12）。

### 11.6 可借鉴清单（推断 — 候选改进点）
1. **回合重置模板**：重跑前彻底清理（杀进程/删日志/清状态）——对照检查我们循环的"回合边界"
2. **失败分类再细化**：dirty/early/in-race 三态 → 决定"重跑还是重启"
3. **启动判据**：90s 无输出=没启动（区别于打一半失败）——我们可加
4. **推送尺寸校验**：我们推 kit/payload 时补"尺寸核对"层
5. **环境门控提示**（温度/slab 基线）不拦路只提示——我们可在循环开头打印一次
6. **"有代价"意识**：alias/sweep 类试探每次都有内核代价——与我们的"每发都有代价"纪律一致，可引用其文案增强操作纪律

## 12. T2 完成：KoUpdater.java 热更新机制（[01:21]）

### 12.1 机制（观察 — 源码 414 行）
- 数据源：`https://api.github.com/repos/tiann/KernelSU/releases/latest`（官方 KernelSU）
- KMI 前缀：内核串含 "6.12" → `lkm-aarch64-android16-6.12`；否则 `lkm-aarch64-android15-6.6`
- 下载到 `<file>.part`，流式 SHA-256；**落盘前四重校验**：
  1. 字节数 == release size
  2. sha256 == release digest
  3. 内容含版本号（文件名 `_(\d{4,6})` 解析）
  4. 含 `vermagic=`（否则"这不是内核模块——拒绝使用"）
- 通过后原子替换（`renameTo`，失败 fallback copy）

### 12.2 与本机关系（推断）
- KMI 映射仅覆盖 6.6/6.12（android15/16）——**不含 6.1/android14**；本机 6.1.157 不在其覆盖内
- CGA-W00 的 KSU 是静态打包（kernelsu_cga.ko），不依赖此更新机制；此机制无本机增量

### 12.3 可借鉴要点（推断）
- "尺寸→哈希→内容特征→魔数"四重校验 + .part + 原子替换 = **"坏文件不落位"完整模式**，我们部署 payload 可采用同构
- 版本号弱校验作为"资产选错"检测层（便宜且能抓到手滑）

---

## 13. T3 完成：m6 路线（selx11）脚本与工具链精读 [02:30]

### 13.1 文件清单（观察 — APK `assets/route/m6/` 全部 12 项，sha256 已与 manifest 核对一致）
| 文件 | 大小 | 角色 |
|---|---|---|
| cve-2026-43499-bin-dc14 | 160240B | 设备专属 dc14——**fmps 载体**（9 处 fmps 串、0 处 sigreturn），非 kit 的 sig 版 |
| dc_ksu_run.sh | 2428B | App 流程入口（精简版，见 13.5） |
| kaslr_leak | 9808B | 与 kit 同尺寸、不同哈希（设备专属泄漏器） |
| kernelsu-os9-selx11.ko | 5533360B | selx11 模块，vermagic=`6.1.157-android14-11-g7d3922fade43` |
| kernelsu.ko | 5459384B | App 流程实际装载的模块（vermagic `6.1.128`，221 个 UND） |
| ko_patch2 | 9992B | 符号重基址工具（13.2） |
| next_sym_addr.txt | 7703B | 231 符号静态地址表（基准 init_task=0xffffffc00a2017c0） |
| ksu_loader.sh | 39466B | 装载链（旧版，见 13.5） |
| ksud | 4556352B | KSU 用户态套件 |
| load_selx11_full.sh / phone_fire.sh / phone_load.sh / post_root.sh / window_chain.sh | 1–4.6KB | **手动流程脚本**（App 不调用；App 仅跑 dc_ksu_run.sh） |

### 13.2 ko_patch2 机理（观察 — capstone 反汇编 main@0x1cd0 全函数）
- 用法：`ko_patch2 <module.ko> <live_init_task_hex16> [sym_addr_file]`
- **硬编码静态基准** init_task=0xffffffc00a2017c0（与 next_sym_addr.txt 一致；二进制内以负常数 0x3FF5DFE840 存放）→ `slide = live_IT − 静态基准`
- 遍历模块 `.symtab`：凡 `st_shndx ∈ {0 (UND), 0xfff1 (SHN_ABS)}` 的具名符号，查表命中即改写 `st_value = 表地址 + slide`、`st_shndx = SHN_ABS`
- 守卫：改写后仍有任何 UND → `ABORT (add to sym list)`（防 init_module 失败）；匹配 0 个 → `nothing patched (already SHN_ABS?)`；入口校验 init_task 合理性门 / ELF64 / ET_REL
- 回写：in-place `fopen("r+b")` + fwrite + sync + 打印 `OK: %d symbols -> SHN_ABS (slide 0x%llx)`

### 13.3 关键判别：selx11.ko 是"预烧录 variant"（观察 → 推断）
- 实测 selx11.ko 符号状态：**0 UND、282 ABS**（其中 218 个名字在表内；**全部 218 个共享同一差值 Δ=0x2115C00000**，2MiB 对齐）→ 该 ko 出厂时已按某次 boot 的地址烧录
- 推断：发布版靠开火前跑 **ko_patch2 无差别重写 UND/ABS 两类符号**实现"按本 boot slide 重定位"；App 流程的 kernelsu.ko 则保持常规 UND 形态、由 load_ko 运行时从 /proc/kallsyms 解析 → **m6 是"两条并行符号路线"的设备**
- 佐证（观察 — load_ko 字符串）：自定义用户态装载器：`undefined symbols to resolve: %d` → `resolved %ld/%d from /proc/kallsyms` → `patched %d symbols to SHN_ABS`；装载用 `finit_module flags=%d`（可带 IGNORE_VERMAGIC——解释 6.1.128 vermagic 模块可上 6.1.157 内核）；未解析完即 abort

### 13.4 m6 手动脚本要点（观察）
- **phone_fire.sh**：单发 + **uptime 90–300s 窗口门**（>300s 判"boot 脏了"直接拒发）+ 命中判据 = `getenforce==Permissive && rootd.fifo 存在`（8 分钟轮询）+ 装载/验证
- **post_root.sh**：真阳性守卫（非 uid0 直接退出，防 miss 轮伪证据）+ kptr_restrict=0 + **全量 kallsyms 快照（"本 boot 专属 = 符号 oracle"）** + slabinfo + rootd fifo 常驻 daemon（"命中一次全 boot 可用，600s+ 不复位"）
- **window_chain.sh**：命中后固定顺序——id 确认 → selx13 备弹上膛（拷成 kernelsu_bvl16.ko，先存 pristine 备份）→ insmod → 判据行 grep → suas allowlist dump → dmesg → ReZygisk 情报。注：selx13.ko 不在 APK 资产中（源软件包遗留；同类遗留还有 ksu_root_bvl16/一键装载.sh 文件名）
- load_selx11_full.sh / phone_load.sh：`ko_patch2 + load_ko` 链的独立重放

### 13.5 m6 vs kit 流水线差异（观察 — diff）
- m6 dc_ksu_run.sh **无**：ALLOW_MULTISHOT 多连发开关、aff_diag、OPTS 注入、USE_SIGRETURN 载体选择、taskset 绑核、SLIDE_DIAG 页内自证；KSNITCH_CPU=7（kit=8）
- m6 ksu_loader.sh **无**：双模块 fallback（kit 有 kernelsu.ko + kernelsu_fallback.ko 两级）、chcon ksu_file 修复（09-28）、post_load 钩子、wakelock 防休眠、KEEP_SIG_OFF；SELinux 收尾为旧行为（默认留 Permissive）
- ⇒ **m6 = kit 流水线的老/简化分支**，与 RouteKit 描述"成功率低，失败需重启"一致
- **修正 §3.1 的旁证（观察）**：manifest 显示 v3.8 中 kit 的 `dc14` 与 `dc14-sig` 同为 sha 0c99f8b4（与我们在用文件一致）；实测该二进制 33 处 sigreturn 串、0 处 fmps ⇒ **v3.8 已把 kit 默认载体固定为 sigreturn 版**（对应 10-03 修复注释）。`dc14-sig1`（788a44e5）同为 sig 载体、另一构建，用途未知

### 13.6 未知
- "selx11/selx13" 字面含义（模块与 loader 内无 "selx" 串；推断为内部版本号/代号）
- next_sym_addr.txt 出自哪次构建（推断 = BVL-AN16 某 boot 的 kallsyms 规范化表；13 个表项不在 selx11 的 ABS 中，留作兼容）
- Δ=0x2115C00000 的确切来源（推断 = 烧录侧那次 boot 的地址位移）

## 14. T4 完成：mep 路线（preload.so）机制 [02:30]

### 14.1 投递方式（观察）
- 载体：`preload.so`（246640B，aarch64 共享库，clang 21.0.0/LLD 21 构建——比 m6 的 clang18、m8 更新）
- 机制：**LD_PRELOAD 构造函数投递**——`.init_array[2] = load@0x35ce8`，以 `LD_PRELOAD=$D/$NAME.so /system/bin/sh -c 'echo FIRE_DONE'` 启动时，dlopen 即触发整条漏洞链（无独立 exploit 二进制）
- 调用（mep_run.sh）：`SLIDE_CARRIER=sigreturn NEO11_ROOT_CHAIN=1 NEO11_SIGRETURN_TABLE=1 …`；判据：diag 出现 `route returned`/`root=1` → `libksud late-load --allow-shell`
- 参数字典：NEO11_*/SLIDE_*/TMP_* 100+ 环境变量（rodata 1517 串已存 `extracted/mep_preload_rodata_strings.txt`）

### 14.2 功能模块（观察 — .symtab 325 个可读命名 FUNC）
| 家族 | 代表符号 | 含义 |
|---|---|---|
| futex | futex_hash/__futex_hash；`route: CMP_REQUEUE_PI` | rtmutex PI 路线（与 43499 同源） |
| kernelsnitch | kernelsnitch_setup/find_collisions/bruteforce/__mm_leak | 布局探测/碰撞定位 |
| slide 写原语 | slide_owner/waiter/consumer 三线程；**pselect/sigreturn/mcast/sendmsg/recvmsg 五种写 stage**；slide_res_arm_bitmaps | 多载体可切换 |
| pipe | pipe_phys_read/write、forge_pipe_buffers_on_page、pipe_cache_matches、pipe_reclaim_cache_gate | pipe 页级物理读写 |
| 别名/物理 | p0_data_alias、p0_alias_image_offset、kaslr_image_addr | 物理别名（同 m8 思路） |
| 泄漏 | tracefs-kaslr-ok（回退 pselect）、perf_leak_text_base | 双渠道 |
| oracle | make_zero_oracle_marker/zero_page_has_marker | 零页回收判定 |
| 还原/修复 | restore_slide_boot_id、repair_fake_fops_llseek、refresh_fake_fops_text、`rootchain: RESTORE misc_fops` | 与我们同代世界观 |
| 提权/持久 | patch_cred_identity/sid/object、install_embedded_su（内嵌 su）、**install_embedded_wallpaper**（壁纸文件写盘）、io_daemon_main（常驻 IO daemon） | 完整收尾链 |

### 14.3 推断
- mep 是与 dc14 平行的**第二条 43499 实现线**（另一团队风格：全函数级命名、LD_PRELOAD 投递、FIRE_DONE 流程）
- 共性：boot_id 还原、fake fops 修复、KSNITCH 泄漏、pipe 原语、late-load KSU——证明这些是此 CVE 的"标准配方"
- 独有：构造函数投递、五载体可切换、tracefs 泄漏、壁纸/内嵌 su 持久化、zero oracle
- 与本机无关（MEP-AN00 设备）；目标内核未知（rodata 无版本串，靠运行时扫描）

## 15. T8 完成：lsp / netfix 脚本分析 [03:35]

### 15.1 资产与调用关系（观察 — 关键发现）
- 资产：`assets/route/lsp/{lsp_enable.sh 5155B, lsp_status.sh 1523B}`、`assets/route/netfix/{netfix.sh 4347B}`；均在 `manifest.json` 顶层键中（manifest 组：common/kit/**lsp**/m6/m8/mep/**netfix**）
- **但：v3.8 的代码完全不引用它们**——
  - `RouteKit.Route` 枚举仅 4 项（KIT/M6/M8/MEP），`deploy()` 只推 `route/common`+`route/<key>/`，且显式跳过 `manifest.json`（RouteKit:164）
  - dex 全量扫描（classes.dex，228KB 单 dex）：`lsp`/`LSP`/`LSPosed`/`zygisk`/`zn-daemon`/`netfix`/`route/lsp`/`route/netfix` 全部 **0 命中**；"启用"仅 1 处（与 LSP 无关）、"修复"6 处（均属 KernelSU 修复器/载荷修复文案）
  - MainActivity 中 `.sh` 文件名常量仅 3 个：`dc_ksu_run.sh`、`mep_run.sh`、`m8_run.sh`
- ⇒ **推断**：lsp/netfix 是「提前装船」的休眠资产——脚本头注释描述的 App 按钮（「启用 LSPosed」「修复lsp」「修复网络」）在 v3.8 中不存在，为下一个 App 版本预置（或作者渠道手动分发用）。**这是 ppgroot 迭代方向的路标：它正在把"root 后运维"（LSPosed 启用 + 网络修复）做进 App。**

### 15.2 lsp_enable.sh 机制（观察）——与本机场景完全同代
- 开篇自述：**"在我们这套「开机后运行时 LKM」的 root 上把 LSPosed 真正拉起来"** ——即本机（CGA-W00）同类 root 场景
- 原理：LSPosed 需要 Zygisk，而 Zygisk 必须在 zygote **启动瞬间**注入；开机后拿到的 root，zygote 早已跑起来 → 直接起 ZN 会 "Last injection failed!"。解法：起 ZN 守护 → **`stop/start zygote` 软重启**（只重启用户态框架；内核 KSU 模块不受影响，root 保留）→ 新 zygote 启动瞬间被注入 → LSPosed 激活弹通知
- 七步流程：① `echo 1 > /data/adb/zygisksu/klog` ② 删 ZN `disable` 标记 ③ 重启 zn-daemon（kill -9 + 跑 post-fs-data.sh，pid 校验失败即退）④ 清 `.abort_msg` + 确保 lspd ⑤ 软重启 zygote（记录旧/新 pid；等 sys.boot_completed，全程 20-60s，关所有 App）⑥ monkey 拉起 `org.lsposed.manager`（靠它弹通知）⑦ 按 netfix 分诊结论自动修网络
- 判据：`.abort_msg` 存在=注入失败；`dumpsys notification --noredact` 中 "LSPosed 已加载/未加载/已激活"
- **身份守卫（2026-09-21 加）**：App 经 Shizuku shell 通道启动脚本，Shizuku 常以 shell(2000) 启动 → 脚本首步 Permission denied（表现为"点了没反应"）；守卫写法：`[ $(id -u) != 0 ] && command -v su && exec su -c "sh $0"` 自提权重跑。**该模式对我们任何经 Shizuku 通道的脚本同样适用**

### 15.3 netfix.sh 分诊机制（观察）
- 三病三修（表现都是"App 说没网"）：
  - **A. netd 路由脱同步**（内核 IPv4 默认路由消失 → ping 不通）→ 修：`setprop ctl.restart netd`；重启 netd 会瞬断当前会话 ⇒ 复验写入 **detached 后台进程**（nohup + netfix.log），脚本自己提示"20 秒后重跑 status"
  - **B. KSU 框架沉降**（路由/ping 都正常，只是 App 报没网）→ 修：`kill -9 $(pidof com.hihonor.android.launcher)`（重启桌面，"别重启平板"）
  - **C. 框架没有默认网络**（内核路由在、ping 通，但 `Active default network: none`）→ 修：重连 Wi-Fi
- **硬知识（脚本自述实测，2026-09-28）**：`svc wifi disable/enable` 之后**必定丢内核默认路由（A）** ⇒ C 的标准修法 = "reconnect 重连 **+ 紧跟着兜底跑一次 A 的修**"（脚本一次做完）
- 机器可读判据：`VERDICT: route=有/缺失 ping=通/不通 defnet=<name>/none`；调用方（lsp_enable 第 7 步）按 case 分派：`defnet=none`→C、`route=缺失`→A、`ping=不通`→上游问题、其余→正常。**"分诊输出 VERDICT 行 + 调用方 case 分派"是可复用设计模式**
- 三个用法：`sh netfix.sh`（诊断+修 A）/ `reconnect` / `status`（只读不动）

### 15.4 适用性（推断）
- 这两个（三个）脚本的场景 = "荣耀设备 + 开机后运行时 LKM root"，与本机（MagicPad3/CGA-W00）**完全同代际**（honor launcher 包名、hihonorcloud 连通性检测域名均为荣耀系）⇒ **可直接用于我们平板后续的 LSPosed 启用 / 网络运维**（前提：平板已装 ZN + zygisk_lsposed 模块）
- 未知：平板当前是否已装 zyigisksu/zygisk_lsposed 模块（决定 lsp_enable 能否直接用）
- 对工具链的启示（→ T10 候选）：① 身份守卫模式 ② VERDICT 分诊+case 分派 ③ 破坏性操作（netd/zygote 重启）的 detached 复验模式

### 15.5 未知
- 带按钮的 App 版本号/发布时间（v3.8 无按钮，脚本注释表明存在/将存在）
- "B. KSU 框架沉降"的机理（脚本未解释为何 KSU 加载会令桌面报没网）

## 16. T5 完成：device-registry.json 全表解析 [03:35]

> 全表结构化导出已存 `extracted/registry_full_dump.md`（A: 11 设备主表 / B: 内核条目+门控字段 / C: 64560 台账 10 条 / D: summary 原表）。以下只记关键结论。

### 16.1 元数据（观察）
- schemaVersion=2；generatedBy=`tools/compile_device_registry.ps1 (+ 手工追加 mtn-an80)`；generatedAt=2026-10-13 15:00:16
- policy（原文）：*"只有 status=adapted 且 verified=true 的内核才允许跑内核漏洞；其余一律拒绝。"*
- kernelCount=9；scannedDirs=`boot_images`；payloadDir=构建机路径 `C:\Users\Admin\Downloads\deepseek-harness2\...\PPG-AN00-64560-临时root\apk-build\assets`（**考古：64560 线的开发目标机 = PPG-AN00/GT Pro**）

### 16.2 11 台设备路线图（观察 — 与本机相关部分加粗）
| deviceId | 机型 | 默认路线 | 备注要点 |
|---|---|---|---|
| **cga-w00** | **MagicPad3** | **43499:kit** | "首次适配这套方案的原始设备"；与 X70 同一次内核构建（g19a495a） |
| x70 | MTN-AN80 | **43499:kit** | **与 CGA-W00 同构建**；其 64560 载荷（pl_mtn-an80 fanout/rotate）在包内但默认走 kit |
| bvl-an16 | Magic6 Pro | 43499:m6 | m6 已被真机验证成功；64560 未跑通 |
| mep-an00 | 500 Pro | 43499:mep | 6.6.118，与 V5 同内核 |
| aap-an00 | WIN | 混合（6.12.38→m8 / 6.12.58→64560） | |
| gtpro / aak / magic7pro / pnm | GT Pro / WIN RT / Magic7 / V6 | 64560 | 6.6.x + 6.12.58 族 |
| mbh-an10 | Magic V5 | 43499:mep 主 + 64560 例外 | |

### 16.3 64560 台账（devices[] 10 条，观察）
- **MTN-AN80 条目升级**：matchRank=3（**boot.img 整镜像 sha256 命中**）、status=adapted、verified=true；buildStamp `Wed May 20 08:35:21 UTC 2026`（与 CGA-W00 内核同一次构建）；仍标注"未经真机 --preflight 验证"
- bvl-an16：fingerprint `HONOR/BVL-AN16/BVL-AN16:16/...10DLDLD175C00E157`、securityPatch 2026-08-01、bootloaderLocked=true；rank3
- gtpro-ebb / aak-ebb：rank3/rank2 + verified=true；e8ce、48b6、2b15 各条 verified=false
- **CGA-W00 确无 64560 条目**（载荷已移除；我们与 X70 同构建 ⇒ X70 载荷理论上覆盖我们的内核——**推断，未真机验证，且铁律禁止操作平板**）
- matchRank 语义：3=整镜像 sha256 命中（最可信）/ 2=release+构建时间戳命中（清单声明）；matchRank 在代码中**仅作展示**，不参与放行逻辑（DeviceRegistry:444 加载后无逻辑引用）

### 16.4 放行门禁的真实实现（观察 — DeviceRegistry.match()，853 行）
- 双闸门：
  1. **内核闸**：release 命中 + buildStamp 一致（不一致 → "视为未核验，不放行"）；entry.verified=false 且无"未核验确认" → 拒绝
  2. **载荷闸**：候选打分 = base 2 + buildStamp一致 4 + ownerDeviceName匹配 4 + declaredVerified 1，取最高分；declaredVerified=false 的载荷 → `unverified=true`，需 `match(localKernel, z=true)`（用户确认风险，MainActivity:1379 二次匹配 + 弹框 + "已确认风险，开始提权。"）才放行
- **gateFree 回退**：载荷无机型门禁时按【内核身份】判定（isCompatible = release+buildStamp 逐字），注释明言"这是 GT Pro / WIN RT / Magic7 Pro 共用载荷的预期行为"；非兼容的 gateFree 载荷警告"物理内存布局是借用的，风险较高"
- 机型门禁 gateDevices：机型码白名单（如 HNAAP/BKQ-AN90/PNM-AN20/HNPNM/HNPNM-Q）；用户手动指定内核/载荷也有校验+回退（"不匹配，已忽略，改用自动选择"）
- ⇒ **这套"内核身份（release+时间戳）+ 机型码 + 载荷归属 + 核验标记 + 用户确认"的多层门禁，是我们工具链可直接借鉴的资产校验模型**（→ T10）

### 16.5 未知
- kernelCount=9 精确口径（可枚举 9 个 pl_* 资产，summary 7 行；推断=按载荷资产计数，未证实）
- mtn/bvl 条目 "PLACEHOLDER" soc 字段（数据未补全）

## 进度记录（滚动）
- [01:20] 首轮：环境 + RouteKit + KIT 对比
- [01:35] 第 7 节：64560 第二漏洞线发现（本机内核构建的载荷存在）
- [01:21] 第 9 节（T6）：ghostlock_m8 全量 CLI——身份=43499 mk2、106 参数、无 6.1 覆盖、help dump 完成
- [01:21] 第 10 节（T7）：命中率来源核实 → MainActivity:4055 启动文案（声称值）
- [01:21] 第 11 节（T1 核心）：自动化设计梳理——配额/重跑3轮/缓存校验/预检/门控/推送校验
- [01:21] 第 12 节（T2）：KoUpdater 热更新——四重校验+原子替换
- [02:30] 第 13 节（T3）：m6 路线精读——ko_patch2 反汇编（符号重基址全机理）、selx11 预烧录 ABS 判别（Δ=0x2115C00000）、load_ko 用户态装载器、m6=kit 老分支、kit 默认已合并 sig 载体
- [02:30] 第 14 节（T4）：mep preload.so——LD_PRELOAD 构造函数投递、五写载体、pipe physrw、内嵌 su/壁纸持久化、NEO11 参数族
- [03:35] 第 15 节（T8）：lsp/netfix——休眠资产判定（dex 零引用）、zygote 软重启启用 LSPosed（与本机同场景）、netfix 三病分诊（svc wifi 必丢内核路由的硬知识）、身份守卫/VERDICT/detached 复验三模式
- [03:35] 第 16 节（T5）：registry 全表——11 设备路线图、64560 台账 10 条（mtn 升级 rank3）、真放行门禁（内核闸×载荷闸 打分制 + 用户确认）；全表导出 `extracted/registry_full_dump.md`
- [04:35] 第 17 节（T9）：**最终对比表**——本机可用性裁决（KIT 无超越/64560 储备/m8 不可移植）+ KIT 两方对照 + 全路线技术矩阵。§3.3 同步加定稿注记。
- [04:35] 第 18 节（深挖）：**ghostlock_m8 反汇编级还原**——发现 m8/dc14 均未 strip（双符号级对比）；alias-oracle 三态判据全流程、faketab/ARW 标定机制、purgerec 净化-重占-伪锁全叙事；dc14 vs m8 十维差异总表。
- [04:35] 第 19 节（T10）：**可借鉴清单最终版 21 条**（A 立即可用 4 / B 工具工程 6 / C 漏洞工程 6 / D 门禁模型 2 / E 无需行动 3）。**待办全清。**

---

## 17. T9 完成：最终对比表 —— ppgroot 全路线 × 我们的方案（[04:35] 定稿）

> 目的：一页回答"ppgroot 对 MagicPad3/CGA-W00 是否有任何超越" + 全路线技术矩阵。
> 证据：本报告 §1–§16、§18；我方侧：`.workbuddy/app_root.sh`、`一键Root.bat`、`GhostLock_击中目标与成败分析报告.md`、`.workbuddy/hitsample/`。

### 17.1 本机（CGA-W00 / 6.1.157-android14-11-g19a495a97bff）可用性裁决

| ppgroot 路线 | 目标内核 | 本机可跑？ | 裁决（观察 → 推断） |
|---|---|---|---|
| **KIT（43499）** | 6.1.157 同构建 | ✅（同套件） | **无超越**。文件字节级相同；流程更保守（1 发/boot + 人工重启）。我们 = 严格超集 |
| **64560** | 6.6.x / 6.12.58 为主 | ⚠ 未知 | **潜在储备**：包内 `pl_mtn-an80_*` 与我们内核同构建（g19a495a）；但 CGA-W00 无部署条目（已移除）；铁律下不做真机验证 |
| **m6（selx11）** | BVL-AN16（6.1.x 另一构建） | ❌ | 参考：ko_patch2 符号重基址 / load_ko 用户态装载 |
| **m8（ghostlock mk2）** | 6.12.38 / 6.6.x | ❌（无 6.1 分支） | **思想级借鉴**（alias-oracle / purgerec / faketab）→ §18 |
| **mep（preload.so）** | MEP-AN00 | ❌ | 参考：LD_PRELOAD 投递 / 五载体 / 零页 oracle |

### 17.2 KIT 路线最终对照（我方 vs ppgroot v3.8）

| 维度 | 我们（现役：app_root.sh 自动循环） | ppgroot v3.8 KIT | 差 |
|---|---|---|---|
| 套件 | dc14≡dc14-sig + dc_ksu_run.sh + ksu_loader.sh + kernelsu_cga.ko（0c99f8b4…） | 完全相同 | = |
| 发射 | 3 发/boot × 20 boot（全自动：Shizuku→App→点击通道） | 1 发/boot（run.lock 纪律），**人工重启** | **我们 +** |
| 多连发 | `ALLOW_MULTISHOT=1`（3 发；第 2 发实测 30s 命中） | 默认关（App 不写 OPTS） | **我们 +** |
| 失败循环 | 自动重启→等 boot→再开火；panic 熔断（2 次停手） | 无（提示用户手动重启） | **我们 +** |
| 命中侦测 | 单 adb 调用合并三判据（HIT/DONE/静默）；DONE 早杀（省 13min）；240s 卡死检测 | dc_ksu.log 5s×96（8 分钟轮询） | **我们 +** |
| 黄金样本 | 命中即抢全量日志（已拿到） | 无此机制 | **我们 +** |
| 声称命中率 | 实测口径：多连发第 2 发命中 | "约 1/3~1/2"（启动文案，无统计支撑，§10） | 口径不同 |

**净结语（推断）**：KIT 路线对 CGA-W00 **无任何超越**；我们的补丁 + 多连发 + 自动循环是严格增量。

### 17.3 全路线技术矩阵（§13/§14/§16/§18 压缩版）

| 技术维度 | dc14（kit / 我们现役） | m6 selx11 | **m8 ghostlock mk2** | mep preload.so | 64560 pl_fanout |
|---|---|---|---|---|---|
| CVE | 43499 | 43499 | 43499 | 43499 | **64560**（posix-cpu-timers） |
| 形态 | 独立 ELF | 独立 ELF | 多阶段 CLI（--stage a/b/c/e/all） | LD_PRELOAD .so（init_array 投递） | fanout/rotate + stdin 脚本 |
| 写载体 | fmps / sigreturn | fmps | pselect/res-encode、pstack(sendmsg)、sigreturn、mcast… | 五载体可切 | pipe + order1 + configfs 桥 |
| 读通道 | fake fops lseek（**本机探针坏**→CFI_SKIP_VERIFY 盲信） | load_ko /proc/kallsyms | **faketab→proc_dostring 非破坏读 + 双读校验** | pipe physrw（read_ok 判据） | MISC_BRIDGE + PHYS_READ（gate 化） |
| 写后验证 | 无（盲信）；成败看 pipe physrw 下游 | ret/gate | **alias-oracle 读回判据**（landed/changed/same 三态） | zero-page marker | `*_PASS/_MISS_CLEAN` 全链 gate |
| miss 代价 | 写偏=panic/僵死；**禁同 boot 重试**（保护 PI 树） | 同左 | **静默写坏 2 处物理页**；可换候选重试（每次仍要打一发 UAF，"有代价"） | - | 主动恢复内核状态（KERNEL_STATE_RESTORE_NOT_PROVEN） |
| 页准备 | prepare_kernel_page + pipe/p0 oracle | - | **purgerec**：purge→buddy→sendmsg 重占→伪锁 base+0x4000 | 零页 oracle | ORDER1_RECLAIM_GATE |
| 尝试模型 | 1 发/boot（保守）→ 我们补 3 发/boot | 单发 + uptime 窗口门 | **--attempts N（usage 示例 20 发/boot）** | 重试 gate | App 侧 3 轮重跑 + 额度熔断 |
| 收尾还原 | boot_id / fake_fops 修复 | - | **faketab restore 一等公民 + sweep 后 table->data 还原钩子** | RESTORE misc_fops | 各 gate restore |
| 与我们的关系 | 我们 = 此线的加强使用者 | 老分支 | 下一代（不可移植） | 平行第二条实现线 | 第二漏洞线储备 |

### 17.4 最终裁决（重点目标①完成）
1. **KIT：无超越**（同套件、更保守流程；我们为严格超集）。
2. **64560：仅情报储备**（同构建载荷存在但未部署、未验证；铁律不验证）。
3. **M8：不可移植**（无 6.1 分支）；其"安全 miss / 读回判据 / 可重试"设计是全包最大思想价值（§18 → §19）。
4. **工具线可用物**：lsp/netfix 脚本（同代场景可直接用）、registry 门禁模型、ko_patch2/load_ko、KoUpdater 四重校验思想。

---

## 18. 深挖（本轮）：ghostlock_m8 反汇编 —— alias-oracle / purgerec / faketab 与 dc14 技术差异 [04:35]

### 18.0 方法（观察 — 本轮最大突破）
- **ghostlock_m8 未 strip**：`.symtab` 6254 符号（1703 个 FUNC，其中 124 个 `gl_*`）+ 完整 DWARF（覆盖 bionic libc）。此前 3 轮只能靠字符串猜结构，本轮起可符号级分析。
- **dc14 也未 strip**：`.symtab` 258 个 FUNC（含 kernelsnitch_* / slide_* / pipe_* / p0_* 全家族）⇒ **首次双符号级对比**。
- 工具链：capstone 5.0.7 全量反汇编 .text（449,984 B）、ADRP+ADD 解析定位字符串引用（22 个关键目标全部命中）、"代码序字符串叙事"重建函数意图。
- 新产物：`extracted/m8/ghostlock_m8_functions.txt`（1703 行全函数表）、`extracted/dc14_functions.txt`（258 行）、`extracted/m8/disasm_deepdive.txt`（4 函数全反汇编+字符串注释）、`extracted/m8/purgerec_narrative.txt`（73 条代码序叙事）。

### 18.1 alias-oracle 完整机理（观察 — `slide_try_phys_load` @0x250f0c，477 指令）
按反汇编顺序：
1. 入参 phys_load；`delta = phys_load − PHYS_OFFSET(0x80000000)`；打印 `[*] alias: 内核物理加载基址 = …`。
2. 计算写①目标别名 = `PAGE_OFFSET | (delta + 0x23ecf00)`（常量为目标镜像偏移）；与全局缓存比较，变化即刷新（`prim: 伪 waiter ->task = …`）。
3. **读基线**：`/proc/sys/kernel/random/boot_id`（open→read→trim CR/LF）。
4. **链走两笔受限写**（经 `gl_prim_ww`）：写① `[table->data] <- comm`、写② `[table->data+8] <- comm[8..16)`（Case-2 第二笔）；期间打印 `按 P1 反推物理: 写① PA=… 段索引 …`（≥512MiB 段索引）。
5. **读回判据**（再读 boot_id）——三态：
   - 逐字与基线相同 → `alias-oracle ✗ 写没落地 (或 phys_load 不对 / 链提前退出)` → **换下一候选（零重启）**；
   - 读失败 → `写后读 boot_id 失败 —— 指针可能已被写成非法值`；
   - 以 "swap"+"pper" 开头 → `✅ init_task.comm 读回 "swapper/"` ⇒ 别名公式 + phys_load + P1 未随机化**三者同时成立**；
   - 改变但不含 swapper → **锚点扫描**：遍历锚点表（stride 0x20，含 值/链接期地址/依据名），经 `gl_kaslr_from_leak` 反算 slide → `★ 别名链命中 (锚点 %d: %s)` / `反算 slide 被拒`。
6. **收尾**：把 `table->data` 还原；失败有显式警告 `收尾还原失败 —— 重启前 boot_id 通道仍是劫持态`。
- **代价公示**（help）：每个**错误**候选按别名写坏两处内核内存 + 打一发 UAF ——"不是免费试探"。
- **判据演化**：`扫描判据 = alias_verify_comm 的读回（不再依赖崩溃与否）；（第 69 轮结论）`（0x202080）。

### 18.2 faketab / ARW（观察 — gl_prim_calibrate @0x2505b4 / gl_prim_ww / gl_prim_read）
- **D-0 标定**：写 `random_table[4].boot_id.data <- init_task.comm-8`（避开 uuid[8]==0 的破坏性分支）；两种 node 编码各试一次；命中即"**受限写成立 + 表项地址正确 + slide 正确**"一次性证明；随后读通道升级。
- **写**：`gl_prim_ww(addr) <- val`，日志 `[enc ret errno] (第 N 发)` —— 每次写入都是可计量的"发"。
- **读**：`gl_prim_read` 走 boot_id 通道 + `GL_PRIM_DOUBLECHECK` 双读一致性校验（`二次读不一致 (有其他写者)`）；proc_dostring 非破坏式；`gl_faketab_restore()` 收尾归还表项（**劫持登记制**）。
- **与 dc14 对照**：dc14 读通道 = fake fops/ashmem lseek（本机探针坏 → CFI_SKIP_VERIFY 盲信）。m8 把"读"从**函数表替换**降级为**单指针重定向 + 标准 proc 读路径**：破坏面小、可校验、可还原。

### 18.3 purgerec 机理（观察 — `gl_purgerec_run` @0x2556c4，73 条代码序叙事）
自述定位：`可控内核页: 把 KernelSnitch 泄漏的 mm_struct 页还给 buddy 并重占`；`零重启风险: 只有 fork/kill/读 slabinfo/sendmsg, 不触发 UAF`。
1. 预备：持久化 `/proc/slabinfo` fd（读缓冲预热）；warmup 对齐。
2. 页面收编：①prepare → ②spray → ③ks setup → ③b 页对齐 → ④pre(Δ=+1) → ⑤leak-child(Δ=+0) → ⑥post(Δ=+1)；⑦⑧ v2.7 跳过 memfd / pre·leak·post 保活。
3. ⑨ 泄漏：KernelSnitch 泄漏 mm_struct；**MTE 顶字节归一化**（0xff=KASAN_TAG_KERNEL）；`泄漏子进程保活（占住 P 第 25 个对象，P3 才 kill）`；**owner 修复**（usage@+0x40=0x1000 ⇒ [9] wake 块整块跳过，第 46 轮）。
4. 布局铺设：伪锁 `{wait_lock=0, rb_node, leftmost, owner=FT}`、伪节点 V {BLACK, prio=0}、**哨兵 V->task=0x5a5a09ec**（"未出现 ⇒ 未被当任务解引用"）、第 109 轮多组 stride 铺、第 118 轮伪 cred（security/user/user_ns/ucounts/group_info；`侧写改道 *(base+off)=node ⇒ off=0x10 砸 suid/sgid 保 uid`）。
5. **P0–P4 净化链**：P0 fork+kill 预热 task_struct/order-2 栈缓存 → P1 预建 → P2 pad put（nr_partial≥5）→ P3 P 清空（inuse=0）→ P4 flush put ×3 ⇒ `discard_slab` 还回 buddy；**"自此到 sendmsg 重占之间不读 /proc、不 fork"**（纪律明文）。
6. **重占**：sendmsg order-3 frag 抢回目标页；判据 `Δcap=-25 / Δslabs=-1` + fork 探针（"第 N 个填充子进程触发新 mm_struct slab 页"）；失败分支 `未命中 discard，清理后重试（%d/%d）`（**同类内自动重试**）。
7. 收尾：`伪锁布局写入载荷` → ⑨b 重新对齐（判据 `readback[0x4008]==[0x4010]==V`，另看 `FT->usage +1`）。
- 目的（推断）：让伪造 waiter 的 `->lock` 指向**真实映射、内容全 0** 的 `base+0x4000` ⇒ rtmutex.c:842 `raw_spin_trylock` 不 oops、链走干净可复现（第 70 轮："与 phys_load 无关，链走应恒干净"）。

### 18.4 dc14 vs m8 差异总表（观察 + 推断）

| # | 维度 | dc14（我们现役） | ghostlock m8（下一代） | 差距性质 |
|---|---|---|---|---|
| 1 | 血缘 | kernelsnitch_* / slide_* / pipe_* / p0_* | gl_* 重构 + 保留同名 kernelsnitch_* | **同源**；m8 = 重构 + 扩展 |
| 2 | 写后验证 | CFI lseek 探针（本机全坏）→ 盲信 | alias-oracle 读回三态判据 | **m8 领先**：区分"没落地 / 落地但下游失败" |
| 3 | miss 语义 | 写偏 = panic/僵死；同 boot 禁重试 | 静默写坏（有代价但可继续） | **m8 领先**：可重试性 |
| 4 | 读通道 | ashmem fake fops（替换函数表） | faketab 单指针重定向 + proc_dostring + 双读校验 | **m8 破坏面小 + 可校验 + 可还原** |
| 5 | 页准备 | pipe/p0 oracle + res-encode 写回 | purgerec 净化 + 重占 + 伪锁 | **m8 系统工程化**（探针/统计/重试齐全） |
| 6 | 尝试模型 | 单发纪律（+我方 3 发补丁） | --attempts N（20 发级） | 前提 = 第 2/3 条 |
| 7 | 阶段 5 | 无 uinput 线 | stage5 uinput_misc 桥 + 页内 payload patch | m8 多一条执行通道 |
| 8 | 收尾 | boot_id / fake fops 修复 | faketab restore 制 + 还原钩子 | m8 制度化更强 |
| 9 | 迭代痕迹 | 10-03 载体修复（单点） | "第 38–118 轮"变更日志内嵌二进制/help | m8 量级碾压 |
| 10 | 可移植性 | **6.1.157 ✓（我们现役）** | 无 6.1 分支 ✗ | **现实中我们唯一能跑的就是 dc14** |

### 18.5 未知
- alias-oracle 依赖 `random_table[4]` 表项偏移（6.6/6.12 布局）；6.1 是否同偏移未验证（不可移植主因之一，另一是 perf/kstack 布局假设）。
- 伪锁 `base+0x4000` 的"恒干净"依赖链在 purgerec 失败路径上的残留行为未完全展开。
- 个别常量归属（如 0x23ecf00 为哪一表项偏移）为脚本推断；capstone 手工解析 ADRP/ADD，理论上有遗漏引用。

---

## 19. T10 完成：可借鉴清单（最终版）[04:35]

> 素材：§11.6（64560 自动化六条）+ §15.4（lsp/netfix 三模式）+ §16.4（registry 门禁模型）+ §13（m6 符号链/post_root）+ §14（mep 投递）+ §18（m8 深挖）。按行动类型分组。

**A. 立即可用（平板运维，不需研究）**
1. **lsp_enable.sh + lsp_status.sh + netfix.sh 全量移植**——与本机完全同代（荣耀 + 开机后运行时 LKM root）。用途：LSPosed 启用（zygote 软重启）与三病网络分诊。前置未知：平板是否已装 zygisksu + zygisk_lsposed（用 lsp_status.sh 先查）。
2. **身份守卫模式**（`[ $(id -u) != 0 ] && command -v su && exec su -c "sh $0"`）：任何经 Shizuku 通道的脚本首步加一行，治"点了没反应"。
3. **VERDICT 分诊 + case 分派**：诊断脚本输出机读判据行，调用方 case 分派（netfix 模式）。
4. **破坏性操作 detached 复验**（nohup + 退出后 20s 复验）：重启 netd/zygote 类操作的标配姿势。

**B. 循环/工具工程（改 app_root.sh 及部署链）**
5. **回合重置模板**：重跑前 pkill 残留 + 清日志 + 状态清零；对应到我们：同 boot 多连发之间可加轻重置（核验 run.lock/清 diag）。
6. **失败三态分类**（dirty/early/in-race）：把 miss 细分为"未进竞态 / 竞态后 miss / 状态脏"，决定"再连发 / 直接重启 / 熔断"。
7. **90s 启动判据**：开火后 90s 无输出 = "没启动"（区别于"打一半失败"）；我们现有 240s 卡死检测偏粗。
8. **推送四重校验**（KoUpdater 模式：尺寸→sha256→内容特征→magic + .part 原子替换）：部署 dc14/ko 资产至少补"尺寸核对" 1 层。
9. **环境门控提示**（不拦路）：开火前打印一次温度 + slab 基线，仅异常时劝"先重启"。
10. **"有代价"纪律文案**：把"每发都有内核代价"明示固化到循环开头提示行。

**C. 漏洞工程（m8 深挖产出 —— 思想级，供未来 6.1 分支/同类工具参考）**
11. **安全写后验证（alias-oracle 思想）**：优先找"落地与否有良性观测量"的验证目标（表项重定向 + 标准读路径回读），替代盲信式 CFI_SKIP_VERIFY；至少把"写没落地 / 写落地但下游失败"区分开（对照我方击中报告：lseek 探针全坏，可能含"已落地却被放弃"的案例）。
12. **非破坏读通道（faketab 模式）**：单指针重定向 + proc 读 + 双读一致性校验 + restore 钩子（劫持登记制）；比 fake fops 大改造破坏面与收尾成本小得多。
13. **可控页伪锁（purgerec 思想）**：写窗口 `->lock` 指向"自有、全 0、真实映射"的页内地址，是"可重复尝试"的地基；现役 dc14 用 res-encode/prim-lock 候选，若未来需提升同 boot 尝试数，此路线为关键参考。
14. **同 boot 重试的前提条件**：m8 的 --attempts 20 级靠"第 11–13 条组合"（miss 静默化 + 还原制 + 干净锁）；我们 3 发/boot 边界（第 4 发退化）本质是"miss=脏"的约束——**要升级先解决 miss 静默化**。
15. **判定探针独立性**（第 58/69 轮教训）：判据不要依赖单一易坏探针（我们 lseek oracle 的教训同款）；用"读回 + 哨兵值 + 双重读"多源判据。
16. **变更日志内嵌**（第 N 轮标记 + help 全文）：我们已有 devlog 习惯，可对齐"轮次号 + 判据演进"的最小写法。

**D. 门禁与资产模型（registry §16.4）**
17. **双层门禁模型**：内核身份闸（release+buildStamp 逐字）+ 载荷闸（归属/核验打分）+ 用户确认位；适用于我们维护多载荷（dc14-sig / dc14 / 64560 若启用）。
18. **gateFree 回退 + "借用布局"警告**：无机型门禁时按内核身份判定并给显式风险文案——可移植到我们的资产自检。

**E. 已吸收 / 无需行动（判定）**
19. KoUpdater：KMI 仅覆盖 6.6/6.12，无 6.1 增量（仅借其校验模式）。
20. ko_patch2 / load_ko（m6）：我们的 KSU 装载链已等价或更强（kit loader 更完整）；保留为"预烧录 ABS 模块"技术储备。
21. 64560 自动化（3 轮重跑/额度/预检）：宿主是 fanout 载荷（未部署到我们），流程设计参考即可。

### 19.1 重点目标核对
- ① ppgroot 对我方 CGA-W00 有无超越 → **§17.4：KIT 无；64560 仅储备；m8 不可移植**。
- ② m8 路线"零重启重试 / alias-oracle / purgerec"细节 → **§18.1–18.3 已反汇编级还原**。
- ③ 最终对比表 + 可借鉴清单 → **§17 + §19（本清单 21 条）**。

---

## 20. 深挖·第 11 轮：64560 mtn-an80 双载荷 fanout vs rotate 差异 [06:15]

> 触发：§7.5 遗留"fanout vs rotate 差异（待反汇编对比）"——本轮完成。这是全包唯一与我们内核（6.1.157 g19a495a97bff）同构建的第二漏洞线载荷。
> 产物：`extracted/64560/`（两载荷 + 字符串表 + `seq_align.txt` 序列对齐 + `disasm_regions.txt` 差异区反汇编）；工具脚本 `scripts/cmp64560.py / align64560.py / ref64560.py / seq64560.py / disasm_regions.py / funcs64560.py`。

### 20.1 结构对比（观察）
| 项 | fanout | rotate |
|---|---|---|
| 大小 / md5 | 98792B / b628f4a9 | 98656B / 151efd63 |
| ELF 节 | 26 节、**无 .symtab（已 strip）** | 同（strip） |
| `.text` | 62848B @0xb730 | 62904B @0xb670 |
| Android note 构建号 | 14206865 | 14206865（同构建环境） |
| CLI | `--preflight \| --probe-task \| --run` | 完全相同 |
| 共同字符串 | 458 条 | 458 条（仅 F 独有 11 / R 独有 5） |
| 指令总量 | 15712 | 15726 |

### 20.2 内嵌目标门禁三常量（观察 — 本轮最大发现）
两载荷均内嵌**我们内核的完整身份三常量**（`.rodata`，多处引用）：
- `6.1.157-android14-11-g19a495a97bff`（release）
- `Wed May 20 08:35:21 UTC 2026`（buildStamp）
- `fc81bc9b81ba93f6b2b1261129d3100fe07eb65772b547b7e3f79e1daa542b9e`（version_sha256）

- 与 registry mtn 条目逐字一致（release、buildStamp 直接印证）；**sha256 为载荷单独内嵌**（registry 中无此字段）
- 门禁形式：`PROFILE_GATE_MATCH by=kernel+sha256 …`（全匹配）/ `by=kernel …(DEGRADED)`（降级仍继续）/ `by=fingerprint`；另有 `TARGET_PROFILE_GATE_FAIL/PASS fingerprint=%s … pipe_reclaim=%d repeats=%d batch=%d attempts=%d controlled=%d`
- **sha256 输入串未确认（未知）**：用 registry 的 banner（含脱敏占位 build-user@build-host）的多变体（含/不含换行、空格、NUL）计算均不匹配 ⇒ 输入很可能是**设备实机 /proc/version（或 linux_banner）的原文**，registry 的 banner 为脱敏文本故无法离线复现。设计意图（推断）= 比 release+buildStamp 更防伪的"版本串精确指纹"
- **全载荷普查（观察）**：9 个 pl_* 中 4 个含 sha256 门禁（mtn×2、bvl-an16、gtpro118）；其余 5 个（aakan/aap×2/gtpro-d59f/gtpro-e8ce）只有 release/stamp ⇒ **三常量门禁是 v3.8 期的新增量，旧载荷未回填**

### 20.3 两变体的分工差异（观察 + 推断）
**A. fanout 独有 = 预算管理强化（PIPE_RECLAIM + BRIDGE_BUDGET）**
- `PIPE_RECLAIM_TRIM want=%d got=%d`：回收不足时记录并 trim 到 min=0x28（40）
- `/proc/sys/fs/pipe-user-pages-soft` 读取（fd 打开→读→关闭，值并入 READY 行）——**感知系统 pipe 页软限额**
- `PIPE_RECLAIM_LIMIT index=%d errno=%d`、`PIPE_RECLAIM_READY reclaim=%d drain_released=%d pipe_user_pages_soft=%ld`
- `PIPE_PREP_FAIL stage=grow_reclaim index=%d errno=%d grown=%d min=%d`（rotate 同串只有 2 字段）
- `BRIDGE_BUDGET attempt=%d/%d remaining=%d elapsed_ms=%lld` + `BRIDGE_BUDGET_HINT remaining=%d`：MISC_BRIDGE 阶段循环内每轮打预算行；含纳秒换算魔法数 `0x431bde82d7b634db`（÷10⁹）与 `0x3b9aca00`（10⁹）——**桥接尝试有明确计数器与剩余额度**（反汇编 @0xd4d8–0xd560）

**B. rotate 独有 = 物理页轮转 + 恢复链加固**
- `STAGE0_SPRAY_CPU attempt=%d physical=%d fragments=%d`：反汇编 @0xe9e0 处 `(attempt−1)%10+2` 计算 physical（**每次 attempt 轮换物理页槽位——"rotate"命名直接呼应**）、fragments=3×计数；随后"prepare spray pairs"批量分配 fd 对
- `MISC_LIST_RESTORE_GATE_FAIL stage=module_ranges direct=%#llx plt=%#llx image=%#llx-%#llx errno=%d`：MISC_LIST 恢复链比 fanout **多一道 module 地址区间校验门**（其余 16 个 stage 两版完全一致）
- 与 registry usageNote 呼应：mtn 适配中 "module_plt_base 与 direct 两处为推导值" —— rotate 针对该风险面加装校验

**C. 同逻辑、不同代码组织（观察）**：巨型检查函数（fanout 0xb8ec–0xe688 / rotate 0xb82c–0xe59c，约 2900 条、无函数序言=全内联）内，PROFILE_GATE 打印序列位置不同（fanout"先判后打"，rotate"边判边打"；device= 参数一处内嵌格式串、一处拆分为独立 `device=%s`）。⇒ **两版是同一代码库的两条并行策略分支**（推断）

### 20.4 registry 交叉与定性（观察 → 推断）
- registry mtn 载荷条目：`"strategy": "fanout"`、`payloadCount: 1` ⇒ **rotate 未登记**（实验变体/备用）
- 9 个 pl_* 资产 = registry `kernelCount: 9` 口径的又一佐证（§16.5 未知项进一步收敛）
- 两变体 usageNote 均为"首次适配（离线完成），尚未经真机验证；module_plt_base 与 direct 为推导值"
- **结论（推断）**：fanout/rotate 是"预算控制流"与"物理页轮转流"两种策略的对照实验。对 CGA-W00 的**直接**意义仍为零（未部署、未验证、铁律禁真机）；但若未来启用 64560 线，MTN-AN80 的①双策略可选②门禁三常量③module_ranges 加固 是三条现成参考。

### 20.5 未知
- version_sha256 输入串（待有实机 /proc/version 或非脱敏 banner 方可复算）
- rotate 的 `physical=(attempt%10)+2` 具体映射到哪个内核对象（推断=spray 目标页的物理槽序号）
- fanout 的 BRIDGE_BUDGET 默认额度、耗尽行为（未展开该循环的退出分支）

---

## 21. 深挖·第 11 轮：tracefs 泄漏渠道对比 —— kaslr_leak（我方现役）vs gl_leak_tracefs（m8 下一代）[06:15]

> 触发：§04:35"后续可选深挖③：gl_leak_tracefs 反汇编（与本机 kaslr_leak 的渠道差异）"。这是**与我们现役工具直接同源**的对比（kit 的 kaslr_leak 就是我们在用的文件）。
> 产物：`extracted/leak/`（kaslr_leak_kit / kaslr_leak_m6 / gl_leak_tracefs_disasm.txt / kaslr_leak_disasm.txt）。

### 21.1 kaslr_leak 全还原（观察 —— 未 strip，`main`@0x4cb8 / `trigger_io`@0x5104 / `tw`@0x5070 全函数反汇编）
**运行时流程（main）**：
1. `tw(en, "1")` → 启用 `…/events/sched/sched_blocked_reason/enable`；打开 `…/trace` 探活
2. 循环≤3 轮（或收满 40 unique）：enable=1 → `trigger_io()` → `sleep(2)` → 逐 CPU 读 `/sys/kernel/tracing/per_cpu/cpu%d/trace_pipe_raw`（每 CPU 读 0x1000/次）→ enable=0
3. ring 解析：4KB 页帧扫描；`ldrh type==0x6a`（**硬编码事件类型过滤**）；命中读 payload+0x10 = caller 地址；要求 caller ≥0xFFFFFF8000000000（内核地址）；**去重入数组（上限 0x28=40）**
4. 反算（每 caller）：`candidate_base = caller − 0x19CD94`、`slide = caller + 0x3FE7E6326C`（kit 版常量）；判定 `candidate_base & 0xFFFF == 0`（64KB 对齐）且 `(caller+0x3FE7E6326C)>>27 < 0x7FD` → 输出 `BASE=0x…`；失败 `[!] no aligned worker caller found`
   > **【08:00 编码级精解补注 — 见 §25】**：实测两常量分工——**slide 输出用 `0x3FF7E6326C`；判据用 `0x3FE7E6326C`（= S − 0x10000000）**；`candidate_base` 即"运行时内核基址 = LB + slide"（LB=0xFFFFFFC008000000）。
5. 输出格式：`=== %d unique callers ===` / `CALLER[%d]=0x%016llx candidate_base=0x%016llx slide=0x%llx`
**trigger_io**：打开 `/data/local/tmp/.kaslr-trigger-%d`（pid 命名）写 0x180B，随后 **≤16 轮 × 256KB 顺序写**（IO 阻塞触发 sched_blocked_reason 记录 worker 调用者）——**"以 IO 压力搅拌调度器"**。
**设备定制（观察）**：kit 与 m6 两版**仅 6 处字节差异，全部落在 main 反算段的立即数常量**（file 0x0f70–0x0fe2，即 vaddr 0x4f70–0x4fe2 的 mov/movk 常量）⇒ kaslr_leak 每设备按内核符号偏移定制常量（发布时逐设备编译）。

### 21.2 gl_leak_tracefs（观察 —— 符号级 @0x25e678，size=4632）
**相对 kaslr_leak 的机制升级（全部为直接观察）**：
| 维度 | kaslr_leak（现役） | gl_leak_tracefs（下一代） |
|---|---|---|
| 事件定位 | **硬编码类型 0x6a** + 固定路径 | **读 `%s/events/sched/sched_blocked_reason/id` 动态获取**；`GL_TRACEFS_EVENT_ID`/`--tp N` 可覆盖 |
| tracefs 根 | 固定 `/sys/kernel/tracing` | `GL_TRACEFS_DIR` 可覆盖（默认同） |
| 搅拌器 | trigger_io（文件写 16×256KB） | **stir = 24×fork**（0x26780c=fork，bionic 符号证实；连续 fork 逼调度器产样）；`GL_TRACEFS_NO_STIR=1` 跳过 |
| 会话控制 | sleep(2) 粗节奏 | 秒级超时（`--leak-tracefs-seconds`，默认 3s）+ 轮询≤3999 轮 + 每轮 usleep(20ms)；`GL_TRACEFS_NO_ARM=1` 跳过启用阶段 |
| 采集 | 每 CPU 单次读；caller 去重 ≤40 | **1MB 缓冲轮询**（min(CPU数,16) 核）；收集 **(caller, pid) 对**；unique ≤128 |
| 反算 | 双常量直算 + 64KB 对齐判据 | **四锚点函数投票**：`worker_thread` / `folio_wait_bit_common` / `synchronize_rcu_expedited` / `rcu_exp_sel_wait_wake`；判据 = caller 相对锚点区间差值 **2MiB 对齐且 <1TB**；delta 得票统计；**≥2 anchor 才合格**（help："只有 1 个 anchor 命中 —— 建议加大 --leak-tracefs-seconds 重跑"） |
| 输出 | CALLER[..] 原始列表 | `[*]     [%02d] %#018llx  pid=%u`（带 pid）+ `[*]   anchor N` + `delta=%#llx 符号名`；空结果时打印**五步排查清单**（含"per_cpu/*/trace_pipe_raw 读不了 (gid not in readtracefs)"） |
| 实测样本（help） | — | `worker_thread+0x2b8 <-> 0xffffffea56ed73f0`（m8 机实测配对，可作判据回归样例） |

### 21.3 与我们的关系（推断）
- 我方现役 kaslr_leak = ppgroot kit 版**字节级同物**（0c99f8b4 体系，9808B）；m8 版是同一工具线的工程化重写 ⇒ **可借鉴清单新增候选**：
  1. **动态事件 ID**（读 id 文件 + 可覆盖）→ 消除"不同内核构建事件号漂移"隐患（现役硬编码 0x6a 是构建相关的定时炸弹）
  2. **2MiB 对齐 + 区间 判据**（与 §18 alias-oracle 的"2MiB 对齐"判据同哲学）——比我们简单 64KB 对齐更严格
  3. **多锚点投票 + ≥2 票合格**（防单点误判；与 §19 第 15 条"判定探针独立性"同向）
  4. **stir 预热 + NO_STIR 开关**（采集前主动制造样本；出问题可关）
  5. **空结果五步诊断**（把"为什么没取到"直接打给用户——与 §15 netfix 的 VERDICT 风格一致）
  6. 采集记录 **pid 字段**（可追溯样本来源进程）
- 注意：以上均为"工具改进候选"，**不代表现役 kaslr_leak 坏**（它在 CGA-W00 上实测可用）；属预防性升级。

### 21.4 未知
- gl_leak_tracefs 的 0x2b3410 锚点表（24B/项）条目数与各锚点链接期地址（未展开数据段）
- "≥2 anchor" 之外的 delta 投票胜出规则细节（SIMD 统计段未全展开）
- ~~kaslr_leak 常量 0x19CD94 / 0x3FE7E6326C 对应的具体符号与链接期地址（推断=某 sched/kworker 返回点 + 内核默认基址差）~~ → **【08:00 已解决 §25】**：常量链编码级解码——`OFF=0x19CD94`（caller 链接期偏移）、`S=0x3FF7E6326C=−(LB+OFF)`、`G=S−0x10000000`；反推两版 LB 均为 `0xFFFFFFC008000000`；caller 符号部分反查（落在 sched/workqueue 区，确切名待 vmlinux）。§21.1 的"slide 常量"表述已在 §25.2 修正（输出 0x3FF7E6326C / 判据 0x3FE7E6326C 为两个常量）。

---

## 进度记录（滚动·补）
- [06:15] 第 20 节（深挖 A）：64560 fanout vs rotate —— 双载荷内嵌三常量门禁（含我们内核的 release/buildStamp/version_sha256）、三线差异（RECLAIM 预算/BRIDGE_BUDGET vs 页轮转/module_ranges 门）、strip 体+序列对齐方法论
- [06:15] 第 21 节（深挖 B）：tracefs 渠道对比 —— kaslr_leak 全还原（触发/采集/反算三函数+每设备常量定制）vs gl_leak_tracefs（动态事件 ID/24×fork stir/四锚点投票/诊断提示）；新增 6 条工具升级候选

---

## 22. 深挖·第 12 轮：m8 stage5 "uinput 桥"全还原 [06:55]

> 触发：①04:35 可选深挖清单"gl_stage5_bridge/pageprobe 细节（uinput 桥）"；②§21.4 未知项"0x2b3410 锚点表未展开"。本轮两项都完成。
> 产物：`extracted/m8/stage5_disasm.txt`（18 函数 1936 行，全带字符串引用注释）、`extracted/dc14_fops_disasm.txt`、`extracted/dc14_bridge_region.txt`；脚本 `scripts/disasm_stage5.py`、`dump_stage5_tables.py`、`dump_anchor_table.py`、`disasm_dc14_fops.py`、`find_dc14_refs.py`。

### 22.1 定位（观察）
stage5 = **在"已有写原语"的基础上，借 `uinput_misc`（/dev/uinput 的 miscdevice）把写原语升级为任意读/写原语**的桥。
- 前置：KASLR slide 已知（`--s5-kaddr` 换算器：链接址→运行址，uinput/uinput10/uinput20/mp/core…）；uinput_misc 运行期地址由常量+slide 算出
- 双载体：**栈模式**（payload 摆在内核栈上——T1 UAF 写场景，`--stage5-self` 自检）／**页模式**（`--purge-page` 后可控内核页 B，`plant_page_fops` 布置）
- 执行门槛：`gl_stage5_bridge` 先查 active/mode；页模式与栈模式的 patch 分支互斥（页模式 patch_payload 为 no-op）——§22.4

### 22.2 11 步桥接序列（观察 —— 步骤表 @0x2b3308，24B/项 {u32 type; u32 val; u64 off; u64 name_ptr}）
| # | type | 动作（引号内为官方步名） | 作用 |
|---|---|---|---|
| 0 | put64 | `[uinput+0x10] = Y` | fops 指向页上伪 fops（Y=伪 fops 基址） |
| 1 | put64 | `[uinput+0x20] = 0` | mutex.owner=0（fast path） |
| 2 | put64 | `[uinput+0x50] = 0` | 清 needs_fill + 两个 in_progress |
| 3 | put64 | `[uinput+0x58] = 0` | 清 buffer（扩容路径要 memmove 它） |
| 4 | put64 | `[uinput+0x60] = 0` | size+max=0 ★漏这步必 fortify_panic |
| 5 | open | `fd1 = open(/dev/uinput)` | private_data=&uinput_misc, f_pos=0 |
| 6 | write | `write(fd1, buf, N)` | 扩容 ⇒ size=N（副作用 [+0x55]=1） |
| 7 | put64 | `[uinput+0x50] = 0` | 清 write_in_progress ⇒ 才能 read |
| 8 | put64 | `[uinput+0x58] = A` | **buffer = 目标内核地址 A** |
| 9 | open | `fd2 = open(/dev/uinput)` | 新 fd ⇒ f_pos 复位为 0 |
| 10 | read/write | `read/write(fd2, N)` | ★ 任意读/写 **[A, A+N)**（-upto 0..10 可截断，建议先 0） |
- bridge 主循环（0x25db80–0x25db7c）：按步骤表线性执行，`--stage5-upto N` 限制；每步打印 `[*] [stage5 %d/%d] %s`；失败打印方括号来源（open 失败回显 errno）
- 先 7 发"字段整理写"+扩容写，再 2 次 open 拿 fd，最后终局 read/write——**"扩容保 buffer 指针改写"的精巧顺序**（推断：先让 size=N 使内核看到合法长度，再把 buffer 偷换成 A）

### 22.3 伪 fops 布局 = 标准 struct file_operations 对齐（观察）
`patch_payload`（栈模式，x0=payload,x1=len≥0xc0）对 10 个字段做检查写；`plant_page_fops`（页模式）把同布局 0x80B 落进可控页。字段与内核 `struct file_operations`（6.x 含 fop_flags）**逐位对齐**：

| fops 内偏移 | 字段 | 写入值 |
|---|---|---|
| +0x00 | owner | 0 |
| +0x08 | fop_flags | 0 |
| +0x10 | llseek | 0 |
| +0x18 | read | 0 |
| +0x20 | write | 0 |
| +0x28 | **read_iter** | **configfs_bin_read_iter**（0xFFFFFFC080FCDACC 链接址 + lookup） |
| +0x30 | **write_iter** | **configfs_bin_write_iter**（read_iter+0x234） |
| +0x38 | iopoll | 0 |
| +0x40 | iterate | 0 |
| +0x48 | iterate_shared | 0 |
| +0x50 | poll | tree.pc（树三联） |
| +0x58 | unlocked_ioctl | tree.rb_right |
| +0x60 | compat_ioctl | tree.rb_left |
| +0x68/0x78 | （res） | 0 |
- "树三联"（pc/rb_right/rb_left）与 fops 的 poll/ioctl 槽**同一块内存双关复用**：这解释了 help 中 `pc=value, rb_right=target, rb_left=0 ⇒ *(target)=pc` 的树写与 ioctl 入口是同一载体
- selftest：校验 5 个关键字段（owner/read/write/read_iter/write_iter）+ `put64` 拒绝禁区（`禁区已拦`）+ 页 fops 7 字段落位
- 页上信息还有"base+0x7000+k*8"多发写自测模式（multishot，n 次写验证稳定性）

### 22.4 "7 组写配对"+ pageprobe 零风险核对（观察）
- 目标页内布置完成后打印：`[*] stage5: 已排布 7 组写配对（页上 fops @ base+0x%x，A=%#llx）`
- `--stage5-pageprobe`：**不碰 UAF**——`#0x257030` 读回目标页到 0x8000 malloc 缓冲 → 逐组核对（7 组写配对 + 伪 fops 落位），每项打 OK/MISMATCH → 通过则 `[+] stage5 pageprobe: 页内布局核对通过（%d 组写配对 + 伪 fops 均落位）`，退出时"目标页已释放"（此路径不消费 UAF 窗口）
- 与整体纪律一致：**先零风险读回验证，再决定开火**（与我们 kaslr_leak/prim 标定同一哲学）

### 22.5 锚点表 @0x2b3410 全量展开（观察 —— §21.4 未知①解决）
紧跟步骤表之后，24B/项 {name_ptr, kernel_link_addr, func_off}，**共 4 条**：

| # | 锚点函数 | 链接期地址 | 函数内偏移 |
|---|---|---|---|
| 0 | worker_thread | 0xFFFFFFC080AD7138 | +0x2b8 |
| 1 | folio_wait_bit_common | 0xFFFFFFC0801871EC | +0x1a4 |
| 2 | synchronize_rcu_expedited | 0xFFFFFFC080CC982C | +0x208 |
| 3 | rcu_exp_sel_wait_wake | 0xFFFFFFC080CCA4D8 | +0x41c |

- **回归验证（观察）**：help 内实测样本 `worker_thread+0x2b8 <-> 0xffffffea56ed73f0` ⇒ slide = 0xffffffea56ed73f0 − (0xFFFFFFC080AD7138+0x2b8) = **0x29D6400000**，恰为 2MiB 整数倍（2^21）✓ —— 与"2MiB 对齐且 <1TB"判据逐字印证
- 表中 4 组 delta 由运行时 caller 反算，多锚点取一致值（"≥2 anchor 命中 ⇒ delta 唯一确定"）
- 表后即 LD_* 环境变量字符串指针表（bionic 数据），非同一结构

### 22.6 未知
- 步骤表 type 编码是否还有第四类动作（本次只观测到 put64/open/write/终局四类；type>3 未发现）
- put64"禁区"具体字段清单（selftest 只回显"禁区已拦"未列名单）
- `configfs_bin_read_iter` 链接址 0xFCDACC/0xFCDD00 对应的 vmlinux 符号名（无该内核符号表；由 plan 打印自证身份）

---

## 23. 深挖·第 12 轮：dc14（我方现役载体）的 bridge/fake-fops 家族 —— 与 m8 stage5 同谱系对比 [06:55]

> 触发：§22 反汇编时发现"我们同款套件"的 dc14 里同样存在完整 fops 桥接设施（此前 §17/§18 未覆盖）。本轮补齐——**重要定性：dc14 不是没有桥，它有"uhid 版桥"，且比 m8 更早工程化**。
> 产物：`extracted/dc14_fops_disasm.txt`（6 函数）、`extracted/dc14_bridge_region.txt`（BRIDGE 区段）、`scripts/find_dc14_refs.py`。

### 23.1 dc14 fake-fops 家族（观察 —— 全部符号级反汇编）
| 函数 | 地址/大小 | 机理 |
|---|---|---|
| `put_fake_fops_table` | 0x13ac4 / 404B | 布置 0xe8 字节假 fops 表。**双态**：flag==0 → 用硬编码链接期常量（0xFFC0_081E3F10 系）；flag≠0 → 用运行期推导（[x9]+0x1ec000+ε）。字段：owner@0=0、llseek@8=NOOP_LLSEEK、read@0x10、write@0x18、+0x20/0x28/0x50/0x58/0x60/0x70/0x80/0xc8/0xe0 函数组 |
| `repair_fake_fops_llseek` | 0x1bce8 / 284B | 用 fd 读 llseek 槽（表+8）→ 比对期望 NOOP_LLSEEK（lookup(0xFFFFFFC081E3F10)）→ 不一致则**写回+复验**（返回 1=修复成功）。专治 rb_erase 破坏 |
| `audit_fake_fops_table` | 0x1d3ac / 812B | 读回整张表 0xe8 → 逐槽比对 → 三态裁决：`(intact NOOP_LLSEEK)` / `(rb_erase clobber -- repair_fake_fops_llseek will fix it)` / `fake fops slot mismatch off=%#zx got=… want=… (or clobber %016llx)`；并打印 span/owner/llseek/read/write 全景 |
| `app_trigger_fops_slide_slot/route(_at)` | 0x1959c 等 | 触发侧：把 fops 重定向写（树写）路由到目标槽，带 attempt/verified/dirty 计数（`APP_FOPS_SINGLE_SHOT … stopping to protect kernel PI tree`——命中即停，保护 PI 树） |
- 相关证据串（观察）：`CFI: fake fops slot mismatch…`、`misc_fops restore via configfs`、`(fake_fops write confirmed)`、`SLIDE_FOPS_EVEN_ONLY`、`lseek oracle CONFIRMED replaced=1 -> write success, skip configfs read path`

### 23.2 dc14 的 BRIDGE（观察 —— "我们方案里已有的桥"）
- **`BRIDGE_ROUTE` / `BRIDGE_FAKE_BASE` 是 dc14 的环境变量**（`prepare_skb_payload` @0x14fb8/0x14fe0 getenv；另见 `SLIDE_TARGET_OVERRIDE`/`SLIDE_TARGET_IMG_OFF`）；`CP: write-geom … bridge=%d` 写 /data/local/tmp/cp.log
- 桥目标：**`uhid_misc.fops ← fake_fops`**（格式串 `BRIDGE_ROUTE on: ctrl_base=%016zx write_pc=%016zx write_left=%016zx`；`BRIDGE_ROUTE=%d: bank slot %d parent=%016llx target=%016zx`）
- `write_pc` / `write_left` = 写入值 / **写预算计数**（进入循环前递减；与 64560 的 `BRIDGE_BUDGET attempt=%d/%d remaining=%d` 同思想——§20.3 互相印证是跨工具的通用做法）
- 桥后读写通道：**configfs bin_write**（`CFI_FRIENDLY_CONFIGFS_BIN_WRITE_OK`，在 `try_cfi_stage` @0x1c794 处：audit 表 → bin_write 写值 → 回读比对 → 打印 OK 标记）
- lseek-oracle（观察）：`cfi lseek probe SKIPPED (geo119): llseek is the rb_erase clobber slot; verification uses the pread-based configfs channel instead` —— 即 dc14 已有"lseek 等值询问 + 回退 pread/configfs 通道"的验证闭环

### 23.3 dc14 vs m8 stage5 对比表（观察 → 推断）
| 维度 | dc14（we现役，CVE-43499 载体） | m8 stage5（下一代） |
|---|---|---|
| 桥目标设备 | **uhid**（/dev/uhid, uhid_misc） | **uinput**（/dev/uinput, uinput_misc） |
| 开关方式 | 环境变量 `BRIDGE_ROUTE`/`BRIDGE_FAKE_BASE` | CLI `--stage5-bridge`（需 --purge-page/阶段 A） |
| 假 fops 载体 | **独立 0xe8 表**（put_fake_fops_table，双态常量/动态） | 页内/栈内嵌（B+0x10 起 0x80B，标准 fops 对齐） |
| 位移函数 | configfs **bin_write**（CFI 友好通道）+ pipe physrw 兜底 | configfs **bin_read_iter/write_iter**（fops 槽直填） |
| 完整性闭环 | **audit（三态裁决）+ repair（槽修复）** 成对 | patch_payload/multishot 重置 + pageprobe 回读核对 |
| 验证哲学 | lseek-oracle 等值询问；不通过则换通道复验 | 零风险 pageprobe 先跑（"强烈建议先验证"） |
| 写预算 | write_left（BRIDGE loop） | 64560 版有 BRIDGE_BUDGET（§20.3）；stage5 用 -upto 分步 |
| 面向的安全机制 | CFI、rb_erase clobber、PI 树保护（SINGLE_SHOT 即停） | fortify_panic（漏清 [+0x60] 必炸）、KASLR slide 强依赖 |
- **推断**：两条是同一"misc-device fops 劫持 → configfs 搬运 → 任意 r/w"路线的两个世代/分支。dc14=uhid 版（工程化最深：audit/repair/lseek-oracle/CFI 通道）；m8 stage5=uinput 版（把"页/栈双载体+零风险 pageprobe+标准 fops 对齐+树三联复用"细化到极致）。
- **对重点目标①复核**：我们现役套件在"桥"维度上**不缺**——dc14 自带 uhid 桥全套；m8 增量主要是：**页模式载体、pageprobe 零风险核对、标准 fops 对齐布局、树三联双关复用**。均为"锦上添花/防御面加固"，不构成对 CGA-W00 方案的替代性超越（结论与 §17 一致）

### 23.4 未知
- ~~dc14 的 uhid 桥是否在 CGA-W00 实机上实际启用过~~ → **本轮已解决**（见 §24.2：未启用，开发记录判定"源码级不通"）
- dc14 fake 表 +0x20/0x28…0xe0 各槽对应的内核符号名（无该内核符号表；由 audit 期望值反推）
- m8 stage5 的"页模式"与 purgerec P0–P4 净化链的耦合点（purgerec 产出的页何时转交 stage5——待读 `gl_uaf_shot`/purgerec 调用点）

---

## 24. 深挖·第 12 轮（附）：dc_ksu_run.sh 开发记录批注 —— 命中率实证 / 多连发 / 载体演进 [06:55]

> 触发：核对 §23.4 未知①时发现 kit 版 `dc_ksu_run.sh`（145 行）自带完整"开发记录"注释块，而 m6 版（71 行）为无批注旧版。这些批注是**破解方内部一手数据**（此前 §10 的"1/3~1/2"只有 App 文案，无统计支撑）。
> 产物：无需新脚本；来源 = `decompiled/resources/assets/route/kit/dc_ksu_run.sh` L16-131。

### 24.1 kit vs m6 脚本代差（观察）
| 项 | m6 版（71 行） | kit 版（145 行，最新开发线） |
|---|---|---|
| OPTS 实验开关 | 无 | 有（2026-09-21 加，KEY=VALUE 文件注入 env） |
| 载体选择 | 无（写死 dc14） | 有（2026-09-26；USE_SIGRETURN 默认 1 → dc14-sig） |
| 多连发守卫 | run.lock 硬守卫 | ALLOW_MULTISHOT=1 可放开（2026-09-28） |
| 亲和/调度诊断 | 无 | aff_diag.log（2026-09-28） |
| KSNITCH_CPU | 7 | 8 |
| kaslr_leak 路径 | $RD/ | /data/local/tmp/（写死） |

### 24.2 实验开关注释全录（观察 —— 破解方原话）
- `GW_CHAIN=1` → "skip fops loop, run cred chain directly"，**绕开"我们统计出来 37% 阵亡的那次 configfs misc_fops 写"**
- `SELINUX_ROUTE=1` → 写目标改 selinux_state.enforcing（"老版本里 1 轮成功过"）
- `BRIDGE_ROUTE=1` → 写目标改 uhid_misc.fops（**"开发记录判为源码级不通"**）⇒ §23.4 未知①解决：**uhid 桥从未在真机启用**，脚本默认 `unset BRIDGE_ROUTE …` 确保关闭。m8 换用 uinput 版 stage5，推测正是对"uhid 直写不通"的换代修复（推断）
- 默认已验证配方 = `SLIDE_FORCE_PSELECT=1 + KSNITCH_CPU=8 + CFI_SKIP_VERIFY=1`，其余全 unset

### 24.3 命中率实证（观察 —— 对 §10/T7 的关键补强）
| 数据 | 出处 | 含义 |
|---|---|---|
| **26 轮 miss 普查：46% 死于 plant 竞速、19% 死于 gate 单试** | 载体选择注释（2026-09-26） | 单发成功率 ≈ 35%；两大死因合计 65% |
| **configfs misc_fops 写：37% 阵亡** | GW_CHAIN 注释 | 默认链最脆单点 |
| **同 boot 连打 4 发：零 panic、boot_id 不变** | 多连发注释（2026-09-28） | "每 boot 一发"过于保守的直接实证 |
| **第 4 发退化：写已落地却卡 pipe 阶段 ⇒ 建议 2-3 发后重启** | 同上 | 连发上限的实证边界 |
- 结论（推断）：App 文案"命中率约 1/3~1/2"与内部"单发≈35%"互为印证；§10 此前标注"无统计支撑"应予更新为"有内部普查支撑（26 轮，约 1/3）"。

### 24.4 载体演进时间线（观察 —— 由脚本批注还原）
1. 2026-09-21：OPTS 实验机制（A/B 不改包）
2. 2026-09-26：dc14-sig（sigreturn 载体）引入——"rt_sigreturn 每次无条件覆盖 waiter 全域，消除 fmps/pselect 的 plant 竞速；另含 pipe cache gate 重试 1→8"；普查 26 轮定死因
3. 2026-09-28：多连发实证 + 亲和诊断
4. **2026-10-03：默认改用 dc14-sig（成功版 6914a30e）——旧默认 fmps 载体 = "App 从未成功提权的根因"**
- 与我们已知互证：v3.8 的 kit 双 dc14 同哈希（0c99f8b4，sig 版）即此决定的产物（§13.6 修正笔记）

### 24.5 与"零重启重试"主题（重点目标②）的关系
- m8 的"零重启重试"哲学在 dc14 时代已有雏形：**ALLOW_MULTISHOT（同 boot 2-3 发）+ 每发独立 miss 分类（plant/gate）+ 失败即重发不重启**
- m8 增量在"retry 粒度的自愈"（alias-oracle 三态、purgerec 净化、stage5 零风险探针）——思路一脉相承、工程化递进

### 24.6 未知
- "37%/46%/19%" 统计样本的具体采集条件（哪台设备、哪个内核版本——批注未注明）
- 第 4 发"卡 pipe 阶段"的内核机制（推断=pipe 缓存/页引用泄漏累积，未验证）

---

## 25. 深挖·第 13 轮（收官）：kaslr_leak 常量链完全解谜 + caller 符号反查 [08:00]

> 触发：§21.4 未知③（"kaslr_leak 常量 0x19CD94 / 0x3FE7E6326C 对应的具体符号与链接期地址"）。本轮用"原始指令编码级解码 + 符号表反查"完全解决。
> 产物：`scripts/leak_const_solve.py`（全字节 diff + 差异区反汇编）、`scripts/decode_leak_moves.py`（MOVN/MOVZ/MOVK 编码级解码）。

### 25.1 精确解码（观察）
kaslr_leak kit vs m6 全文件仅 6 处字节差异，全部位于 main 反算段的 move 立即数（file 0x0f70–0x0fe2）。按 ARM64 编码规范逐条现场解码（MOVN/MOVZ/MOVK 的 imm16/hw 重建）：

| 寄存器链 | kit（g19a495a97bff） | m6（g7d3922fade43） |
|---|---|---|
| x26（减法常量，candidate=caller+x26） | MOVN #0xcd93; MOVK #0xffe6,lsl16 → `0xFFFFFFFFFFE6326C` ⇒ **OFF=0x19CD94** | MOVN #0x41f7; MOVK #0xffee,lsl16 → `0xFFFFFFFFFFEEBE08` ⇒ **OFF=0x1141F8** |
| x27（slide 输出常量 S） | `0x3FF7E6326C` | `0x3FF7EEBE08` |
| x8（判据常量 G） | `0x3FE7E6326C` | `0x3FE7EEBE08` |
| S−G | **0x10000000**（256MiB） | 同 |

> 解码细节：capstone 将 MOVN 显示为 `mov x26, #-0xcd94`（数学负值形式，imm16 实为 0xcd93 经补码 +1）；直接读原始字节按编码规范解码后获得完整 64 位重建。另：上轮手抄有 1 处笔误（m6 的第二个 movk 是 0xffee 非 0xffe6），本轮起全部以原字节解码为准。

### 25.2 数学结构闭环（观察 → 推断）
设 LB=链接期基址、OFF=caller 链接期偏移、slide=运行时 KASLR 位移：
- candidate_base = caller − OFF；slide = caller + S
- **恒等式：S ≡ −(LB + OFF) (mod 2^64)** ⇒ `LB = (2^64 − S − OFF) mod 2^64`
- 判据展开：(candidate_base & 0xFFFF)==0（64KB 对齐）+ (caller + G)>>27 < 0x7FD ⇒ **slide ∈ [0x10000000, 0x3FF8000000)**（256MiB ~ 255.88GiB）

**两版反推结果（本轮核心发现）**：

| | kit | m6 |
|---|---|---|
| `2^64 − S` = LB+OFF | 0xFFFFFFC00819CD94 | 0xFFFFFFC0081141F8 |
| **反推 LB** | **0xFFFFFFC008000000** | **0xFFFFFFC008000000** |
| caller 链接期地址 | 0xFFFFFFC00819CD94 | 0xFFFFFFC0081141F8 |
| OFF 差值 | — | 0x8B9C（35,740 B） |

⇒ **两构建采用同一标准 GKI 链接基址（0xFFFFFFC008000000，android14-6.1 规范值）；"每设备定制"的差异仅来自 caller 偏移随构建布局漂移 35KB**。这是"常量用错 → candidate 全盘算错"的定量证明（防御性判据即为拦截此类漂移而设）。

**修正 §21.1**：原记录"slide = caller + 0x3FE7E6326C（kit 版常量）"应更正为两个常量分工——**slide 输出用 `0x3FF7E6326C`；判据用 `0x3FE7E6326C`（= S − 0x10000000）**。

### 25.3 caller 符号反查（观察 + 推断 —— 部分解决）
用 m6 资产 `next_sym_addr.txt`（231 符号链接期表）反查：
- **m6 caller（偏移 0x1141F8）**：下邻 `delayed_work_timer_fn`@0x10F868（距 0x4990）、上邻 `strlen`@0x120D90（距 0xCB98）——落在 workqueue/sched/locking 代码区（表中 `schedule`@0x10F6DBC、`mutex_lock`@0x10F73CC、`down_read`@0x10FBC10 同在 0x10Fxxxx 区段），与"sched_blocked_reason 阻塞调用点"的定位一致
- **kit caller（偏移 0x19CD94，用 m6 表仅作跨构建参考）**：落在 `__arch_copy_to_user`@0x195E00 与 `__set_fixmap`@0x1AB850 之间
- **未知**：确切符号名需各自构建的 vmlinux/BTF（表是 231 条白名单，区间几十 KB 无法唯一化）

### 25.4 next_sym_addr.txt 定性修正（观察 —— 修正 §13.6 推断）
表中地址全部形如 `0xFFFFFFC008xxxxxx`（slide=0 归一化）⇒ **它是"链接期地址表"**（与 LB=0xFFFFFFC008000000 同坐标系），而非 §13.6 推断的"某 boot 运行期 kallsyms 快照"。与 ko_patch2 的联动由此完全清晰：`链接期表地址 + live_slide → 运行时地址`（slide 由 live init_task 差值或 kaslr_leak 提供）——**m6 符号重定位链的坐标系闭环成立**。

### 25.5 未知（残余）
- 两 caller 的确切符号名（需 vmlinux；m6 构建 g7d3922fade43 的 BTF/vmlinux 不在包内）
- kit caller 0x19CD94 在 kit 构建中的真正邻居（缺 kit 专属符号表；现为跨构建参考）

### 25.6 对工具链的意义（推断）
1. kaslr_leak 的"设备定制"可程序化：**由 (LB, OFF) 两个值生成常量**（S=−(LB+OFF)、G=S−0x10000000），替代手工编译
2. 现役判据（64KB 对齐 + 范围检查）与 m8 下一代（锚点投票 / 动态事件 ID，§21.3）之间是明确的升级路线
3. 我方若复刻 m6 式"链接期符号表 + 重定位"工作流，**next_sym_addr.txt 模板 + ko_patch2 逻辑（§13.2/§25.4）已构成完整参考实现**

---

## 进度记录（滚动·补 2）
- [08:00] 第 25 节（深挖第 13 轮·收官）：kaslr_leak 常量链完全解谜——两版 LB 均为 0xFFFFFFC008000000、caller 偏移差 0x8B9C；判据区间 [256MiB, 255.88GiB) 精确展开；caller 符号反查（部分）；next_sym_addr 定性修正（链接期表）。§21.1/§21.4 注记已更新。
