# 荣耀 MagicPad3 (CGA-W00) 运行时 KernelSU Root 研究

> **设备**：荣耀 MagicPad3（CGA-W00 / SM8650，MagicOS 10.0.0.170，内核 `6.1.157-android14-11-g19a495a97bff`）
> **主题**：基于 CVE-2026-43499（GhostLock）的运行时 LKM root 全自动化 —— 自动循环、二进制补丁增强、社区方案深度逆向分析
> **性质**：本设备自有设备的个人安全研究记录（BL 锁定、不写任何分区、重启即失效的运行时方案）
> **整理**：saltlyfish666 ｜ 研究与工程协作：WorkBuddy

---

## 成果亮点

| # | 成果 | 说明 |
|---|---|---|
| 1 | **全自动提权循环** `tools/app_root_v2.sh` | 重启→等 boot→Shizuku→开火→判定→未中自动重启循环；命中即停并自动收档"黄金样本"；含熔断保护（连续 panic 保护数据） |
| 2 | **二进制补丁** `tools/patch_guard.py` | 反汇编定位并 NOP 掉套件二进制里的"首发射击后拒绝重试"护栏——单发 1 次机会 → **8 次 attempt**；补丁后可稳定跑满 8 次（补丁后的首次命中即是第 2 次 attempt 打中的） |
| 3 | **吞吐优化** | "gate 失败僵死"自动检测 + 40 秒提前收轮（原需 7 分钟）；每轮循环显著提速 |
| 4 | **深度逆向分析报告** `docs/09` | 对社区工具"一键提权"(ppgroot v3.8) 的完整逆向：4 条设备路线、双漏洞线（43499/64560）、下一代 GhostLock(mk2) 技术还原（alias-oracle / purgerec / faketab / stage5） |
| 5 | **完整实验记录** `docs/04-06` | 三杠杆 env 实验（SETTLE_UPTIME/EXPLOIT_ATTEMPTS/EVEN_ONLY 全负结论）、knowlily 移植计划、多方案对比 |
| 6 | **失败模式法证** `docs/02/07` | 命中/未命中全链路日志对比分析，定位关键失败点（write 落地率 → pipe cache gate） |

## 目录结构

```
├── docs/                     # 主体报告（9 篇）
│   ├── 01-完整交接文档.md            # 方案全貌、配方、风险（总入口）
│   ├── 02-击中目标与成败分析报告.md    # 命中/失败全对比
│   ├── 03-社区路线调研报告.md         # 社区方案横评
│   ├── 04-联网调研报告.md             # 公开资料+来源链接
│   ├── 05-环境变量实验记录.md         # 三杠杆实验（全负）
│   ├── 06-关键洞察.md
│   ├── 07-失败模式法证分析.md
│   ├── 08-knowlily移植计划.md
│   └── 09-ppgroot逆向分析报告.md      # 899 行完整逆向（jadx 1.5.6）
├── tools/                    # 自动化与补丁工具
│   ├── app_root.sh / app_root_v2.sh   # 自动循环（v2 = 生产版）
│   ├── patch_guard.py                 # 二进制护栏补丁（NOP，可回滚）
│   ├── 一键Root.bat
│   └── analysis/                      # 反汇编/取证分析脚本（Python）
├── samples/hitsample/        # 黄金命中样本（命中时刻全量日志）
└── worklog/                  # 逐日工作日志（2026-10-13 ~ 10-16）
```

## 使用方式（复现概要）

```bash
# 前置：Windows + adb + 平板已开启 USB 调试
# 1) 部署套件（详见 docs/01 完整交接文档）
# 2) 应用二进制补丁（可选，提升单发机会数）
python tools/patch_guard.py     # 见脚本内说明；对目标二进制做 1 指令 NOP
# 3) 挂自动循环（命中即停）
bash tools/app_root_v2.sh go
```

> ⚠️ 本仓库**不包含**任何第三方漏洞利用二进制/内核模块（版权与合规原因），
> 仅含分析文档、原创工具与样本日志。上游组件请见 [ATTRIBUTION.md](ATTRIBUTION.md) 的来源指引。

## 致谢与作者归属

本研究建立的完整归属清单见 **[ATTRIBUTION.md](ATTRIBUTION.md)**。核心致谢（不分先后）：

- **Nebula Security（NebuSec）** —— GhostLock / CVE-2026-43499 原始漏洞研究与利用链（[ionstack-part-2](https://nebusec.ai/research/ionstack-part-2)）
- **zj520** —— 本套件（设备定制 build）作者，XDA 发布帖：<https://forum.xda-developers.com/t/4803975>
- **knowlily** —— 荣耀内核适配关键修复（res-encode 等七项）开源研究仓
- **CyberMeowfia / JoinChang / madpowah 及社区各位研究者** —— 利用源码、移植笔记与公开资料
- **"一键提权"（ppgroot）作者及社区工具作者们** —— 逆向分析对象与多设备知识来源

## 免责声明

本仓库内容仅用于**自有设备的安全研究与技术学习**。请勿将任何内容用于未授权设备。
运行时 root 具有固有风险（崩溃重启、数据损坏可能），所有操作请自行评估。
相关漏洞的修复进展请关注荣耀官方安全公告。
