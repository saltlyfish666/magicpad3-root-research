# 作者归属与致谢（ATTRIBUTION）

> 本研究是站在众多公开研究与社区工作之上的个人实践记录。
> 以下按"对本项目的贡献"分类列明所有应致谢的作者与来源。若任何归属有误或遗漏，欢迎指正。

---

## 一、漏洞原研与利用链

| 组件 | 作者 / 来源 | 说明 | 链接 |
|---|---|---|---|
| **CVE-2026-43499（GhostLock）** | **Nebula Security（NebuSec）** | 漏洞发现与完整利用链公开研究（futex rt_mutex 栈上 UAF） | https://nebusec.ai/research/ionstack-part-2 |
| 利用源码（上游） | **NebuSec / CyberMeowfia** | GhostLock PoC 源码（Apache License 2.0） | https://github.com/NebuSec/CyberMeowfia |
| 技术解析（社区） | **madpowah** | CVE-2026-43499 深度解析文章 | https://madpowah.github.io/2026/07/09/cve-2026-43499-ghostlock-ionstack.html |
| OnePlus 移植参考 | **JoinChang** | ghostlock-oneplus 仓库 | https://github.com/JoinChang/ghostlock-oneplus |
| GhostLock 官方项目 | **GhostLock 项目组** | GhostLock-App 官方文档与工具 | （见官方发布渠道） |

## 二、本设备（荣耀 MagicPad3 / CGA-W00）方案作者

| 组件 | 作者 / 来源 | 说明 |
|---|---|---|
| **设备定制套件（"赞助版"）** | **zj520** | `cga-w00-6.1.157-honor-magicpad3-app` 定制 build：包含 dc14/dc14-sig 载体、dc_ksu_run.sh、KernelSU 荣耀移植模块与全套装载链。**本项目全自动方案的核心载荷即来自该作者**。XDA 发布帖：<https://forum.xda-developers.com/t/4803975> |
| 套件内 KernelSU 移植 | zj520（基于 KernelSU 官方） | KernelSU v3.2.5 荣耀定制模块（`kernelsu_cga.ko` 等）；KernelSU 上游：<https://github.com/tiann/KernelSU> |

## 三、荣耀内核适配关键研究

| 组件 | 作者 / 来源 | 说明 |
|---|---|---|
| **荣耀 6.1 内核适配七修复** | **knowlily** | res-encode / PSELECT_WAITER_WORD_SHIFT=11 / P0_KERNEL_PHYS_LOAD 等关键参数与修复；开源研究仓 `cve-2026-43499-honor` |
| CGA-W00→BVL-AN16 适配工作区 | 匿名社区研究者 | 本机分析中参考的 target.h 生成器、反汇编工具链、PATCHES.md 等工作（经社区渠道传播，作者未具名） |

## 四、多设备社区工具（逆向分析对象）

| 组件 | 作者 / 来源 | 说明 |
|---|---|---|
| **"一键提权"（ppgroot）v3.8** | ppgroot 作者（应用包名 `com.dsh.ppgroot`） | 多设备提权框架；本项目对其做了完整逆向分析（docs/09），其路由表、双漏洞线（43499/64560）与下一代 GhostLock(mk2) 技术为重要知识来源 |
| 其他社区资源 | 荣耀 root 社区各研究者 | DFRoot 等工具、社区经验帖（详见 docs/03/04 的来源标注） |

## 五、本项目原创部分

| 组件 | 作者 | 说明 |
|---|---|---|
| 自动提权循环（app_root.sh / app_root_v2.sh） | **saltlyfish666**（协作：WorkBuddy） | 全自动循环、早杀优化、熔断保护、样本收档 |
| 二进制护栏补丁（patch_guard.py） | **saltlyfish666**（协作：WorkBuddy） | 反汇编定位 + NOP 指令级补丁（8 attempts 解锁） |
| 全部分析报告与实验记录（docs/） | **saltlyfish666**（协作：WorkBuddy） | 逆向分析、法证、实验与横评 |

---

## 许可与合规说明

- 本仓库中的**原创内容**（报告、脚本、工具）采用 **MIT 许可** 发布，欢迎参考。
- **第三方组件**（利用二进制、内核模块、APK 等）**不在本仓库分发**——请通过上述来源与社区渠道获取，并遵守其各自许可（如 GhostLock 源码为 Apache 2.0）。
- 所有内容仅供安全研究与学习使用。
