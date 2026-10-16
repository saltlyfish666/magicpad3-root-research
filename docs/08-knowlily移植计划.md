# knowlily 研究仓 → CGL-W00 移植计划（2026-10-15 04:00）

> 目标：把 `github.com/knowlily/cve-2026-43499-honor` 的 exploit 移植到本机（CGL-W00 / 6.1.157-android14-11-g19a495a97bff），
> 获得完整 res-encode 实现 + 可调参数的自建 exploit（公开记录该路径命中率 40-50%，本 kit 仅 5-7%）。

## 0. 侦察结论（已完成，只读）

- 仓库结构：`exploit/`（源码 + honor-BVL-AN16 适配）、`tools/`（**target.h 生成器**，含荣耀扁平 waiter / do_futex 内联适配 + 编译脚本）、`scripts/`（123 个反汇编脚本，capstone 读 kernel.bin）、`docs/progress_20261011.md`（7 项移植缺陷 + 3 个真 bug 的完整修复记录）
- **关键前提：其 6.1.157 参数属于 BVL-AN16（git hash g7d3922fade43）；本机是 g19a495a97bff，同代不同 build ⇒ 偏移必须重新生成**（仓库 README 明确警告两代/两 build 常数不可混用）
- 其自述剩余差距 = "把 crafting 字节投放到被抢占的那页"（与我们的 8 字节落点问题同源）——所以即使移植成功，也是"同机理 + 完整实现 + 可调参"，命中率能否到 40% 仍需实测
- 本机已有资产可直接复用：`boot_b.img`（内核镜像）、`kallsyms.txt`（实时符号）、官方提取器（已能解析本机几何）

## 1. 移植步骤（预估 1-2 天）

1. **拉仓库**：`git clone https://github.com/knowlily/cve-2026-43499-honor`（只读研究，不动设备）
2. **读修复清单**：`docs/progress_20261011.md` —— 逐条核对其 7 项移植缺陷，确认哪些与本 kit 的差异对应（尤其 res-encode 的 res_in/res_out/res_ex 投放逻辑、shift_candidates 修正）
3. **生成本机 target.h**：用其 `tools/` 生成器 + 我们的 `boot_b.img`/`kallsyms.txt` 生成 CGL-W00 专用偏移表；**自检判据**（来自其 README）：
   - `ASHMEM_MISC_FOPS_OFF ≠ ASHMEM_FOPS_OFF`（相等 = 生成器静默 fallback，写原语会打错地方）
   - `P0_KERNEL_PHYS_LOAD = 0xa8000000`（写 0x80000000 落进 gunyah_hyp_region）
   - `MM_STRUCT_SZ = 0x400`（取 /proc/slabinfo 的 kmem_cache object size，非 BTF 0x3c0）
   - `PSELECT_WAITER_WORD_SHIFT = 11`（本机同为荣耀 6.1 内联 do_futex，需确认）
4. **构建**：按其 `tools/` 编译脚本（Docker + NDK，首次拉取 ~1.2GB）产出 arm64 二进制
5. **本机验证（只读不冒进）**：先跑其 `--info/--check` 类自检（若有），确认 offsets 解析正确、KASLR 泄露成功
6. **小样本试射**：3-5 发对比 prep_fails 与命中率 vs 现役 kit（基线 mean 1.94 / 5-7%）
7. **若显著优**：接入循环（把 app_root_v2 的部署目标换成自建二进制）；否则归档结论

## 2. 风险与备查

- 构建环境：Docker Desktop 是否可用、NDK 1.2GB 下载（走代理）
- 二进制入口：自建二进制可用同样方式驱动（Shizuku/rish 或替换 kit 目录的 bin），**但不要覆盖设备上现役 kit**（保留可回退）
- 法务/安全：仅本机自有设备研究使用
- 时间盒：单日不超过；若构建/移植卡住超过半天，回退到"等 CVE-2026-43284"路线

## 3. 当前状态

- [ ] 待执行（今晚已完成侦察 + 计划；构建需白天网络/时间窗口）
- 并行：过夜循环已挂（默认配置 40 boot 上限），命中即停并保留 root
