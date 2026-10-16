#!/bin/bash
# =============================================================================
# app_root.sh — 用平板里的 GhostLock App（Shizuku 授权）提权，全自动循环
#
# 背景（2026-10-13）：用户反馈 adb shell 直跑 exploit 一直 miss，而 14:48 那次
#   成功是「平板里的 App 通过 Shizuku 点部署」达成的。故改用 App 通道：
#   拉 Shizuku → 拉起 GhostLock App → 模拟点击「一键部署执行」→ 盯 /proc/modules。
#
# 用法：
#   bash app_root.sh           # 单次部署+点按钮（不重启）
#   bash app_root.sh go        # 自动循环：重启→Shizuku→App点部署→盯命中，miss 重试
#   MAX_BOOTS=15 bash app_root.sh go
# =============================================================================
set -u
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

ADB="/c/Users/user/AppData/Local/Microsoft/WinGet/Packages/Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe/platform-tools/adb"
PY="C:/Users/user/.workbuddy/binaries/python/envs/default/Scripts/python.exe"
LOGDIR="D:/file/文档/workbuddy/2026-10-13-11-14-12/auto_root_logs"
GHOSTLOCK_PKG="com.ghostlock.ksu"
SHIZUKU_PKG="moe.shizuku.privileged.api"
# 2026-10-13 23:24 Shizuku 重装后安装路径已变（旧 ~~J5KeCGPNYhqd1SMo8i9lgw== 失效），固定路径作首选 + pm path 动态兜底
SHIZUKU_STARTER="/data/app/~~BaK86ZMC8N7EQlfmE7Gxpw==/moe.shizuku.privileged.api-MpB5OyMJgjXfHVbWq5dgpw==/lib/arm64/libshizuku.so"
MAX_BOOTS="${MAX_BOOTS:-15}"
ABNORMAL_MAX="${ABNORMAL_MAX:-2}"   # 熔断：连续 N 次内核 panic 自动重启即停手
SHOTS_PER_BOOT="${SHOTS_PER_BOOT:-3}"  # 多连发：同 boot 连开几发再重启（kit 作者配方 2-3 发安全）
UPTIME_GATE="${UPTIME_GATE:-30}"     # PC 侧等 boot 完成即可（App 内部会自等 95s）
FIRE_TIMEOUT=900
MODE="${1:-dry}"

mkdir -p "$LOGDIR"
LOG="$LOGDIR/app_root_$(date +%m%d_%H%M%S).log"
log(){ echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }
# 所有 adb 调用带超时：设备 panic 死掉时 adb 会永久阻塞，脚本曾因此吊死
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
# uiautomator 只 dump 获得焦点的窗口：弹框一弹，底层 App 的按钮就不在 dump 里，
# find_btn 必然失败。且按 BACK 无效（会重弹）。唯一可靠解 = 直接点「传输文件」。
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
  # 上滑解锁（锁屏为无密码滑动锁时，从屏幕下方往上滑）
  q "input swipe 1524 1900 1524 300 300" >/dev/null 2>&1
  sleep 1
  q "input keyevent 82" >/dev/null
  sleep 1
  q "wm dismiss-keyguard" >/dev/null 2>&1
  # 关掉重启后可能弹出的 USB 模式选择框 + 重设免弹窗开关（荣耀会被手动操作/重启重置）
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

start_shizuku(){
  if q "ps -A -o NAME 2>/dev/null" | grep -q shizuku_server; then
    log "✓ Shizuku server 已在运行"
    return 0
  fi
  if q "test -f $SHIZUKU_STARTER"; then
    q "$SHIZUKU_STARTER" >/dev/null 2>&1
    sleep 3
  else
    # 兜底：pm path 拿 base.apk 路径，动态拼出 lib/arm64/libshizuku.so
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

# ---------- 解析「一键部署执行」按钮坐标（从 uiautomator dump） ----------
find_btn(){
  q "uiautomator dump /sdcard/gh.xml" >/dev/null 2>&1
  timeout 30 "$ADB" pull /sdcard/gh.xml "$LOGDIR/gh.xml" >/dev/null 2>&1
  "$PY" - "$LOGDIR/gh.xml" <<'EOF'
import re, sys
xml = open(sys.argv[1], encoding='utf-8').read()
# 找 text="一键部署执行" 的节点，取 bounds 中心
for m in re.finditer(r'text="一键部署执行"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', xml):
    x = (int(m.group(1)) + int(m.group(3))) // 2
    y = (int(m.group(2)) + int(m.group(4))) // 2
    print(f"{x} {y}")
    break
EOF
}

# ---------- kit 路径兼容（App 部署到 ksu_app，脚本内部硬编码 RD=/data/local/tmp/ksu） ----------
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

# ---------- App 提权：拉起 App + 点部署 + 盯命中 ----------
app_fire(){
  log "拉起 GhostLock App ..."
  q "monkey -p $GHOSTLOCK_PKG -c android.intent.category.LAUNCHER 1" >/dev/null 2>&1
  sleep 4
  local btn; btn=$(find_btn)
  if [ -z "$btn" ]; then
    # 按钮找不到 ≈ USB 弹框挡住（uiautomator 只 dump 焦点窗口）→ 点掉弹框后重找
    log "⚠ 首次未找到「一键部署执行」→ 尝试关闭 USB 弹框后重试"
    dismiss_usb_dialog
    sleep 2
    btn=$(find_btn)
  fi
  if [ -z "$btn" ]; then
    log "✗ 找不到「一键部署执行」按钮（可能 App 未加载或已在提权中）"
    return 1
  fi
  local bx by
  bx=${btn% *}; by=${btn#* }
  ensure_link && log "kit 路径已就绪（$LINK）"
  log "点击「一键部署执行」($bx,$by) ..."
  q "input tap $bx $by" >/dev/null 2>&1
  # 首次点击若因 kit 尚未释放/路径不通而空转，20s 后修链再点一次
  sleep 20
  if ensure_link; then
    if ! q "test -f $LINK/dc_ksu.log -o -f $LINK/run.lock" ; then
      log "⚠ 未见运行痕迹，补点一次「一键部署执行」..."
      q "input tap $bx $by" >/dev/null 2>&1
    fi
  fi
  # 盯命中：单次 adb 调用合并三种判定（降低 fork 压力，防 PortableGit fork 耗尽）
  local i=0 r empty=0
  local t0; t0=$(date +%s)
  local elapsed=0
  while [ $i -lt $((FIRE_TIMEOUT / 5 + 20)) ]; do
    r=$(q "if grep -qi kernelsu /proc/modules; then echo HIT; elif grep -q 'dc12 exit=' $LINK/dc_ksu.log 2>/dev/null; then echo DONE; elif [ $elapsed -ge 70 ] && [ -f $LINK/run.lock ] && ! pgrep -f cve-2026-43499 >/dev/null 2>&1; then echo DONE; fi")
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
        return 0 ;;
      *DONE*)
        log "exploit 已自行收尾（本轮 miss，提前重启省 13 分钟）"
        q "grep -E 'APP_FOPS_SINGLE_SHOT|pipe physrw|refusing retry|dc12 exit' $LINK/dc_ksu.log | tail -4" >> "$LOG" 2>&1
        return 1 ;;
    esac
    # 卡死保护：正常开火 60~75s 出结论；若 4 分钟仍无结论且无 root，判定内核分配器
    # 被开火残留卡死（slub-alloc/free 转 D 状态，整机假死）→ 立即结束本轮，靠轮末重启恢复
    elapsed=$(( $(date +%s) - t0 ))   # 真实时钟（设备死掉时 adb 每次吃满超时，按次数计会严重拖长）
    if [ $elapsed -ge 240 ]; then
      log "⚠ 开火 240s 无结论 → 判定内核分配器被残留卡死（整机假死），结束本轮靠重启恢复"
      return 1
    fi
    sleep 5; i=$((i+1))
  done
  log "本 boot 未命中 → miss"
  return 1
}

# ---------- 主流程 ----------
main(){
  check_device || exit 1
  # 自愈：确保 USB 默认走传输文件(免手动选)，荣耀侧可能被手动操作重置
  q "settings put system usb_cancel_mtp_dialog 1" >/dev/null 2>&1
  log "已确保 usb_cancel_mtp_dialog=1（插线免手动选传输文件）"

  if [ "$MODE" != "go" ]; then
    log "dry 模式：单次拉 Shizuku + 点部署（不重启）"
    start_shizuku || true
    app_fire && log "=== ROOT 成功 ===" || log "=== 未命中 ==="
    exit 0
  fi

  log "=== App 通道自动提权循环开始（上限 $MAX_BOOTS 个 boot × 每 boot $SHOTS_PER_BOOT 发）==="
  # 多连发：OPTS 写 ALLOW_MULTISHOT=1（kit 作者配方：同 boot 连开 2-3 发安全，第 4 发退化）
  # 2026-10-14 实测：同一 boot 第 2 发 30 秒命中 —— 第 1 发的 KASLR/页准备可被后续发复用
  q "echo 'ALLOW_MULTISHOT=1' > /data/local/tmp/ksu/OPTS" >/dev/null 2>&1
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
      BID=$(q "cat /proc/sys/kernel/random/boot_id")
    else
      log "-------- 第 $n/$MAX_BOOTS 轮（同 boot 第 $((fires+1)) 发，免解锁直接开火）--------"
      # 屏幕已解锁且常亮，App 还在前台：只处理可能随机弹出的 USB 弹框，不做滑动/按键
      dismiss_usb_dialog
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
    # ---------- 熔断：识别「内核 panic 自动重启」 ----------
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
    # 同 boot 再来一发（不重启，复用第 1 发的 KASLR/页准备）
  done
  log "✗ $MAX_BOOTS 个 boot 未命中。检查 $LOG"
  exit 2
}

main
