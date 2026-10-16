@echo off
chcp 936 >nul
title MagicPad 3 (CGL-W00) 一键 Root
cd /d "%~dp0"

set "BASH=C:/Program Files\Git\bin\bash.exe"
if not exist "%BASH%" set "BASH=C:/Users/Curtaincall/AppData/Local/Programs/WorkBuddy/resources/vendor/PortableGit/bin/bash.exe"
if not exist "%BASH%" (
  echo [错误] 找不到 bash.exe，请检查 Git for Windows 是否安装。
  pause
  exit /b 1
)

echo ============================================================
echo   MagicPad 3 (CGL-W00) 一键 Root   --  App 通道 + Shizuku
echo ============================================================
echo.
echo  开始前请确认：
echo    1. 平板已用 USB 线连上电脑
echo    2. 平板已开启「开发者选项 - USB 调试」并已授权本电脑
echo    3. 平板电量足够 / 保持插电
echo.
echo  脚本会自动：重启平板 -^> 拉 Shizuku -^> 开 GhostLock 点部署
echo  每个 boot 连开 3 发（实测第 2 发常中），最多 20 个 boot
echo  中途想停就按 Ctrl+C
echo.
pause

"%BASH%" -c "MAX_BOOTS=20 ABNORMAL_MAX=2 bash .workbuddy/app_root.sh go"
set RC=%ERRORLEVEL%

echo.
echo ============================================================
if "%RC%"=="0" (
  echo   结果：ROOT 成功
  echo   请到平板上打开 KernelSU 管理器，应显示「工作中 [越狱模式]」
  echo   注意：重启后 root 会丢失，届时再双击本脚本即可
) else if "%RC%"=="3" (
  echo   结果：熔断停止（连续内核 panic），设备已自动重启，可正常使用
  echo   建议稍后再试，或先看日志
) else (
  echo   结果：20 个 boot 未命中（退出码 %RC%），可再次双击重跑
)
echo.
echo   日志目录：D:/file/文档/workbuddy/2026-10-13-11-14-12/auto_root_logs/
echo ============================================================
pause
