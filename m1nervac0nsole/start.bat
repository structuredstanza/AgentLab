@echo off
rem Switch the console to UTF-8. Otherwise, Korean text in this file garbles on GBK terminals.
chcp 65001 >nul 2>&1
rem m1nervac0nsole daemon start script (Windows)
rem
rem Usage:
rem   start.bat                  Run in foreground (stop with Ctrl-C)
rem   start.bat -addr :9000      Extra arguments are passed through to m1nervac0nsole unchanged
rem
rem This script runs m1nervac0nsole.exe, and when the process exits, it reads the exit code:
rem
rem   0      User stopped normally  -> exit loop
rem   other  Abnormal exit          -> run again after backoff (1->2->4... up to 60 seconds)

setlocal enabledelayedexpansion
cd /d "%~dp0"

set "BIN=m1nervac0nsole.exe"
if not exist "%BIN%" (
	echo [m1nervac0nsole] Executable not found: %BIN% 1>&2
	exit /b 1
)

set "MAX_DELAY=60"
set /a delay=1

:loop
"%BIN%" %*
set "code=!ERRORLEVEL!"

if "!code!"=="0" (
	echo [m1nervac0nsole] Exited normally
	exit /b 0
)


echo [m1nervac0nsole] Abnormal exit ^(code=!code!^), restarting after !delay!s 1>&2
rem timeout fails on a redirected console, so ping is used instead (a delay of N seconds needs N+1 pings).
set /a pings=!delay!+1
ping -n !pings! 127.0.0.1 >nul 2>&1
set /a delay=!delay!*2
if !delay! gtr %MAX_DELAY% set /a delay=%MAX_DELAY%
goto loop
