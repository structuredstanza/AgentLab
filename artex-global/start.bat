@echo off
rem Switch the console to UTF-8. Otherwise, Korean text in this file garbles on GBK terminals.
chcp 65001 >nul 2>&1
rem ARTEX daemon start script (Windows)
rem
rem Usage:
rem   start.bat                  Run in foreground (stop with Ctrl-C)
rem   start.bat -addr :9000      Extra arguments are passed through to artex unchanged
rem
rem This script does one thing only. It runs artex.exe, and when the process exits, it reads the exit code to decide whether to start it again.
rem
rem   0      User stopped normally  -> exit loop
rem   75     Program requested restart -> run again immediately (press "one-click update" or "rollback" on screen)
rem   other  Abnormal exit          -> run again after backoff (1->2->4... up to 60 seconds)
rem
rem Downloading, SHA256 checksum verification, and version replacement are not done here; artex handles all of them itself when it starts
rem (selfupdate package). The script is kept simple. For details, see the header comment in start.sh.

setlocal enabledelayedexpansion
cd /d "%~dp0"

set "BIN=artex.exe"
if not exist "%BIN%" (
	echo [artex] Executable not found: %BIN% 1>&2
	exit /b 1
)

set "RESTART_CODE=75"
set "MAX_DELAY=60"
set /a delay=1

:loop
"%BIN%" %*
set "code=!ERRORLEVEL!"

if "!code!"=="0" (
	echo [artex] Exited normally
	exit /b 0
)

if "!code!"=="%RESTART_CODE%" (
	rem Update/rollback is ready. Running again lets artex complete the version swap at startup.
	echo [artex] Restart requested: applying new version...
	set /a delay=1
	goto loop
)

echo [artex] Abnormal exit ^(code=!code!^), restarting after !delay!s 1>&2
rem timeout fails on a redirected console, so ping is used instead (a delay of N seconds needs N+1 pings).
set /a pings=!delay!+1
ping -n !pings! 127.0.0.1 >nul 2>&1
set /a delay=!delay!*2
if !delay! gtr %MAX_DELAY% set /a delay=%MAX_DELAY%
goto loop
