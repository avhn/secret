@echo off
rem Development only: build secret.exe beside this shim. Never installed by manifests.
setlocal DisableDelayedExpansion
rem Do not let an inherited ERRORLEVEL value replace cmd's numeric status.
set "ERRORLEVEL="
if not exist "%~dp0secret.exe" goto unavailable
"%~dp0secret.exe" hook claude
exit /b %errorlevel%
:unavailable
echo {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"secret: development binary unavailable; build hooks/secret.exe"}}
if errorlevel 1 goto output_failure
exit /b 0
:output_failure
echo secret: development binary unavailable 1>&2
exit /b 2
