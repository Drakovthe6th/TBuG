@echo off
setlocal enabledelayedexpansion

:: Configuration
set "KEY=s3cr3t_k3y*!"
set "INPUT_ZIP=mall2.zip"
set "OUTPUT_BIN=mall.bin"

:: Convert ZIP to encrypted BIN using PowerShell
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$key = [Text.Encoding]::UTF8.GetBytes('%KEY%'); " ^
    "$inBytes = [System.IO.File]::ReadAllBytes('%INPUT_ZIP%'); " ^
    "$outStream = [System.IO.File]::Create('%OUTPUT_BIN%'); " ^
    "for ($i=0; $i -lt $inBytes.Length; $i++) { " ^
        "$byte = $inBytes[$i]; " ^
        "$keyIndex = $i %% $key.Length; " ^
        "$outStream.WriteByte( ($byte -bxor $key[$keyIndex]) ); " ^
    "} " ^
    "$outStream.Close();"

echo [+] Conversion successful
echo [*] Input ZIP:  %INPUT_ZIP%
echo [*] Output BIN: %OUTPUT_BIN%