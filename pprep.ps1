$ScriptContent = Get-Content -Path "/home/x3n0k/c/TBuG/Bypass.ps1" -Raw
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($ScriptContent)
$Base64 = [Convert]::ToBase64String($Bytes)
$Base64 | Out-File -FilePath "/home/x3n0k/c/TBuG/Encoded.txt"