# SECURITY WARNING: This script disables critical security measures!
# Only run in isolated test environments. Do NOT use on production systems.

Requires -RunAsAdministrator

# Bypass PowerShell execution policies
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
Set-ExecutionPolicy Bypass -Scope LocalMachine -Force

# Disable Windows Firewall profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Disable Windows Defender real-time protection (if active)
if (Get-Service WinDefend -ErrorAction SilentlyContinue) {
    Set-MpPreference -DisableRealtimeMonitoring $true
    Stop-Service -Name WinDefend -Force
}

# Allow all network traffic (IPSec bypass)
Set-NetFirewallRule -Enabled True -Action Allow -Direction Inbound,Outbound

# Disable script block logging (obscures script activities)
Disable-ScriptBlockLogging

# Disable SmartScreen for EXEs
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 0 -Force

# Lower UAC to never notify (disables prompts)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 0 -Force

# Allow execution of apps from any source (if Group Policy allows)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Associations" -Name "LowRiskFileTypes" -Value ".exe;.ps1" -Force

Write-Host "SECURITY RESTRICTIONS DISABLED!" -ForegroundColor Red
Write-Warning "System is now vulnerable to network attacks and malware"
Write-Host "Firewall: DISABLED`nExecution Policy: BYPASS`nDefender: NEUTRALIZED" -ForegroundColor Yellow