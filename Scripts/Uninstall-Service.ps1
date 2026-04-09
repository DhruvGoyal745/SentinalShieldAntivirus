#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Uninstalls the Sentinel Shield Antivirus Windows service.

.DESCRIPTION
    Stops and removes SentinelShieldService, cleans up the firewall rule,
    and removes the tray auto-start registry entry. Must be run as Administrator.

.PARAMETER RemoveData
    If specified, also removes the ProgramData\SentinelShield directory
    (quarantine vault, logs, signature packs).
#>
param(
    [switch]$RemoveData
)

$ServiceName = "SentinelShieldService"

Write-Host "Stopping tray application..."
Get-Process -Name "SentinelShieldTray" -ErrorAction SilentlyContinue | Stop-Process -Force

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Stopping service..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    Write-Host "Removing service..."
    sc.exe delete $ServiceName | Out-Null
    Write-Host "  Service removed."
} else {
    Write-Host "Service '$ServiceName' not found — skipping."
}

Write-Host "Removing tray auto-start registry entry..."
Remove-ItemProperty `
    -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
    -Name "SentinelShieldTray" `
    -ErrorAction SilentlyContinue

Write-Host "Removing Explorer context menu entries..."
@(
    "HKLM:\SOFTWARE\Classes\*\shell\SentinelShieldScan",
    "HKLM:\SOFTWARE\Classes\Directory\shell\SentinelShieldScan"
) | ForEach-Object {
    if (Test-Path $_) {
        Remove-Item -Path $_ -Recurse -Force
        Write-Host "  Removed: $_"
    }
}

Write-Host "Removing firewall rule..."
$ruleName = "Sentinel Shield Antivirus (localhost)"
Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

if ($RemoveData) {
    $dataRoot = Join-Path $env:ProgramData "SentinelShield"
    if (Test-Path $dataRoot) {
        Write-Host "Removing data directory: $dataRoot"
        Remove-Item -Path $dataRoot -Recurse -Force
    }
}

Write-Host ""
Write-Host "Sentinel Shield Antivirus has been uninstalled." -ForegroundColor Green
if (-not $RemoveData) {
    Write-Host "Scan history and quarantine data were preserved at:"
    Write-Host "  $(Join-Path $env:ProgramData 'SentinelShield')"
    Write-Host "  Use -RemoveData to delete them."
}
