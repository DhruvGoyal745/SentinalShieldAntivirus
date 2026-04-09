#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the Sentinel Shield Antivirus Windows service.

.DESCRIPTION
    Registers SentinelShieldService as a Windows service with delayed auto-start
    and automatic crash recovery. Must be run as Administrator.

.PARAMETER InstallPath
    Path to the directory containing SentinelShieldAntivirus.exe.
    Defaults to the script's own directory.
#>
param(
    [string]$InstallPath = $PSScriptRoot
)

$ServiceName = "SentinelShieldService"
$DisplayName = "Sentinel Shield Antivirus Protection Service"
$Description = "Provides real-time antivirus protection, file scanning, and threat remediation."
$ExePath = Join-Path $InstallPath "SentinelShieldAntivirus.exe"

if (-not (Test-Path $ExePath)) {
    Write-Error "Service executable not found at: $ExePath"
    exit 1
}

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Service '$ServiceName' already exists. Stopping..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

Write-Host "Creating data directories..."
$dataRoot = Join-Path $env:ProgramData "SentinelShield"
@("Quarantine", "Logs", "SignaturePacks") | ForEach-Object {
    $dir = Join-Path $dataRoot $_
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "  Created: $dir"
    }
}

Write-Host "Installing service..."
New-Service `
    -Name $ServiceName `
    -BinaryPathName "`"$ExePath`"" `
    -DisplayName $DisplayName `
    -Description $Description `
    -StartupType Automatic `
    | Out-Null

Write-Host "Configuring delayed auto-start..."
sc.exe config $ServiceName start= delayed-auto | Out-Null

Write-Host "Configuring crash recovery (restart after 5 seconds)..."
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null

Write-Host "Adding localhost firewall rule..."
$ruleName = "Sentinel Shield Antivirus (localhost)"
$existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if (-not $existingRule) {
    New-NetFirewallRule `
        -DisplayName $ruleName `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort 5100 `
        -LocalAddress 127.0.0.1 `
        -Action Allow `
        -Profile Any `
        | Out-Null
    Write-Host "  Firewall rule created."
}

Write-Host "Starting service..."
Start-Service -Name $ServiceName

$svc = Get-Service -Name $ServiceName
Write-Host ""
Write-Host "Service installed successfully." -ForegroundColor Green
Write-Host "  Name:   $ServiceName"
Write-Host "  Status: $($svc.Status)"
Write-Host "  URL:    https://127.0.0.1:5100"
Write-Host ""
Write-Host "The tray app can be launched from: $(Join-Path $InstallPath 'SentinelShieldTray.exe')"
