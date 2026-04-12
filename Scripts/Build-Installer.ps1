#Requires -Version 5.1
<#
.SYNOPSIS
    Builds the Sentinel Shield Antivirus installer.

.DESCRIPTION
    1. Publishes the service (ASP.NET Core) as self-contained single-file exe
    2. Publishes the desktop dashboard shell (WPF + WebView2) as self-contained single-file exe
    3. Publishes the tray app (WinForms) as self-contained single-file exe
    4. Compiles the Inno Setup installer into SentinelShieldSetup.exe

.PARAMETER Configuration
    Build configuration. Default: Release

.PARAMETER SkipPublish
    Skip the dotnet publish step (use existing artifacts).

.PARAMETER InnoSetupPath
    Path to iscc.exe. Auto-detected from default install locations.

.EXAMPLE
    .\Build-Installer.ps1
    .\Build-Installer.ps1 -Configuration Debug
    .\Build-Installer.ps1 -SkipPublish
#>
param(
    [string]$Configuration = "Release",
    [switch]$SkipPublish,
    [string]$InnoSetupPath
)

$ErrorActionPreference = "Stop"
$ScriptsDir = $PSScriptRoot
$AntivirusDir = Split-Path $ScriptsDir -Parent
$RepoRoot = Split-Path $AntivirusDir -Parent
$ArtifactsDir = Join-Path $RepoRoot "artifacts"
$ServicePublishDir = Join-Path $ArtifactsDir "publish\service"
$DesktopPublishDir = Join-Path $ArtifactsDir "publish\desktop"
$TrayPublishDir = Join-Path $ArtifactsDir "publish\tray"
$InstallerOutputDir = Join-Path $ArtifactsDir "installer"
$AntivirusProject = Join-Path $AntivirusDir "Antivirus.csproj"
$DesktopProject = Join-Path $AntivirusDir "SentinelShield.Desktop\SentinelShield.Desktop.csproj"
$TrayProject = Join-Path $AntivirusDir "SentinelShield.Tray\SentinelShield.Tray.csproj"
$InnoScript = Join-Path $AntivirusDir "SentinelShield.Installer\SentinelShieldSetup.iss"

function Find-InnoSetup {
    if ($InnoSetupPath -and (Test-Path $InnoSetupPath)) {
        return $InnoSetupPath
    }

    $searchPaths = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 5\ISCC.exe"
    )

    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            return $path
        }
    }

    $inPath = Get-Command "iscc.exe" -ErrorAction SilentlyContinue
    if ($inPath) {
        return $inPath.Source
    }

    return $null
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Sentinel Shield Antivirus Installer   " -ForegroundColor Cyan
Write-Host "  Build Pipeline                        " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 0: Check prerequisites
$iscc = Find-InnoSetup
if (-not $iscc) {
    Write-Host "[ERROR] Inno Setup 6 is required but was not found." -ForegroundColor Red
    Write-Host ""
    Write-Host "Download it free from: https://jrsoftware.org/isdl.php" -ForegroundColor Yellow
    Write-Host "Install it, then re-run this script."
    Write-Host ""
    Write-Host "Or specify the path manually:" -ForegroundColor Yellow
    Write-Host "  .\Build-Installer.ps1 -InnoSetupPath 'C:\path\to\ISCC.exe'"
    exit 1
}
Write-Host "[OK] Inno Setup found: $iscc" -ForegroundColor Green

if (-not $SkipPublish) {
    # Step 1: Clean artifacts
    Write-Host ""
    Write-Host "[1/5] Cleaning artifacts..." -ForegroundColor Yellow
    if (Test-Path $ArtifactsDir) {
        Remove-Item $ArtifactsDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $ServicePublishDir -Force | Out-Null
    New-Item -ItemType Directory -Path $DesktopPublishDir -Force | Out-Null
    New-Item -ItemType Directory -Path $TrayPublishDir -Force | Out-Null
    New-Item -ItemType Directory -Path $InstallerOutputDir -Force | Out-Null

    # Step 2: Build the React frontend
    Write-Host "[2/5] Building React frontend..." -ForegroundColor Yellow
    $clientAppDir = Join-Path $RepoRoot "Antivirus\ClientApp"
    if (Test-Path $clientAppDir) {
        Push-Location $clientAppDir
        npm install --silent 2>&1 | Out-Null
        npm run build 2>&1 | Out-Null
        Pop-Location
        Write-Host "  React build complete." -ForegroundColor Green
    }

    # Step 3: Publish the service
    Write-Host "[3/5] Publishing service (self-contained, single-file)..." -ForegroundColor Yellow
    dotnet publish $AntivirusProject `
        -c $Configuration `
        -r win-x64 `
        --self-contained `
        -o $ServicePublishDir `
        /p:PublishSingleFile=true `
        /p:IncludeNativeLibrariesForSelfExtract=true `
        /p:EnableCompressionInSingleFile=true

    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Service publish failed." -ForegroundColor Red
        exit 1
    }
    $serviceExe = Join-Path $ServicePublishDir "SentinelShieldAntivirus.exe"
    $serviceSize = [math]::Round((Get-Item $serviceExe).Length / 1MB, 1)
    Write-Host "  Service published: $serviceSize MB" -ForegroundColor Green

    # Step 4: Publish the desktop shell
    Write-Host "[4/5] Publishing desktop shell (self-contained, single-file)..." -ForegroundColor Yellow
    dotnet publish $DesktopProject `
        -c $Configuration `
        -r win-x64 `
        --self-contained `
        -o $DesktopPublishDir `
        /p:PublishSingleFile=true `
        /p:IncludeNativeLibrariesForSelfExtract=true `
        /p:EnableCompressionInSingleFile=true

    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Desktop publish failed." -ForegroundColor Red
        exit 1
    }
    $desktopExe = Join-Path $DesktopPublishDir "SentinelShieldDesktop.exe"
    $desktopSize = [math]::Round((Get-Item $desktopExe).Length / 1MB, 1)
    Write-Host "  Desktop published: $desktopSize MB" -ForegroundColor Green

    # Step 5: Publish the tray app
    Write-Host "[5/5] Publishing tray app (self-contained, single-file)..." -ForegroundColor Yellow
    dotnet publish $TrayProject `
        -c $Configuration `
        -r win-x64 `
        --self-contained `
        -o $TrayPublishDir `
        /p:PublishSingleFile=true `
        /p:IncludeNativeLibrariesForSelfExtract=true

    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Tray publish failed." -ForegroundColor Red
        exit 1
    }
    $trayExe = Join-Path $TrayPublishDir "SentinelShieldTray.exe"
    $traySize = [math]::Round((Get-Item $trayExe).Length / 1MB, 1)
    Write-Host "  Tray published: $traySize MB" -ForegroundColor Green
} else {
    Write-Host "[SKIP] Using existing publish artifacts." -ForegroundColor Yellow
}

# Step 5: Compile the installer
Write-Host ""
Write-Host "Compiling Inno Setup installer..." -ForegroundColor Yellow
& $iscc $InnoScript

if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Installer compilation failed." -ForegroundColor Red
    exit 1
}

$installerExe = Join-Path $InstallerOutputDir "SentinelShieldSetup.exe"
if (Test-Path $installerExe) {
    $installerSize = [math]::Round((Get-Item $installerExe).Length / 1MB, 1)
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  BUILD SUCCESSFUL" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Installer: $installerExe"
    Write-Host "  Size:      $installerSize MB"
    Write-Host ""
    Write-Host "  Double-click the .exe to install." -ForegroundColor Cyan
    Write-Host ""
} else {
    Write-Host "[ERROR] Installer file not found at expected path." -ForegroundColor Red
    exit 1
}
