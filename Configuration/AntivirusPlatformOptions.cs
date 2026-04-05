namespace Antivirus.Configuration;

public sealed class AntivirusPlatformOptions
{
    public const string SectionName = "AntivirusPlatform";

    public string QuarantineRoot { get; set; } = "Data\\Quarantine";

    public int MaxHeuristicFiles { get; set; } = 1500;

    public string DefaultRequestedBy { get; set; } = "desktop-user";

    public bool RealtimeWatcherEnabled { get; set; } = true;

    public string[] WatchRoots { get; set; } = Array.Empty<string>();

    public int FileEventDebounceSeconds { get; set; } = 5;

    public int MaxFileScanBytes { get; set; } = 104857600;

    public int MaxHashComputationBytes { get; set; } = 33554432;

    public int MaxContentInspectionBytes { get; set; } = 131072;

    public int MaxParallelScanWorkers { get; set; } = 4;

    public int ProgressPersistEveryFiles { get; set; } = 25;

    public int ProgressPersistMinIntervalMs { get; set; } = 750;

    public string YaraExecutablePath { get; set; } = "Tools\\Yara\\yara64.exe";

    public string YaraRulesPath { get; set; } = "Rules\\Yara\\starter-rules.yar";

    public bool YaraRulesCompiled { get; set; }

    public string ClamAvExecutablePath { get; set; } = "Tools\\ClamAV\\clamscan.exe";

    public string ClamAvDaemonExecutablePath { get; set; } = "Tools\\ClamAV\\clamdscan.exe";

    public bool PreferClamAvDaemon { get; set; }

    public bool UseOpenSourceScanners { get; set; }

    public bool UseLegacyShadowMode { get; set; } = true;

    public bool UseNativeEngineBridge { get; set; } = true;

    public bool UseManagedNativeEngineFallback { get; set; } = true;

    public string NativeEngineDaemonPath { get; set; } = "NativeEngine\\artifacts\\sentinel-engine-daemon.exe";

    public string NativeEnginePipeName { get; set; } = "sentinel-engine-daemon";

    public string NativeEngineSocketPath { get; set; } = "/tmp/sentinel-engine-daemon.sock";

    public string SignaturePackRoot { get; set; } = "Data\\SignaturePacks";

    public string ParserCompatibilityVersion { get; set; } = "parser-1.0.0";

    public string SignatureCompilerVersion { get; set; } = "sigc-1.0.0";

    public string DefaultTenantKey { get; set; } = "sentinel-demo";

    public string TenantDatabasePrefix { get; set; } = "SentinelShieldTenant_";

    public string CurrentSignaturePackVersion { get; set; } = "pack-2026.03.29.1";

    public string CurrentPolicyVersion { get; set; } = "policy-1.0.0";

    public string ProprietaryEngineVersion { get; set; } = "engine-1.0.0";

    public bool SandboxEnabled { get; set; } = true;

    public bool AllowSampleUpload { get; set; }

    public string SignaturePackChannel { get; set; } = "stable";

    public string SignaturePackDownloadUrl { get; set; } = "/downloads/signature-pack";
}
