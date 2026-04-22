namespace Antivirus.Configuration;

public sealed class AntivirusPlatformOptions
{
    public const string SectionName = "AntivirusPlatform";

    public string DataRoot { get; set; } = "Data";

    public string QuarantineRoot { get; set; } = "Data\\Quarantine";

    public string LogsRoot { get; set; } = "Data\\Logs";

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

    public int FileDecisionTimeoutSeconds { get; set; } = 300;

    public bool UseInHouseScanners { get; set; } = true;


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

    // ── Phase 1: Platform Security ──────────────────────────────────────

    public bool RequireSignedManifests { get; set; }

    public bool LocalTrustBoundaryEnabled { get; set; }

    public string LocalTrustTokenHeaderName { get; set; } = "X-Local-Token";

    // ── Phase 0A: Authentication ────────────────────────────────────────

    public string? JwtSigningKey { get; set; }

    public string? DefaultAdminPassword { get; set; }

    // ── Phase 2A: Secure Quarantine ─────────────────────────────────

    public bool QuarantineEncryptionEnabled { get; set; } = true;

    public int QuarantineRetentionDays { get; set; } = 30;

    public int SecureDeletePasses { get; set; } = 3;

    // ── Phase 2B: Ransomware Shield ─────────────────────────────────

    public string[] ProtectedFolders { get; set; } = Array.Empty<string>();

    public int RansomwareFileWriteThresholdPerMinute { get; set; } = 50;

    public double RansomwareEntropyThreshold { get; set; } = 7.0;

    public long RansomwareMaxEntropyFileSizeBytes { get; set; } = 33554432; // 32MB

    public bool RansomwareAutoKillEnabled { get; set; }

    public bool RansomwareAutoSuspendEnabled { get; set; }
}
