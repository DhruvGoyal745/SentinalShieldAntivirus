namespace Antivirus.Domain;

public enum ScanMode
{
    Quick,
    Full,
    Custom
}

public enum ScanStatus
{
    Pending,
    Running,
    Cancelled,
    Completed,
    Failed
}

public enum ScanStage
{
    Queued,
    Observe,
    Normalize,
    StaticAnalysis,
    HeuristicAnalysis,
    ReputationLookup,
    Response,
    Telemetry,
    WaitingForInput,
    Cancelled,
    Completed,
    Failed
}

public enum ThreatSeverity
{
    Informational,
    Low,
    Medium,
    High,
    Critical
}

public enum ThreatSource
{
    WindowsDefender,
    Heuristic,
    Yara,
    ClamAv,
    ProprietaryStatic,
    Behavior,
    Reputation,
    Sandbox,
    LegacyShadow,
    PatternRule,
    SignatureHash
}

public enum FileEventType
{
    Created,
    Changed,
    Renamed,
    Deleted
}

public enum FileEventStatus
{
    Pending,
    Processing,
    Clean,
    Suspicious,
    ThreatDetected,
    Error,
    Skipped
}

public enum FileEngineResultStatus
{
    Clean,
    Suspicious,
    ThreatDetected,
    Error,
    Unavailable,
    Skipped
}

public sealed class ScanRequest
{
    public ScanMode Mode { get; init; } = ScanMode.Quick;

    public string? TargetPath { get; init; }

    public string RequestedBy { get; init; } = "desktop-user";

    public bool RunHeuristics { get; init; } = true;
}

public sealed class ScanJob
{
    public int Id { get; init; }

    public ScanMode Mode { get; init; }

    public string? TargetPath { get; init; }

    public string RequestedBy { get; init; } = string.Empty;

    public ScanStatus Status { get; init; }

    public int ThreatCount { get; init; }

    public int PercentComplete { get; init; }

    public ScanStage Stage { get; init; }

    public int FilesScanned { get; init; }

    public int? TotalFiles { get; init; }

    public string? CurrentTarget { get; init; }

    public string? Notes { get; init; }

    public DateTimeOffset CreatedAt { get; init; }

    public DateTimeOffset? StartedAt { get; init; }

    public DateTimeOffset? CompletedAt { get; init; }
}

public sealed class ScanProgressEvent
{
    public int ScanJobId { get; init; }

    public ScanStage Stage { get; init; }

    public int PercentComplete { get; init; }

    public string? CurrentPath { get; init; }

    public int FilesScanned { get; init; }

    public int? TotalFiles { get; init; }

    public int FindingsCount { get; init; }

    public bool IsSkipped { get; init; }

    public string? DetailMessage { get; init; }

    public DateTimeOffset StartedAt { get; init; }

    public DateTimeOffset? CompletedAt { get; init; }

    public DateTimeOffset RecordedAt { get; init; } = DateTimeOffset.UtcNow;
}

public sealed class ScanHandle
{
    public int ScanJobId { get; init; }

    public string EngineScanId { get; init; } = string.Empty;
}

public sealed class ScanControlResult
{
    public bool Success { get; init; }

    public ScanStatus Status { get; init; }

    public string Message { get; init; } = string.Empty;
}

public enum ScanFileDecisionAction
{
    Retry,
    Skip
}

public sealed class ScanFileDecision
{
    public required string FilePath { get; init; }

    public required ScanFileDecisionAction Action { get; init; }
}

public sealed class ScanFileDecisionResult
{
    public bool Success { get; init; }

    public string Message { get; init; } = string.Empty;
}

public sealed class PendingScanFilePrompt
{
    public required int ScanId { get; init; }

    public required string FilePath { get; init; }

    public required string Reason { get; init; }

    public required DateTimeOffset OccurredAt { get; init; }
}

public sealed class ScanStatusSnapshot
{
    public int ScanJobId { get; init; }

    public ScanStatus Status { get; init; }

    public ScanStage Stage { get; init; }

    public int PercentComplete { get; init; }

    public int FilesScanned { get; init; }

    public int? TotalFiles { get; init; }

    public string? CurrentTarget { get; init; }

    public int FindingsCount { get; init; }

    public DateTimeOffset StartedAt { get; init; }

    public DateTimeOffset? CompletedAt { get; init; }
}

public sealed class FileArtifact
{
    public string FullPath { get; init; } = string.Empty;

    public string FileName { get; init; } = string.Empty;

    public long SizeBytes { get; init; }

    public string? HashSha256 { get; init; }

    public FileEventType EventType { get; init; }

    public DateTimeOffset ObservedAt { get; init; } = DateTimeOffset.UtcNow;
}

public sealed class EngineDetection
{
    public string RuleId { get; init; } = string.Empty;

    public string EngineName { get; init; } = string.Empty;

    public ThreatSource Source { get; init; }

    public ThreatSeverity Severity { get; init; }

    public decimal Confidence { get; init; }

    public string Summary { get; init; } = string.Empty;

    public string? ArtifactPath { get; init; }

    public string? EvidenceJson { get; init; }
}

public sealed class EngineHealthSnapshot
{
    public bool EngineOnline { get; init; }

    public string EngineVersion { get; init; } = string.Empty;

    public string SignaturePackVersion { get; init; } = string.Empty;

    public string ParserCompatibilityVersion { get; init; } = string.Empty;

    public bool RealtimeMonitoringEnabled { get; init; }

    public string DaemonTransport { get; init; } = string.Empty;

    public DateTimeOffset CapturedAt { get; init; } = DateTimeOffset.UtcNow;
}

public sealed class RealtimeSubmissionResult
{
    public int FileEventId { get; init; }

    public string EngineSubmissionId { get; init; } = string.Empty;

    public bool Accepted { get; init; }

    public string Message { get; init; } = string.Empty;
}

public sealed class LoadSignaturePackResult
{
    public bool Success { get; init; }

    public string Version { get; init; } = string.Empty;

    public int RuleCount { get; init; }

    public string Message { get; init; } = string.Empty;
}

public enum SignatureRuleKind
{
    Hash,
    FileName,
    PathFragment,
    ContentLiteral,
    PeMetadata,
    ElfMetadata,
    ArchiveMemberName,
    DocumentMetadata
}

public sealed class CompiledSignatureRule
{
    public string RuleId { get; init; } = string.Empty;

    public string RuleName { get; init; } = string.Empty;

    public SignatureRuleKind RuleKind { get; init; }

    public string Pattern { get; init; } = string.Empty;

    public ThreatSeverity Severity { get; init; }
}

public sealed class ProprietarySignaturePack
{
    public SignaturePackManifest Manifest { get; init; } = new();

    public string ParserCompatibilityVersion { get; init; } = "1.0.0";

    public string SigningMetadata { get; init; } = string.Empty;

    public IReadOnlyCollection<CompiledSignatureRule> Rules { get; init; } = Array.Empty<CompiledSignatureRule>();

    public byte[] SerializedBytes { get; init; } = Array.Empty<byte>();
}

public sealed class ThreatDetection
{
    public int Id { get; init; }

    public int? ScanJobId { get; init; }

    public string Name { get; init; } = string.Empty;

    public string Category { get; init; } = "Malware";

    public ThreatSeverity Severity { get; init; }

    public ThreatSource Source { get; init; }

    public string? Resource { get; init; }

    public string? Description { get; init; }

    public string? EngineName { get; init; }

    public bool IsQuarantined { get; init; }

    public string? QuarantinePath { get; init; }

    public string? EvidenceJson { get; init; }

    public DateTimeOffset DetectedAt { get; init; }
}

public sealed class DeviceHealthSnapshot
{
    public DateTimeOffset CapturedAt { get; init; }

    public bool AntivirusEnabled { get; init; }

    public bool RealTimeProtectionEnabled { get; init; }

    public bool IoavProtectionEnabled { get; init; }

    public bool NetworkInspectionEnabled { get; init; }

    public bool EngineServiceEnabled { get; init; }

    public bool SignaturesOutOfDate { get; init; }

    public string? AntivirusSignatureVersion { get; init; }

    public DateTimeOffset? AntivirusSignatureLastUpdated { get; init; }

    public int? QuickScanAgeDays { get; init; }

    public int? FullScanAgeDays { get; init; }
}

public sealed class DashboardSummary
{
    public DeviceHealthSnapshot? Health { get; init; }

    public IReadOnlyCollection<ScanJob> RecentScans { get; init; } = Array.Empty<ScanJob>();

    public IReadOnlyCollection<ThreatDetection> ActiveThreats { get; init; } = Array.Empty<ThreatDetection>();

    public IReadOnlyCollection<FileSecurityEvent> RecentFileEvents { get; init; } = Array.Empty<FileSecurityEvent>();
}

public sealed class ScanExecutionResult
{
    public ScanJob Scan { get; init; } = new();

    public IReadOnlyCollection<ThreatDetection> Threats { get; init; } = Array.Empty<ThreatDetection>();
}

public sealed class QueuedScanWorkItem
{
    public required int ScanId { get; init; }

    public required ScanRequest Request { get; init; }
}

public sealed class FileWatchNotification
{
    public required string FilePath { get; init; }

    public required FileEventType EventType { get; init; }

    public string? PreviousPath { get; init; }

    public DateTimeOffset ObservedAt { get; init; } = DateTimeOffset.UtcNow;
}

public sealed class QueuedFileEventWorkItem
{
    public required int FileEventId { get; init; }

    public required FileWatchNotification Notification { get; init; }
}

public sealed class FileSecurityEvent
{
    public int Id { get; init; }

    public string FilePath { get; init; } = string.Empty;

    public string? PreviousPath { get; init; }

    public FileEventType EventType { get; init; }

    public FileEventStatus Status { get; init; }

    public string? HashSha256 { get; init; }

    public long? FileSizeBytes { get; init; }

    public int ThreatCount { get; init; }

    public string? Notes { get; init; }

    public DateTimeOffset ObservedAt { get; init; }

    public DateTimeOffset CreatedAt { get; init; }

    public DateTimeOffset? ProcessedAt { get; init; }

    public IReadOnlyCollection<FileEngineResult> EngineResults { get; init; } = Array.Empty<FileEngineResult>();
}

public sealed class FileEngineResult
{
    public int Id { get; init; }

    public int FileSecurityEventId { get; init; }

    public string EngineName { get; init; } = string.Empty;

    public ThreatSource Source { get; init; }

    public FileEngineResultStatus Status { get; init; }

    public bool IsMatch { get; init; }

    public string? SignatureName { get; init; }

    public string? Details { get; init; }

    public string? RawOutput { get; init; }

    public DateTimeOffset ScannedAt { get; init; }
}

public sealed class FileScannerEngineResult
{
    public string EngineName { get; init; } = string.Empty;

    public ThreatSource Source { get; init; }

    public FileEngineResultStatus Status { get; init; }

    public bool IsMatch { get; init; }

    public string? SignatureName { get; init; }

    public string? Details { get; init; }

    public string? RawOutput { get; init; }

    public DateTimeOffset ScannedAt { get; init; } = DateTimeOffset.UtcNow;
}

public sealed class QuarantineResult
{
    public bool Success { get; init; }

    public string Message { get; init; } = string.Empty;
}

public sealed class DefenderScanResult
{
    public string Output { get; init; } = string.Empty;

    public IReadOnlyCollection<ThreatDetection> Threats { get; init; } = Array.Empty<ThreatDetection>();
}

public sealed class FileScanContext
{
    public required FileInfo File { get; init; }

    public required string RootPath { get; init; }

    public required ScanMode Mode { get; init; }
}
