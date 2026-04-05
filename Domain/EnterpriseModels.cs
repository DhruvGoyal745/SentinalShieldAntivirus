namespace Antivirus.Domain;

public enum OperatingSystemPlatform
{
    Windows,
    MacOs,
    Linux
}

public enum DeviceEnrollmentStatus
{
    Pending,
    Active,
    Disabled
}

public enum PackRolloutRing
{
    Internal,
    Canary,
    EarlyAdopter,
    Broad
}

public enum SignaturePackStatus
{
    Draft,
    Released,
    Paused,
    RolledBack
}

public enum IncidentStatus
{
    Open,
    Investigating,
    Contained,
    Resolved
}

public enum RemediationActionKind
{
    Quarantine,
    BlockExecution,
    KillProcess,
    Rollback
}

public enum RemediationStatus
{
    Pending,
    Completed,
    Failed
}

public enum FalsePositiveScope
{
    DeviceLocal,
    TenantPolicy,
    GlobalPackCandidate
}

public enum FalsePositiveReviewStatus
{
    Submitted,
    UnderReview,
    Approved,
    Rejected
}

public enum SandboxSubmissionStatus
{
    Queued,
    Submitted,
    Completed,
    Failed
}

public enum SandboxVerdict
{
    Unknown,
    Benign,
    Suspicious,
    Malicious
}

public enum ComplianceReportType
{
    Posture,
    Audit,
    Export
}

public enum PipelineVerdict
{
    Clean,
    Suspicious,
    Malicious
}

public sealed class TenantSummary
{
    public int Id { get; init; }

    public string TenantKey { get; init; } = string.Empty;

    public string DisplayName { get; init; } = string.Empty;

    public string DatabaseName { get; init; } = string.Empty;

    public bool IsActive { get; init; }

    public DateTimeOffset CreatedAt { get; init; }
}

public sealed class FleetPostureSummary
{
    public string TenantKey { get; init; } = string.Empty;

    public int DeviceCount { get; init; }

    public int ActiveDeviceCount { get; init; }

    public int OpenIncidentCount { get; init; }

    public int CriticalThreatCount { get; init; }

    public decimal AgentCoveragePercent { get; init; }

    public decimal SignatureCurrencyPercent { get; init; }

    public decimal PolicyCompliancePercent { get; init; }

    public decimal BaselineCoveragePercent { get; init; }

    public decimal SelfProtectionCoveragePercent { get; init; }

    public bool LegacyShadowModeEnabled { get; init; }

    public string CurrentPackVersion { get; init; } = string.Empty;
}

public sealed class AgentSelfProtectionStatus
{
    public bool ProcessProtectionEnabled { get; init; }

    public bool FileProtectionEnabled { get; init; }

    public bool ServiceProtectionEnabled { get; init; }

    public bool DriverProtectionEnabled { get; init; }

    public bool WatchdogHealthy { get; init; }

    public bool SignedUpdatesOnly { get; init; }
}

public sealed class DeviceProfile
{
    public int Id { get; init; }

    public string DeviceId { get; init; } = string.Empty;

    public string DeviceName { get; init; } = string.Empty;

    public OperatingSystemPlatform OperatingSystem { get; init; }

    public string AgentVersion { get; init; } = string.Empty;

    public string EngineVersion { get; init; } = string.Empty;

    public string SignaturePackVersion { get; init; } = string.Empty;

    public string PolicyVersion { get; init; } = string.Empty;

    public PackRolloutRing RolloutRing { get; init; }

    public DeviceEnrollmentStatus EnrollmentStatus { get; init; }

    public bool BaselineScanCompleted { get; init; }

    public bool LegacyShadowModeEnabled { get; init; }

    public AgentSelfProtectionStatus SelfProtection { get; init; } = new();

    public IReadOnlyCollection<string> Capabilities { get; init; } = Array.Empty<string>();

    public DateTimeOffset CreatedAt { get; init; }

    public DateTimeOffset? LastSeenAt { get; init; }
}

public sealed class DevicePolicyBundle
{
    public int Id { get; init; }

    public string PolicyName { get; init; } = string.Empty;

    public string Version { get; init; } = string.Empty;

    public PackRolloutRing RolloutRing { get; init; }

    public bool QuarantineOnMalicious { get; init; } = true;

    public bool BlockHighConfidenceDetections { get; init; } = true;

    public bool AllowSampleUpload { get; init; }

    public bool EnableLegacyShadowMode { get; init; } = true;

    public string PolicyJson { get; init; } = "{}";

    public DateTimeOffset CreatedAt { get; init; }
}

public sealed class SignaturePackManifest
{
    public int Id { get; init; }

    public string Version { get; init; } = string.Empty;

    public PackRolloutRing RolloutRing { get; init; }

    public string Channel { get; init; } = "stable";

    public bool IsDelta { get; init; }

    public string Sha256 { get; init; } = string.Empty;

    public string DownloadUrl { get; init; } = string.Empty;

    public int SignatureCount { get; init; }

    public string MinAgentVersion { get; init; } = "1.0.0";

    public SignaturePackStatus Status { get; init; }

    public DateTimeOffset CreatedAt { get; init; }

    public DateTimeOffset? ReleasedAt { get; init; }
}

public sealed class ComplianceReport
{
    public int Id { get; init; }

    public ComplianceReportType ReportType { get; init; }

    public DateTimeOffset ReportDate { get; init; }

    public decimal AgentCoveragePercent { get; init; }

    public decimal SignatureCurrencyPercent { get; init; }

    public decimal PolicyCompliancePercent { get; init; }

    public decimal BaselineScanCompletionPercent { get; init; }

    public int OpenCriticalIncidentCount { get; init; }

    public int QuarantinedThreatCount { get; init; }

    public decimal SelfProtectionCoveragePercent { get; init; }

    public int AuditFindingCount { get; init; }

    public string ExportJson { get; init; } = "{}";

    public DateTimeOffset CreatedAt { get; init; }
}

public sealed class FalsePositiveReview
{
    public int Id { get; init; }

    public int? ThreatDetectionId { get; init; }

    public string ArtifactHash { get; init; } = string.Empty;

    public string RuleId { get; init; } = string.Empty;

    public FalsePositiveScope Scope { get; init; }

    public FalsePositiveReviewStatus Status { get; init; }

    public string Analyst { get; init; } = string.Empty;

    public string Notes { get; init; } = string.Empty;

    public DateTimeOffset SubmittedAt { get; init; }

    public DateTimeOffset? DecisionedAt { get; init; }
}

public sealed class SandboxSubmission
{
    public int Id { get; init; }

    public string DeviceId { get; init; } = string.Empty;

    public string ArtifactHash { get; init; } = string.Empty;

    public string FileName { get; init; } = string.Empty;

    public SandboxSubmissionStatus Status { get; init; }

    public string CorrelationId { get; init; } = string.Empty;

    public SandboxVerdict Verdict { get; init; }

    public string BehaviorSummary { get; init; } = string.Empty;

    public string IndicatorsJson { get; init; } = "[]";

    public string FamilyName { get; init; } = string.Empty;

    public string TagsJson { get; init; } = "[]";

    public DateTimeOffset CreatedAt { get; init; }

    public DateTimeOffset? UpdatedAt { get; init; }
}

public sealed class LegacyParitySnapshot
{
    public int Id { get; init; }

    public string DeviceId { get; init; } = string.Empty;

    public OperatingSystemPlatform OperatingSystem { get; init; }

    public string MalwareFamily { get; init; } = string.Empty;

    public decimal DetectionRecallPercent { get; init; }

    public decimal FalsePositiveRatePercent { get; init; }

    public decimal VerdictLatencyMilliseconds { get; init; }

    public decimal RemediationSuccessPercent { get; init; }

    public decimal CrashTamperRatePercent { get; init; }

    public DateTimeOffset CreatedAt { get; init; }
}

public sealed class SecurityIncident
{
    public int Id { get; init; }

    public string DeviceId { get; init; } = string.Empty;

    public string Title { get; init; } = string.Empty;

    public ThreatSeverity Severity { get; init; }

    public IncidentStatus Status { get; init; }

    public string Source { get; init; } = string.Empty;

    public string PrimaryArtifact { get; init; } = string.Empty;

    public string RuleId { get; init; } = string.Empty;

    public decimal Confidence { get; init; }

    public string Summary { get; init; } = string.Empty;

    public DateTimeOffset CreatedAt { get; init; }

    public DateTimeOffset? UpdatedAt { get; init; }
}

public sealed class RemediationActionRecord
{
    public int Id { get; init; }

    public string DeviceId { get; init; } = string.Empty;

    public int? ThreatDetectionId { get; init; }

    public int? IncidentId { get; init; }

    public RemediationActionKind ActionKind { get; init; }

    public RemediationStatus Status { get; init; }

    public string RequestedBy { get; init; } = string.Empty;

    public string Notes { get; init; } = string.Empty;

    public DateTimeOffset CreatedAt { get; init; }

    public DateTimeOffset? CompletedAt { get; init; }
}

public sealed class AgentRegistrationRequest
{
    public string DeviceId { get; init; } = string.Empty;

    public string DeviceName { get; init; } = string.Empty;

    public OperatingSystemPlatform OperatingSystem { get; init; }

    public string AgentVersion { get; init; } = "1.0.0";

    public string EngineVersion { get; init; } = "1.0.0";

    public PackRolloutRing RolloutRing { get; init; } = PackRolloutRing.Canary;

    public IReadOnlyCollection<string> Capabilities { get; init; } = Array.Empty<string>();
}

public sealed class AgentRegistrationResponse
{
    public string TenantKey { get; init; } = string.Empty;

    public DeviceProfile Device { get; init; } = new();

    public DevicePolicyBundle Policy { get; init; } = new();

    public SignaturePackManifest SignaturePack { get; init; } = new();
}

public sealed class AgentHeartbeatRequest
{
    public string DeviceId { get; init; } = string.Empty;

    public string AgentVersion { get; init; } = "1.0.0";

    public string EngineVersion { get; init; } = "1.0.0";

    public string SignaturePackVersion { get; init; } = string.Empty;

    public string PolicyVersion { get; init; } = string.Empty;

    public bool BaselineScanCompleted { get; init; }

    public bool LegacyShadowModeEnabled { get; init; }

    public AgentSelfProtectionStatus SelfProtection { get; init; } = new();
}

public sealed class AgentHeartbeatResponse
{
    public DevicePolicyBundle Policy { get; init; } = new();

    public SignaturePackManifest SignaturePack { get; init; } = new();

    public bool PolicyChanged { get; init; }

    public bool PackChanged { get; init; }
}

public sealed class SignatureRuleDefinition
{
    public int Id { get; init; }

    public string RuleName { get; init; } = string.Empty;

    public string Pattern { get; init; } = string.Empty;

    public ThreatSeverity Severity { get; init; }
}

public sealed class DetectionEventRecord
{
    public string RuleId { get; init; } = string.Empty;

    public string EngineName { get; init; } = string.Empty;

    public ThreatSource Source { get; init; }

    public ThreatSeverity Severity { get; init; }

    public decimal Confidence { get; init; }

    public string Summary { get; init; } = string.Empty;
}

public sealed class PipelineScanResult
{
    public PipelineVerdict Verdict { get; init; }

    public IReadOnlyCollection<FileScannerEngineResult> EngineResults { get; init; } = Array.Empty<FileScannerEngineResult>();

    public IReadOnlyCollection<ThreatDetection> Threats { get; init; } = Array.Empty<ThreatDetection>();

    public IReadOnlyCollection<DetectionEventRecord> DetectionEvents { get; init; } = Array.Empty<DetectionEventRecord>();

    public bool Quarantined { get; init; }

    public string? QuarantinePath { get; init; }

    public SandboxSubmission? SandboxSubmission { get; init; }
}

public sealed class EnterpriseDashboardSummary
{
    public TenantSummary Tenant { get; init; } = new();

    public FleetPostureSummary Fleet { get; init; } = new();

    public IReadOnlyCollection<DeviceProfile> Devices { get; init; } = Array.Empty<DeviceProfile>();

    public IReadOnlyCollection<SecurityIncident> Incidents { get; init; } = Array.Empty<SecurityIncident>();

    public IReadOnlyCollection<ComplianceReport> ComplianceReports { get; init; } = Array.Empty<ComplianceReport>();

    public IReadOnlyCollection<SignaturePackManifest> SignaturePacks { get; init; } = Array.Empty<SignaturePackManifest>();

    public IReadOnlyCollection<LegacyParitySnapshot> ParitySnapshots { get; init; } = Array.Empty<LegacyParitySnapshot>();

    public IReadOnlyCollection<SandboxSubmission> SandboxSubmissions { get; init; } = Array.Empty<SandboxSubmission>();

    public IReadOnlyCollection<FalsePositiveReview> FalsePositiveReviews { get; init; } = Array.Empty<FalsePositiveReview>();
}

public sealed class ScanReportExport
{
    public int Id { get; init; }

    public int? ScanJobId { get; init; }

    public string FileName { get; init; } = string.Empty;

    public string Format { get; init; } = "xls";

    public string ExportedBy { get; init; } = string.Empty;

    public int VulnerabilityCount { get; init; }

    public DateTimeOffset ExportedAt { get; init; }
}
