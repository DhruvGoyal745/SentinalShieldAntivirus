using Antivirus.Domain;
using Microsoft.Data.SqlClient;

namespace Antivirus.Application.Contracts;

public interface ITenantContextAccessor
{
    string? CurrentTenantKey { get; set; }
}

public interface ITenantRegistry
{
    string GetCurrentTenantKey();

    Task<TenantSummary> EnsureTenantAsync(string tenantKey, CancellationToken cancellationToken = default);

    Task<TenantSummary> GetCurrentTenantAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<TenantSummary>> GetTenantsAsync(CancellationToken cancellationToken = default);

    Task<SqlConnection> OpenTenantConnectionAsync(CancellationToken cancellationToken = default);

    Task<SqlConnection> OpenPlatformConnectionAsync(CancellationToken cancellationToken = default);
}

public interface IControlPlaneRepository
{
    Task<DeviceProfile> UpsertDeviceAsync(AgentRegistrationRequest request, CancellationToken cancellationToken = default);

    Task<DeviceProfile?> GetDeviceAsync(string deviceId, CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<DeviceProfile>> GetDevicesAsync(CancellationToken cancellationToken = default);

    Task SaveHeartbeatAsync(AgentHeartbeatRequest request, CancellationToken cancellationToken = default);

    Task<DevicePolicyBundle> GetActivePolicyAsync(CancellationToken cancellationToken = default);

    Task<SignaturePackManifest> GetCurrentSignaturePackAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<SignaturePackManifest>> GetSignaturePacksAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<SignatureRuleDefinition>> GetEnabledSignatureRulesAsync(CancellationToken cancellationToken = default);

    Task<SecurityIncident> CreateIncidentAsync(SecurityIncident incident, CancellationToken cancellationToken = default);

    Task<bool> ResolveIncidentAsync(int incidentId, string resolvedBy, CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<SecurityIncident>> GetIncidentsAsync(CancellationToken cancellationToken = default);

    Task SaveRemediationActionAsync(RemediationActionRecord action, CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<ComplianceReport>> GetComplianceReportsAsync(CancellationToken cancellationToken = default);

    Task<ComplianceReport> SaveComplianceReportAsync(ComplianceReport report, CancellationToken cancellationToken = default);

    Task<FalsePositiveReview> CreateFalsePositiveReviewAsync(FalsePositiveReview review, CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<FalsePositiveReview>> GetFalsePositiveReviewsAsync(CancellationToken cancellationToken = default);

    Task<SandboxSubmission> CreateSandboxSubmissionAsync(SandboxSubmission submission, CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<SandboxSubmission>> GetSandboxSubmissionsAsync(CancellationToken cancellationToken = default);

    Task SaveLegacyParitySnapshotAsync(LegacyParitySnapshot snapshot, CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<LegacyParitySnapshot>> GetLegacyParitySnapshotsAsync(CancellationToken cancellationToken = default);
}

public interface IAgentControlPlaneService
{
    Task<AgentRegistrationResponse> RegisterAsync(AgentRegistrationRequest request, CancellationToken cancellationToken = default);

    Task<AgentHeartbeatResponse> HeartbeatAsync(AgentHeartbeatRequest request, CancellationToken cancellationToken = default);
}

public interface IEnterpriseDashboardService
{
    Task<EnterpriseDashboardSummary> GetSummaryAsync(CancellationToken cancellationToken = default);
}

public interface IComplianceService
{
    Task<ComplianceReport> CaptureAsync(CancellationToken cancellationToken = default);
}

public interface IStaticFileScanner
{
    Task<IReadOnlyCollection<DetectionEventRecord>> ScanAsync(FileInfo file, string hashSha256, CancellationToken cancellationToken = default);
}

public interface IBehaviorMonitor
{
    Task<IReadOnlyCollection<DetectionEventRecord>> AnalyzeAsync(FileWatchNotification notification, FileInfo file, CancellationToken cancellationToken = default);
}

public interface IReputationClient
{
    Task<DetectionEventRecord?> EvaluateAsync(FileInfo file, string hashSha256, CancellationToken cancellationToken = default);
}

public interface IRemediationCoordinator
{
    Task<(bool Quarantined, string? QuarantinePath)> QuarantineAsync(FileInfo file, CancellationToken cancellationToken = default);
}

public interface ISignaturePackProvider
{
    Task<SignaturePackManifest> GetCurrentPackAsync(CancellationToken cancellationToken = default);

    Task<ProprietarySignaturePack> GetCompiledPackAsync(CancellationToken cancellationToken = default);
}

public interface ISandboxSubmissionClient
{
    Task<SandboxSubmission?> SubmitIfNeededAsync(
        string deviceId,
        FileInfo file,
        string hashSha256,
        PipelineVerdict verdict,
        IReadOnlyCollection<DetectionEventRecord> detections,
        CancellationToken cancellationToken = default);
}

public interface IProprietaryProtectionEngine
{
    Task<PipelineScanResult> ScanFileAsync(
        int? scanJobId,
        FileWatchNotification notification,
        FileInfo file,
        string requestedBy,
        CancellationToken cancellationToken = default);

    Task<PipelineScanResult> ScanRequestAsync(int scanJobId, ScanRequest request, CancellationToken cancellationToken = default);

    Task<DeviceHealthSnapshot> CaptureAgentHealthAsync(CancellationToken cancellationToken = default);
}

public interface ISignaturePackCompiler
{
    Task<ProprietarySignaturePack> CompileAsync(
        SignaturePackManifest manifest,
        IReadOnlyCollection<SignatureRuleDefinition> rules,
        CancellationToken cancellationToken = default);
}

public interface IEngineDaemonClient
{
    Task<LoadSignaturePackResult> LoadSignaturePackAsync(ProprietarySignaturePack pack, CancellationToken cancellationToken = default);

    Task<ScanHandle> StartManualScanAsync(
        int scanJobId,
        ScanRequest request,
        Func<ScanProgressEvent, Task> onProgress,
        CancellationToken cancellationToken = default);

    Task<ScanStatusSnapshot> GetScanStatusAsync(int scanJobId, CancellationToken cancellationToken = default);

    IAsyncEnumerable<ScanProgressEvent> SubscribeScanProgressAsync(int scanJobId, CancellationToken cancellationToken = default);

    Task<(PipelineScanResult Result, RealtimeSubmissionResult Submission)> SubmitRealtimeFileEventAsync(
        int fileEventId,
        FileArtifact artifact,
        string requestedBy,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<EngineDetection>> GetDetectionsForScanAsync(int scanJobId, CancellationToken cancellationToken = default);

    Task<QuarantineResult> QuarantineFileAsync(string path, CancellationToken cancellationToken = default);

    Task<EngineHealthSnapshot> GetEngineHealthAsync(CancellationToken cancellationToken = default);
}

public interface IScanReportService
{
    Task<IReadOnlyCollection<ScanReportExport>> GetExportsAsync(CancellationToken cancellationToken = default);

    Task<(byte[] Content, string FileName, string ContentType)> ExportAllScansAsync(string requestedBy, CancellationToken cancellationToken = default);

    Task<(byte[] Content, string FileName, string ContentType)> ExportScanAsync(int scanId, string requestedBy, CancellationToken cancellationToken = default);
}
