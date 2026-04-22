using Antivirus.Domain;

namespace Antivirus.Application.Contracts;

public interface IDatabaseBootstrapper
{
    Task InitializeAsync(CancellationToken cancellationToken = default);
}

public interface ISqlConnectionFactory
{
    string PlatformConnectionString { get; }

    string MasterConnectionString { get; }
}

// ── Segregated repository interfaces (ISP) ──────────────────────

public interface IScanRepository
{
    Task<int> CreateScanAsync(ScanRequest request, CancellationToken cancellationToken = default);

    Task<ScanJob?> GetScanByIdAsync(int id, CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<ScanJob>> GetRecoverableScansAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<ScanJob>> GetRecentScansAsync(int take, CancellationToken cancellationToken = default);

    Task UpdateScanStatusAsync(int scanId, ScanStatusUpdate update, CancellationToken cancellationToken = default);

    Task AppendScanProgressAsync(ScanProgressEvent progressEvent, CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<ScanProgressEvent>> GetScanProgressEventsAsync(int scanId, int take, CancellationToken cancellationToken = default);
}

public interface IThreatRepository
{
    Task UpsertThreatsAsync(int? scanJobId, IEnumerable<ThreatDetection> threats, CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<ThreatDetection>> GetThreatsAsync(bool activeOnly, CancellationToken cancellationToken = default);

    Task<ThreatDetection?> GetThreatByIdAsync(int id, CancellationToken cancellationToken = default);

    Task MarkThreatQuarantinedAsync(int id, string? quarantinePath, CancellationToken cancellationToken = default);
}

public interface IFileEventRepository
{
    Task<int> CreateFileEventAsync(FileWatchNotification notification, int? scanJobId = null, CancellationToken cancellationToken = default);

    Task UpdateFileEventAsync(int fileEventId, FileEventUpdate update, CancellationToken cancellationToken = default);

    Task SaveFileEngineResultsAsync(int fileEventId, IEnumerable<FileScannerEngineResult> results, CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<FileSecurityEvent>> GetRecentFileEventsAsync(int take, CancellationToken cancellationToken = default);
}

public interface IHealthSnapshotRepository
{
    Task SaveHealthSnapshotAsync(DeviceHealthSnapshot snapshot, CancellationToken cancellationToken = default);

    Task<DeviceHealthSnapshot?> GetLatestHealthSnapshotAsync(CancellationToken cancellationToken = default);
}

public interface IReportExportRepository
{
    Task<ScanReportExport> CreateScanReportExportAsync(ScanReportExport export, CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<ScanReportExport>> GetScanReportExportsAsync(int take, CancellationToken cancellationToken = default);
}

public interface ISecurityStatsRepository
{
    Task<int> GetDistinctFileCountAsync(CancellationToken cancellationToken = default);

    Task<int> GetDistinctThreatCountAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Composite interface preserved for backward compatibility during migration.
/// New consumers should depend on the specific segregated interface they need.
/// </summary>
public interface ISecurityRepository : IScanRepository, IThreatRepository, IFileEventRepository,
    IHealthSnapshotRepository, IReportExportRepository, ISecurityStatsRepository
{
}

public interface IPowerShellRunner
{
    Task<PowerShellCommandResult> RunAsync(string command, CancellationToken cancellationToken = default);
}

public sealed record PowerShellCommandResult(int ExitCode, string StandardOutput, string StandardError);

public interface IWindowsDefenderClient
{
    Task<DeviceHealthSnapshot> GetHealthAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<ThreatDetection>> GetActiveThreatsAsync(CancellationToken cancellationToken = default);

    Task<DefenderScanResult> StartScanAsync(ScanRequest request, CancellationToken cancellationToken = default);
}

public interface IHeuristicRule
{
    ThreatDetection? Evaluate(FileScanContext context);
}

public interface IHeuristicAnalyzer
{
    Task<IReadOnlyCollection<ThreatDetection>> AnalyzeAsync(ScanRequest request, CancellationToken cancellationToken = default);
}

public interface ISecurityOrchestrator
{
    Task<ScanJob> QueueScanAsync(ScanRequest request, CancellationToken cancellationToken = default);

    Task ExecuteQueuedScanAsync(QueuedScanWorkItem workItem, CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<ScanJob>> GetRecentScansAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<ScanProgressEvent>> GetScanProgressAsync(int scanId, CancellationToken cancellationToken = default);

    Task<ScanControlResult> StopScanAsync(int scanId, CancellationToken cancellationToken = default);

    Task<ScanFileDecisionResult> SubmitFileDecisionAsync(int scanId, ScanFileDecision decision, CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<ThreatDetection>> SyncThreatsAsync(CancellationToken cancellationToken = default);

    Task<QuarantineResult> QuarantineThreatAsync(int threatId, CancellationToken cancellationToken = default);

    Task<DeviceHealthSnapshot> CaptureHealthAsync(CancellationToken cancellationToken = default);
}

public interface IDashboardService
{
    Task<DashboardSummary> GetDashboardAsync(CancellationToken cancellationToken = default);
}

public interface IScanBackgroundQueue
{
    ValueTask QueueAsync(QueuedScanWorkItem workItem, CancellationToken cancellationToken = default);

    ValueTask<QueuedScanWorkItem> DequeueAsync(CancellationToken cancellationToken);
}

public interface IScanCancellationRegistry
{
    CancellationToken BeginExecution(int scanId, CancellationToken stoppingToken);

    bool RequestStop(int scanId);

    bool ConsumePendingStop(int scanId);

    bool IsStopRequested(int scanId);

    void Complete(int scanId);
}

public interface IScanFileDecisionRegistry
{
    Task<ScanFileDecisionAction> WaitForDecisionAsync(int scanId, string filePath, string reason, CancellationToken cancellationToken);

    bool SubmitDecision(int scanId, string filePath, ScanFileDecisionAction action);

    PendingScanFilePrompt? GetPendingPrompt(int scanId);

    void Clear(int scanId);
}

public interface IFileEventBackgroundQueue
{
    ValueTask QueueAsync(QueuedFileEventWorkItem workItem, CancellationToken cancellationToken = default);

    ValueTask<QueuedFileEventWorkItem> DequeueAsync(CancellationToken cancellationToken);
}

public interface IRealtimeProtectionService
{
    Task RegisterFileEventAsync(FileWatchNotification notification, CancellationToken cancellationToken = default);

    Task ProcessQueuedFileEventAsync(QueuedFileEventWorkItem workItem, CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<FileSecurityEvent>> GetRecentFileEventsAsync(CancellationToken cancellationToken = default);
}

public interface IProcessCommandRunner
{
    Task<ProcessCommandResult> RunAsync(string fileName, string arguments, CancellationToken cancellationToken = default);
}

public sealed record ProcessCommandResult(int ExitCode, string StandardOutput, string StandardError);

public interface IProcessTreeTracker
{
    ProcessLineage? GetProcessLineage(int processId, int maxDepth = 3);

    bool IsLOLBinChain(string parentPath, string childPath);

    bool IsSuspiciousParentChild(string parentPath, string childPath);
}

public interface IVerdictScoringEngine
{
    DetectionVerdict ComputeVerdict(
        IReadOnlyCollection<DetectionEventRecord> detectionEvents,
        ScoringThresholds? thresholds = null,
        ScoringWeights? weights = null);
}

// ── Phase 2: Secure Quarantine & Ransomware Shield ──────────────

public interface IQuarantineVault
{
    Task<QuarantineVaultItem> QuarantineAsync(FileInfo file, QuarantineDetectionContext context, CancellationToken ct = default);
    Task<RestoreResult> RestoreAsync(Guid itemId, string requestedBy, string? restoreToPath = null, CancellationToken ct = default);
    Task<bool> PurgeAsync(Guid itemId, CancellationToken ct = default);
    Task<int> PurgeExpiredAsync(CancellationToken ct = default);
    Task<QuarantineVaultItem?> GetItemAsync(Guid itemId, CancellationToken ct = default);
    Task<IReadOnlyCollection<QuarantineVaultItem>> ListAsync(QuarantineListFilter filter, CancellationToken ct = default);
}

public interface IQuarantineRepository
{
    Task InsertAsync(QuarantineVaultItem item, CancellationToken ct = default);
    Task UpdateAsync(QuarantineVaultItem item, CancellationToken ct = default);
    Task<QuarantineVaultItem?> GetByIdAsync(Guid id, CancellationToken ct = default);
    Task<IReadOnlyCollection<QuarantineVaultItem>> ListAsync(QuarantineListFilter filter, CancellationToken ct = default);
    Task<IReadOnlyCollection<QuarantineVaultItem>> GetExpiredActiveItemsAsync(CancellationToken ct = default);
}

public interface IRansomwareShield
{
    Task<RansomwareDetectionSignal?> RecordFileWriteAsync(FileWatchNotification notification, FileInfo file, CancellationToken ct = default);
    bool IsProtectedFolder(string path);
    IReadOnlyCollection<RansomwareDetectionSignal> GetRecentSignals(int maxCount = 20);
}

public interface IProcessRemediator
{
    bool KillProcess(int processId);
    bool SuspendProcess(int processId);
}
