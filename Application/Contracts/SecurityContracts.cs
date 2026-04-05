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

public interface ISecurityRepository
{
    Task<int> CreateScanAsync(ScanRequest request, CancellationToken cancellationToken = default);

    Task<ScanJob?> GetScanByIdAsync(int id, CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<ScanJob>> GetRecoverableScansAsync(CancellationToken cancellationToken = default);

    Task<int> CreateFileEventAsync(FileWatchNotification notification, CancellationToken cancellationToken = default);

    Task UpdateFileEventAsync(
        int fileEventId,
        FileEventStatus status,
        int threatCount,
        string? notes,
        string? hashSha256,
        long? fileSizeBytes,
        DateTimeOffset? processedAt,
        CancellationToken cancellationToken = default);

    Task SaveFileEngineResultsAsync(
        int fileEventId,
        IEnumerable<FileScannerEngineResult> results,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<FileSecurityEvent>> GetRecentFileEventsAsync(int take, CancellationToken cancellationToken = default);

    Task UpdateScanStatusAsync(
        int scanId,
        ScanStatus status,
        ScanStage stage,
        int percentComplete,
        int filesScanned,
        int? totalFiles,
        string? currentTarget,
        int threatCount,
        string? notes,
        DateTimeOffset? startedAt,
        DateTimeOffset? completedAt,
        CancellationToken cancellationToken = default);

    Task AppendScanProgressAsync(ScanProgressEvent progressEvent, CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<ScanJob>> GetRecentScansAsync(int take, CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<ScanProgressEvent>> GetScanProgressEventsAsync(int scanId, int take, CancellationToken cancellationToken = default);

    Task UpsertThreatsAsync(int? scanJobId, IEnumerable<ThreatDetection> threats, CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<ThreatDetection>> GetThreatsAsync(bool activeOnly, CancellationToken cancellationToken = default);

    Task<ThreatDetection?> GetThreatByIdAsync(int id, CancellationToken cancellationToken = default);

    Task MarkThreatQuarantinedAsync(int id, string? quarantinePath, CancellationToken cancellationToken = default);

    Task<ScanReportExport> CreateScanReportExportAsync(ScanReportExport export, CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<ScanReportExport>> GetScanReportExportsAsync(int take, CancellationToken cancellationToken = default);

    Task SaveHealthSnapshotAsync(DeviceHealthSnapshot snapshot, CancellationToken cancellationToken = default);

    Task<DeviceHealthSnapshot?> GetLatestHealthSnapshotAsync(CancellationToken cancellationToken = default);
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

public interface IOpenSourceScannerEngine
{
    string EngineName { get; }

    ThreatSource Source { get; }

    Task<FileScannerEngineResult> ScanAsync(FileInfo file, CancellationToken cancellationToken = default);
}

public interface ISecurityOrchestrator
{
    Task<ScanJob> QueueScanAsync(ScanRequest request, CancellationToken cancellationToken = default);

    Task ExecuteQueuedScanAsync(QueuedScanWorkItem workItem, CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<ScanJob>> GetRecentScansAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyCollection<ScanProgressEvent>> GetScanProgressAsync(int scanId, CancellationToken cancellationToken = default);

    Task<ScanControlResult> StopScanAsync(int scanId, CancellationToken cancellationToken = default);

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
