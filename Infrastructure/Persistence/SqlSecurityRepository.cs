using Antivirus.Application.Contracts;
using Antivirus.Domain;
using Microsoft.Data.SqlClient;

namespace Antivirus.Infrastructure.Persistence;

public sealed class SqlSecurityRepository : ISecurityRepository
{
    private readonly ITenantRegistry _tenantRegistry;

    public SqlSecurityRepository(ITenantRegistry tenantRegistry)
    {
        _tenantRegistry = tenantRegistry;
    }

    private const string ScanJobColumns = "Id, Mode, TargetPath, RequestedBy, Status, Stage, PercentComplete, FilesScanned, TotalFiles, CurrentTarget, ThreatCount, Notes, CreatedAt, StartedAt, CompletedAt";

    private const string ThreatColumns = "Id, ScanJobId, Name, Category, Severity, Source, Resource, Description, EngineName, IsQuarantined, QuarantinePath, EvidenceJson, DetectedAt";

    public async Task<int> CreateScanAsync(ScanRequest request, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO ScanJobs (Mode, TargetPath, RequestedBy, Status, Stage, PercentComplete, FilesScanned, TotalFiles, CurrentTarget, ThreatCount, Notes, CreatedAt, StartedAt, CompletedAt)
            OUTPUT INSERTED.Id
            VALUES (@Mode, @TargetPath, @RequestedBy, @Status, @Stage, 0, 0, NULL, NULL, 0, NULL, SYSUTCDATETIME(), NULL, NULL);
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);
        return await connection.ExecuteScalarIntAsync(sql, p =>
        {
            p.AddWithValue("@Mode", request.Mode.ToString());
            p.AddNullable("@TargetPath", request.TargetPath);
            p.AddWithValue("@RequestedBy", request.RequestedBy);
            p.AddWithValue("@Status", ScanStatus.Pending.ToString());
            p.AddWithValue("@Stage", ScanStage.Queued.ToString());
        }, cancellationToken);
    }

    public async Task<ScanJob?> GetScanByIdAsync(int id, CancellationToken cancellationToken = default)
    {
        var sql = $"SELECT TOP (1) {ScanJobColumns} FROM ScanJobs WHERE Id = @Id;";
        await using var connection = await OpenConnectionAsync(cancellationToken);
        return await connection.QuerySingleOrDefaultAsync(sql, p => p.AddWithValue("@Id", id), SecurityMappers.MapScanJob, cancellationToken);
    }

    public async Task<IReadOnlyCollection<ScanJob>> GetRecoverableScansAsync(CancellationToken cancellationToken = default)
    {
        var sql = $"SELECT {ScanJobColumns} FROM ScanJobs WHERE Status IN (@PendingStatus, @RunningStatus) ORDER BY CreatedAt ASC;";
        await using var connection = await OpenConnectionAsync(cancellationToken);
        return await connection.QueryAsync(sql, p =>
        {
            p.AddWithValue("@PendingStatus", ScanStatus.Pending.ToString());
            p.AddWithValue("@RunningStatus", ScanStatus.Running.ToString());
        }, SecurityMappers.MapScanJob, cancellationToken);
    }

    public async Task<IReadOnlyCollection<ScanJob>> GetRecentScansAsync(int take, CancellationToken cancellationToken = default)
    {
        var sql = $"SELECT TOP (@Take) {ScanJobColumns} FROM ScanJobs ORDER BY CreatedAt DESC;";
        await using var connection = await OpenConnectionAsync(cancellationToken);
        return await connection.QueryAsync(sql, p => p.AddWithValue("@Take", take), SecurityMappers.MapScanJob, cancellationToken);
    }

    public async Task UpdateScanStatusAsync(int scanId, ScanStatusUpdate update, CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE ScanJobs
            SET Status = @Status, Stage = @Stage, PercentComplete = @PercentComplete,
                FilesScanned = @FilesScanned, TotalFiles = @TotalFiles, CurrentTarget = @CurrentTarget,
                ThreatCount = @ThreatCount, Notes = @Notes,
                StartedAt = COALESCE(@StartedAt, StartedAt), CompletedAt = @CompletedAt
            WHERE Id = @Id;
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);
        await connection.ExecuteNonQueryAsync(sql, p =>
        {
            p.AddWithValue("@Id", scanId);
            p.AddWithValue("@Status", update.Status.ToString());
            p.AddWithValue("@Stage", update.Stage.ToString());
            p.AddWithValue("@PercentComplete", update.PercentComplete);
            p.AddWithValue("@FilesScanned", update.FilesScanned);
            p.AddNullable("@TotalFiles", update.TotalFiles);
            p.AddNullable("@CurrentTarget", update.CurrentTarget);
            p.AddWithValue("@ThreatCount", update.ThreatCount);
            p.AddNullable("@Notes", update.Notes);
            p.AddNullable("@StartedAt", update.StartedAt);
            p.AddNullable("@CompletedAt", update.CompletedAt);
        }, cancellationToken);
    }

    public async Task AppendScanProgressAsync(ScanProgressEvent progressEvent, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO ScanProgressEvents
            (ScanJobId, Stage, PercentComplete, CurrentPath, FilesScanned, TotalFiles, FindingsCount, IsSkipped, DetailMessage, StartedAt, CompletedAt, RecordedAt)
            VALUES
            (@ScanJobId, @Stage, @PercentComplete, @CurrentPath, @FilesScanned, @TotalFiles, @FindingsCount, @IsSkipped, @DetailMessage, @StartedAt, @CompletedAt, @RecordedAt);
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);
        await connection.ExecuteNonQueryAsync(sql, p =>
        {
            p.AddWithValue("@ScanJobId", progressEvent.ScanJobId);
            p.AddWithValue("@Stage", progressEvent.Stage.ToString());
            p.AddWithValue("@PercentComplete", progressEvent.PercentComplete);
            p.AddNullable("@CurrentPath", progressEvent.CurrentPath);
            p.AddWithValue("@FilesScanned", progressEvent.FilesScanned);
            p.AddNullable("@TotalFiles", progressEvent.TotalFiles);
            p.AddWithValue("@FindingsCount", progressEvent.FindingsCount);
            p.AddWithValue("@IsSkipped", progressEvent.IsSkipped);
            p.AddNullable("@DetailMessage", progressEvent.DetailMessage);
            p.AddWithValue("@StartedAt", progressEvent.StartedAt);
            p.AddNullable("@CompletedAt", progressEvent.CompletedAt);
            p.AddWithValue("@RecordedAt", progressEvent.RecordedAt);
        }, cancellationToken);
    }

    public async Task<IReadOnlyCollection<ScanProgressEvent>> GetScanProgressEventsAsync(int scanId, int take, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT TOP (@Take) ScanJobId, Stage, PercentComplete, CurrentPath, FilesScanned, TotalFiles, FindingsCount, IsSkipped, DetailMessage, StartedAt, CompletedAt, RecordedAt
            FROM ScanProgressEvents
            WHERE ScanJobId = @ScanJobId
            ORDER BY RecordedAt DESC, Id DESC;
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);
        return await connection.QueryAsync(sql, p =>
        {
            p.AddWithValue("@Take", take);
            p.AddWithValue("@ScanJobId", scanId);
        }, SecurityMappers.MapProgressEvent, cancellationToken);
    }

    public async Task<int> CreateFileEventAsync(FileWatchNotification notification, int? scanJobId = null, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO FileSecurityEvents (ScanJobId, FilePath, PreviousPath, EventType, Status, HashSha256, FileSizeBytes, ThreatCount, Notes, ObservedAt, ProcessedAt)
            OUTPUT INSERTED.Id
            VALUES (@ScanJobId, @FilePath, @PreviousPath, @EventType, @Status, NULL, NULL, 0, NULL, @ObservedAt, NULL);
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);
        return await connection.ExecuteScalarIntAsync(sql, p =>
        {
            p.AddNullable("@ScanJobId", scanJobId);
            p.AddWithValue("@FilePath", notification.FilePath);
            p.AddNullable("@PreviousPath", notification.PreviousPath);
            p.AddWithValue("@EventType", notification.EventType.ToString());
            p.AddWithValue("@Status", FileEventStatus.Pending.ToString());
            p.AddWithValue("@ObservedAt", notification.ObservedAt);
        }, cancellationToken);
    }

    public async Task UpdateFileEventAsync(int fileEventId, FileEventUpdate update, CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE FileSecurityEvents
            SET Status = @Status, ThreatCount = @ThreatCount, Notes = @Notes,
                HashSha256 = COALESCE(@HashSha256, HashSha256),
                FileSizeBytes = COALESCE(@FileSizeBytes, FileSizeBytes),
                ProcessedAt = @ProcessedAt
            WHERE Id = @Id;
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);
        await connection.ExecuteNonQueryAsync(sql, p =>
        {
            p.AddWithValue("@Id", fileEventId);
            p.AddWithValue("@Status", update.Status.ToString());
            p.AddWithValue("@ThreatCount", update.ThreatCount);
            p.AddNullable("@Notes", update.Notes);
            p.AddNullable("@HashSha256", update.HashSha256);
            p.AddNullable("@FileSizeBytes", update.FileSizeBytes);
            p.AddNullable("@ProcessedAt", update.ProcessedAt);
        }, cancellationToken);
    }

    public async Task SaveFileEngineResultsAsync(int fileEventId, IEnumerable<FileScannerEngineResult> results, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO FileEngineResults
            (FileSecurityEventId, EngineName, Source, Status, IsMatch, SignatureName, Details, RawOutput, ScannedAt)
            VALUES
            (@FileSecurityEventId, @EngineName, @Source, @Status, @IsMatch, @SignatureName, @Details, @RawOutput, @ScannedAt);
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);
        foreach (var result in results)
        {
            await connection.ExecuteNonQueryAsync(sql, p =>
            {
                p.AddWithValue("@FileSecurityEventId", fileEventId);
                p.AddWithValue("@EngineName", result.EngineName);
                p.AddWithValue("@Source", result.Source.ToString());
                p.AddWithValue("@Status", result.Status.ToString());
                p.AddWithValue("@IsMatch", result.IsMatch);
                p.AddNullable("@SignatureName", result.SignatureName);
                p.AddNullable("@Details", result.Details);
                p.AddNullable("@RawOutput", result.RawOutput);
                p.AddWithValue("@ScannedAt", result.ScannedAt);
            }, cancellationToken);
        }
    }

    public async Task<IReadOnlyCollection<FileSecurityEvent>> GetRecentFileEventsAsync(int take, CancellationToken cancellationToken = default)
    {
        const string eventsSql = """
            SELECT TOP (@Take) Id, ScanJobId, FilePath, PreviousPath, EventType, Status, HashSha256, FileSizeBytes, ThreatCount, Notes, ObservedAt, CreatedAt, ProcessedAt
            FROM FileSecurityEvents
            ORDER BY ObservedAt DESC, Id DESC;
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);
        var events = await connection.QueryAsync(eventsSql, p => p.AddWithValue("@Take", take), SecurityMappers.MapFileEvent, cancellationToken);

        if (events.Count == 0) return events;

        var engineResults = await LoadEngineResultsAsync(connection, events, cancellationToken);
        return events.Select(e => new FileSecurityEvent
        {
            Id = e.Id, ScanJobId = e.ScanJobId, FilePath = e.FilePath, PreviousPath = e.PreviousPath,
            EventType = e.EventType, Status = e.Status, HashSha256 = e.HashSha256, FileSizeBytes = e.FileSizeBytes,
            ThreatCount = e.ThreatCount, Notes = e.Notes, ObservedAt = e.ObservedAt, CreatedAt = e.CreatedAt,
            ProcessedAt = e.ProcessedAt,
            EngineResults = engineResults.TryGetValue(e.Id, out var bucket) ? bucket : Array.Empty<FileEngineResult>()
        }).ToArray();
    }

    private static async Task<Dictionary<int, List<FileEngineResult>>> LoadEngineResultsAsync(
        SqlConnection connection, List<FileSecurityEvent> events, CancellationToken cancellationToken)
    {
        var eventIds = string.Join(", ", events.Select(e => e.Id));
        var sql = $"SELECT Id, FileSecurityEventId, EngineName, Source, Status, IsMatch, SignatureName, Details, RawOutput, ScannedAt FROM FileEngineResults WHERE FileSecurityEventId IN ({eventIds}) ORDER BY ScannedAt DESC;";

        var allResults = await connection.QueryAsync(sql, _ => { }, SecurityMappers.MapEngineResult, cancellationToken);
        var grouped = new Dictionary<int, List<FileEngineResult>>();
        foreach (var r in allResults)
        {
            if (!grouped.TryGetValue(r.FileSecurityEventId, out var bucket))
            {
                bucket = [];
                grouped[r.FileSecurityEventId] = bucket;
            }
            bucket.Add(r);
        }
        return grouped;
    }

    public async Task UpsertThreatsAsync(int? scanJobId, IEnumerable<ThreatDetection> threats, CancellationToken cancellationToken = default)
    {
        const string sql = """
            IF NOT EXISTS (
                SELECT 1 FROM ThreatDetections
                WHERE Name = @Name AND Source = @Source AND ISNULL(Resource, '') = ISNULL(@Resource, '') AND DetectedAt = @DetectedAt
            )
            BEGIN
                INSERT INTO ThreatDetections (ScanJobId, Name, Category, Severity, Source, Resource, Description, EngineName, IsQuarantined, QuarantinePath, EvidenceJson, DetectedAt)
                VALUES (@ScanJobId, @Name, @Category, @Severity, @Source, @Resource, @Description, @EngineName, @IsQuarantined, @QuarantinePath, @EvidenceJson, @DetectedAt);
            END
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);
        foreach (var threat in threats)
        {
            await connection.ExecuteNonQueryAsync(sql, p =>
            {
                p.AddNullable("@ScanJobId", (object?)scanJobId ?? threat.ScanJobId);
                p.AddWithValue("@Name", threat.Name);
                p.AddWithValue("@Category", threat.Category);
                p.AddWithValue("@Severity", threat.Severity.ToString());
                p.AddWithValue("@Source", threat.Source.ToString());
                p.AddNullable("@Resource", threat.Resource);
                p.AddNullable("@Description", threat.Description);
                p.AddNullable("@EngineName", threat.EngineName);
                p.AddWithValue("@IsQuarantined", threat.IsQuarantined);
                p.AddNullable("@QuarantinePath", threat.QuarantinePath);
                p.AddNullable("@EvidenceJson", threat.EvidenceJson);
                p.AddWithValue("@DetectedAt", threat.DetectedAt);
            }, cancellationToken);
        }
    }

    public async Task<IReadOnlyCollection<ThreatDetection>> GetThreatsAsync(bool activeOnly, CancellationToken cancellationToken = default)
    {
        var sql = $"SELECT {ThreatColumns} FROM ThreatDetections WHERE (@ActiveOnly = 0 OR IsQuarantined = 0) ORDER BY DetectedAt DESC;";
        await using var connection = await OpenConnectionAsync(cancellationToken);
        return await connection.QueryAsync(sql, p => p.AddWithValue("@ActiveOnly", activeOnly), SecurityMappers.MapThreat, cancellationToken);
    }

    public async Task<ThreatDetection?> GetThreatByIdAsync(int id, CancellationToken cancellationToken = default)
    {
        var sql = $"SELECT TOP (1) {ThreatColumns} FROM ThreatDetections WHERE Id = @Id;";
        await using var connection = await OpenConnectionAsync(cancellationToken);
        return await connection.QuerySingleOrDefaultAsync(sql, p => p.AddWithValue("@Id", id), SecurityMappers.MapThreat, cancellationToken);
    }

    public async Task MarkThreatQuarantinedAsync(int id, string? quarantinePath, CancellationToken cancellationToken = default)
    {
        const string sql = "UPDATE ThreatDetections SET IsQuarantined = 1, QuarantinePath = @QuarantinePath WHERE Id = @Id;";
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await connection.ExecuteNonQueryAsync(sql, p =>
        {
            p.AddWithValue("@Id", id);
            p.AddNullable("@QuarantinePath", quarantinePath);
        }, cancellationToken);
    }

    public async Task<ScanReportExport> CreateScanReportExportAsync(ScanReportExport export, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO ScanReportExports (ScanJobId, FileName, Format, ExportedBy, VulnerabilityCount, ExportedAt)
            OUTPUT INSERTED.Id, INSERTED.ScanJobId, INSERTED.FileName, INSERTED.Format, INSERTED.ExportedBy, INSERTED.VulnerabilityCount, INSERTED.ExportedAt
            VALUES (@ScanJobId, @FileName, @Format, @ExportedBy, @VulnerabilityCount, @ExportedAt);
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);
        return (await connection.QuerySingleOrDefaultAsync(sql, p =>
        {
            p.AddNullable("@ScanJobId", export.ScanJobId);
            p.AddWithValue("@FileName", export.FileName);
            p.AddWithValue("@Format", export.Format);
            p.AddWithValue("@ExportedBy", export.ExportedBy);
            p.AddWithValue("@VulnerabilityCount", export.VulnerabilityCount);
            p.AddWithValue("@ExportedAt", export.ExportedAt);
        }, SecurityMappers.MapReportExport, cancellationToken))!;
    }

    public async Task<IReadOnlyCollection<ScanReportExport>> GetScanReportExportsAsync(int take, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT TOP (@Take) Id, ScanJobId, FileName, Format, ExportedBy, VulnerabilityCount, ExportedAt
            FROM ScanReportExports
            ORDER BY ExportedAt DESC, Id DESC;
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);
        return await connection.QueryAsync(sql, p => p.AddWithValue("@Take", take), SecurityMappers.MapReportExport, cancellationToken);
    }

    public async Task SaveHealthSnapshotAsync(DeviceHealthSnapshot snapshot, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO DeviceHealthSnapshots
            (CapturedAt, AntivirusEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled, NetworkInspectionEnabled, EngineServiceEnabled, SignaturesOutOfDate, AntivirusSignatureVersion, AntivirusSignatureLastUpdated, QuickScanAgeDays, FullScanAgeDays)
            VALUES
            (@CapturedAt, @AntivirusEnabled, @RealTimeProtectionEnabled, @IoavProtectionEnabled, @NetworkInspectionEnabled, @EngineServiceEnabled, @SignaturesOutOfDate, @AntivirusSignatureVersion, @AntivirusSignatureLastUpdated, @QuickScanAgeDays, @FullScanAgeDays);
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);
        await connection.ExecuteNonQueryAsync(sql, p =>
        {
            p.AddWithValue("@CapturedAt", snapshot.CapturedAt);
            p.AddWithValue("@AntivirusEnabled", snapshot.AntivirusEnabled);
            p.AddWithValue("@RealTimeProtectionEnabled", snapshot.RealTimeProtectionEnabled);
            p.AddWithValue("@IoavProtectionEnabled", snapshot.IoavProtectionEnabled);
            p.AddWithValue("@NetworkInspectionEnabled", snapshot.NetworkInspectionEnabled);
            p.AddWithValue("@EngineServiceEnabled", snapshot.EngineServiceEnabled);
            p.AddWithValue("@SignaturesOutOfDate", snapshot.SignaturesOutOfDate);
            p.AddNullable("@AntivirusSignatureVersion", snapshot.AntivirusSignatureVersion);
            p.AddNullable("@AntivirusSignatureLastUpdated", snapshot.AntivirusSignatureLastUpdated);
            p.AddNullable("@QuickScanAgeDays", snapshot.QuickScanAgeDays);
            p.AddNullable("@FullScanAgeDays", snapshot.FullScanAgeDays);
        }, cancellationToken);
    }

    public async Task<DeviceHealthSnapshot?> GetLatestHealthSnapshotAsync(CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT TOP (1) CapturedAt, AntivirusEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled, NetworkInspectionEnabled, EngineServiceEnabled, SignaturesOutOfDate, AntivirusSignatureVersion, AntivirusSignatureLastUpdated, QuickScanAgeDays, FullScanAgeDays
            FROM DeviceHealthSnapshots
            ORDER BY CapturedAt DESC;
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);
        return await connection.QuerySingleOrDefaultAsync(sql, _ => { }, SecurityMappers.MapHealthSnapshot, cancellationToken);
    }

    public async Task<int> GetDistinctFileCountAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenConnectionAsync(cancellationToken);
        return await connection.ExecuteScalarIntAsync("SELECT COUNT(DISTINCT FilePath) FROM FileSecurityEvents;", _ => { }, cancellationToken);
    }

    public async Task<int> GetDistinctThreatCountAsync(CancellationToken cancellationToken = default)
    {
        const string sql = "SELECT COUNT(*) FROM (SELECT DISTINCT LOWER(Name) AS ThreatName, LOWER(ISNULL(Resource, '')) AS ThreatResource FROM ThreatDetections) AS UniquePairs;";
        await using var connection = await OpenConnectionAsync(cancellationToken);
        return await connection.ExecuteScalarIntAsync(sql, _ => { }, cancellationToken);
    }

    private Task<SqlConnection> OpenConnectionAsync(CancellationToken cancellationToken)
    {
        return _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
    }
}