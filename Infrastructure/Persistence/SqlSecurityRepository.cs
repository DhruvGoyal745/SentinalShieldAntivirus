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

    public async Task<int> CreateScanAsync(ScanRequest request, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO ScanJobs (Mode, TargetPath, RequestedBy, Status, Stage, PercentComplete, FilesScanned, TotalFiles, CurrentTarget, ThreatCount, Notes, CreatedAt, StartedAt, CompletedAt)
            OUTPUT INSERTED.Id
            VALUES (@Mode, @TargetPath, @RequestedBy, @Status, @Stage, 0, 0, NULL, NULL, 0, NULL, SYSUTCDATETIME(), NULL, NULL);
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@Mode", request.Mode.ToString());
        command.Parameters.AddWithValue("@TargetPath", (object?)request.TargetPath ?? DBNull.Value);
        command.Parameters.AddWithValue("@RequestedBy", request.RequestedBy);
        command.Parameters.AddWithValue("@Status", ScanStatus.Pending.ToString());
        command.Parameters.AddWithValue("@Stage", ScanStage.Queued.ToString());

        return Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken));
    }

    public async Task<ScanJob?> GetScanByIdAsync(int id, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT TOP (1) Id, Mode, TargetPath, RequestedBy, Status, Stage, PercentComplete, FilesScanned, TotalFiles, CurrentTarget, ThreatCount, Notes, CreatedAt, StartedAt, CompletedAt
            FROM ScanJobs
            WHERE Id = @Id;
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@Id", id);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new ScanJob
        {
            Id = reader.GetInt32(0),
            Mode = Enum.Parse<ScanMode>(reader.GetString(1)),
            TargetPath = reader.IsDBNull(2) ? null : reader.GetString(2),
            RequestedBy = reader.GetString(3),
            Status = Enum.Parse<ScanStatus>(reader.GetString(4)),
            Stage = Enum.Parse<ScanStage>(reader.GetString(5)),
            PercentComplete = reader.GetInt32(6),
            FilesScanned = reader.GetInt32(7),
            TotalFiles = reader.IsDBNull(8) ? null : reader.GetInt32(8),
            CurrentTarget = reader.IsDBNull(9) ? null : reader.GetString(9),
            ThreatCount = reader.GetInt32(10),
            Notes = reader.IsDBNull(11) ? null : reader.GetString(11),
            CreatedAt = reader.GetDateTimeOffset(12),
            StartedAt = reader.IsDBNull(13) ? null : reader.GetFieldValue<DateTimeOffset>(13),
            CompletedAt = reader.IsDBNull(14) ? null : reader.GetFieldValue<DateTimeOffset>(14)
        };
    }

    public async Task<IReadOnlyCollection<ScanJob>> GetRecoverableScansAsync(CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT Id, Mode, TargetPath, RequestedBy, Status, Stage, PercentComplete, FilesScanned, TotalFiles, CurrentTarget, ThreatCount, Notes, CreatedAt, StartedAt, CompletedAt
            FROM ScanJobs
            WHERE Status IN (@PendingStatus, @RunningStatus)
            ORDER BY CreatedAt ASC;
            """;

        var scans = new List<ScanJob>();
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@PendingStatus", ScanStatus.Pending.ToString());
        command.Parameters.AddWithValue("@RunningStatus", ScanStatus.Running.ToString());
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);

        while (await reader.ReadAsync(cancellationToken))
        {
            scans.Add(new ScanJob
            {
                Id = reader.GetInt32(0),
                Mode = Enum.Parse<ScanMode>(reader.GetString(1)),
                TargetPath = reader.IsDBNull(2) ? null : reader.GetString(2),
                RequestedBy = reader.GetString(3),
                Status = Enum.Parse<ScanStatus>(reader.GetString(4)),
                Stage = Enum.Parse<ScanStage>(reader.GetString(5)),
                PercentComplete = reader.GetInt32(6),
                FilesScanned = reader.GetInt32(7),
                TotalFiles = reader.IsDBNull(8) ? null : reader.GetInt32(8),
                CurrentTarget = reader.IsDBNull(9) ? null : reader.GetString(9),
                ThreatCount = reader.GetInt32(10),
                Notes = reader.IsDBNull(11) ? null : reader.GetString(11),
                CreatedAt = reader.GetDateTimeOffset(12),
                StartedAt = reader.IsDBNull(13) ? null : reader.GetFieldValue<DateTimeOffset>(13),
                CompletedAt = reader.IsDBNull(14) ? null : reader.GetFieldValue<DateTimeOffset>(14)
            });
        }

        return scans;
    }

    public async Task<int> CreateFileEventAsync(FileWatchNotification notification, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO FileSecurityEvents (FilePath, PreviousPath, EventType, Status, HashSha256, FileSizeBytes, ThreatCount, Notes, ObservedAt, ProcessedAt)
            OUTPUT INSERTED.Id
            VALUES (@FilePath, @PreviousPath, @EventType, @Status, NULL, NULL, 0, NULL, @ObservedAt, NULL);
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@FilePath", notification.FilePath);
        command.Parameters.AddWithValue("@PreviousPath", (object?)notification.PreviousPath ?? DBNull.Value);
        command.Parameters.AddWithValue("@EventType", notification.EventType.ToString());
        command.Parameters.AddWithValue("@Status", FileEventStatus.Pending.ToString());
        command.Parameters.AddWithValue("@ObservedAt", notification.ObservedAt);

        return Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken));
    }

    public async Task UpdateFileEventAsync(
        int fileEventId,
        FileEventStatus status,
        int threatCount,
        string? notes,
        string? hashSha256,
        long? fileSizeBytes,
        DateTimeOffset? processedAt,
        CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE FileSecurityEvents
            SET Status = @Status,
                ThreatCount = @ThreatCount,
                Notes = @Notes,
                HashSha256 = COALESCE(@HashSha256, HashSha256),
                FileSizeBytes = COALESCE(@FileSizeBytes, FileSizeBytes),
                ProcessedAt = @ProcessedAt
            WHERE Id = @Id;
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@Id", fileEventId);
        command.Parameters.AddWithValue("@Status", status.ToString());
        command.Parameters.AddWithValue("@ThreatCount", threatCount);
        command.Parameters.AddWithValue("@Notes", (object?)notes ?? DBNull.Value);
        command.Parameters.AddWithValue("@HashSha256", (object?)hashSha256 ?? DBNull.Value);
        command.Parameters.AddWithValue("@FileSizeBytes", fileSizeBytes.HasValue ? fileSizeBytes.Value : DBNull.Value);
        command.Parameters.AddWithValue("@ProcessedAt", processedAt.HasValue ? processedAt.Value : DBNull.Value);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task SaveFileEngineResultsAsync(
        int fileEventId,
        IEnumerable<FileScannerEngineResult> results,
        CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO FileEngineResults
            (
                FileSecurityEventId,
                EngineName,
                Source,
                Status,
                IsMatch,
                SignatureName,
                Details,
                RawOutput,
                ScannedAt
            )
            VALUES
            (
                @FileSecurityEventId,
                @EngineName,
                @Source,
                @Status,
                @IsMatch,
                @SignatureName,
                @Details,
                @RawOutput,
                @ScannedAt
            );
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);

        foreach (var result in results)
        {
            await using var command = new SqlCommand(sql, connection);
            command.Parameters.AddWithValue("@FileSecurityEventId", fileEventId);
            command.Parameters.AddWithValue("@EngineName", result.EngineName);
            command.Parameters.AddWithValue("@Source", result.Source.ToString());
            command.Parameters.AddWithValue("@Status", result.Status.ToString());
            command.Parameters.AddWithValue("@IsMatch", result.IsMatch);
            command.Parameters.AddWithValue("@SignatureName", (object?)result.SignatureName ?? DBNull.Value);
            command.Parameters.AddWithValue("@Details", (object?)result.Details ?? DBNull.Value);
            command.Parameters.AddWithValue("@RawOutput", (object?)result.RawOutput ?? DBNull.Value);
            command.Parameters.AddWithValue("@ScannedAt", result.ScannedAt);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    public async Task<IReadOnlyCollection<FileSecurityEvent>> GetRecentFileEventsAsync(int take, CancellationToken cancellationToken = default)
    {
        const string eventsSql = """
            SELECT TOP (@Take) Id, FilePath, PreviousPath, EventType, Status, HashSha256, FileSizeBytes, ThreatCount, Notes, ObservedAt, CreatedAt, ProcessedAt
            FROM FileSecurityEvents
            ORDER BY ObservedAt DESC, Id DESC;
            """;

        var events = new List<FileSecurityEvent>();

        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using (var command = new SqlCommand(eventsSql, connection))
        {
            command.Parameters.AddWithValue("@Take", take);

            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                events.Add(new FileSecurityEvent
                {
                    Id = reader.GetInt32(0),
                    FilePath = reader.GetString(1),
                    PreviousPath = reader.IsDBNull(2) ? null : reader.GetString(2),
                    EventType = Enum.Parse<FileEventType>(reader.GetString(3)),
                    Status = Enum.Parse<FileEventStatus>(reader.GetString(4)),
                    HashSha256 = reader.IsDBNull(5) ? null : reader.GetString(5),
                    FileSizeBytes = reader.IsDBNull(6) ? null : reader.GetInt64(6),
                    ThreatCount = reader.GetInt32(7),
                    Notes = reader.IsDBNull(8) ? null : reader.GetString(8),
                    ObservedAt = reader.GetDateTimeOffset(9),
                    CreatedAt = reader.GetDateTimeOffset(10),
                    ProcessedAt = reader.IsDBNull(11) ? null : reader.GetFieldValue<DateTimeOffset>(11)
                });
            }
        }

        if (events.Count == 0)
        {
            return events;
        }

        var eventIds = string.Join(", ", events.Select(fileEvent => fileEvent.Id));
        var resultsSql = $"""
            SELECT Id, FileSecurityEventId, EngineName, Source, Status, IsMatch, SignatureName, Details, RawOutput, ScannedAt
            FROM FileEngineResults
            WHERE FileSecurityEventId IN ({eventIds})
            ORDER BY ScannedAt DESC;
            """;

        var resultsByEventId = new Dictionary<int, List<FileEngineResult>>();
        await using (var command = new SqlCommand(resultsSql, connection))
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                var result = new FileEngineResult
                {
                    Id = reader.GetInt32(0),
                    FileSecurityEventId = reader.GetInt32(1),
                    EngineName = reader.GetString(2),
                    Source = Enum.Parse<ThreatSource>(reader.GetString(3)),
                    Status = Enum.Parse<FileEngineResultStatus>(reader.GetString(4)),
                    IsMatch = reader.GetBoolean(5),
                    SignatureName = reader.IsDBNull(6) ? null : reader.GetString(6),
                    Details = reader.IsDBNull(7) ? null : reader.GetString(7),
                    RawOutput = reader.IsDBNull(8) ? null : reader.GetString(8),
                    ScannedAt = reader.GetDateTimeOffset(9)
                };

                if (!resultsByEventId.TryGetValue(result.FileSecurityEventId, out var bucket))
                {
                    bucket = new List<FileEngineResult>();
                    resultsByEventId[result.FileSecurityEventId] = bucket;
                }

                bucket.Add(result);
            }
        }

        return events
            .Select(fileEvent => new FileSecurityEvent
            {
                Id = fileEvent.Id,
                FilePath = fileEvent.FilePath,
                PreviousPath = fileEvent.PreviousPath,
                EventType = fileEvent.EventType,
                Status = fileEvent.Status,
                HashSha256 = fileEvent.HashSha256,
                FileSizeBytes = fileEvent.FileSizeBytes,
                ThreatCount = fileEvent.ThreatCount,
                Notes = fileEvent.Notes,
                ObservedAt = fileEvent.ObservedAt,
                CreatedAt = fileEvent.CreatedAt,
                ProcessedAt = fileEvent.ProcessedAt,
                EngineResults = resultsByEventId.TryGetValue(fileEvent.Id, out var bucket)
                    ? bucket
                    : Array.Empty<FileEngineResult>()
            })
            .ToArray();
    }

    public async Task UpdateScanStatusAsync(
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
        CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE ScanJobs
            SET Status = @Status,
                Stage = @Stage,
                PercentComplete = @PercentComplete,
                FilesScanned = @FilesScanned,
                TotalFiles = @TotalFiles,
                CurrentTarget = @CurrentTarget,
                ThreatCount = @ThreatCount,
                Notes = @Notes,
                StartedAt = COALESCE(@StartedAt, StartedAt),
                CompletedAt = @CompletedAt
            WHERE Id = @Id;
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@Id", scanId);
        command.Parameters.AddWithValue("@Status", status.ToString());
        command.Parameters.AddWithValue("@Stage", stage.ToString());
        command.Parameters.AddWithValue("@PercentComplete", percentComplete);
        command.Parameters.AddWithValue("@FilesScanned", filesScanned);
        command.Parameters.AddWithValue("@TotalFiles", totalFiles.HasValue ? totalFiles.Value : DBNull.Value);
        command.Parameters.AddWithValue("@CurrentTarget", (object?)currentTarget ?? DBNull.Value);
        command.Parameters.AddWithValue("@ThreatCount", threatCount);
        command.Parameters.AddWithValue("@Notes", (object?)notes ?? DBNull.Value);
        command.Parameters.AddWithValue("@StartedAt", startedAt.HasValue ? startedAt.Value : DBNull.Value);
        command.Parameters.AddWithValue("@CompletedAt", completedAt.HasValue ? completedAt.Value : DBNull.Value);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task AppendScanProgressAsync(ScanProgressEvent progressEvent, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO ScanProgressEvents
            (
                ScanJobId,
                Stage,
                PercentComplete,
                CurrentPath,
                FilesScanned,
                TotalFiles,
                FindingsCount,
                IsSkipped,
                DetailMessage,
                StartedAt,
                CompletedAt,
                RecordedAt
            )
            VALUES
            (
                @ScanJobId,
                @Stage,
                @PercentComplete,
                @CurrentPath,
                @FilesScanned,
                @TotalFiles,
                @FindingsCount,
                @IsSkipped,
                @DetailMessage,
                @StartedAt,
                @CompletedAt,
                @RecordedAt
            );
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@ScanJobId", progressEvent.ScanJobId);
        command.Parameters.AddWithValue("@Stage", progressEvent.Stage.ToString());
        command.Parameters.AddWithValue("@PercentComplete", progressEvent.PercentComplete);
        command.Parameters.AddWithValue("@CurrentPath", (object?)progressEvent.CurrentPath ?? DBNull.Value);
        command.Parameters.AddWithValue("@FilesScanned", progressEvent.FilesScanned);
        command.Parameters.AddWithValue("@TotalFiles", progressEvent.TotalFiles.HasValue ? progressEvent.TotalFiles.Value : DBNull.Value);
        command.Parameters.AddWithValue("@FindingsCount", progressEvent.FindingsCount);
        command.Parameters.AddWithValue("@IsSkipped", progressEvent.IsSkipped);
        command.Parameters.AddWithValue("@DetailMessage", (object?)progressEvent.DetailMessage ?? DBNull.Value);
        command.Parameters.AddWithValue("@StartedAt", progressEvent.StartedAt);
        command.Parameters.AddWithValue("@CompletedAt", progressEvent.CompletedAt.HasValue ? progressEvent.CompletedAt.Value : DBNull.Value);
        command.Parameters.AddWithValue("@RecordedAt", progressEvent.RecordedAt);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<IReadOnlyCollection<ScanJob>> GetRecentScansAsync(int take, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT TOP (@Take) Id, Mode, TargetPath, RequestedBy, Status, Stage, PercentComplete, FilesScanned, TotalFiles, CurrentTarget, ThreatCount, Notes, CreatedAt, StartedAt, CompletedAt
            FROM ScanJobs
            ORDER BY CreatedAt DESC;
            """;

        var scans = new List<ScanJob>();

        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@Take", take);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            scans.Add(new ScanJob
            {
                Id = reader.GetInt32(0),
                Mode = Enum.Parse<ScanMode>(reader.GetString(1)),
                TargetPath = reader.IsDBNull(2) ? null : reader.GetString(2),
                RequestedBy = reader.GetString(3),
                Status = Enum.Parse<ScanStatus>(reader.GetString(4)),
                Stage = Enum.Parse<ScanStage>(reader.GetString(5)),
                PercentComplete = reader.GetInt32(6),
                FilesScanned = reader.GetInt32(7),
                TotalFiles = reader.IsDBNull(8) ? null : reader.GetInt32(8),
                CurrentTarget = reader.IsDBNull(9) ? null : reader.GetString(9),
                ThreatCount = reader.GetInt32(10),
                Notes = reader.IsDBNull(11) ? null : reader.GetString(11),
                CreatedAt = reader.GetDateTimeOffset(12),
                StartedAt = reader.IsDBNull(13) ? null : reader.GetFieldValue<DateTimeOffset>(13),
                CompletedAt = reader.IsDBNull(14) ? null : reader.GetFieldValue<DateTimeOffset>(14)
            });
        }

        return scans;
    }

    public async Task<IReadOnlyCollection<ScanProgressEvent>> GetScanProgressEventsAsync(int scanId, int take, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT TOP (@Take) ScanJobId, Stage, PercentComplete, CurrentPath, FilesScanned, TotalFiles, FindingsCount, IsSkipped, DetailMessage, StartedAt, CompletedAt, RecordedAt
            FROM ScanProgressEvents
            WHERE ScanJobId = @ScanJobId
            ORDER BY RecordedAt DESC, Id DESC;
            """;

        var events = new List<ScanProgressEvent>();
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@Take", take);
        command.Parameters.AddWithValue("@ScanJobId", scanId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);

        while (await reader.ReadAsync(cancellationToken))
        {
            events.Add(new ScanProgressEvent
            {
                ScanJobId = reader.GetInt32(0),
                Stage = Enum.Parse<ScanStage>(reader.GetString(1)),
                PercentComplete = reader.GetInt32(2),
                CurrentPath = reader.IsDBNull(3) ? null : reader.GetString(3),
                FilesScanned = reader.GetInt32(4),
                TotalFiles = reader.IsDBNull(5) ? null : reader.GetInt32(5),
                FindingsCount = reader.GetInt32(6),
                IsSkipped = reader.GetBoolean(7),
                DetailMessage = reader.IsDBNull(8) ? null : reader.GetString(8),
                StartedAt = reader.GetDateTimeOffset(9),
                CompletedAt = reader.IsDBNull(10) ? null : reader.GetFieldValue<DateTimeOffset>(10),
                RecordedAt = reader.GetDateTimeOffset(11)
            });
        }

        return events;
    }

    public async Task UpsertThreatsAsync(int? scanJobId, IEnumerable<ThreatDetection> threats, CancellationToken cancellationToken = default)
    {
        const string sql = """
            IF NOT EXISTS (
                SELECT 1
                FROM ThreatDetections
                WHERE Name = @Name
                  AND Source = @Source
                  AND ISNULL(Resource, '') = ISNULL(@Resource, '')
                  AND DetectedAt = @DetectedAt
            )
            BEGIN
                INSERT INTO ThreatDetections
                (
                    ScanJobId,
                    Name,
                    Category,
                    Severity,
                    Source,
                    Resource,
                    Description,
                    EngineName,
                    IsQuarantined,
                    QuarantinePath,
                    EvidenceJson,
                    DetectedAt
                )
                VALUES
                (
                    @ScanJobId,
                    @Name,
                    @Category,
                    @Severity,
                    @Source,
                    @Resource,
                    @Description,
                    @EngineName,
                    @IsQuarantined,
                    @QuarantinePath,
                    @EvidenceJson,
                    @DetectedAt
                );
            END
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);

        foreach (var threat in threats)
        {
            await using var command = new SqlCommand(sql, connection);
            command.Parameters.AddWithValue("@ScanJobId", (object?)scanJobId ?? (object?)threat.ScanJobId ?? DBNull.Value);
            command.Parameters.AddWithValue("@Name", threat.Name);
            command.Parameters.AddWithValue("@Category", threat.Category);
            command.Parameters.AddWithValue("@Severity", threat.Severity.ToString());
            command.Parameters.AddWithValue("@Source", threat.Source.ToString());
            command.Parameters.AddWithValue("@Resource", (object?)threat.Resource ?? DBNull.Value);
            command.Parameters.AddWithValue("@Description", (object?)threat.Description ?? DBNull.Value);
            command.Parameters.AddWithValue("@EngineName", (object?)threat.EngineName ?? DBNull.Value);
            command.Parameters.AddWithValue("@IsQuarantined", threat.IsQuarantined);
            command.Parameters.AddWithValue("@QuarantinePath", (object?)threat.QuarantinePath ?? DBNull.Value);
            command.Parameters.AddWithValue("@EvidenceJson", (object?)threat.EvidenceJson ?? DBNull.Value);
            command.Parameters.AddWithValue("@DetectedAt", threat.DetectedAt);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    public async Task<IReadOnlyCollection<ThreatDetection>> GetThreatsAsync(bool activeOnly, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT Id, ScanJobId, Name, Category, Severity, Source, Resource, Description, EngineName, IsQuarantined, QuarantinePath, EvidenceJson, DetectedAt
            FROM ThreatDetections
            WHERE (@ActiveOnly = 0 OR IsQuarantined = 0)
            ORDER BY DetectedAt DESC;
            """;

        var threats = new List<ThreatDetection>();

        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@ActiveOnly", activeOnly);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            threats.Add(new ThreatDetection
            {
                Id = reader.GetInt32(0),
                ScanJobId = reader.IsDBNull(1) ? null : reader.GetInt32(1),
                Name = reader.GetString(2),
                Category = reader.GetString(3),
                Severity = Enum.Parse<ThreatSeverity>(reader.GetString(4)),
                Source = Enum.Parse<ThreatSource>(reader.GetString(5)),
                Resource = reader.IsDBNull(6) ? null : reader.GetString(6),
                Description = reader.IsDBNull(7) ? null : reader.GetString(7),
                EngineName = reader.IsDBNull(8) ? null : reader.GetString(8),
                IsQuarantined = reader.GetBoolean(9),
                QuarantinePath = reader.IsDBNull(10) ? null : reader.GetString(10),
                EvidenceJson = reader.IsDBNull(11) ? null : reader.GetString(11),
                DetectedAt = reader.GetDateTimeOffset(12)
            });
        }

        return threats;
    }

    public async Task<ThreatDetection?> GetThreatByIdAsync(int id, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT TOP (1) Id, ScanJobId, Name, Category, Severity, Source, Resource, Description, EngineName, IsQuarantined, QuarantinePath, EvidenceJson, DetectedAt
            FROM ThreatDetections
            WHERE Id = @Id;
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@Id", id);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new ThreatDetection
        {
            Id = reader.GetInt32(0),
            ScanJobId = reader.IsDBNull(1) ? null : reader.GetInt32(1),
            Name = reader.GetString(2),
            Category = reader.GetString(3),
            Severity = Enum.Parse<ThreatSeverity>(reader.GetString(4)),
            Source = Enum.Parse<ThreatSource>(reader.GetString(5)),
            Resource = reader.IsDBNull(6) ? null : reader.GetString(6),
            Description = reader.IsDBNull(7) ? null : reader.GetString(7),
            EngineName = reader.IsDBNull(8) ? null : reader.GetString(8),
            IsQuarantined = reader.GetBoolean(9),
            QuarantinePath = reader.IsDBNull(10) ? null : reader.GetString(10),
            EvidenceJson = reader.IsDBNull(11) ? null : reader.GetString(11),
            DetectedAt = reader.GetDateTimeOffset(12)
        };
    }

    public async Task MarkThreatQuarantinedAsync(int id, string? quarantinePath, CancellationToken cancellationToken = default)
    {
        const string sql = """
            UPDATE ThreatDetections
            SET IsQuarantined = 1,
                QuarantinePath = @QuarantinePath
            WHERE Id = @Id;
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@Id", id);
        command.Parameters.AddWithValue("@QuarantinePath", (object?)quarantinePath ?? DBNull.Value);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<ScanReportExport> CreateScanReportExportAsync(ScanReportExport export, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO ScanReportExports
            (
                ScanJobId,
                FileName,
                Format,
                ExportedBy,
                VulnerabilityCount,
                ExportedAt
            )
            OUTPUT INSERTED.Id, INSERTED.ScanJobId, INSERTED.FileName, INSERTED.Format, INSERTED.ExportedBy, INSERTED.VulnerabilityCount, INSERTED.ExportedAt
            VALUES
            (
                @ScanJobId,
                @FileName,
                @Format,
                @ExportedBy,
                @VulnerabilityCount,
                @ExportedAt
            );
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@ScanJobId", export.ScanJobId.HasValue ? export.ScanJobId.Value : DBNull.Value);
        command.Parameters.AddWithValue("@FileName", export.FileName);
        command.Parameters.AddWithValue("@Format", export.Format);
        command.Parameters.AddWithValue("@ExportedBy", export.ExportedBy);
        command.Parameters.AddWithValue("@VulnerabilityCount", export.VulnerabilityCount);
        command.Parameters.AddWithValue("@ExportedAt", export.ExportedAt);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);

        return new ScanReportExport
        {
            Id = reader.GetInt32(0),
            ScanJobId = reader.IsDBNull(1) ? null : reader.GetInt32(1),
            FileName = reader.GetString(2),
            Format = reader.GetString(3),
            ExportedBy = reader.GetString(4),
            VulnerabilityCount = reader.GetInt32(5),
            ExportedAt = reader.GetDateTimeOffset(6)
        };
    }

    public async Task<IReadOnlyCollection<ScanReportExport>> GetScanReportExportsAsync(int take, CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT TOP (@Take) Id, ScanJobId, FileName, Format, ExportedBy, VulnerabilityCount, ExportedAt
            FROM ScanReportExports
            ORDER BY ExportedAt DESC, Id DESC;
            """;

        var exports = new List<ScanReportExport>();
        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@Take", take);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);

        while (await reader.ReadAsync(cancellationToken))
        {
            exports.Add(new ScanReportExport
            {
                Id = reader.GetInt32(0),
                ScanJobId = reader.IsDBNull(1) ? null : reader.GetInt32(1),
                FileName = reader.GetString(2),
                Format = reader.GetString(3),
                ExportedBy = reader.GetString(4),
                VulnerabilityCount = reader.GetInt32(5),
                ExportedAt = reader.GetDateTimeOffset(6)
            });
        }

        return exports;
    }

    public async Task SaveHealthSnapshotAsync(DeviceHealthSnapshot snapshot, CancellationToken cancellationToken = default)
    {
        const string sql = """
            INSERT INTO DeviceHealthSnapshots
            (
                CapturedAt,
                AntivirusEnabled,
                RealTimeProtectionEnabled,
                IoavProtectionEnabled,
                NetworkInspectionEnabled,
                EngineServiceEnabled,
                SignaturesOutOfDate,
                AntivirusSignatureVersion,
                AntivirusSignatureLastUpdated,
                QuickScanAgeDays,
                FullScanAgeDays
            )
            VALUES
            (
                @CapturedAt,
                @AntivirusEnabled,
                @RealTimeProtectionEnabled,
                @IoavProtectionEnabled,
                @NetworkInspectionEnabled,
                @EngineServiceEnabled,
                @SignaturesOutOfDate,
                @AntivirusSignatureVersion,
                @AntivirusSignatureLastUpdated,
                @QuickScanAgeDays,
                @FullScanAgeDays
            );
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@CapturedAt", snapshot.CapturedAt);
        command.Parameters.AddWithValue("@AntivirusEnabled", snapshot.AntivirusEnabled);
        command.Parameters.AddWithValue("@RealTimeProtectionEnabled", snapshot.RealTimeProtectionEnabled);
        command.Parameters.AddWithValue("@IoavProtectionEnabled", snapshot.IoavProtectionEnabled);
        command.Parameters.AddWithValue("@NetworkInspectionEnabled", snapshot.NetworkInspectionEnabled);
        command.Parameters.AddWithValue("@EngineServiceEnabled", snapshot.EngineServiceEnabled);
        command.Parameters.AddWithValue("@SignaturesOutOfDate", snapshot.SignaturesOutOfDate);
        command.Parameters.AddWithValue("@AntivirusSignatureVersion", (object?)snapshot.AntivirusSignatureVersion ?? DBNull.Value);
        command.Parameters.AddWithValue("@AntivirusSignatureLastUpdated", snapshot.AntivirusSignatureLastUpdated.HasValue ? snapshot.AntivirusSignatureLastUpdated.Value : DBNull.Value);
        command.Parameters.AddWithValue("@QuickScanAgeDays", snapshot.QuickScanAgeDays.HasValue ? snapshot.QuickScanAgeDays.Value : DBNull.Value);
        command.Parameters.AddWithValue("@FullScanAgeDays", snapshot.FullScanAgeDays.HasValue ? snapshot.FullScanAgeDays.Value : DBNull.Value);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<DeviceHealthSnapshot?> GetLatestHealthSnapshotAsync(CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT TOP (1) CapturedAt, AntivirusEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled, NetworkInspectionEnabled, EngineServiceEnabled, SignaturesOutOfDate, AntivirusSignatureVersion, AntivirusSignatureLastUpdated, QuickScanAgeDays, FullScanAgeDays
            FROM DeviceHealthSnapshots
            ORDER BY CapturedAt DESC;
            """;

        await using var connection = await OpenConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);

        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new DeviceHealthSnapshot
        {
            CapturedAt = reader.GetDateTimeOffset(0),
            AntivirusEnabled = reader.GetBoolean(1),
            RealTimeProtectionEnabled = reader.GetBoolean(2),
            IoavProtectionEnabled = reader.GetBoolean(3),
            NetworkInspectionEnabled = reader.GetBoolean(4),
            EngineServiceEnabled = reader.GetBoolean(5),
            SignaturesOutOfDate = reader.GetBoolean(6),
            AntivirusSignatureVersion = reader.IsDBNull(7) ? null : reader.GetString(7),
            AntivirusSignatureLastUpdated = reader.IsDBNull(8) ? null : reader.GetFieldValue<DateTimeOffset>(8),
            QuickScanAgeDays = reader.IsDBNull(9) ? null : reader.GetInt32(9),
            FullScanAgeDays = reader.IsDBNull(10) ? null : reader.GetInt32(10)
        };
    }

    private async Task<SqlConnection> OpenConnectionAsync(CancellationToken cancellationToken)
    {
        return await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
    }
}
