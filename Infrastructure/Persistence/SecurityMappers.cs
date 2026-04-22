using Antivirus.Domain;
using Microsoft.Data.SqlClient;

namespace Antivirus.Infrastructure.Persistence;

/// <summary>
/// Centralised row mappers for all security domain objects.
/// Each mapper is a pure function: SqlDataReader → domain object.
/// This eliminates the 4× duplicate ScanJob mapping, 3× ThreatDetection mapping, etc.
/// </summary>
internal static class SecurityMappers
{
    /// <summary>
    /// Maps a row from: Id, Mode, TargetPath, RequestedBy, Status, Stage, PercentComplete,
    /// FilesScanned, TotalFiles, CurrentTarget, ThreatCount, Notes, CreatedAt, StartedAt, CompletedAt
    /// </summary>
    public static ScanJob MapScanJob(SqlDataReader r) => new()
    {
        Id = r.GetInt32(0),
        Mode = Enum.Parse<ScanMode>(r.GetString(1)),
        TargetPath = r.IsDBNull(2) ? null : r.GetString(2),
        RequestedBy = r.GetString(3),
        Status = Enum.Parse<ScanStatus>(r.GetString(4)),
        Stage = Enum.Parse<ScanStage>(r.GetString(5)),
        PercentComplete = r.GetInt32(6),
        FilesScanned = r.GetInt32(7),
        TotalFiles = r.IsDBNull(8) ? null : r.GetInt32(8),
        CurrentTarget = r.IsDBNull(9) ? null : r.GetString(9),
        ThreatCount = r.GetInt32(10),
        Notes = r.IsDBNull(11) ? null : r.GetString(11),
        CreatedAt = r.GetDateTimeOffset(12),
        StartedAt = r.IsDBNull(13) ? null : r.GetFieldValue<DateTimeOffset>(13),
        CompletedAt = r.IsDBNull(14) ? null : r.GetFieldValue<DateTimeOffset>(14)
    };

    /// <summary>
    /// Maps a row from: Id, ScanJobId, Name, Category, Severity, Source, Resource,
    /// Description, EngineName, IsQuarantined, QuarantinePath, EvidenceJson, DetectedAt
    /// </summary>
    public static ThreatDetection MapThreat(SqlDataReader r) => new()
    {
        Id = r.GetInt32(0),
        ScanJobId = r.IsDBNull(1) ? null : r.GetInt32(1),
        Name = r.GetString(2),
        Category = r.GetString(3),
        Severity = Enum.Parse<ThreatSeverity>(r.GetString(4)),
        Source = Enum.Parse<ThreatSource>(r.GetString(5)),
        Resource = r.IsDBNull(6) ? null : r.GetString(6),
        Description = r.IsDBNull(7) ? null : r.GetString(7),
        EngineName = r.IsDBNull(8) ? null : r.GetString(8),
        IsQuarantined = r.GetBoolean(9),
        QuarantinePath = r.IsDBNull(10) ? null : r.GetString(10),
        EvidenceJson = r.IsDBNull(11) ? null : r.GetString(11),
        DetectedAt = r.GetDateTimeOffset(12)
    };

    /// <summary>
    /// Maps a row from: Id, ScanJobId, FilePath, PreviousPath, EventType, Status,
    /// HashSha256, FileSizeBytes, ThreatCount, Notes, ObservedAt, CreatedAt, ProcessedAt
    /// </summary>
    public static FileSecurityEvent MapFileEvent(SqlDataReader r) => new()
    {
        Id = r.GetInt32(0),
        ScanJobId = r.IsDBNull(1) ? null : r.GetInt32(1),
        FilePath = r.GetString(2),
        PreviousPath = r.IsDBNull(3) ? null : r.GetString(3),
        EventType = Enum.Parse<FileEventType>(r.GetString(4)),
        Status = Enum.Parse<FileEventStatus>(r.GetString(5)),
        HashSha256 = r.IsDBNull(6) ? null : r.GetString(6),
        FileSizeBytes = r.IsDBNull(7) ? null : r.GetInt64(7),
        ThreatCount = r.GetInt32(8),
        Notes = r.IsDBNull(9) ? null : r.GetString(9),
        ObservedAt = r.GetDateTimeOffset(10),
        CreatedAt = r.GetDateTimeOffset(11),
        ProcessedAt = r.IsDBNull(12) ? null : r.GetFieldValue<DateTimeOffset>(12)
    };

    /// <summary>
    /// Maps a row from: Id, FileSecurityEventId, EngineName, Source, Status, IsMatch,
    /// SignatureName, Details, RawOutput, ScannedAt
    /// </summary>
    public static FileEngineResult MapEngineResult(SqlDataReader r) => new()
    {
        Id = r.GetInt32(0),
        FileSecurityEventId = r.GetInt32(1),
        EngineName = r.GetString(2),
        Source = Enum.Parse<ThreatSource>(r.GetString(3)),
        Status = Enum.Parse<FileEngineResultStatus>(r.GetString(4)),
        IsMatch = r.GetBoolean(5),
        SignatureName = r.IsDBNull(6) ? null : r.GetString(6),
        Details = r.IsDBNull(7) ? null : r.GetString(7),
        RawOutput = r.IsDBNull(8) ? null : r.GetString(8),
        ScannedAt = r.GetDateTimeOffset(9)
    };

    /// <summary>
    /// Maps a row from: ScanJobId, Stage, PercentComplete, CurrentPath, FilesScanned,
    /// TotalFiles, FindingsCount, IsSkipped, DetailMessage, StartedAt, CompletedAt, RecordedAt
    /// </summary>
    public static ScanProgressEvent MapProgressEvent(SqlDataReader r) => new()
    {
        ScanJobId = r.GetInt32(0),
        Stage = Enum.Parse<ScanStage>(r.GetString(1)),
        PercentComplete = r.GetInt32(2),
        CurrentPath = r.IsDBNull(3) ? null : r.GetString(3),
        FilesScanned = r.GetInt32(4),
        TotalFiles = r.IsDBNull(5) ? null : r.GetInt32(5),
        FindingsCount = r.GetInt32(6),
        IsSkipped = r.GetBoolean(7),
        DetailMessage = r.IsDBNull(8) ? null : r.GetString(8),
        StartedAt = r.GetDateTimeOffset(9),
        CompletedAt = r.IsDBNull(10) ? null : r.GetFieldValue<DateTimeOffset>(10),
        RecordedAt = r.GetDateTimeOffset(11)
    };

    /// <summary>
    /// Maps a row from: Id, ScanJobId, FileName, Format, ExportedBy, VulnerabilityCount, ExportedAt
    /// </summary>
    public static ScanReportExport MapReportExport(SqlDataReader r) => new()
    {
        Id = r.GetInt32(0),
        ScanJobId = r.IsDBNull(1) ? null : r.GetInt32(1),
        FileName = r.GetString(2),
        Format = r.GetString(3),
        ExportedBy = r.GetString(4),
        VulnerabilityCount = r.GetInt32(5),
        ExportedAt = r.GetDateTimeOffset(6)
    };

    /// <summary>
    /// Maps a row from: CapturedAt, AntivirusEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled,
    /// NetworkInspectionEnabled, EngineServiceEnabled, SignaturesOutOfDate, AntivirusSignatureVersion,
    /// AntivirusSignatureLastUpdated, QuickScanAgeDays, FullScanAgeDays
    /// </summary>
    public static DeviceHealthSnapshot MapHealthSnapshot(SqlDataReader r) => new()
    {
        CapturedAt = r.GetDateTimeOffset(0),
        AntivirusEnabled = r.GetBoolean(1),
        RealTimeProtectionEnabled = r.GetBoolean(2),
        IoavProtectionEnabled = r.GetBoolean(3),
        NetworkInspectionEnabled = r.GetBoolean(4),
        EngineServiceEnabled = r.GetBoolean(5),
        SignaturesOutOfDate = r.GetBoolean(6),
        AntivirusSignatureVersion = r.IsDBNull(7) ? null : r.GetString(7),
        AntivirusSignatureLastUpdated = r.IsDBNull(8) ? null : r.GetFieldValue<DateTimeOffset>(8),
        QuickScanAgeDays = r.IsDBNull(9) ? null : r.GetInt32(9),
        FullScanAgeDays = r.IsDBNull(10) ? null : r.GetInt32(10)
    };
}
