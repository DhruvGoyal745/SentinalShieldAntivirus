namespace Antivirus.Domain;

public sealed record ScanStatusUpdate
{
    public required ScanStatus Status { get; init; }

    public required ScanStage Stage { get; init; }

    public int PercentComplete { get; init; }

    public int FilesScanned { get; init; }

    public int? TotalFiles { get; init; }

    public string? CurrentTarget { get; init; }

    public int ThreatCount { get; init; }

    public string? Notes { get; init; }

    public DateTimeOffset? StartedAt { get; init; }

    public DateTimeOffset? CompletedAt { get; init; }
}

public sealed record FileEventUpdate
{
    public required FileEventStatus Status { get; init; }

    public int ThreatCount { get; init; }

    public string? Notes { get; init; }

    public string? HashSha256 { get; init; }

    public long? FileSizeBytes { get; init; }

    public DateTimeOffset? ProcessedAt { get; init; }
}
