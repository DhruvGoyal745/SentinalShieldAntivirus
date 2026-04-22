namespace Antivirus.Domain;

public enum PurgeState
{
    Active,
    Expired,
    Purged,
    Restored
}

public sealed class QuarantineVaultItem
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public string OriginalPath { get; init; } = string.Empty;
    public string OriginalFileName { get; init; } = string.Empty;
    public string VaultPath { get; init; } = string.Empty;
    public string HashSha256 { get; init; } = string.Empty;
    public long FileSizeBytes { get; init; }
    public string EncryptionKeyId { get; init; } = string.Empty;
    public byte[] EncryptionIV { get; init; } = Array.Empty<byte>();
    public string? ThreatName { get; init; }
    public ThreatSeverity ThreatSeverity { get; init; }
    public string? ThreatSource { get; init; }
    public string? DetectionContextJson { get; init; }
    public PurgeState PurgeState { get; set; } = PurgeState.Active;
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset RetentionExpiresAt { get; init; }
    public DateTimeOffset? RestoredAt { get; set; }
    public DateTimeOffset? PurgedAt { get; set; }
    public string? RestoredBy { get; set; }
}

public sealed class RestoreRequest
{
    public Guid QuarantineItemId { get; init; }
    public string RequestedBy { get; init; } = string.Empty;
    public string? Reason { get; init; }
    public string? RestoreToPath { get; init; }
}

public sealed class RestoreResult
{
    public bool Success { get; init; }
    public string Message { get; init; } = string.Empty;
    public string? RestoredPath { get; init; }
}

public sealed class QuarantineListFilter
{
    public PurgeState? Status { get; init; }
    public string? ThreatName { get; init; }
    public DateTimeOffset? FromDate { get; init; }
    public DateTimeOffset? ToDate { get; init; }
    public int PageSize { get; init; } = 50;
    public int PageNumber { get; init; } = 1;
}

public sealed class QuarantineDetectionContext
{
    public int? ScanJobId { get; init; }
    public int? ThreatDetectionId { get; init; }
    public string? ThreatName { get; init; }
    public ThreatSeverity ThreatSeverity { get; init; }
    public string? ThreatSource { get; init; }
    public decimal Confidence { get; init; }
    public string? Summary { get; init; }
}
