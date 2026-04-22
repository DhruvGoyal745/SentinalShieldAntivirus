namespace Antivirus.Domain;

// ── Phase 3: IOC (Indicators of Compromise) Models ───────────────────

public enum IocType
{
    Sha256 = 0,
    Sha1 = 1,
    Md5 = 2,
    Ip = 3,
    Domain = 4,
    Url = 5,
    PathGlob = 6
}

public sealed class IocIndicator
{
    public Guid Id { get; init; }
    public string TenantKey { get; init; } = string.Empty;
    public IocType Type { get; init; }
    public string NormalizedValue { get; init; } = string.Empty;
    public string DisplayValue { get; init; } = string.Empty;
    public string Source { get; init; } = string.Empty;
    public ThreatSeverity Severity { get; init; }
    public decimal Confidence { get; init; }
    public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();
    public string? Description { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset? ExpiresAt { get; init; }
    public bool IsActive { get; init; } = true;
}

public sealed class IocIndicatorMatch
{
    public Guid IndicatorId { get; init; }
    public IocType Type { get; init; }
    public string NormalizedValue { get; init; } = string.Empty;
    public string Source { get; init; } = string.Empty;
    public ThreatSeverity Severity { get; init; }
    public decimal Confidence { get; init; }
    public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();
    public string? Description { get; init; }
}

public sealed class IocSource
{
    public string Provider { get; init; } = string.Empty;
    public string TenantKey { get; init; } = string.Empty;
    public DateTimeOffset? LastSyncAt { get; init; }
    public string? LastCursor { get; init; }
    public bool Enabled { get; init; } = true;
}

public sealed class IocFeedSyncRun
{
    public long Id { get; init; }
    public string Provider { get; init; } = string.Empty;
    public string TenantKey { get; init; } = string.Empty;
    public DateTimeOffset StartedAt { get; init; }
    public DateTimeOffset? CompletedAt { get; init; }
    public int IndicatorsImported { get; init; }
    public int IndicatorsSkipped { get; init; }
    public bool Success { get; init; }
    public string? FailureReason { get; init; }
    public string? CursorAfter { get; init; }
}

public sealed class IocSearchFilter
{
    public string? TenantKey { get; init; }
    public IocType? Type { get; init; }
    public string? ValueContains { get; init; }
    public string? Source { get; init; }
    public bool? IsActive { get; init; }
    public int PageNumber { get; init; } = 1;
    public int PageSize { get; init; } = 50;
}

public sealed class IocStats
{
    public int Total { get; init; }
    public int Active { get; init; }
    public IReadOnlyDictionary<IocType, int> ByType { get; init; } = new Dictionary<IocType, int>();
    public IReadOnlyDictionary<string, int> BySource { get; init; } = new Dictionary<string, int>();
}
