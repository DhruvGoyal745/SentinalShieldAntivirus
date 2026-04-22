namespace Antivirus.Domain;

// ── Phase 3: Cloud Reputation & Threat Intelligence ──────────────────

public enum ReputationVerdict
{
    Unknown = 0,
    Clean = 1,
    Suspicious = 2,
    Malicious = 3
}

public enum ReputationLookupType
{
    Sha256 = 0,
    Sha1 = 1,
    Md5 = 2,
    Ip = 3,
    Domain = 4,
    Url = 5
}

public enum ReputationCacheStatus
{
    Miss = 0,
    Hit = 1,
    Bypassed = 2
}

public enum ProviderCircuitState
{
    Closed = 0,
    Open = 1,
    HalfOpen = 2
}

public sealed class ReputationLookupRequest
{
    public string TenantKey { get; init; } = string.Empty;
    public ReputationLookupType LookupType { get; init; }
    public string Value { get; init; } = string.Empty;
    public string? RequestedBy { get; init; }
    public string? CorrelationId { get; init; }
    public bool AllowCloud { get; init; } = true;
}

public sealed class ProviderEvidence
{
    public string Key { get; init; } = string.Empty;
    public string Value { get; init; } = string.Empty;
}

public sealed class ProviderVerdict
{
    public string Provider { get; init; } = string.Empty;
    public ReputationVerdict Verdict { get; init; }
    public decimal Confidence { get; init; }
    public IReadOnlyList<string> ReasonCodes { get; init; } = Array.Empty<string>();
    public string EvidenceSummary { get; init; } = string.Empty;
    public IReadOnlyList<ProviderEvidence> Evidence { get; init; } = Array.Empty<ProviderEvidence>();
    public bool FromCache { get; init; }
    public bool TimedOut { get; init; }
    public bool RateLimited { get; init; }
    public int LatencyMs { get; init; }
}

public sealed class ReputationLookupResult
{
    public ReputationVerdict AggregateVerdict { get; init; }
    public decimal AggregateConfidence { get; init; }
    public IReadOnlyList<ProviderVerdict> ProviderResults { get; init; } = Array.Empty<ProviderVerdict>();
    public IocIndicatorMatch? LocalIocMatch { get; init; }
    public ReputationCacheStatus CacheStatus { get; init; }
    public int DurationMs { get; init; }
    public string? FailureReason { get; init; }
}

public sealed class ProviderHealth
{
    public string Provider { get; init; } = string.Empty;
    public bool Enabled { get; init; }
    public DateTimeOffset? LastSuccessAt { get; init; }
    public DateTimeOffset? LastFailureAt { get; init; }
    public string? LastFailureReason { get; init; }
    public ProviderCircuitState CircuitState { get; init; }
    public int RateLimitTokensRemaining { get; init; }
    public int LastSyncDurationMs { get; init; }
    public int LastSyncCount { get; init; }
    public DateTimeOffset? LastSyncAt { get; init; }
}
