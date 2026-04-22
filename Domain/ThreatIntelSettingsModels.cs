namespace Antivirus.Domain;

// ── Phase 3: Per-Tenant Threat Intel Settings ────────────────────────

public sealed class ThreatIntelProviderSettings
{
    public string Provider { get; set; } = string.Empty;
    public bool Enabled { get; set; }
    public decimal TrustWeight { get; set; } = 0.5m;
    public int RateLimitPerMinute { get; set; } = 60;
    public int OverflowQueueCapacity { get; set; } = 32;
    public int CircuitBreakerFailureThreshold { get; set; } = 5;
    public int CircuitBreakerResetSeconds { get; set; } = 60;
}

public sealed class ThreatIntelTtlSettings
{
    public int HashTtlSeconds { get; set; } = 86400;        // 24h
    public int UrlTtlSeconds { get; set; } = 21600;         // 6h
    public int IpTtlSeconds { get; set; } = 3600;           // 1h
    public int DomainTtlSeconds { get; set; } = 21600;      // 6h
    public int NegativeTtlSeconds { get; set; } = 600;      // 10m
}

public sealed class ThreatIntelSettings
{
    public string TenantKey { get; set; } = string.Empty;
    public bool CloudReputationEnabled { get; set; } = true;
    public IList<ThreatIntelProviderSettings> Providers { get; set; } = new List<ThreatIntelProviderSettings>();
    public ThreatIntelTtlSettings Ttl { get; set; } = new();
    public int SyncWindowDays { get; set; } = 7;
    public int MaxIndicatorsPerSync { get; set; } = 10000;
    public int CloudFanoutTimeoutMs { get; set; } = 1500;
    public DateTimeOffset UpdatedAt { get; set; }
}

public sealed class SecretMetadata
{
    public string Provider { get; init; } = string.Empty;
    public string Key { get; init; } = string.Empty;
    public string TenantKey { get; init; } = string.Empty;
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset UpdatedAt { get; init; }
    public bool HasValue { get; init; }
}

public sealed class ReputationLookupAuditEntry
{
    public long Id { get; init; }
    public string TenantKey { get; init; } = string.Empty;
    public string? CallerUser { get; init; }
    public ReputationLookupType LookupType { get; init; }
    public string RedactedValue { get; init; } = string.Empty;
    public string ProvidersAttempted { get; init; } = string.Empty;
    public bool CacheHit { get; init; }
    public bool LocalIocHit { get; init; }
    public int LatencyMs { get; init; }
    public ReputationVerdict FinalVerdict { get; init; }
    public string? FailureReason { get; init; }
    public string? CorrelationId { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
}
