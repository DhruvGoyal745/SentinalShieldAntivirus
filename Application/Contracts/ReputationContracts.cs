using Antivirus.Domain;

namespace Antivirus.Application.Contracts;

// ── Phase 3: Reputation Provider & Orchestration Contracts ───────────

/// <summary>
/// Pluggable provider abstraction for cloud reputation lookups. Each
/// provider declares which lookup types it supports; the orchestrator
/// filters lookups before fan-out using <see cref="SupportedLookupTypes"/>.
/// </summary>
public interface IReputationProvider
{
    /// <summary>Stable provider name (e.g. "virustotal", "mock"). Used in DI keying, audit, and cache keys.</summary>
    string Name { get; }

    /// <summary>Lookup types this provider supports. Cloud providers MUST NOT advertise <see cref="ReputationLookupType"/> values they cannot handle.</summary>
    IReadOnlySet<ReputationLookupType> SupportedLookupTypes { get; }

    /// <summary>True when the provider has been explicitly enabled via tenant settings AND has the credentials it needs to operate.</summary>
    Task<bool> IsAvailableAsync(string tenantKey, CancellationToken cancellationToken = default);

    /// <summary>Execute a single lookup. Implementations MUST honor <paramref name="cancellationToken"/> and return a <see cref="ProviderVerdict"/> even on failure (with <c>TimedOut</c>/<c>RateLimited</c> set or <c>Verdict = Unknown</c>).</summary>
    Task<ProviderVerdict> LookupAsync(ReputationLookupRequest request, CancellationToken cancellationToken = default);
}

/// <summary>
/// Hot-path facade used by the scan pipeline and HTTP API. Performs:
/// (1) local IOC pre-check (synchronous), (2) cache lookup (synchronous),
/// (3) bounded best-effort cloud fan-out to enabled providers.
/// </summary>
public interface IReputationOrchestrator
{
    Task<ReputationLookupResult> EvaluateAsync(ReputationLookupRequest request, CancellationToken cancellationToken = default);

    /// <summary>Snapshot of every registered provider's current health (rate limits, breaker, last sync). Used by Settings UI and Telemetry page.</summary>
    Task<IReadOnlyList<ProviderHealth>> GetProviderHealthAsync(string tenantKey, CancellationToken cancellationToken = default);
}

/// <summary>
/// Persistent cache of provider verdicts keyed by (tenant, provider, lookupType, normalizedValue).
/// Negative results are cached with a shorter TTL to avoid hammering providers on
/// repeated unknown lookups.
/// </summary>
public interface IReputationCache
{
    Task<ProviderVerdict?> TryGetAsync(string tenantKey, string provider, ReputationLookupType type, string normalizedValue, CancellationToken cancellationToken = default);
    Task SetAsync(string tenantKey, string provider, ReputationLookupType type, string normalizedValue, ProviderVerdict verdict, TimeSpan ttl, CancellationToken cancellationToken = default);
    Task EvictExpiredAsync(CancellationToken cancellationToken = default);
}
