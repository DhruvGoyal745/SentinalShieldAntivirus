using Antivirus.Domain;

namespace Antivirus.Application.Contracts;

// ── Phase 3: IOC Repository & Matcher Contracts ─────────────────────

/// <summary>
/// Persistent IOC store. All operations are tenant-scoped via the
/// indicator's <see cref="IocIndicator.TenantKey"/>; queries that omit
/// a tenant key are admin-only and span all tenants.
/// </summary>
public interface IIocRepository
{
    Task<IocIndicator> AddAsync(IocIndicator indicator, CancellationToken cancellationToken = default);

    /// <summary>Idempotent bulk upsert. Uses (tenantKey, type, normalizedValue, source) as the dedupe key.</summary>
    Task<int> BulkUpsertAsync(IReadOnlyCollection<IocIndicator> indicators, CancellationToken cancellationToken = default);

    Task<IocIndicator?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);

    Task<IocIndicator?> GetByValueAsync(string tenantKey, IocType type, string normalizedValue, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<IocIndicator>> SearchAsync(IocSearchFilter filter, CancellationToken cancellationToken = default);

    Task<IocStats> GetStatsAsync(string tenantKey, CancellationToken cancellationToken = default);

    Task<bool> DeleteAsync(Guid id, CancellationToken cancellationToken = default);

    /// <summary>Sets <see cref="IocIndicator.IsActive"/> = false for any indicator past its <c>ExpiresAt</c>. Returns the number affected.</summary>
    Task<int> ExpireOldAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Synchronous-friendly local IOC matcher used inside the scan hot path.
/// Implementations MUST be safe for concurrent use and SHOULD cache hot
/// indicators in memory.
/// </summary>
public interface IIocMatcher
{
    Task<IocIndicatorMatch?> MatchAsync(string tenantKey, IocType type, string normalizedValue, CancellationToken cancellationToken = default);

    /// <summary>Match arbitrary file paths against active <see cref="IocType.PathGlob"/> indicators.</summary>
    Task<IocIndicatorMatch?> MatchPathAsync(string tenantKey, string filePath, CancellationToken cancellationToken = default);
}

/// <summary>Pulls indicators from a feed provider and writes them via <see cref="IIocRepository"/>.</summary>
public interface IIocIngestionService
{
    Task<IocFeedSyncRun> SyncProviderAsync(string provider, string tenantKey, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<IocFeedSyncRun>> GetRecentSyncRunsAsync(string? provider, string? tenantKey, int maxCount, CancellationToken cancellationToken = default);
}
