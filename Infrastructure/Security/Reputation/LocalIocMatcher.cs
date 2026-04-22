using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.Reputation;

/// <summary>
/// In-memory IOC matcher backed by <see cref="IIocRepository"/>. Caches the
/// per-tenant active indicator set for a short TTL so the scan hot path can
/// match without round-tripping to SQL on every file. PathGlob entries are
/// kept in a separate compiled-regex list because they can't be O(1) hashed.
/// </summary>
public sealed class LocalIocMatcher : IIocMatcher
{
    private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(5);

    private readonly IIocRepository _repository;
    private readonly ILogger<LocalIocMatcher> _logger;
    private readonly ConcurrentDictionary<string, TenantSnapshot> _byTenant = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _refreshGate = new(1, 1);

    public LocalIocMatcher(IIocRepository repository, ILogger<LocalIocMatcher> logger)
    {
        _repository = repository;
        _logger = logger;
    }

    public async Task<IocIndicatorMatch?> MatchAsync(string tenantKey, IocType type, string normalizedValue, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(normalizedValue) || type == IocType.PathGlob) return null;
        var snapshot = await GetSnapshotAsync(tenantKey, cancellationToken);
        var key = (type, normalizedValue);
        return snapshot.ByValue.TryGetValue(key, out var match) ? match : null;
    }

    public async Task<IocIndicatorMatch?> MatchPathAsync(string tenantKey, string filePath, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return null;
        var snapshot = await GetSnapshotAsync(tenantKey, cancellationToken);
        if (snapshot.PathGlobs.Count == 0) return null;
        var normalized = filePath.Replace('/', '\\');
        foreach (var (regex, match) in snapshot.PathGlobs)
        {
            if (regex.IsMatch(normalized)) return match;
        }
        return null;
    }

    /// <summary>Force-refresh the next time the snapshot is requested. Used after writes.</summary>
    public void Invalidate(string tenantKey) => _byTenant.TryRemove(tenantKey, out _);

    private async Task<TenantSnapshot> GetSnapshotAsync(string tenantKey, CancellationToken cancellationToken)
    {
        if (_byTenant.TryGetValue(tenantKey, out var existing) && DateTimeOffset.UtcNow - existing.LoadedAt < CacheTtl)
        {
            return existing;
        }

        await _refreshGate.WaitAsync(cancellationToken);
        try
        {
            if (_byTenant.TryGetValue(tenantKey, out existing) && DateTimeOffset.UtcNow - existing.LoadedAt < CacheTtl)
            {
                return existing;
            }
            var fresh = await LoadAsync(tenantKey, cancellationToken);
            _byTenant[tenantKey] = fresh;
            return fresh;
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    private async Task<TenantSnapshot> LoadAsync(string tenantKey, CancellationToken cancellationToken)
    {
        var byValue = new Dictionary<(IocType, string), IocIndicatorMatch>();
        var pathGlobs = new List<(Regex, IocIndicatorMatch)>();

        try
        {
            // Pull active indicators in pages. Conservative ceiling to keep memory bounded.
            const int pageSize = 500;
            for (var page = 1; page <= 50; page++)
            {
                var batch = await _repository.SearchAsync(new IocSearchFilter
                {
                    TenantKey = tenantKey,
                    IsActive = true,
                    PageNumber = page,
                    PageSize = pageSize
                }, cancellationToken);
                if (batch.Count == 0) break;

                foreach (var indicator in batch)
                {
                    var match = ToMatch(indicator);
                    if (indicator.Type == IocType.PathGlob)
                    {
                        var regex = TryCompileGlob(indicator.NormalizedValue);
                        if (regex is not null) pathGlobs.Add((regex, match));
                    }
                    else
                    {
                        // Best-confidence wins on duplicates across sources.
                        var key = (indicator.Type, indicator.NormalizedValue);
                        if (!byValue.TryGetValue(key, out var existing) || existing.Confidence < indicator.Confidence)
                        {
                            byValue[key] = match;
                        }
                    }
                }

                if (batch.Count < pageSize) break;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load IOC snapshot for tenant {Tenant}", tenantKey);
        }

        return new TenantSnapshot(byValue, pathGlobs, DateTimeOffset.UtcNow);
    }

    private static IocIndicatorMatch ToMatch(IocIndicator indicator) => new()
    {
        IndicatorId = indicator.Id,
        Type = indicator.Type,
        NormalizedValue = indicator.NormalizedValue,
        Source = indicator.Source,
        Severity = indicator.Severity,
        Confidence = indicator.Confidence,
        Tags = indicator.Tags,
        Description = indicator.Description
    };

    /// <summary>Convert a Windows-style file glob (supports * and ?) into an anchored, case-insensitive regex.</summary>
    private static Regex? TryCompileGlob(string glob)
    {
        try
        {
            var sb = new System.Text.StringBuilder("^");
            foreach (var ch in glob)
            {
                sb.Append(ch switch
                {
                    '*' => ".*",
                    '?' => ".",
                    _ => Regex.Escape(ch.ToString())
                });
            }
            sb.Append('$');
            return new Regex(sb.ToString(), RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        }
        catch
        {
            return null;
        }
    }

    private sealed record TenantSnapshot(
        IReadOnlyDictionary<(IocType, string), IocIndicatorMatch> ByValue,
        IReadOnlyList<(Regex Regex, IocIndicatorMatch Match)> PathGlobs,
        DateTimeOffset LoadedAt);
}
