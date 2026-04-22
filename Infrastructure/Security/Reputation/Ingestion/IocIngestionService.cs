using System.Diagnostics;
using Antivirus.Application.Contracts;
using Antivirus.Domain;
using Antivirus.Infrastructure.Persistence;

namespace Antivirus.Infrastructure.Security.Reputation.Ingestion;

/// <summary>
/// Coordinates pulling indicators from <see cref="IIocFeedSource"/>
/// implementations into the IOC repository. Stateless across runs;
/// per-tenant cursor state lives in <see cref="IIocFeedSyncStore"/>.
/// </summary>
public sealed class IocIngestionService : IIocIngestionService
{
    private readonly IReadOnlyDictionary<string, IIocFeedSource> _sources;
    private readonly IIocRepository _iocRepository;
    private readonly IIocFeedSyncStore _syncStore;
    private readonly LocalIocMatcher? _matcher;
    private readonly IThreatIntelSettingsRepository _settingsRepository;
    private readonly ILogger<IocIngestionService> _logger;

    public IocIngestionService(
        IEnumerable<IIocFeedSource> sources,
        IIocRepository iocRepository,
        IIocFeedSyncStore syncStore,
        IIocMatcher matcher,
        IThreatIntelSettingsRepository settingsRepository,
        ILogger<IocIngestionService> logger)
    {
        _sources = sources.ToDictionary(s => s.Provider, StringComparer.OrdinalIgnoreCase);
        _iocRepository = iocRepository;
        _syncStore = syncStore;
        // The hot-path matcher exposes Invalidate(); we only need that surface here.
        _matcher = matcher as LocalIocMatcher;
        _settingsRepository = settingsRepository;
        _logger = logger;
    }

    public async Task<IocFeedSyncRun> SyncProviderAsync(string provider, string tenantKey, CancellationToken cancellationToken = default)
    {
        var startedAt = DateTimeOffset.UtcNow;
        var sw = Stopwatch.StartNew();

        if (!_sources.TryGetValue(provider, out var source))
        {
            return await PersistRunAsync(new IocFeedSyncRun
            {
                Provider = provider, TenantKey = tenantKey,
                StartedAt = startedAt, CompletedAt = DateTimeOffset.UtcNow,
                Success = false, FailureReason = "unknown-provider"
            }, cancellationToken);
        }

        var settings = await _settingsRepository.GetOrCreateAsync(tenantKey, cancellationToken);
        var maxItems = Math.Max(1, settings.MaxIndicatorsPerSync);
        var existing = await _syncStore.GetSourceAsync(tenantKey, provider, cancellationToken);
        if (existing is { Enabled: false })
        {
            return await PersistRunAsync(new IocFeedSyncRun
            {
                Provider = provider, TenantKey = tenantKey,
                StartedAt = startedAt, CompletedAt = DateTimeOffset.UtcNow,
                Success = false, FailureReason = "source-disabled"
            }, cancellationToken);
        }

        var fetch = await source.FetchAsync(tenantKey, existing?.LastCursor, maxItems, cancellationToken);
        if (!fetch.Success)
        {
            _logger.LogWarning("Feed sync failed for {Provider}/{Tenant}: {Reason}", provider, tenantKey, fetch.FailureReason);
            return await PersistRunAsync(new IocFeedSyncRun
            {
                Provider = provider, TenantKey = tenantKey,
                StartedAt = startedAt, CompletedAt = DateTimeOffset.UtcNow,
                Success = false, FailureReason = fetch.FailureReason
            }, cancellationToken);
        }

        var imported = 0;
        var skipped = 0;
        if (fetch.Indicators.Count > 0)
        {
            try
            {
                imported = await _iocRepository.BulkUpsertAsync(fetch.Indicators, cancellationToken);
                skipped = fetch.Indicators.Count - imported;
                _matcher?.Invalidate(tenantKey);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Bulk upsert failed for {Provider}/{Tenant}", provider, tenantKey);
                return await PersistRunAsync(new IocFeedSyncRun
                {
                    Provider = provider, TenantKey = tenantKey,
                    StartedAt = startedAt, CompletedAt = DateTimeOffset.UtcNow,
                    Success = false, FailureReason = "upsert-failed: " + ex.GetType().Name
                }, cancellationToken);
            }
        }

        await _syncStore.UpsertSourceAsync(new IocSource
        {
            TenantKey = tenantKey,
            Provider = provider,
            LastSyncAt = DateTimeOffset.UtcNow,
            LastCursor = fetch.NextCursor,
            Enabled = existing?.Enabled ?? true
        }, cancellationToken);

        var run = new IocFeedSyncRun
        {
            Provider = provider,
            TenantKey = tenantKey,
            StartedAt = startedAt,
            CompletedAt = DateTimeOffset.UtcNow,
            IndicatorsImported = imported,
            IndicatorsSkipped = skipped,
            Success = true,
            CursorAfter = fetch.NextCursor
        };
        _logger.LogInformation("Feed sync {Provider}/{Tenant} imported {Imported} indicators in {Ms}ms", provider, tenantKey, imported, sw.ElapsedMilliseconds);
        return await PersistRunAsync(run, cancellationToken);
    }

    public Task<IReadOnlyList<IocFeedSyncRun>> GetRecentSyncRunsAsync(string? provider, string? tenantKey, int maxCount, CancellationToken cancellationToken = default)
        => _syncStore.RecentAsync(provider, tenantKey, maxCount, cancellationToken);

    private async Task<IocFeedSyncRun> PersistRunAsync(IocFeedSyncRun run, CancellationToken cancellationToken)
    {
        try
        {
            var id = await _syncStore.RecordRunAsync(run, cancellationToken);
            return new IocFeedSyncRun
            {
                Id = id,
                Provider = run.Provider, TenantKey = run.TenantKey,
                StartedAt = run.StartedAt, CompletedAt = run.CompletedAt,
                IndicatorsImported = run.IndicatorsImported, IndicatorsSkipped = run.IndicatorsSkipped,
                Success = run.Success, FailureReason = run.FailureReason, CursorAfter = run.CursorAfter
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to persist sync run for {Provider}/{Tenant}", run.Provider, run.TenantKey);
            return run;
        }
    }
}
