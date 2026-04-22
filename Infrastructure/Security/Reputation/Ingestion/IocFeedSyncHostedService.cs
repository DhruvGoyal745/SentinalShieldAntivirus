using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.Reputation.Ingestion;

/// <summary>
/// Periodically iterates all tenants × all enabled feed sources, runs
/// <see cref="IIocIngestionService.SyncProviderAsync"/>, and also expires
/// stale indicators. Failures are logged and never propagate; one bad
/// tenant must not stop the loop.
/// </summary>
public sealed class IocFeedSyncHostedService : BackgroundService
{
    // Conservative cadence — feeds are slow-moving by nature and we want to be
    // a polite citizen against the upstream rate limits.
    private static readonly TimeSpan SyncInterval = TimeSpan.FromHours(6);
    private static readonly TimeSpan StartupDelay = TimeSpan.FromMinutes(2);

    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<IocFeedSyncHostedService> _logger;

    public IocFeedSyncHostedService(IServiceProvider serviceProvider, ILogger<IocFeedSyncHostedService> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try { await Task.Delay(StartupDelay, stoppingToken); }
        catch (OperationCanceledException) { return; }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await SyncOnceAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "IOC feed sync iteration failed");
            }

            try { await Task.Delay(SyncInterval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task SyncOnceAsync(CancellationToken cancellationToken)
    {
        using var scope = _serviceProvider.CreateScope();
        var tenantRegistry = scope.ServiceProvider.GetRequiredService<ITenantRegistry>();
        var ingestion = scope.ServiceProvider.GetRequiredService<IIocIngestionService>();
        var sources = scope.ServiceProvider.GetServices<IIocFeedSource>().ToList();
        var iocRepo = scope.ServiceProvider.GetRequiredService<IIocRepository>();
        var settings = scope.ServiceProvider.GetRequiredService<IThreatIntelSettingsRepository>();

        if (sources.Count == 0) return;

        IReadOnlyCollection<TenantSummary> tenants;
        try { tenants = await tenantRegistry.GetTenantsAsync(cancellationToken); }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not enumerate tenants for IOC feed sync");
            return;
        }

        foreach (var tenant in tenants)
        {
            if (cancellationToken.IsCancellationRequested) return;
            if (!tenant.IsActive) continue;
            ThreatIntelSettings tenantSettings;
            try { tenantSettings = await settings.GetOrCreateAsync(tenant.TenantKey, cancellationToken); }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not load threat intel settings for {Tenant}", tenant.TenantKey);
                continue;
            }

            foreach (var source in sources)
            {
                var providerCfg = tenantSettings.Providers.FirstOrDefault(p => string.Equals(p.Provider, source.Provider, StringComparison.OrdinalIgnoreCase));
                if (providerCfg is null || !providerCfg.Enabled) continue;
                try
                {
                    await ingestion.SyncProviderAsync(source.Provider, tenant.TenantKey, cancellationToken);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Sync failed for {Provider}/{Tenant}", source.Provider, tenant.TenantKey);
                }
            }
        }

        try { await iocRepo.ExpireOldAsync(cancellationToken); }
        catch (Exception ex) { _logger.LogWarning(ex, "ExpireOldAsync failed"); }
    }
}
