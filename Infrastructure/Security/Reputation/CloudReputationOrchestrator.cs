using System.Diagnostics;
using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.Reputation;

/// <summary>
/// Hot-path orchestrator. Order: (1) local IOC pre-check synchronous,
/// (2) cache lookup synchronous, (3) bounded best-effort cloud fan-out
/// to all enabled-and-supporting providers in parallel.
///
/// Combiner rules:
///  - Local IOC hit short-circuits to Malicious.
///  - Provider results with verdict=Unknown OR TimedOut OR RateLimited
///    are EXCLUDED from scoring (do not dilute strong signals).
///  - If any provider with TrustWeight >= 0.7 returns Malicious with
///    confidence >= 0.8, aggregate is promoted to Malicious.
///  - Otherwise weighted score over remaining providers determines
///    aggregate.
///  - Per-provider results are preserved in <see cref="ReputationLookupResult.ProviderResults"/>.
///
/// Phase 3 scope: cloud results are advisory only — they enrich downstream
/// detections but never act as the sole blocking authority.
/// </summary>
public sealed class CloudReputationOrchestrator : IReputationOrchestrator
{
    private readonly IReadOnlyList<IReputationProvider> _providers;
    private readonly IReputationCache _cache;
    private readonly IIocMatcher _iocMatcher;
    private readonly IThreatIntelSettingsRepository _settingsRepository;
    private readonly IProviderHealthRepository _healthRepository;
    private readonly IReputationLookupAuditRepository _auditRepository;
    private readonly ILogger<CloudReputationOrchestrator> _logger;

    public CloudReputationOrchestrator(
        IEnumerable<IReputationProvider> providers,
        IReputationCache cache,
        IIocMatcher iocMatcher,
        IThreatIntelSettingsRepository settingsRepository,
        IProviderHealthRepository healthRepository,
        IReputationLookupAuditRepository auditRepository,
        ILogger<CloudReputationOrchestrator> logger)
    {
        _providers = providers.ToList();
        _cache = cache;
        _iocMatcher = iocMatcher;
        _settingsRepository = settingsRepository;
        _healthRepository = healthRepository;
        _auditRepository = auditRepository;
        _logger = logger;
    }

    public async Task<ReputationLookupResult> EvaluateAsync(ReputationLookupRequest request, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        var normalized = IndicatorNormalization.Normalize(request.LookupType, request.Value);
        var settings = await _settingsRepository.GetOrCreateAsync(request.TenantKey, cancellationToken);

        // 1. Local IOC pre-check (synchronous in the hot path).
        var iocType = ToIocType(request.LookupType);
        IocIndicatorMatch? iocMatch = iocType is null
            ? null
            : await _iocMatcher.MatchAsync(request.TenantKey, iocType.Value, normalized, cancellationToken);

        if (iocMatch is not null)
        {
            var iocResult = new ReputationLookupResult
            {
                AggregateVerdict = ReputationVerdict.Malicious,
                AggregateConfidence = iocMatch.Confidence,
                ProviderResults = Array.Empty<ProviderVerdict>(),
                LocalIocMatch = iocMatch,
                CacheStatus = ReputationCacheStatus.Bypassed,
                DurationMs = (int)sw.ElapsedMilliseconds
            };
            await RecordAuditAsync(request, iocResult, providersAttempted: "local-ioc", cancellationToken);
            return iocResult;
        }

        // 2 + 3. Per-provider cache check + cloud fan-out.
        var enabledProviders = _providers
            .Where(p => p.SupportedLookupTypes.Contains(request.LookupType))
            .Select(p => (Provider: p, Settings: settings.Providers.FirstOrDefault(s => string.Equals(s.Provider, p.Name, StringComparison.OrdinalIgnoreCase))))
            .Where(t => t.Settings is { Enabled: true })
            .ToList();

        if (enabledProviders.Count == 0)
        {
            var emptyResult = new ReputationLookupResult
            {
                AggregateVerdict = ReputationVerdict.Unknown,
                AggregateConfidence = 0m,
                ProviderResults = Array.Empty<ProviderVerdict>(),
                CacheStatus = ReputationCacheStatus.Miss,
                DurationMs = (int)sw.ElapsedMilliseconds,
                FailureReason = "no-enabled-providers"
            };
            await RecordAuditAsync(request, emptyResult, providersAttempted: string.Empty, cancellationToken);
            return emptyResult;
        }

        if (!settings.CloudReputationEnabled || !request.AllowCloud)
        {
            // Settings disable cloud altogether: still query cache (free), skip live calls.
            var cacheOnlyVerdicts = new List<ProviderVerdict>();
            foreach (var (provider, _) in enabledProviders)
            {
                var hit = await _cache.TryGetAsync(request.TenantKey, provider.Name, request.LookupType, normalized, cancellationToken);
                if (hit is not null) cacheOnlyVerdicts.Add(hit);
            }
            var cacheOnlyAgg = Combine(cacheOnlyVerdicts, settings);
            var cacheOnlyResult = new ReputationLookupResult
            {
                AggregateVerdict = cacheOnlyAgg.verdict,
                AggregateConfidence = cacheOnlyAgg.confidence,
                ProviderResults = cacheOnlyVerdicts,
                CacheStatus = cacheOnlyVerdicts.Count > 0 ? ReputationCacheStatus.Hit : ReputationCacheStatus.Miss,
                DurationMs = (int)sw.ElapsedMilliseconds,
                FailureReason = "cloud-disabled"
            };
            await RecordAuditAsync(request, cacheOnlyResult, providersAttempted: string.Join(',', enabledProviders.Select(p => p.Provider.Name)), cancellationToken);
            return cacheOnlyResult;
        }

        var ttl = TtlFor(request.LookupType, settings);
        var negativeTtl = TimeSpan.FromSeconds(settings.Ttl.NegativeTtlSeconds);
        var providerResults = new List<ProviderVerdict>(enabledProviders.Count);
        var anyCacheHit = false;
        var allCacheHit = true;

        // First pass: synchronous cache lookups.
        var liveCallTargets = new List<IReputationProvider>();
        foreach (var (provider, _) in enabledProviders)
        {
            var cached = await _cache.TryGetAsync(request.TenantKey, provider.Name, request.LookupType, normalized, cancellationToken);
            if (cached is not null)
            {
                providerResults.Add(cached);
                anyCacheHit = true;
            }
            else
            {
                allCacheHit = false;
                liveCallTargets.Add(provider);
            }
        }

        // Second pass: bounded cloud fan-out for cache misses.
        if (liveCallTargets.Count > 0)
        {
            using var fanoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            fanoutCts.CancelAfter(TimeSpan.FromMilliseconds(Math.Max(250, settings.CloudFanoutTimeoutMs)));
            var tasks = liveCallTargets.Select(p => InvokeProviderSafelyAsync(p, request, fanoutCts.Token)).ToArray();
            try { await Task.WhenAll(tasks); }
            catch { /* per-task already swallowed in InvokeProviderSafelyAsync */ }

            for (int i = 0; i < liveCallTargets.Count; i++)
            {
                var verdict = tasks[i].IsCompletedSuccessfully ? tasks[i].Result : Timeout(liveCallTargets[i].Name);
                providerResults.Add(verdict);

                // Cache only "real" (non-timeout, non-rate-limit) responses, with shorter TTL on Unknown.
                if (!verdict.TimedOut && !verdict.RateLimited)
                {
                    var effectiveTtl = verdict.Verdict == ReputationVerdict.Unknown ? negativeTtl : ttl;
                    await _cache.SetAsync(request.TenantKey, verdict.Provider, request.LookupType, normalized, verdict, effectiveTtl, cancellationToken);
                }

                await RecordHealthAsync(request.TenantKey, verdict, settings, cancellationToken);
            }
        }

        var (aggVerdict, aggConfidence) = Combine(providerResults, settings);
        var result = new ReputationLookupResult
        {
            AggregateVerdict = aggVerdict,
            AggregateConfidence = aggConfidence,
            ProviderResults = providerResults,
            CacheStatus = allCacheHit && anyCacheHit ? ReputationCacheStatus.Hit
                          : anyCacheHit ? ReputationCacheStatus.Hit
                          : ReputationCacheStatus.Miss,
            DurationMs = (int)sw.ElapsedMilliseconds
        };

        await RecordAuditAsync(request, result, providersAttempted: string.Join(',', enabledProviders.Select(p => p.Provider.Name)), cancellationToken);
        return result;
    }

    public async Task<IReadOnlyList<ProviderHealth>> GetProviderHealthAsync(string tenantKey, CancellationToken cancellationToken = default)
    {
        var stored = await _healthRepository.ListAsync(tenantKey, cancellationToken);
        var byName = stored.ToDictionary(h => h.Provider, StringComparer.OrdinalIgnoreCase);
        var settings = await _settingsRepository.GetOrCreateAsync(tenantKey, cancellationToken);
        var result = new List<ProviderHealth>(_providers.Count);
        foreach (var provider in _providers)
        {
            var s = settings.Providers.FirstOrDefault(p => string.Equals(p.Provider, provider.Name, StringComparison.OrdinalIgnoreCase));
            if (byName.TryGetValue(provider.Name, out var health))
            {
                result.Add(new ProviderHealth
                {
                    Provider = provider.Name,
                    Enabled = s?.Enabled ?? false,
                    LastSuccessAt = health.LastSuccessAt,
                    LastFailureAt = health.LastFailureAt,
                    LastFailureReason = health.LastFailureReason,
                    CircuitState = health.CircuitState,
                    RateLimitTokensRemaining = health.RateLimitTokensRemaining,
                    LastSyncDurationMs = health.LastSyncDurationMs,
                    LastSyncCount = health.LastSyncCount,
                    LastSyncAt = health.LastSyncAt
                });
            }
            else
            {
                result.Add(new ProviderHealth
                {
                    Provider = provider.Name,
                    Enabled = s?.Enabled ?? false,
                    CircuitState = ProviderCircuitState.Closed
                });
            }
        }
        return result;
    }

    private async Task<ProviderVerdict> InvokeProviderSafelyAsync(IReputationProvider provider, ReputationLookupRequest request, CancellationToken token)
    {
        try
        {
            return await provider.LookupAsync(request, token);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            return Timeout(provider.Name);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Provider {Provider} threw during lookup", provider.Name);
            return new ProviderVerdict
            {
                Provider = provider.Name,
                Verdict = ReputationVerdict.Unknown,
                Confidence = 0m,
                ReasonCodes = new[] { "provider-exception" },
                EvidenceSummary = ex.GetType().Name
            };
        }
    }

    private static ProviderVerdict Timeout(string provider) => new()
    {
        Provider = provider,
        Verdict = ReputationVerdict.Unknown,
        Confidence = 0m,
        ReasonCodes = new[] { "fanout-timeout" },
        EvidenceSummary = "Cloud fanout timeout exceeded",
        TimedOut = true
    };

    /// <summary>
    /// Verdict combiner. Excludes Unknown/timeout/rate-limited from scoring.
    /// Strong-malicious override: any trusted provider (>=0.7 weight) reporting
    /// Malicious with confidence >=0.8 promotes the aggregate to Malicious.
    /// </summary>
    internal static (ReputationVerdict verdict, decimal confidence) Combine(IReadOnlyList<ProviderVerdict> results, ThreatIntelSettings settings)
    {
        var scoring = results
            .Where(r => !r.TimedOut && !r.RateLimited && r.Verdict != ReputationVerdict.Unknown)
            .ToList();

        if (scoring.Count == 0) return (ReputationVerdict.Unknown, 0m);

        // Strong-malicious override.
        foreach (var r in scoring)
        {
            var trust = settings.Providers.FirstOrDefault(p => string.Equals(p.Provider, r.Provider, StringComparison.OrdinalIgnoreCase))?.TrustWeight ?? 0.5m;
            if (r.Verdict == ReputationVerdict.Malicious && r.Confidence >= 0.8m && trust >= 0.7m)
            {
                return (ReputationVerdict.Malicious, Math.Max(r.Confidence, 0.85m));
            }
        }

        decimal scoreSum = 0m, weightSum = 0m;
        foreach (var r in scoring)
        {
            var trust = settings.Providers.FirstOrDefault(p => string.Equals(p.Provider, r.Provider, StringComparison.OrdinalIgnoreCase))?.TrustWeight ?? 0.5m;
            if (trust <= 0m) continue; // mock provider has 0 trust by default
            var verdictScore = r.Verdict switch
            {
                ReputationVerdict.Malicious => 1m,
                ReputationVerdict.Suspicious => 0.6m,
                ReputationVerdict.Clean => 0m,
                _ => 0m
            };
            var weight = trust * r.Confidence;
            scoreSum += verdictScore * weight;
            weightSum += weight;
        }

        if (weightSum <= 0m) return (ReputationVerdict.Unknown, 0m);
        var avg = scoreSum / weightSum;
        var aggVerdict = avg switch
        {
            >= 0.7m => ReputationVerdict.Malicious,
            >= 0.4m => ReputationVerdict.Suspicious,
            > 0m => ReputationVerdict.Clean,
            _ => ReputationVerdict.Clean
        };
        return (aggVerdict, weightSum > 0m ? Math.Min(0.99m, weightSum / scoring.Count) : 0m);
    }

    private static IocType? ToIocType(ReputationLookupType type) => type switch
    {
        ReputationLookupType.Sha256 => IocType.Sha256,
        ReputationLookupType.Sha1 => IocType.Sha1,
        ReputationLookupType.Md5 => IocType.Md5,
        ReputationLookupType.Ip => IocType.Ip,
        ReputationLookupType.Domain => IocType.Domain,
        ReputationLookupType.Url => IocType.Url,
        _ => null
    };

    private static TimeSpan TtlFor(ReputationLookupType type, ThreatIntelSettings settings) => type switch
    {
        ReputationLookupType.Sha256 or ReputationLookupType.Sha1 or ReputationLookupType.Md5
            => TimeSpan.FromSeconds(settings.Ttl.HashTtlSeconds),
        ReputationLookupType.Url => TimeSpan.FromSeconds(settings.Ttl.UrlTtlSeconds),
        ReputationLookupType.Ip => TimeSpan.FromSeconds(settings.Ttl.IpTtlSeconds),
        ReputationLookupType.Domain => TimeSpan.FromSeconds(settings.Ttl.DomainTtlSeconds),
        _ => TimeSpan.FromMinutes(10)
    };

    private async Task RecordAuditAsync(ReputationLookupRequest request, ReputationLookupResult result, string providersAttempted, CancellationToken cancellationToken)
    {
        await _auditRepository.RecordAsync(new ReputationLookupAuditEntry
        {
            TenantKey = request.TenantKey,
            CallerUser = request.RequestedBy,
            LookupType = request.LookupType,
            RedactedValue = IndicatorNormalization.RedactForAudit(request.LookupType, request.Value),
            ProvidersAttempted = providersAttempted,
            CacheHit = result.CacheStatus == ReputationCacheStatus.Hit,
            LocalIocHit = result.LocalIocMatch is not null,
            LatencyMs = result.DurationMs,
            FinalVerdict = result.AggregateVerdict,
            FailureReason = result.FailureReason,
            CorrelationId = request.CorrelationId
        }, cancellationToken);
    }

    private async Task RecordHealthAsync(string tenantKey, ProviderVerdict verdict, ThreatIntelSettings settings, CancellationToken cancellationToken)
    {
        var providerCfg = settings.Providers.FirstOrDefault(p => string.Equals(p.Provider, verdict.Provider, StringComparison.OrdinalIgnoreCase));
        var health = new ProviderHealth
        {
            Provider = verdict.Provider,
            Enabled = providerCfg?.Enabled ?? false,
            LastSuccessAt = verdict.TimedOut || verdict.RateLimited ? null : DateTimeOffset.UtcNow,
            LastFailureAt = verdict.TimedOut || verdict.RateLimited ? DateTimeOffset.UtcNow : null,
            LastFailureReason = verdict.TimedOut ? "timeout" : verdict.RateLimited ? "rate-limited" : null,
            CircuitState = ProviderCircuitState.Closed,
            RateLimitTokensRemaining = providerCfg?.RateLimitPerMinute ?? 0
        };
        await _healthRepository.UpsertAsync(health, tenantKey, cancellationToken);
    }
}
