using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.Reputation;

/// <summary>
/// Deterministic offline-friendly provider used for tests, demos, and as
/// a baseline so the orchestrator always has at least one available
/// provider. Verdict is derived from the indicator value so behavior is
/// reproducible across runs.
/// </summary>
public sealed class MockReputationProvider : IReputationProvider
{
    public string Name => "mock";

    public IReadOnlySet<ReputationLookupType> SupportedLookupTypes { get; } = new HashSet<ReputationLookupType>
    {
        ReputationLookupType.Sha256,
        ReputationLookupType.Sha1,
        ReputationLookupType.Md5,
        ReputationLookupType.Ip,
        ReputationLookupType.Domain,
        ReputationLookupType.Url
    };

    public Task<bool> IsAvailableAsync(string tenantKey, CancellationToken cancellationToken = default) => Task.FromResult(true);

    public Task<ProviderVerdict> LookupAsync(ReputationLookupRequest request, CancellationToken cancellationToken = default)
    {
        var normalized = IndicatorNormalization.Normalize(request.LookupType, request.Value);
        var (verdict, confidence, reason) = Classify(normalized);

        return Task.FromResult(new ProviderVerdict
        {
            Provider = Name,
            Verdict = verdict,
            Confidence = confidence,
            ReasonCodes = new[] { reason },
            EvidenceSummary = $"mock {request.LookupType} {verdict}",
            Evidence = Array.Empty<ProviderEvidence>(),
            FromCache = false,
            TimedOut = false,
            RateLimited = false,
            LatencyMs = 1
        });
    }

    /// <summary>Deterministic mock classification. Documented values let tests assert specific verdicts.</summary>
    private static (ReputationVerdict verdict, decimal confidence, string reason) Classify(string normalized)
    {
        if (string.IsNullOrEmpty(normalized)) return (ReputationVerdict.Unknown, 0m, "mock-empty");
        if (normalized.Contains("malicious", StringComparison.OrdinalIgnoreCase)) return (ReputationVerdict.Malicious, 0.95m, "mock-name-malicious");
        if (normalized.Contains("suspicious", StringComparison.OrdinalIgnoreCase)) return (ReputationVerdict.Suspicious, 0.7m, "mock-name-suspicious");
        if (normalized.EndsWith("bad", StringComparison.OrdinalIgnoreCase)) return (ReputationVerdict.Malicious, 0.9m, "mock-suffix-bad");
        if (normalized.EndsWith("clean", StringComparison.OrdinalIgnoreCase)) return (ReputationVerdict.Clean, 0.85m, "mock-suffix-clean");
        if (normalized.StartsWith("000")) return (ReputationVerdict.Clean, 0.6m, "mock-prefix-clean");
        return (ReputationVerdict.Unknown, 0m, "mock-no-signal");
    }
}
