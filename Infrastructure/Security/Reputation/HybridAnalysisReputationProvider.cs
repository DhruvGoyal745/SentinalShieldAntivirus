using System.Diagnostics;
using System.Net;
using System.Text.Json;
using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.Reputation;

/// <summary>
/// Hybrid Analysis Falcon Sandbox v2 reputation provider. File-hash search
/// only — Hybrid Analysis does not expose URL/IP/domain reputation in the
/// same shape as VT, so unsupported types resolve to <see cref="ReputationVerdict.Unknown"/>.
/// </summary>
public sealed class HybridAnalysisReputationProvider : IReputationProvider
{
    private const string SecretKey = "api-key";
    private const string BaseUrl = "https://www.hybrid-analysis.com/api/v2/";

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ISecretsVault _secretsVault;
    private readonly ILogger<HybridAnalysisReputationProvider> _logger;

    public HybridAnalysisReputationProvider(IHttpClientFactory httpClientFactory, ISecretsVault secretsVault, ILogger<HybridAnalysisReputationProvider> logger)
    {
        _httpClientFactory = httpClientFactory;
        _secretsVault = secretsVault;
        _logger = logger;
    }

    public string Name => "hybridanalysis";

    public IReadOnlySet<ReputationLookupType> SupportedLookupTypes { get; } = new HashSet<ReputationLookupType>
    {
        ReputationLookupType.Sha256,
        ReputationLookupType.Sha1,
        ReputationLookupType.Md5
    };

    public async Task<bool> IsAvailableAsync(string tenantKey, CancellationToken cancellationToken = default)
        => !string.IsNullOrWhiteSpace(await _secretsVault.GetSecretAsync(tenantKey, Name, SecretKey, cancellationToken));

    public async Task<ProviderVerdict> LookupAsync(ReputationLookupRequest request, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            if (!SupportedLookupTypes.Contains(request.LookupType)) return Unknown(sw, "ha-unsupported-type");

            var apiKey = await _secretsVault.GetSecretAsync(request.TenantKey, Name, SecretKey, cancellationToken);
            if (string.IsNullOrWhiteSpace(apiKey)) return Unknown(sw, "ha-no-api-key");

            var hash = IndicatorNormalization.Normalize(request.LookupType, request.Value);
            using var client = _httpClientFactory.CreateClient("hybridanalysis");
            client.BaseAddress ??= new Uri(BaseUrl);
            client.DefaultRequestHeaders.Remove("api-key");
            client.DefaultRequestHeaders.Add("api-key", apiKey);
            client.DefaultRequestHeaders.Remove("User-Agent");
            client.DefaultRequestHeaders.Add("User-Agent", "Falcon Sandbox");

            using var content = new FormUrlEncodedContent(new Dictionary<string, string> { ["hash"] = hash });
            using var response = await client.PostAsync("search/hash", content, cancellationToken);

            if (response.StatusCode == HttpStatusCode.TooManyRequests) return RateLimited(sw);
            response.EnsureSuccessStatusCode();

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            return Parse(doc, sw);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { return Timeout(sw); }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Hybrid Analysis lookup failed");
            return new ProviderVerdict
            {
                Provider = Name, Verdict = ReputationVerdict.Unknown, Confidence = 0m,
                ReasonCodes = new[] { "ha-error" }, EvidenceSummary = "HA error: " + ex.GetType().Name,
                LatencyMs = (int)sw.ElapsedMilliseconds
            };
        }
    }

    private ProviderVerdict Parse(JsonDocument doc, Stopwatch sw)
    {
        // search/hash returns an array of report summaries.
        if (doc.RootElement.ValueKind != JsonValueKind.Array || doc.RootElement.GetArrayLength() == 0)
            return Unknown(sw, "ha-no-reports");

        int malicious = 0, suspicious = 0, total = 0;
        decimal maxScore = 0m;
        foreach (var report in doc.RootElement.EnumerateArray())
        {
            total++;
            // verdict: "malicious" | "suspicious" | "no specific threat" | "whitelisted"
            var verdict = report.TryGetProperty("verdict", out var v) ? v.GetString() ?? string.Empty : string.Empty;
            if (verdict.Equals("malicious", StringComparison.OrdinalIgnoreCase)) malicious++;
            else if (verdict.Equals("suspicious", StringComparison.OrdinalIgnoreCase)) suspicious++;
            if (report.TryGetProperty("threat_score", out var sc) && sc.ValueKind == JsonValueKind.Number)
            {
                var s = sc.GetDecimal() / 100m;
                if (s > maxScore) maxScore = s;
            }
        }

        ReputationVerdict aggregate;
        decimal confidence;
        if (malicious > 0) { aggregate = ReputationVerdict.Malicious; confidence = Math.Max(0.85m, Math.Min(0.99m, 0.7m + maxScore * 0.3m)); }
        else if (suspicious > 0) { aggregate = ReputationVerdict.Suspicious; confidence = Math.Max(0.6m, maxScore); }
        else if (total > 0) { aggregate = ReputationVerdict.Clean; confidence = 0.65m; }
        else { aggregate = ReputationVerdict.Unknown; confidence = 0m; }

        return new ProviderVerdict
        {
            Provider = Name,
            Verdict = aggregate,
            Confidence = confidence,
            ReasonCodes = new[] { $"ha-reports-{total}-mal{malicious}-sus{suspicious}" },
            EvidenceSummary = $"HA: {total} reports ({malicious} malicious, {suspicious} suspicious), max score {maxScore:F2}",
            Evidence = new[]
            {
                new ProviderEvidence { Key = "reports", Value = total.ToString() },
                new ProviderEvidence { Key = "malicious", Value = malicious.ToString() },
                new ProviderEvidence { Key = "suspicious", Value = suspicious.ToString() },
                new ProviderEvidence { Key = "max_threat_score", Value = maxScore.ToString("F2") }
            },
            LatencyMs = (int)sw.ElapsedMilliseconds
        };
    }

    private ProviderVerdict Unknown(Stopwatch sw, string reason) => new()
    {
        Provider = Name, Verdict = ReputationVerdict.Unknown, Confidence = 0m,
        ReasonCodes = new[] { reason }, EvidenceSummary = "Hybrid Analysis returned no signal",
        LatencyMs = (int)sw.ElapsedMilliseconds
    };
    private ProviderVerdict Timeout(Stopwatch sw) => new()
    {
        Provider = Name, Verdict = ReputationVerdict.Unknown, Confidence = 0m,
        ReasonCodes = new[] { "ha-timeout" }, EvidenceSummary = "HA timed out", TimedOut = true,
        LatencyMs = (int)sw.ElapsedMilliseconds
    };
    private ProviderVerdict RateLimited(Stopwatch sw) => new()
    {
        Provider = Name, Verdict = ReputationVerdict.Unknown, Confidence = 0m,
        ReasonCodes = new[] { "ha-rate-limited" }, EvidenceSummary = "Rate limited by HA", RateLimited = true,
        LatencyMs = (int)sw.ElapsedMilliseconds
    };
}
