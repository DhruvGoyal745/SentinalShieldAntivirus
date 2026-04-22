using System.Diagnostics;
using System.Net;
using System.Text.Json;
using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.Reputation;

/// <summary>
/// AlienVault OTX (Open Threat Exchange) reputation provider. Uses the
/// /api/v1/indicators/{type}/{value}/general endpoint and inspects the
/// pulse_info count. OTX itself does not score severity, so we map pulse
/// counts to verdict heuristics: any pulses → Suspicious, ≥3 pulses with
/// recent activity → Malicious.
/// </summary>
public sealed class OtxReputationProvider : IReputationProvider
{
    private const string SecretKey = "api-key";
    private const string BaseUrl = "https://otx.alienvault.com/api/v1/";

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ISecretsVault _secretsVault;
    private readonly ILogger<OtxReputationProvider> _logger;

    public OtxReputationProvider(IHttpClientFactory httpClientFactory, ISecretsVault secretsVault, ILogger<OtxReputationProvider> logger)
    {
        _httpClientFactory = httpClientFactory;
        _secretsVault = secretsVault;
        _logger = logger;
    }

    public string Name => "otx";

    public IReadOnlySet<ReputationLookupType> SupportedLookupTypes { get; } = new HashSet<ReputationLookupType>
    {
        ReputationLookupType.Sha256, ReputationLookupType.Sha1, ReputationLookupType.Md5,
        ReputationLookupType.Ip, ReputationLookupType.Domain, ReputationLookupType.Url
    };

    public async Task<bool> IsAvailableAsync(string tenantKey, CancellationToken cancellationToken = default)
        => !string.IsNullOrWhiteSpace(await _secretsVault.GetSecretAsync(tenantKey, Name, SecretKey, cancellationToken));

    public async Task<ProviderVerdict> LookupAsync(ReputationLookupRequest request, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var apiKey = await _secretsVault.GetSecretAsync(request.TenantKey, Name, SecretKey, cancellationToken);
            if (string.IsNullOrWhiteSpace(apiKey)) return Unknown(sw, "otx-no-api-key");

            var endpoint = BuildEndpoint(request.LookupType, request.Value);
            if (endpoint is null) return Unknown(sw, "otx-unsupported-type");

            using var client = _httpClientFactory.CreateClient("otx");
            client.BaseAddress ??= new Uri(BaseUrl);
            client.DefaultRequestHeaders.Remove("X-OTX-API-KEY");
            client.DefaultRequestHeaders.Add("X-OTX-API-KEY", apiKey);

            using var response = await client.GetAsync(endpoint, cancellationToken);
            if (response.StatusCode == HttpStatusCode.TooManyRequests) return RateLimited(sw);
            if (response.StatusCode == HttpStatusCode.NotFound) return Unknown(sw, "otx-not-found");
            response.EnsureSuccessStatusCode();

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            return Parse(doc, sw);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { return Timeout(sw); }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "OTX lookup failed");
            return new ProviderVerdict
            {
                Provider = Name, Verdict = ReputationVerdict.Unknown, Confidence = 0m,
                ReasonCodes = new[] { "otx-error" }, EvidenceSummary = "OTX error: " + ex.GetType().Name,
                LatencyMs = (int)sw.ElapsedMilliseconds
            };
        }
    }

    private static string? BuildEndpoint(ReputationLookupType type, string value)
    {
        var normalized = IndicatorNormalization.Normalize(type, value);
        var encoded = Uri.EscapeDataString(normalized);
        return type switch
        {
            ReputationLookupType.Sha256 or ReputationLookupType.Sha1 or ReputationLookupType.Md5 => $"indicators/file/{encoded}/general",
            ReputationLookupType.Ip => $"indicators/IPv4/{encoded}/general",
            ReputationLookupType.Domain => $"indicators/domain/{encoded}/general",
            ReputationLookupType.Url => $"indicators/url/{encoded}/general",
            _ => null
        };
    }

    private ProviderVerdict Parse(JsonDocument doc, Stopwatch sw)
    {
        var root = doc.RootElement;
        int pulseCount = 0;
        var pulseNames = new List<string>();
        if (root.TryGetProperty("pulse_info", out var pi))
        {
            if (pi.TryGetProperty("count", out var c) && c.ValueKind == JsonValueKind.Number)
                pulseCount = c.GetInt32();
            if (pi.TryGetProperty("pulses", out var pulses) && pulses.ValueKind == JsonValueKind.Array)
            {
                foreach (var p in pulses.EnumerateArray().Take(3))
                {
                    if (p.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String)
                        pulseNames.Add(n.GetString() ?? string.Empty);
                }
            }
        }

        ReputationVerdict verdict;
        decimal confidence;
        if (pulseCount >= 3) { verdict = ReputationVerdict.Malicious; confidence = Math.Min(0.92m, 0.65m + pulseCount * 0.02m); }
        else if (pulseCount >= 1) { verdict = ReputationVerdict.Suspicious; confidence = 0.6m; }
        else { verdict = ReputationVerdict.Unknown; confidence = 0m; }

        return new ProviderVerdict
        {
            Provider = Name,
            Verdict = verdict,
            Confidence = confidence,
            ReasonCodes = new[] { $"otx-pulses-{pulseCount}" },
            EvidenceSummary = pulseCount > 0
                ? $"OTX: {pulseCount} pulse(s); top: {string.Join("; ", pulseNames)}"
                : "OTX: no pulses",
            Evidence = new[]
            {
                new ProviderEvidence { Key = "pulses", Value = pulseCount.ToString() },
                new ProviderEvidence { Key = "top_pulses", Value = string.Join("|", pulseNames) }
            },
            LatencyMs = (int)sw.ElapsedMilliseconds
        };
    }

    private ProviderVerdict Unknown(Stopwatch sw, string reason) => new()
    {
        Provider = Name, Verdict = ReputationVerdict.Unknown, Confidence = 0m,
        ReasonCodes = new[] { reason }, EvidenceSummary = "OTX returned no signal",
        LatencyMs = (int)sw.ElapsedMilliseconds
    };
    private ProviderVerdict Timeout(Stopwatch sw) => new()
    {
        Provider = Name, Verdict = ReputationVerdict.Unknown, Confidence = 0m,
        ReasonCodes = new[] { "otx-timeout" }, EvidenceSummary = "OTX timed out", TimedOut = true,
        LatencyMs = (int)sw.ElapsedMilliseconds
    };
    private ProviderVerdict RateLimited(Stopwatch sw) => new()
    {
        Provider = Name, Verdict = ReputationVerdict.Unknown, Confidence = 0m,
        ReasonCodes = new[] { "otx-rate-limited" }, EvidenceSummary = "Rate limited by OTX", RateLimited = true,
        LatencyMs = (int)sw.ElapsedMilliseconds
    };
}
