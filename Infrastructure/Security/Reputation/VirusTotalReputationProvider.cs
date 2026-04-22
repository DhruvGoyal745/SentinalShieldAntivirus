using System.Diagnostics;
using System.Net;
using System.Text.Json;
using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.Reputation;

/// <summary>
/// VirusTotal v3 reputation provider. Uses the per-tenant API key from
/// the secrets vault. Returns Unknown when the API key is missing so the
/// orchestrator can drop the provider from this lookup without failing.
/// Honors the orchestrator-level timeout via the passed cancellation token.
/// </summary>
public sealed class VirusTotalReputationProvider : IReputationProvider
{
    private const string SecretKey = "api-key";
    private const string BaseUrl = "https://www.virustotal.com/api/v3/";

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ISecretsVault _secretsVault;
    private readonly ILogger<VirusTotalReputationProvider> _logger;

    public VirusTotalReputationProvider(IHttpClientFactory httpClientFactory, ISecretsVault secretsVault, ILogger<VirusTotalReputationProvider> logger)
    {
        _httpClientFactory = httpClientFactory;
        _secretsVault = secretsVault;
        _logger = logger;
    }

    public string Name => "virustotal";

    public IReadOnlySet<ReputationLookupType> SupportedLookupTypes { get; } = new HashSet<ReputationLookupType>
    {
        ReputationLookupType.Sha256,
        ReputationLookupType.Sha1,
        ReputationLookupType.Md5,
        ReputationLookupType.Domain,
        ReputationLookupType.Ip,
        ReputationLookupType.Url
    };

    public async Task<bool> IsAvailableAsync(string tenantKey, CancellationToken cancellationToken = default)
    {
        var key = await _secretsVault.GetSecretAsync(tenantKey, Name, SecretKey, cancellationToken);
        return !string.IsNullOrWhiteSpace(key);
    }

    public async Task<ProviderVerdict> LookupAsync(ReputationLookupRequest request, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var apiKey = await _secretsVault.GetSecretAsync(request.TenantKey, Name, SecretKey, cancellationToken);
            if (string.IsNullOrWhiteSpace(apiKey))
            {
                return Unknown(sw, "vt-no-api-key");
            }

            var endpoint = BuildEndpoint(request.LookupType, request.Value);
            if (endpoint is null) return Unknown(sw, "vt-unsupported-type");

            using var client = _httpClientFactory.CreateClient("virustotal");
            client.BaseAddress ??= new Uri(BaseUrl);
            client.DefaultRequestHeaders.Remove("x-apikey");
            client.DefaultRequestHeaders.Add("x-apikey", apiKey);

            using var response = await client.GetAsync(endpoint, cancellationToken);
            if (response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                return new ProviderVerdict
                {
                    Provider = Name,
                    Verdict = ReputationVerdict.Unknown,
                    Confidence = 0m,
                    ReasonCodes = new[] { "vt-rate-limited" },
                    EvidenceSummary = "Rate limited by VirusTotal",
                    RateLimited = true,
                    LatencyMs = (int)sw.ElapsedMilliseconds
                };
            }
            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                return new ProviderVerdict
                {
                    Provider = Name,
                    Verdict = ReputationVerdict.Unknown,
                    Confidence = 0m,
                    ReasonCodes = new[] { "vt-not-found" },
                    EvidenceSummary = "Indicator unknown to VirusTotal",
                    LatencyMs = (int)sw.ElapsedMilliseconds
                };
            }
            response.EnsureSuccessStatusCode();

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            return ParseAnalysis(doc, sw);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return new ProviderVerdict
            {
                Provider = Name,
                Verdict = ReputationVerdict.Unknown,
                Confidence = 0m,
                ReasonCodes = new[] { "vt-timeout" },
                EvidenceSummary = "VirusTotal timed out",
                TimedOut = true,
                LatencyMs = (int)sw.ElapsedMilliseconds
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "VirusTotal lookup failed for {Type}", request.LookupType);
            return new ProviderVerdict
            {
                Provider = Name,
                Verdict = ReputationVerdict.Unknown,
                Confidence = 0m,
                ReasonCodes = new[] { "vt-error" },
                EvidenceSummary = "VirusTotal error: " + ex.GetType().Name,
                LatencyMs = (int)sw.ElapsedMilliseconds
            };
        }
    }

    private static string? BuildEndpoint(ReputationLookupType type, string value)
    {
        var normalized = IndicatorNormalization.Normalize(type, value);
        return type switch
        {
            ReputationLookupType.Sha256 or ReputationLookupType.Sha1 or ReputationLookupType.Md5
                => "files/" + Uri.EscapeDataString(normalized),
            ReputationLookupType.Domain => "domains/" + Uri.EscapeDataString(normalized),
            ReputationLookupType.Ip => "ip_addresses/" + Uri.EscapeDataString(normalized),
            ReputationLookupType.Url => "urls/" + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(normalized))
                                                 .TrimEnd('=').Replace('+', '-').Replace('/', '_'),
            _ => null
        };
    }

    private static ProviderVerdict ParseAnalysis(JsonDocument doc, Stopwatch sw)
    {
        // Pull last_analysis_stats { malicious, suspicious, undetected, harmless, timeout }
        var stats = doc.RootElement.GetProperty("data").GetProperty("attributes").TryGetProperty("last_analysis_stats", out var statsEl)
            ? statsEl
            : default;
        int malicious = 0, suspicious = 0, harmless = 0, undetected = 0;
        if (stats.ValueKind == JsonValueKind.Object)
        {
            if (stats.TryGetProperty("malicious", out var m)) malicious = m.GetInt32();
            if (stats.TryGetProperty("suspicious", out var s)) suspicious = s.GetInt32();
            if (stats.TryGetProperty("harmless", out var h)) harmless = h.GetInt32();
            if (stats.TryGetProperty("undetected", out var u)) undetected = u.GetInt32();
        }
        var total = malicious + suspicious + harmless + undetected;
        ReputationVerdict verdict;
        decimal confidence;
        if (malicious >= 3) { verdict = ReputationVerdict.Malicious; confidence = Math.Min(0.99m, 0.6m + (decimal)malicious / 100m); }
        else if (malicious >= 1 || suspicious >= 2) { verdict = ReputationVerdict.Suspicious; confidence = 0.6m; }
        else if (harmless >= 5 && malicious == 0 && suspicious == 0) { verdict = ReputationVerdict.Clean; confidence = 0.7m; }
        else { verdict = ReputationVerdict.Unknown; confidence = 0m; }

        return new ProviderVerdict
        {
            Provider = "virustotal",
            Verdict = verdict,
            Confidence = confidence,
            ReasonCodes = new[] { $"vt-stats-{malicious}-{suspicious}-{harmless}-{undetected}" },
            EvidenceSummary = $"VT engines: {malicious} malicious, {suspicious} suspicious, {harmless} clean, {undetected} undetected (total {total})",
            Evidence = new[]
            {
                new ProviderEvidence { Key = "malicious", Value = malicious.ToString() },
                new ProviderEvidence { Key = "suspicious", Value = suspicious.ToString() },
                new ProviderEvidence { Key = "harmless", Value = harmless.ToString() },
                new ProviderEvidence { Key = "undetected", Value = undetected.ToString() }
            },
            LatencyMs = (int)sw.ElapsedMilliseconds
        };
    }

    private ProviderVerdict Unknown(Stopwatch sw, string reason) => new()
    {
        Provider = Name,
        Verdict = ReputationVerdict.Unknown,
        Confidence = 0m,
        ReasonCodes = new[] { reason },
        EvidenceSummary = "VirusTotal returned no signal",
        LatencyMs = (int)sw.ElapsedMilliseconds
    };
}
