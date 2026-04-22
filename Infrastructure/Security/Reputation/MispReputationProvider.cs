using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.Reputation;

/// <summary>
/// MISP threat-sharing platform reputation provider. Uses /attributes/restSearch
/// to look up an indicator value across the configured tenant MISP instance.
/// Requires both <c>base-url</c> and <c>api-key</c> secrets per tenant; absent
/// either drops the provider from the lookup.
/// </summary>
public sealed class MispReputationProvider : IReputationProvider
{
    private const string ApiKeySecret = "api-key";
    private const string BaseUrlSecret = "base-url";

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ISecretsVault _secretsVault;
    private readonly ILogger<MispReputationProvider> _logger;

    public MispReputationProvider(IHttpClientFactory httpClientFactory, ISecretsVault secretsVault, ILogger<MispReputationProvider> logger)
    {
        _httpClientFactory = httpClientFactory;
        _secretsVault = secretsVault;
        _logger = logger;
    }

    public string Name => "misp";

    public IReadOnlySet<ReputationLookupType> SupportedLookupTypes { get; } = new HashSet<ReputationLookupType>
    {
        ReputationLookupType.Sha256, ReputationLookupType.Sha1, ReputationLookupType.Md5,
        ReputationLookupType.Ip, ReputationLookupType.Domain, ReputationLookupType.Url
    };

    public async Task<bool> IsAvailableAsync(string tenantKey, CancellationToken cancellationToken = default)
    {
        var key = await _secretsVault.GetSecretAsync(tenantKey, Name, ApiKeySecret, cancellationToken);
        var url = await _secretsVault.GetSecretAsync(tenantKey, Name, BaseUrlSecret, cancellationToken);
        return !string.IsNullOrWhiteSpace(key) && !string.IsNullOrWhiteSpace(url);
    }

    public async Task<ProviderVerdict> LookupAsync(ReputationLookupRequest request, CancellationToken cancellationToken = default)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var apiKey = await _secretsVault.GetSecretAsync(request.TenantKey, Name, ApiKeySecret, cancellationToken);
            var baseUrl = await _secretsVault.GetSecretAsync(request.TenantKey, Name, BaseUrlSecret, cancellationToken);
            if (string.IsNullOrWhiteSpace(apiKey) || string.IsNullOrWhiteSpace(baseUrl))
                return Unknown(sw, "misp-not-configured");

            var normalized = IndicatorNormalization.Normalize(request.LookupType, request.Value);
            using var client = _httpClientFactory.CreateClient("misp");
            client.BaseAddress = new Uri(baseUrl.TrimEnd('/') + "/");
            client.DefaultRequestHeaders.Authorization = null;
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            client.DefaultRequestHeaders.Remove("Authorization");
            client.DefaultRequestHeaders.Add("Authorization", apiKey);

            // POST /attributes/restSearch with type filter + value match.
            var body = JsonSerializer.Serialize(new
            {
                returnFormat = "json",
                value = normalized,
                type = MapType(request.LookupType),
                limit = 50,
                to_ids = 1
            });
            using var content = new StringContent(body, Encoding.UTF8, "application/json");
            using var response = await client.PostAsync("attributes/restSearch", content, cancellationToken);
            if (response.StatusCode == HttpStatusCode.TooManyRequests) return RateLimited(sw);
            response.EnsureSuccessStatusCode();

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
            return Parse(doc, sw);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { return Timeout(sw); }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "MISP lookup failed");
            return new ProviderVerdict
            {
                Provider = Name, Verdict = ReputationVerdict.Unknown, Confidence = 0m,
                ReasonCodes = new[] { "misp-error" }, EvidenceSummary = "MISP error: " + ex.GetType().Name,
                LatencyMs = (int)sw.ElapsedMilliseconds
            };
        }
    }

    private ProviderVerdict Parse(JsonDocument doc, Stopwatch sw)
    {
        // Response: { "response": { "Attribute": [ { ..., "Event": { "threat_level_id": "1", ... } } ] } }
        if (!doc.RootElement.TryGetProperty("response", out var responseEl)) return Unknown(sw, "misp-no-response");
        var attrs = responseEl.TryGetProperty("Attribute", out var ae) && ae.ValueKind == JsonValueKind.Array
            ? ae
            : default;
        if (attrs.ValueKind != JsonValueKind.Array || attrs.GetArrayLength() == 0)
            return Unknown(sw, "misp-no-hits");

        // MISP threat_level_id: 1=High, 2=Medium, 3=Low, 4=Undefined
        int hits = 0, high = 0, medium = 0;
        foreach (var attr in attrs.EnumerateArray())
        {
            hits++;
            if (attr.TryGetProperty("Event", out var evt) && evt.TryGetProperty("threat_level_id", out var tl))
            {
                var level = tl.GetString();
                if (level == "1") high++;
                else if (level == "2") medium++;
            }
        }

        ReputationVerdict verdict;
        decimal confidence;
        if (high > 0) { verdict = ReputationVerdict.Malicious; confidence = Math.Min(0.95m, 0.75m + high * 0.05m); }
        else if (medium > 0) { verdict = ReputationVerdict.Suspicious; confidence = 0.7m; }
        else { verdict = ReputationVerdict.Suspicious; confidence = 0.55m; }

        return new ProviderVerdict
        {
            Provider = Name,
            Verdict = verdict,
            Confidence = confidence,
            ReasonCodes = new[] { $"misp-hits-{hits}-high{high}-med{medium}" },
            EvidenceSummary = $"MISP: {hits} attribute hits ({high} high-threat events, {medium} medium)",
            Evidence = new[]
            {
                new ProviderEvidence { Key = "hits", Value = hits.ToString() },
                new ProviderEvidence { Key = "high_threat", Value = high.ToString() },
                new ProviderEvidence { Key = "medium_threat", Value = medium.ToString() }
            },
            LatencyMs = (int)sw.ElapsedMilliseconds
        };
    }

    private static string MapType(ReputationLookupType type) => type switch
    {
        ReputationLookupType.Sha256 => "sha256",
        ReputationLookupType.Sha1 => "sha1",
        ReputationLookupType.Md5 => "md5",
        ReputationLookupType.Ip => "ip-dst",
        ReputationLookupType.Domain => "domain",
        ReputationLookupType.Url => "url",
        _ => string.Empty
    };

    private ProviderVerdict Unknown(Stopwatch sw, string reason) => new()
    {
        Provider = Name, Verdict = ReputationVerdict.Unknown, Confidence = 0m,
        ReasonCodes = new[] { reason }, EvidenceSummary = "MISP returned no signal",
        LatencyMs = (int)sw.ElapsedMilliseconds
    };
    private ProviderVerdict Timeout(Stopwatch sw) => new()
    {
        Provider = Name, Verdict = ReputationVerdict.Unknown, Confidence = 0m,
        ReasonCodes = new[] { "misp-timeout" }, EvidenceSummary = "MISP timed out", TimedOut = true,
        LatencyMs = (int)sw.ElapsedMilliseconds
    };
    private ProviderVerdict RateLimited(Stopwatch sw) => new()
    {
        Provider = Name, Verdict = ReputationVerdict.Unknown, Confidence = 0m,
        ReasonCodes = new[] { "misp-rate-limited" }, EvidenceSummary = "Rate limited by MISP", RateLimited = true,
        LatencyMs = (int)sw.ElapsedMilliseconds
    };
}
