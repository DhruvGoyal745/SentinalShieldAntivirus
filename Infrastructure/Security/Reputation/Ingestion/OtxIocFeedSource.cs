using System.Text.Json;
using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.Reputation.Ingestion;

/// <summary>
/// Pulls subscribed pulses from AlienVault OTX. Cursor is an ISO-8601
/// timestamp ("modified_since"). Each pulse fans out into multiple
/// indicators. Translation table:
///   FileHash-SHA256 → IocType.Sha256
///   FileHash-SHA1   → IocType.Sha1
///   FileHash-MD5    → IocType.Md5
///   IPv4            → IocType.Ip
///   domain/hostname → IocType.Domain
///   URL/URI         → IocType.Url
/// All other indicator types are skipped.
/// </summary>
public sealed class OtxIocFeedSource : IIocFeedSource
{
    private const string SecretKey = "api-key";
    private const string BaseUrl = "https://otx.alienvault.com/api/v1/";

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ISecretsVault _secretsVault;
    private readonly ILogger<OtxIocFeedSource> _logger;

    public OtxIocFeedSource(IHttpClientFactory httpClientFactory, ISecretsVault secretsVault, ILogger<OtxIocFeedSource> logger)
    {
        _httpClientFactory = httpClientFactory;
        _secretsVault = secretsVault;
        _logger = logger;
    }

    public string Provider => "otx";

    public async Task<IocFeedFetchResult> FetchAsync(string tenantKey, string? cursor, int maxItems, CancellationToken cancellationToken)
    {
        try
        {
            var apiKey = await _secretsVault.GetSecretAsync(tenantKey, Provider, SecretKey, cancellationToken);
            if (string.IsNullOrWhiteSpace(apiKey))
                return new IocFeedFetchResult { FailureReason = "otx-no-api-key" };

            using var client = _httpClientFactory.CreateClient("otx");
            client.BaseAddress ??= new Uri(BaseUrl);
            client.DefaultRequestHeaders.Remove("X-OTX-API-KEY");
            client.DefaultRequestHeaders.Add("X-OTX-API-KEY", apiKey);

            var modifiedSince = cursor ?? DateTime.UtcNow.AddDays(-7).ToString("o");
            var url = $"pulses/subscribed?modified_since={Uri.EscapeDataString(modifiedSince)}&limit=50";
            using var response = await client.GetAsync(url, cancellationToken);
            response.EnsureSuccessStatusCode();

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);

            var collected = new List<IocIndicator>(capacity: maxItems);
            string? newestModified = null;
            if (doc.RootElement.TryGetProperty("results", out var pulses) && pulses.ValueKind == JsonValueKind.Array)
            {
                foreach (var pulse in pulses.EnumerateArray())
                {
                    if (pulse.TryGetProperty("modified", out var mod) && mod.ValueKind == JsonValueKind.String)
                    {
                        var modStr = mod.GetString();
                        if (modStr is not null && (newestModified is null || string.Compare(modStr, newestModified, StringComparison.Ordinal) > 0))
                            newestModified = modStr;
                    }
                    var pulseName = pulse.TryGetProperty("name", out var pn) ? pn.GetString() ?? "otx-pulse" : "otx-pulse";
                    var description = pulse.TryGetProperty("description", out var pd) ? pd.GetString() : null;
                    var pulseTags = pulse.TryGetProperty("tags", out var pt) && pt.ValueKind == JsonValueKind.Array
                        ? pt.EnumerateArray().Where(t => t.ValueKind == JsonValueKind.String).Select(t => t.GetString()!).Take(8).ToArray()
                        : Array.Empty<string>();

                    if (!pulse.TryGetProperty("indicators", out var indicatorsEl) || indicatorsEl.ValueKind != JsonValueKind.Array)
                        continue;

                    foreach (var ind in indicatorsEl.EnumerateArray())
                    {
                        if (collected.Count >= maxItems) break;
                        var typeStr = ind.TryGetProperty("type", out var t) ? t.GetString() : null;
                        var valueStr = ind.TryGetProperty("indicator", out var vEl) ? vEl.GetString() : null;
                        if (string.IsNullOrWhiteSpace(typeStr) || string.IsNullOrWhiteSpace(valueStr)) continue;
                        var iocType = MapType(typeStr);
                        if (iocType is null) continue;

                        var normalized = IndicatorNormalization.NormalizeIoc(iocType.Value, valueStr);
                        collected.Add(new IocIndicator
                        {
                            Id = Guid.NewGuid(),
                            TenantKey = tenantKey,
                            Type = iocType.Value,
                            NormalizedValue = normalized,
                            DisplayValue = valueStr,
                            Source = Provider,
                            Severity = ThreatSeverity.High,
                            Confidence = 0.7m,
                            Tags = pulseTags,
                            Description = string.IsNullOrWhiteSpace(description) ? pulseName : pulseName + ": " + description,
                            CreatedAt = DateTimeOffset.UtcNow,
                            ExpiresAt = DateTimeOffset.UtcNow.AddDays(30),
                            IsActive = true
                        });
                    }
                    if (collected.Count >= maxItems) break;
                }
            }

            return new IocFeedFetchResult
            {
                Indicators = collected,
                NextCursor = newestModified ?? cursor
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return new IocFeedFetchResult { FailureReason = "otx-timeout" };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "OTX feed fetch failed");
            return new IocFeedFetchResult { FailureReason = "otx-error: " + ex.GetType().Name };
        }
    }

    private static IocType? MapType(string raw) => raw switch
    {
        "FileHash-SHA256" => IocType.Sha256,
        "FileHash-SHA1" => IocType.Sha1,
        "FileHash-MD5" => IocType.Md5,
        "IPv4" => IocType.Ip,
        "domain" or "hostname" => IocType.Domain,
        "URL" or "URI" => IocType.Url,
        _ => null
    };
}
