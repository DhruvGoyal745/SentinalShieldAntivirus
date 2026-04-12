using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;

namespace SentinelShield.Desktop.Services;

internal sealed class DashboardClient : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _httpClient;
    private readonly string _baseUrl;

    public DashboardClient(string baseUrl)
    {
        _baseUrl = baseUrl;
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };
        _httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri(_baseUrl),
            Timeout = TimeSpan.FromSeconds(5)
        };
        _httpClient.DefaultRequestHeaders.Add("X-Tenant-Key", "sentinel-demo");
    }

    public Uri BuildDashboardUri(string page, int? scanId = null)
    {
        var builder = new UriBuilder(_baseUrl)
        {
            Path = "/",
            Query = scanId is int id ? $"scanId={id}" : string.Empty,
            Fragment = page
        };

        return builder.Uri;
    }

    public async Task<bool> WaitForServiceAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        var startedAt = DateTimeOffset.UtcNow;

        while (DateTimeOffset.UtcNow - startedAt < timeout)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                using var response = await _httpClient.GetAsync("api/service/status", cancellationToken);
                if (response.IsSuccessStatusCode)
                {
                    return true;
                }
            }
            catch
            {
                // The local service may still be starting.
            }

            await Task.Delay(TimeSpan.FromMilliseconds(750), cancellationToken);
        }

        return false;
    }

    public async Task<int?> StartCustomScanAsync(string targetPath, CancellationToken cancellationToken)
    {
        var payload = new
        {
            mode = "Custom",
            targetPath,
            requestedBy = "desktop-shell",
            runHeuristics = true
        };

        using var response = await _httpClient.PostAsJsonAsync("api/scans", payload, JsonOptions, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        await using var contentStream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(contentStream, cancellationToken: cancellationToken);
        return document.RootElement.TryGetProperty("id", out var idElement) && idElement.TryGetInt32(out var scanId)
            ? scanId
            : null;
    }

    public void Dispose() => _httpClient.Dispose();
}
