using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SentinelShield.Tray;

public sealed class ServiceApiClient : IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly HttpClient _http;

    public ServiceApiClient(string baseUrl = "http://127.0.0.1:5100")
    {
        _http = new HttpClient
        {
            BaseAddress = new Uri(baseUrl),
            Timeout = TimeSpan.FromSeconds(10)
        };
    }

    public async Task<ServiceStatus?> GetStatusAsync()
    {
        try
        {
            return await _http.GetFromJsonAsync<ServiceStatus>("api/service/status", JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    public async Task<bool> StartQuickScanAsync()
    {
        try
        {
            var response = await _http.PostAsync("api/service/scan/quick", null);
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    public async Task<bool> PauseProtectionAsync(int minutes = 30)
    {
        try
        {
            var response = await _http.PostAsync($"api/service/protection/pause?minutes={minutes}", null);
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    public async Task<bool> ResumeProtectionAsync()
    {
        try
        {
            var response = await _http.PostAsync("api/service/protection/resume", null);
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    public async Task<bool> CheckForUpdatesAsync()
    {
        try
        {
            var response = await _http.PostAsync("api/service/updates/check", null);
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    public void Dispose() => _http.Dispose();

    public sealed class ServiceStatus
    {
        public bool ServiceRunning { get; init; }
        public bool RealtimeProtectionEnabled { get; init; }
        public bool RealtimeProtectionPaused { get; init; }
        public int ActiveThreatCount { get; init; }
        public string EngineVersion { get; init; } = "";
        public string SignaturePackVersion { get; init; } = "";
    }
}
