using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;

namespace SentinelShield.Desktop.Services;

internal sealed class EmbeddedServiceHost : IDisposable
{
    private const string ServiceExeName = "SentinelShieldAntivirus.exe";
    private const string DefaultServiceUrl = "http://127.0.0.1:5100";

    private static readonly string[] KnownServiceUrls =
    [
        "http://127.0.0.1:5100",
        "http://localhost:5091",
        "https://localhost:7000"
    ];

    private Process? _serviceProcess;
    private bool _disposed;

    public string BaseUrl { get; private set; } = DefaultServiceUrl;

    public bool IsEmbeddedProcess => _serviceProcess is not null;

    public async Task<bool> EnsureRunningAsync(CancellationToken cancellationToken)
    {
        foreach (var url in KnownServiceUrls)
        {
            if (await IsServiceReachableAsync(url, cancellationToken))
            {
                BaseUrl = url;
                return true;
            }
        }

        var serviceExePath = FindServiceExecutable();
        if (serviceExePath is null)
        {
            return false;
        }

        var port = FindFreePort();
        var url2 = $"http://127.0.0.1:{port}";

        var startInfo = new ProcessStartInfo
        {
            FileName = serviceExePath,
            Arguments = $"--urls \"{url2}\"",
            WorkingDirectory = Path.GetDirectoryName(serviceExePath)!,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = false,
            RedirectStandardError = false
        };

        startInfo.Environment["ASPNETCORE_ENVIRONMENT"] = "Service";

        try
        {
            _serviceProcess = Process.Start(startInfo);
        }
        catch
        {
            return false;
        }

        if (_serviceProcess is null || _serviceProcess.HasExited)
        {
            _serviceProcess = null;
            return false;
        }

        BaseUrl = url2;

        var ready = await WaitForServiceStartupAsync(url2, TimeSpan.FromSeconds(30), cancellationToken);
        if (!ready)
        {
            StopEmbeddedProcess();
            return false;
        }

        return true;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        StopEmbeddedProcess();
    }

    private void StopEmbeddedProcess()
    {
        if (_serviceProcess is null)
        {
            return;
        }

        try
        {
            if (!_serviceProcess.HasExited)
            {
                _serviceProcess.Kill(entireProcessTree: true);
                _serviceProcess.WaitForExit(5000);
            }
        }
        catch
        {
            // Best-effort cleanup.
        }
        finally
        {
            _serviceProcess.Dispose();
            _serviceProcess = null;
        }
    }

    private static string? FindServiceExecutable()
    {
        var appDir = Path.GetDirectoryName(Environment.ProcessPath) ?? AppContext.BaseDirectory;

        var sameFolder = Path.Combine(appDir, ServiceExeName);
        if (File.Exists(sameFolder))
        {
            return sameFolder;
        }

        var parentFolder = Path.Combine(Directory.GetParent(appDir)?.FullName ?? appDir, ServiceExeName);
        if (File.Exists(parentFolder))
        {
            return parentFolder;
        }

        var programFiles = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "SentinelShield",
            ServiceExeName);
        if (File.Exists(programFiles))
        {
            return programFiles;
        }

        return null;
    }

    private static int FindFreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static async Task<bool> IsServiceReachableAsync(string baseUrl, CancellationToken cancellationToken)
    {
        try
        {
            using var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            };
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(3) };
            using var response = await http.GetAsync($"{baseUrl}/api/service/status", cancellationToken);
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<bool> WaitForServiceStartupAsync(string baseUrl, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;

        while (DateTimeOffset.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (await IsServiceReachableAsync(baseUrl, cancellationToken))
            {
                return true;
            }

            await Task.Delay(500, cancellationToken);
        }

        return false;
    }
}
