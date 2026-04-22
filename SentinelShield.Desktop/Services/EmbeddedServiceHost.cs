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
        "https://localhost:44380",
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

        var port = FindFreePort();
        var url2 = $"http://127.0.0.1:{port}";

        var startInfo = BuildServiceStartInfo(url2);
        if (startInfo is null)
        {
            return false;
        }

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

        var ready = await WaitForServiceStartupAsync(url2, TimeSpan.FromSeconds(60), cancellationToken);
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

    private static ProcessStartInfo? BuildServiceStartInfo(string url)
    {
        var exePath = FindServiceExecutable();
        if (exePath is not null)
        {
            var info = new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = $"--urls \"{url}\"",
                WorkingDirectory = Path.GetDirectoryName(exePath)!,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = false,
                RedirectStandardError = false
            };
            info.Environment["ASPNETCORE_ENVIRONMENT"] = "Service";
            return info;
        }

        // Development fallback: use 'dotnet run' on the service .csproj
        var projectPath = FindServiceProject();
        if (projectPath is not null)
        {
            var info = new ProcessStartInfo
            {
                FileName = "dotnet",
                Arguments = $"run --project \"{projectPath}\" --no-launch-profile -- --urls \"{url}\"",
                WorkingDirectory = Path.GetDirectoryName(projectPath)!,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = false,
                RedirectStandardError = false
            };
            info.Environment["ASPNETCORE_ENVIRONMENT"] = "Development";
            info.Environment["BuildInstaller"] = "false";
            return info;
        }

        return null;
    }

    private static string? FindServiceExecutable()
    {
        var appDir = Path.GetDirectoryName(Environment.ProcessPath) ?? AppContext.BaseDirectory;

        // 1. Same folder as the desktop app (published/installed layout)
        var sameFolder = Path.Combine(appDir, ServiceExeName);
        if (File.Exists(sameFolder))
        {
            return sameFolder;
        }

        // 2. Parent folder
        var parentFolder = Path.Combine(Directory.GetParent(appDir)?.FullName ?? appDir, ServiceExeName);
        if (File.Exists(parentFolder))
        {
            return parentFolder;
        }

        // 3. Program Files (installed via installer)
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

    /// <summary>
    /// Walks up from the desktop exe's directory to find Antivirus.csproj for 'dotnet run' during development.
    /// </summary>
    private static string? FindServiceProject()
    {
        var dir = Path.GetDirectoryName(Environment.ProcessPath) ?? AppContext.BaseDirectory;

        for (var i = 0; i < 8 && dir is not null; i++)
        {
            dir = Directory.GetParent(dir)?.FullName;
            if (dir is null) break;

            var csproj = Path.Combine(dir, "Antivirus.csproj");
            if (File.Exists(csproj))
            {
                return csproj;
            }
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
            // Any HTTP response means the service is running — even 401/403 from auth middleware.
            return true;
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
