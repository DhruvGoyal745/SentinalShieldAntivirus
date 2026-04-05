using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Security;

public sealed class ClamAvScannerEngine : IOpenSourceScannerEngine
{
    private readonly IProcessCommandRunner _processCommandRunner;
    private readonly AntivirusPlatformOptions _options;
    private readonly IWebHostEnvironment _environment;

    public ClamAvScannerEngine(
        IProcessCommandRunner processCommandRunner,
        IOptions<AntivirusPlatformOptions> options,
        IWebHostEnvironment environment)
    {
        _processCommandRunner = processCommandRunner;
        _options = options.Value;
        _environment = environment;
    }

    public string EngineName => _options.PreferClamAvDaemon ? "ClamAV (daemon)" : "ClamAV (command)";

    public ThreatSource Source => ThreatSource.ClamAv;

    public async Task<FileScannerEngineResult> ScanAsync(FileInfo file, CancellationToken cancellationToken = default)
    {
        var executablePath = ResolveConfiguredPath(
            _options.PreferClamAvDaemon ? _options.ClamAvDaemonExecutablePath : _options.ClamAvExecutablePath);

        if (!File.Exists(executablePath))
        {
            return Unavailable($"ClamAV executable was not found at {executablePath}.");
        }

        var arguments = _options.PreferClamAvDaemon
            ? $"--fdpass --no-summary \"{file.FullName}\""
            : $"--no-summary \"{file.FullName}\"";

        var result = await _processCommandRunner.RunAsync(executablePath, arguments, cancellationToken);
        var output = string.Join(Environment.NewLine, new[] { result.StandardOutput, result.StandardError }.Where(value => !string.IsNullOrWhiteSpace(value)));

        return result.ExitCode switch
        {
            0 => new FileScannerEngineResult
            {
                EngineName = EngineName,
                Source = Source,
                Status = FileEngineResultStatus.Clean,
                Details = "ClamAV found no threats.",
                RawOutput = output
            },
            1 => new FileScannerEngineResult
            {
                EngineName = EngineName,
                Source = Source,
                Status = FileEngineResultStatus.ThreatDetected,
                IsMatch = true,
                SignatureName = ParseSignatureName(output),
                Details = "ClamAV reported the file as infected.",
                RawOutput = output
            },
            _ => new FileScannerEngineResult
            {
                EngineName = EngineName,
                Source = Source,
                Status = FileEngineResultStatus.Error,
                Details = "ClamAV scan failed.",
                RawOutput = output
            }
        };
    }

    private FileScannerEngineResult Unavailable(string details) =>
        new()
        {
            EngineName = EngineName,
            Source = Source,
            Status = FileEngineResultStatus.Unavailable,
            Details = details
        };

    private string ResolveConfiguredPath(string path) =>
        Path.IsPathRooted(path) ? path : Path.GetFullPath(Path.Combine(_environment.ContentRootPath, path));

    private static string? ParseSignatureName(string output)
    {
        var line = output
            .Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault(candidate => candidate.Contains("FOUND", StringComparison.OrdinalIgnoreCase));

        if (string.IsNullOrWhiteSpace(line))
        {
            return null;
        }

        var colonIndex = line.IndexOf(':');
        var foundIndex = line.LastIndexOf("FOUND", StringComparison.OrdinalIgnoreCase);
        if (colonIndex < 0 || foundIndex <= colonIndex)
        {
            return line;
        }

        return line[(colonIndex + 1)..foundIndex].Trim();
    }
}
