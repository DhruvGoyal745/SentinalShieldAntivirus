using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Security;

public sealed class YaraScannerEngine : IOpenSourceScannerEngine
{
    private readonly IProcessCommandRunner _processCommandRunner;
    private readonly AntivirusPlatformOptions _options;
    private readonly IWebHostEnvironment _environment;

    public YaraScannerEngine(
        IProcessCommandRunner processCommandRunner,
        IOptions<AntivirusPlatformOptions> options,
        IWebHostEnvironment environment)
    {
        _processCommandRunner = processCommandRunner;
        _options = options.Value;
        _environment = environment;
    }

    public string EngineName => "YARA";

    public ThreatSource Source => ThreatSource.Yara;

    public async Task<FileScannerEngineResult> ScanAsync(FileInfo file, CancellationToken cancellationToken = default)
    {
        var executablePath = ResolveConfiguredPath(_options.YaraExecutablePath);
        var rulesPath = ResolveConfiguredPath(_options.YaraRulesPath);

        if (!File.Exists(executablePath))
        {
            return Unavailable($"YARA executable was not found at {executablePath}.");
        }

        if (!File.Exists(rulesPath))
        {
            return Unavailable($"YARA rules were not found at {rulesPath}.");
        }

        var compiledFlag = _options.YaraRulesCompiled ? "-C " : string.Empty;
        var result = await _processCommandRunner.RunAsync(
            executablePath,
            $"{compiledFlag}\"{rulesPath}\" \"{file.FullName}\"",
            cancellationToken);

        if (result.ExitCode != 0 && string.IsNullOrWhiteSpace(result.StandardOutput))
        {
            return new FileScannerEngineResult
            {
                EngineName = EngineName,
                Source = Source,
                Status = FileEngineResultStatus.Error,
                Details = "YARA scan failed.",
                RawOutput = string.Join(Environment.NewLine, new[] { result.StandardOutput, result.StandardError }.Where(value => !string.IsNullOrWhiteSpace(value)))
            };
        }

        var matches = result.StandardOutput
            .Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (matches.Length == 0)
        {
            return new FileScannerEngineResult
            {
                EngineName = EngineName,
                Source = Source,
                Status = FileEngineResultStatus.Clean,
                Details = "No YARA rules matched."
            };
        }

        var signatureName = matches[0].Split(' ', StringSplitOptions.RemoveEmptyEntries)[0];
        return new FileScannerEngineResult
        {
            EngineName = EngineName,
            Source = Source,
            Status = FileEngineResultStatus.ThreatDetected,
            IsMatch = true,
            SignatureName = signatureName,
            Details = $"{matches.Length} YARA rule match(es) were detected.",
            RawOutput = result.StandardOutput
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
}
