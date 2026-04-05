using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Security;

public sealed class HeuristicAnalyzer : IHeuristicAnalyzer
{
    private readonly IReadOnlyCollection<IHeuristicRule> _rules;
    private readonly AntivirusPlatformOptions _options;
    private readonly IWebHostEnvironment _environment;

    public HeuristicAnalyzer(
        IEnumerable<IHeuristicRule> rules,
        IOptions<AntivirusPlatformOptions> options,
        IWebHostEnvironment environment)
    {
        _rules = rules.ToArray();
        _options = options.Value;
        _environment = environment;
    }

    public Task<IReadOnlyCollection<ThreatDetection>> AnalyzeAsync(ScanRequest request, CancellationToken cancellationToken = default)
    {
        var findings = new List<ThreatDetection>();
        var scannedCount = 0;

        foreach (var root in ResolveRoots(request))
        {
            if (!Directory.Exists(root))
            {
                continue;
            }

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(
                    root,
                    "*",
                    new EnumerationOptions
                    {
                        IgnoreInaccessible = true,
                        RecurseSubdirectories = true,
                        AttributesToSkip = 0
                    });
            }
            catch
            {
                continue;
            }

            foreach (var path in files)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (scannedCount >= _options.MaxHeuristicFiles)
                {
                    return Task.FromResult<IReadOnlyCollection<ThreatDetection>>(findings);
                }

                scannedCount++;

                FileInfo fileInfo;
                try
                {
                    fileInfo = new FileInfo(path);
                }
                catch
                {
                    continue;
                }

                var context = new FileScanContext
                {
                    File = fileInfo,
                    RootPath = root,
                    Mode = request.Mode
                };

                foreach (var rule in _rules)
                {
                    var threat = rule.Evaluate(context);
                    if (threat is not null)
                    {
                        findings.Add(threat);
                    }
                }
            }
        }

        return Task.FromResult<IReadOnlyCollection<ThreatDetection>>(findings);
    }

    private IEnumerable<string> ResolveRoots(ScanRequest request)
    {
        if (request.Mode == ScanMode.Custom && !string.IsNullOrWhiteSpace(request.TargetPath))
        {
            yield return request.TargetPath;
            yield break;
        }

        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        var temp = Path.GetTempPath();

        foreach (var candidate in new[]
                 {
                     Path.Combine(userProfile, "Downloads"),
                     Path.Combine(userProfile, "Desktop"),
                     startup,
                     temp,
                     Path.Combine(userProfile, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
                 })
        {
            yield return candidate;
        }
    }
}
