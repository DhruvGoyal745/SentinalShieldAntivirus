using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.Rules;

public sealed class SuspiciousExtensionRule : IHeuristicRule
{
    private static readonly HashSet<string> RiskyExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe",
        ".dll",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".jse",
        ".scr"
    };

    public ThreatDetection? Evaluate(FileScanContext context)
    {
        if (!RiskyExtensions.Contains(context.File.Extension))
        {
            return null;
        }

        var path = context.File.FullName;
        if (!path.Contains("Downloads", StringComparison.OrdinalIgnoreCase)
            && !path.Contains("Desktop", StringComparison.OrdinalIgnoreCase)
            && !path.Contains("Temp", StringComparison.OrdinalIgnoreCase)
            && !path.Contains("Startup", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return new ThreatDetection
        {
            Name = "Suspicious executable or script in risky location",
            Category = "Heuristic",
            Severity = ThreatSeverity.Medium,
            Source = ThreatSource.Heuristic,
            Resource = path,
            Description = "Executable or script discovered in a high-risk user location.",
            EngineName = "Sentinel Shield Heuristics",
            DetectedAt = DateTimeOffset.UtcNow
        };
    }
}
