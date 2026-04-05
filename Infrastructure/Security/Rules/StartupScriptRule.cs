using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.Rules;

public sealed class StartupScriptRule : IHeuristicRule
{
    private static readonly HashSet<string> StartupExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js"
    };

    public ThreatDetection? Evaluate(FileScanContext context)
    {
        if (!context.File.FullName.Contains("Startup", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (!StartupExtensions.Contains(context.File.Extension))
        {
            return null;
        }

        return new ThreatDetection
        {
            Name = "Persistence candidate in startup location",
            Category = "Persistence",
            Severity = ThreatSeverity.Critical,
            Source = ThreatSource.Heuristic,
            Resource = context.File.FullName,
            Description = "A startup entry contains an executable or script and should be reviewed immediately.",
            EngineName = "Sentinel Shield Heuristics",
            DetectedAt = DateTimeOffset.UtcNow
        };
    }
}
