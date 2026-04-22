using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.Rules;

public sealed class HtaFileRule : IHeuristicRule
{
    public ThreatDetection? Evaluate(FileScanContext context)
    {
        if (!context.File.Extension.Equals(".hta", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return new ThreatDetection
        {
            Name = "HTML Application (.hta) detected",
            Category = "Script",
            Severity = ThreatSeverity.High,
            Source = ThreatSource.Heuristic,
            Resource = context.File.FullName,
            Description = $"File '{context.File.Name}' is an HTML Application that can execute scripts with full system access. HTA files are frequently abused for malware delivery.",
            EngineName = "Sentinel Shield Heuristics",
            DetectedAt = DateTimeOffset.UtcNow
        };
    }
}
