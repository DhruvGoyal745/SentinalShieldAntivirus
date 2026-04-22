using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.Rules;

public sealed class MacroDocumentRule : IHeuristicRule
{
    private static readonly HashSet<string> MacroExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"
    };

    public ThreatDetection? Evaluate(FileScanContext context)
    {
        if (!MacroExtensions.Contains(context.File.Extension))
        {
            return null;
        }

        return new ThreatDetection
        {
            Name = "Macro-enabled document detected",
            Category = "Macro",
            Severity = ThreatSeverity.Medium,
            Source = ThreatSource.Heuristic,
            Resource = context.File.FullName,
            Description = $"File '{context.File.Name}' is a macro-enabled Office document that could contain malicious VBA code.",
            EngineName = "Sentinel Shield Heuristics",
            DetectedAt = DateTimeOffset.UtcNow
        };
    }
}
