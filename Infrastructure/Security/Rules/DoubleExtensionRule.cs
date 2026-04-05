using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.Rules;

public sealed class DoubleExtensionRule : IHeuristicRule
{
    private static readonly HashSet<string> DecoyExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".jpg",
        ".jpeg",
        ".png",
        ".txt"
    };

    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".ps1",
        ".js"
    };

    public ThreatDetection? Evaluate(FileScanContext context)
    {
        var segments = context.File.Name.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length < 3)
        {
            return null;
        }

        var decoyExtension = "." + segments[^2];
        var realExtension = "." + segments[^1];

        if (!DecoyExtensions.Contains(decoyExtension) || !ExecutableExtensions.Contains(realExtension))
        {
            return null;
        }

        return new ThreatDetection
        {
            Name = "Potential double-extension masquerading payload",
            Category = "Masquerading",
            Severity = ThreatSeverity.High,
            Source = ThreatSource.Heuristic,
            Resource = context.File.FullName,
            Description = $"File name {context.File.Name} appears to hide an executable behind a document-like extension.",
            EngineName = "Sentinel Shield Heuristics",
            DetectedAt = DateTimeOffset.UtcNow
        };
    }
}
