using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.Rules;

public sealed class EncodedCommandRule : IHeuristicRule
{
    private static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".bat", ".cmd"
    };

    private static readonly string[] SuspiciousPatterns =
    [
        "-enc ",
        "-encodedcommand ",
        "-e ",
        "FromBase64String",
        "[Convert]::"
    ];

    public ThreatDetection? Evaluate(FileScanContext context)
    {
        if (!ScriptExtensions.Contains(context.File.Extension))
        {
            return null;
        }

        string content;
        try
        {
            using var stream = new FileStream(
                context.File.FullName,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);
            var buffer = new char[4096];
            var charsRead = reader.Read(buffer, 0, buffer.Length);
            if (charsRead == 0)
            {
                return null;
            }

            content = new string(buffer, 0, charsRead);
        }
        catch
        {
            return null;
        }

        var matchedPatterns = SuspiciousPatterns
            .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (matchedPatterns.Count == 0)
        {
            return null;
        }

        return new ThreatDetection
        {
            Name = "Encoded PowerShell command detected",
            Category = "Obfuscation",
            Severity = ThreatSeverity.High,
            Source = ThreatSource.Heuristic,
            Resource = context.File.FullName,
            Description = $"File '{context.File.Name}' contains encoded command patterns: {string.Join(", ", matchedPatterns)}. Encoded commands are frequently used to obfuscate malicious payloads.",
            EngineName = "Sentinel Shield Heuristics",
            DetectedAt = DateTimeOffset.UtcNow
        };
    }
}
