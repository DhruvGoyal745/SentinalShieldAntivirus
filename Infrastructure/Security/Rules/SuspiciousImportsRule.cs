using System.Text;
using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.Rules;

public sealed class SuspiciousImportsRule : IHeuristicRule
{
    private static readonly HashSet<string> PeExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys"
    };

    private static readonly string[] SuspiciousApis =
    [
        "VirtualAlloc",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtUnmapViewOfSection",
        "VirtualProtect",
        "NtWriteVirtualMemory"
    ];

    public ThreatDetection? Evaluate(FileScanContext context)
    {
        if (!PeExtensions.Contains(context.File.Extension))
        {
            return null;
        }

        string asciiContent;
        try
        {
            using var stream = new FileStream(
                context.File.FullName,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            var buffer = new byte[(int)Math.Min(stream.Length, 8192)];
            var bytesRead = stream.Read(buffer, 0, buffer.Length);
            if (bytesRead == 0)
            {
                return null;
            }

            asciiContent = Encoding.ASCII.GetString(buffer, 0, bytesRead);
        }
        catch
        {
            return null;
        }

        var found = SuspiciousApis
            .Where(api => asciiContent.Contains(api, StringComparison.Ordinal))
            .ToList();

        if (found.Count == 0)
        {
            return null;
        }

        return new ThreatDetection
        {
            Name = "Suspicious API imports detected",
            Category = "Process Injection",
            Severity = ThreatSeverity.Medium,
            Source = ThreatSource.Heuristic,
            Resource = context.File.FullName,
            Description = $"PE file '{context.File.Name}' contains references to suspicious API functions: {string.Join(", ", found)}. These APIs are commonly used for process injection and memory manipulation. (Heuristic approximation based on string analysis of first 8KB.)",
            EngineName = "Sentinel Shield Heuristics",
            DetectedAt = DateTimeOffset.UtcNow
        };
    }
}
