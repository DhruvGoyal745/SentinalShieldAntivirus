using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.Rules;

public sealed class DllSideloadingRule : IHeuristicRule
{
    public ThreatDetection? Evaluate(FileScanContext context)
    {
        if (!context.File.Extension.Equals(".dll", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var directory = context.File.DirectoryName;
        if (string.IsNullOrEmpty(directory))
        {
            return null;
        }

        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var isUserWritable =
            directory.Contains("Downloads", StringComparison.OrdinalIgnoreCase) ||
            directory.Contains("Desktop", StringComparison.OrdinalIgnoreCase) ||
            directory.Contains(@"AppData\Local\Temp", StringComparison.OrdinalIgnoreCase) ||
            directory.Contains(@"Local\Temp", StringComparison.OrdinalIgnoreCase) ||
            (!string.IsNullOrEmpty(userProfile) &&
             directory.StartsWith(userProfile, StringComparison.OrdinalIgnoreCase) &&
             !directory.Contains("AppData\\Local\\Programs", StringComparison.OrdinalIgnoreCase));

        if (!isUserWritable)
        {
            return null;
        }

        return new ThreatDetection
        {
            Name = "DLL in user-writable directory",
            Category = "DLL Sideloading",
            Severity = ThreatSeverity.Medium,
            Source = ThreatSource.Heuristic,
            Resource = context.File.FullName,
            Description = $"DLL '{context.File.Name}' found in user-writable directory '{directory}'. This may indicate a DLL sideloading or planting attack.",
            EngineName = "Sentinel Shield Heuristics",
            DetectedAt = DateTimeOffset.UtcNow
        };
    }
}
