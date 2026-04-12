using Antivirus.Configuration;

namespace Antivirus.Infrastructure.Runtime;

public static class SentinelRuntimePaths
{
    private static readonly string[] ExcludedProfiles =
    [
        "All Users",
        "Default",
        "Default User",
        "Public",
        "WDAGUtilityAccount"
    ];

    public static string ResolveWritableDataRoot(AntivirusPlatformOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.DataRoot))
        {
            return ResolveConfiguredRoot(options.DataRoot);
        }

        return GetDefaultWritableRoot();
    }

    public static string ResolveQuarantineRoot(AntivirusPlatformOptions options) =>
        ResolveUnderWritableRoot(options, options.QuarantineRoot);

    public static string ResolveSignaturePackRoot(AntivirusPlatformOptions options) =>
        ResolveUnderWritableRoot(options, options.SignaturePackRoot);

    public static string ResolveLogsRoot(AntivirusPlatformOptions options) =>
        ResolveUnderWritableRoot(options, options.LogsRoot);

    public static IReadOnlyCollection<string> ResolveWatchRoots(IEnumerable<string> configuredRoots)
    {
        var resolved = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var roots = configuredRoots.ToArray();
        if (roots.Length == 0)
        {
            roots =
            [
                "%USERPROFILE%\\Downloads",
                "%USERPROFILE%\\Desktop",
                "%USERPROFILE%\\Documents",
                "%TEMP%",
                "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
            ];
        }

        foreach (var root in roots)
        {
            foreach (var expanded in ExpandWatchRoot(root))
            {
                resolved.Add(expanded);
            }
        }

        return resolved.ToArray();
    }

    private static IEnumerable<string> ExpandWatchRoot(string configuredRoot)
    {
        if (string.IsNullOrWhiteSpace(configuredRoot))
        {
            yield break;
        }

        var hasUserToken = configuredRoot.Contains("%USERPROFILE%", StringComparison.OrdinalIgnoreCase)
            || configuredRoot.Contains("%APPDATA%", StringComparison.OrdinalIgnoreCase)
            || configuredRoot.Contains("%TEMP%", StringComparison.OrdinalIgnoreCase);

        if (!hasUserToken)
        {
            yield return Path.GetFullPath(configuredRoot);
            yield break;
        }

        var systemTemp = Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar);
        var yielded = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var profile in EnumerateUserProfiles())
        {
            var expanded = configuredRoot
                .Replace("%USERPROFILE%", profile, StringComparison.OrdinalIgnoreCase)
                .Replace("%APPDATA%", Path.Combine(profile, "AppData", "Roaming"), StringComparison.OrdinalIgnoreCase)
                .Replace("%TEMP%", Path.Combine(profile, "AppData", "Local", "Temp"), StringComparison.OrdinalIgnoreCase);

            var fullPath = Path.GetFullPath(expanded);
            if (yielded.Add(fullPath))
            {
                yield return fullPath;
            }
        }

        var systemExpanded = configuredRoot
            .Replace("%USERPROFILE%", Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), StringComparison.OrdinalIgnoreCase)
            .Replace("%APPDATA%", Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), StringComparison.OrdinalIgnoreCase)
            .Replace("%TEMP%", systemTemp, StringComparison.OrdinalIgnoreCase);

        var systemFullPath = Path.GetFullPath(systemExpanded);
        if (yielded.Add(systemFullPath))
        {
            yield return systemFullPath;
        }
    }

    private static IEnumerable<string> EnumerateUserProfiles()
    {
        if (!OperatingSystem.IsWindows())
        {
            yield break;
        }

        // Use the system drive to locate C:\Users reliably, even when running as NT AUTHORITY\SYSTEM
        // where Environment.SpecialFolder.UserProfile resolves to the SYSTEM profile directory.
        var systemDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
        var usersRoot = Path.Combine(systemDrive, "Users");

        if (!Directory.Exists(usersRoot))
        {
            // Fallback: derive from current process profile (works when running as a real user)
            var profileParent = Path.GetFullPath(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".."));

            if (Directory.Exists(profileParent))
            {
                usersRoot = profileParent;
            }
            else
            {
                yield break;
            }
        }

        foreach (var directory in Directory.EnumerateDirectories(usersRoot))
        {
            var profileName = Path.GetFileName(directory);
            if (string.IsNullOrWhiteSpace(profileName))
            {
                continue;
            }

            if (ExcludedProfiles.Contains(profileName, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            yield return directory;
        }
    }

    private static string ResolveUnderWritableRoot(AntivirusPlatformOptions options, string configuredPath)
    {
        if (Path.IsPathRooted(configuredPath))
        {
            return Path.GetFullPath(configuredPath);
        }

        var writableRoot = ResolveWritableDataRoot(options);
        var relative = StripLeadingDataSegment(configuredPath);
        return Path.GetFullPath(Path.Combine(writableRoot, relative));
    }

    private static string ResolveConfiguredRoot(string configuredRoot)
    {
        if (Path.IsPathRooted(configuredRoot))
        {
            return Path.GetFullPath(configuredRoot);
        }

        if (LooksLikeInstalledApp())
        {
            return Path.GetFullPath(Path.Combine(GetDefaultWritableRoot(), StripLeadingDataSegment(configuredRoot)));
        }

        return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, configuredRoot));
    }

    private static string GetDefaultWritableRoot()
    {
        if (LooksLikeInstalledApp())
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "SentinelShield");
        }

        return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "Data"));
    }

    private static bool LooksLikeInstalledApp()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        var baseDirectory = Path.GetFullPath(AppContext.BaseDirectory);
        var programFiles = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        var commonData = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));

        return baseDirectory.StartsWith(programFiles, StringComparison.OrdinalIgnoreCase)
            || baseDirectory.StartsWith(commonData, StringComparison.OrdinalIgnoreCase);
    }

    private static string StripLeadingDataSegment(string configuredPath)
    {
        var normalized = configuredPath
            .TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            .Replace('/', Path.DirectorySeparatorChar);

        if (normalized.StartsWith($"Data{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase))
        {
            return normalized[(5)..];
        }

        return normalized;
    }
}
