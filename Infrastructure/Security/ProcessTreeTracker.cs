using System.Diagnostics;
using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security;

public sealed class ProcessTreeTracker : IProcessTreeTracker
{
    private static readonly LOLBinPattern[] s_lolBinPatterns =
    [
        new() { ParentPattern = "cmd.exe", ChildPattern = "certutil.exe", Description = "cmd spawning certutil (download cradle)", Severity = ThreatSeverity.High, Confidence = 0.90m },
        new() { ParentPattern = "cmd.exe", ChildPattern = "mshta.exe", Description = "cmd spawning mshta (script execution)", Severity = ThreatSeverity.High, Confidence = 0.88m },
        new() { ParentPattern = "cmd.exe", ChildPattern = "regsvr32.exe", Description = "cmd spawning regsvr32 (squiblydoo)", Severity = ThreatSeverity.High, Confidence = 0.87m },
        new() { ParentPattern = "explorer.exe", ChildPattern = "mshta.exe", Description = "Explorer spawning mshta", Severity = ThreatSeverity.High, Confidence = 0.85m },
        new() { ParentPattern = "excel.exe", ChildPattern = "cmd.exe", Description = "Excel spawning cmd (macro execution)", Severity = ThreatSeverity.Critical, Confidence = 0.92m },
        new() { ParentPattern = "excel.exe", ChildPattern = "powershell.exe", Description = "Excel spawning PowerShell (macro execution)", Severity = ThreatSeverity.Critical, Confidence = 0.93m },
        new() { ParentPattern = "winword.exe", ChildPattern = "cmd.exe", Description = "Word spawning cmd (macro execution)", Severity = ThreatSeverity.Critical, Confidence = 0.92m },
        new() { ParentPattern = "winword.exe", ChildPattern = "powershell.exe", Description = "Word spawning PowerShell (macro execution)", Severity = ThreatSeverity.Critical, Confidence = 0.93m },
        new() { ParentPattern = "outlook.exe", ChildPattern = "powershell.exe", Description = "Outlook spawning PowerShell", Severity = ThreatSeverity.Critical, Confidence = 0.91m },
        new() { ParentPattern = "svchost.exe", ChildPattern = "cmd.exe", Description = "svchost spawning cmd (possible service abuse)", Severity = ThreatSeverity.High, Confidence = 0.80m },
        new() { ParentPattern = "wmiprvse.exe", ChildPattern = "powershell.exe", Description = "WMI provider spawning PowerShell (lateral movement)", Severity = ThreatSeverity.High, Confidence = 0.89m },
        new() { ParentPattern = "cmd.exe", ChildPattern = "bitsadmin.exe", Description = "cmd spawning bitsadmin (download cradle)", Severity = ThreatSeverity.High, Confidence = 0.86m },
        new() { ParentPattern = "cmd.exe", ChildPattern = "cmstp.exe", Description = "cmd spawning cmstp (UAC bypass)", Severity = ThreatSeverity.High, Confidence = 0.88m },
    ];

    private static readonly Dictionary<string, HashSet<string>> s_suspiciousParentChild = new(StringComparer.OrdinalIgnoreCase)
    {
        ["winword.exe"] = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe" },
        ["excel.exe"] = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe" },
        ["outlook.exe"] = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe" },
        ["svchost.exe"] = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "certutil.exe", "bitsadmin.exe" },
        ["wmiprvse.exe"] = new(StringComparer.OrdinalIgnoreCase) { "powershell.exe", "pwsh.exe", "cmd.exe" },
        ["services.exe"] = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe" },
        ["lsass.exe"] = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe" },
        ["spoolsv.exe"] = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe", "certutil.exe" },
        ["notepad.exe"] = new(StringComparer.OrdinalIgnoreCase) { "cmd.exe", "powershell.exe", "pwsh.exe" },
    };

    public ProcessLineage? GetProcessLineage(int processId, int maxDepth = 3)
    {
        try
        {
            return BuildLineage(processId, maxDepth, depth: 0);
        }
        catch
        {
            return null;
        }
    }

    public bool IsLOLBinChain(string parentPath, string childPath)
    {
        var parentName = Path.GetFileName(parentPath);
        var childName = Path.GetFileName(childPath);

        foreach (var pattern in s_lolBinPatterns)
        {
            if (string.Equals(parentName, pattern.ParentPattern, StringComparison.OrdinalIgnoreCase)
                && string.Equals(childName, pattern.ChildPattern, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    public bool IsSuspiciousParentChild(string parentPath, string childPath)
    {
        var parentName = Path.GetFileName(parentPath);
        var childName = Path.GetFileName(childPath);

        return s_suspiciousParentChild.TryGetValue(parentName, out var disallowed)
            && disallowed.Contains(childName);
    }

    private static ProcessLineage? BuildLineage(int processId, int maxDepth, int depth)
    {
        if (depth > maxDepth)
            return null;

        try
        {
            using var process = Process.GetProcessById(processId);
            var processPath = GetProcessPath(process);

            var parentPid = GetParentProcessId(processId);
            string? parentPath = null;
            if (parentPid.HasValue)
            {
                try
                {
                    using var parentProcess = Process.GetProcessById(parentPid.Value);
                    parentPath = GetProcessPath(parentProcess);
                }
                catch
                {
                    // Parent process may have exited
                }
            }

            return new ProcessLineage
            {
                ProcessId = processId,
                ProcessPath = processPath ?? "unknown",
                CommandLine = GetCommandLine(processId),
                ParentProcessId = parentPid,
                ParentProcessPath = parentPath,
                CreationTime = DateTimeOffset.UtcNow,
                Children = []
            };
        }
        catch
        {
            return null;
        }
    }

    private static string? GetProcessPath(Process process)
    {
        try
        {
            return process.MainModule?.FileName;
        }
        catch
        {
            // Access denied or 32/64-bit mismatch
            return null;
        }
    }

    private static int? GetParentProcessId(int processId)
    {
        try
        {
            // Use System.Management WMI query for parent PID.
            // If System.Management is unavailable, this will throw and we return null.
            return GetParentPidViaWmi(processId);
        }
        catch
        {
            return null;
        }
    }

    private static int? GetParentPidViaWmi(int processId)
    {
        // Dynamic invocation to avoid hard compile-time dependency on System.Management.
        // At runtime, if the assembly is present, we query WMI; otherwise we gracefully fail.
        try
        {
            var managementType = Type.GetType("System.Management.ManagementObjectSearcher, System.Management");
            if (managementType is null)
                return null;

            var query = $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {processId}";
            using var searcher = (IDisposable)Activator.CreateInstance(managementType, query)!;
            var getMethod = managementType.GetMethod("Get", Type.EmptyTypes)!;
            var results = getMethod.Invoke(searcher, null)!;

            foreach (var obj in (System.Collections.IEnumerable)results)
            {
                var indexer = obj.GetType().GetProperty("Item", new[] { typeof(string) })!;
                var parentPid = indexer.GetValue(obj, ["ParentProcessId"]);
                if (parentPid is not null)
                {
                    return Convert.ToInt32(parentPid);
                }
            }
        }
        catch
        {
            // WMI unavailable or access denied
        }

        return null;
    }

    private static string? GetCommandLine(int processId)
    {
        try
        {
            var managementType = Type.GetType("System.Management.ManagementObjectSearcher, System.Management");
            if (managementType is null)
                return null;

            var query = $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {processId}";
            using var searcher = (IDisposable)Activator.CreateInstance(managementType, query)!;
            var getMethod = managementType.GetMethod("Get", Type.EmptyTypes)!;
            var results = getMethod.Invoke(searcher, null)!;

            foreach (var obj in (System.Collections.IEnumerable)results)
            {
                var indexer = obj.GetType().GetProperty("Item", new[] { typeof(string) })!;
                var cmdLine = indexer.GetValue(obj, ["CommandLine"]);
                return cmdLine?.ToString();
            }
        }
        catch
        {
            // WMI unavailable
        }

        return null;
    }
}
