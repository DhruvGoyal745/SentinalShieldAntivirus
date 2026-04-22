using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security;

public sealed class BehaviorMonitor : IBehaviorMonitor
{
    private readonly IProcessTreeTracker? _processTreeTracker;
    private readonly IRansomwareShield? _ransomwareShield;

    private static readonly HashSet<string> s_lolBins = new(StringComparer.OrdinalIgnoreCase)
    {
        "certutil.exe", "mshta.exe", "regsvr32.exe", "bitsadmin.exe", "cmstp.exe", "msiexec.exe"
    };

    private static readonly HashSet<string> s_ransomwareExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".encrypted", ".crypted", ".crypt", ".enc", ".locked", ".crypto", ".zzz", ".aaa", ".xyz", ".locky"
    };

    private static readonly HashSet<string> s_scriptExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".vbs", ".js", ".hta", ".bat", ".cmd", ".wsf"
    };

    private static readonly HashSet<string> s_commonFileExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".csv",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp3", ".mp4", ".avi", ".mov",
        ".zip", ".rar", ".7z", ".html", ".htm", ".xml", ".json", ".sql", ".db",
        ".mdb", ".accdb", ".psd", ".ai", ".svg", ".rtf", ".odt", ".ods"
    };

    public BehaviorMonitor() { }

    public BehaviorMonitor(IProcessTreeTracker processTreeTracker)
    {
        _processTreeTracker = processTreeTracker;
    }

    public BehaviorMonitor(IProcessTreeTracker processTreeTracker, IRansomwareShield ransomwareShield)
    {
        _processTreeTracker = processTreeTracker;
        _ransomwareShield = ransomwareShield;
    }

    public async Task<IReadOnlyCollection<DetectionEventRecord>> AnalyzeAsync(FileWatchNotification notification, FileInfo file, CancellationToken cancellationToken = default)
    {
        var detections = new List<DetectionEventRecord>();
        var fullPath = file.FullName;

        // 1. Persistence-style startup path (existing)
        if (fullPath.Contains("startup", StringComparison.OrdinalIgnoreCase)
            || fullPath.Contains("runonce", StringComparison.OrdinalIgnoreCase))
        {
            detections.Add(Create("beh-startup", ThreatSeverity.High, 0.91m, "Persistence-style startup path activity detected."));
        }

        // 2. Ransomware rename (existing, expanded as beh-ext-rename)
        if (notification.EventType == FileEventType.Renamed)
        {
            if (s_ransomwareExtensions.Contains(file.Extension))
            {
                detections.Add(Create("beh-ext-rename", ThreatSeverity.Critical, 0.93m, "File renamed to known ransomware extension."));
            }
            else if (file.Extension.Contains("locked", StringComparison.OrdinalIgnoreCase))
            {
                detections.Add(Create("beh-ransom", ThreatSeverity.Critical, 0.95m, "Rename pattern resembles ransomware extension activity."));
            }
        }

        // 3. Script dropper (existing)
        if (notification.EventType == FileEventType.Created
            && (file.Extension.Equals(".ps1", StringComparison.OrdinalIgnoreCase)
                || file.Extension.Equals(".vbs", StringComparison.OrdinalIgnoreCase)
                || file.Extension.Equals(".js", StringComparison.OrdinalIgnoreCase))
            && !IsBenignSystemScript(file))
        {
            detections.Add(Create("beh-scriptdrop", ThreatSeverity.Medium, 0.66m, "Script dropper behavior observed in realtime monitor."));
        }

        // 4. LOLBin execution in non-system directories
        CheckLOLBin(notification, file, fullPath, detections);

        // 5. Encoded PowerShell
        CheckEncodedPowerShell(notification, file, fullPath, detections);

        // 7. Hidden executable
        CheckHiddenExecutable(notification, file, detections);

        // 8. Temp-to-startup movement
        CheckTempToStartup(notification, file, fullPath, detections);

        // 9. Script in downloads
        CheckScriptInDownloads(notification, file, fullPath, detections);

        // 10. Scheduled task creation
        CheckScheduledTask(notification, file, fullPath, detections);

        // 11. DLL in writable directory
        CheckDllPlant(notification, file, fullPath, detections);

        // 12. Mass file operations / suspicious rename
        CheckMassOpsRename(notification, file, detections);

        // Ransomware shield mass-write detection
        if (_ransomwareShield is not null)
        {
            var signal = await _ransomwareShield.RecordFileWriteAsync(notification, file, cancellationToken);
            if (signal is not null)
            {
                detections.Add(Create("beh-ransomware-mass", ThreatSeverity.Critical, 0.96m,
                    $"Mass file-write ransomware activity: {signal.AffectedFileCount} files affected by process '{signal.ProcessPath}'. " +
                    $"Entropy: {signal.MaxEntropyScore:F2}, Extension changes: {signal.ExtensionChangeCount}. " +
                    $"Action: {signal.RecommendedAction}."));
            }
        }

        return detections;
    }

    private static void CheckLOLBin(FileWatchNotification notification, FileInfo file, string fullPath, List<DetectionEventRecord> detections)
    {
        if (notification.EventType is not (FileEventType.Created or FileEventType.Changed))
            return;

        var fileName = file.Name;
        if (!s_lolBins.Contains(fileName))
            return;

        var systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrEmpty(systemRoot)
            && fullPath.StartsWith(systemRoot, StringComparison.OrdinalIgnoreCase))
            return;

        detections.Add(Create("beh-lolbin", ThreatSeverity.High, 0.85m,
            $"LOLBin '{fileName}' detected in non-system directory: {Path.GetDirectoryName(fullPath)}."));
    }

    private static void CheckEncodedPowerShell(FileWatchNotification notification, FileInfo file, string fullPath, List<DetectionEventRecord> detections)
    {
        if (notification.EventType is not (FileEventType.Created or FileEventType.Changed))
            return;

        if (!file.Extension.Equals(".ps1", StringComparison.OrdinalIgnoreCase))
            return;

        try
        {
            if (!file.Exists || file.Length == 0 || file.Length > 1_048_576) // skip files > 1MB
                return;

            // Read just the first portion to check for encoded command patterns
            using var reader = new StreamReader(fullPath);
            var header = new char[2048];
            var charsRead = reader.Read(header, 0, header.Length);
            var content = new string(header, 0, charsRead);

            if (ContainsEncodedPowerShellFlag(content))
            {
                detections.Add(Create("beh-encoded-ps", ThreatSeverity.High, 0.88m,
                    "PowerShell script contains encoded command flags."));
            }
        }
        catch
        {
            // File may be locked or inaccessible
        }
    }

    private static bool ContainsEncodedPowerShellFlag(string content)
    {
        if (string.IsNullOrEmpty(content))
            return false;

        var hasShell = content.Contains("powershell", StringComparison.OrdinalIgnoreCase)
                    || content.Contains("pwsh", StringComparison.OrdinalIgnoreCase);
        if (!hasShell)
            return false;

        return content.Contains(" -enc ", StringComparison.OrdinalIgnoreCase)
            || content.Contains(" -encodedcommand ", StringComparison.OrdinalIgnoreCase)
            || content.Contains(" -e ", StringComparison.OrdinalIgnoreCase)
            || content.Contains(" -enc\"", StringComparison.OrdinalIgnoreCase)
            || content.Contains(" -encodedcommand\"", StringComparison.OrdinalIgnoreCase);
    }

    private static void CheckHiddenExecutable(FileWatchNotification notification, FileInfo file, List<DetectionEventRecord> detections)
    {
        if (notification.EventType != FileEventType.Created)
            return;

        var ext = file.Extension;
        if (!ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)
            && !ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)
            && !ext.Equals(".scr", StringComparison.OrdinalIgnoreCase))
            return;

        try
        {
            if (!file.Exists)
                return;

            var attrs = file.Attributes;
            if ((attrs & FileAttributes.Hidden) != 0 || (attrs & FileAttributes.System) != 0)
            {
                detections.Add(Create("beh-hidden-exe", ThreatSeverity.High, 0.80m,
                    $"Hidden/system executable created: {file.Name}."));
            }
        }
        catch
        {
            // File may have been removed already
        }
    }

    private static void CheckTempToStartup(FileWatchNotification notification, FileInfo file, string fullPath, List<DetectionEventRecord> detections)
    {
        if (notification.EventType != FileEventType.Created)
            return;

        var isStartupPath = fullPath.Contains("startup", StringComparison.OrdinalIgnoreCase)
                         || fullPath.Contains("Start Menu", StringComparison.OrdinalIgnoreCase);
        if (!isStartupPath)
            return;

        var tempPath = Path.GetTempPath();
        var localAppDataTemp = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp");

        try
        {
            var matchInTemp = Path.Combine(tempPath, file.Name);
            var matchInLocalTemp = Path.Combine(localAppDataTemp, file.Name);

            if (File.Exists(matchInTemp) || File.Exists(matchInLocalTemp))
            {
                detections.Add(Create("beh-temp-persist", ThreatSeverity.Critical, 0.90m,
                    $"File '{file.Name}' created in startup path with matching copy in temp directory."));
            }
        }
        catch
        {
            // Access issues
        }
    }

    private static void CheckScriptInDownloads(FileWatchNotification notification, FileInfo file, string fullPath, List<DetectionEventRecord> detections)
    {
        if (notification.EventType != FileEventType.Created)
            return;

        if (!s_scriptExtensions.Contains(file.Extension))
            return;

        if (fullPath.Contains("Downloads", StringComparison.OrdinalIgnoreCase))
        {
            detections.Add(Create("beh-download-script", ThreatSeverity.Medium, 0.70m,
                $"Script file '{file.Name}' created in Downloads folder."));
        }
    }

    private static void CheckScheduledTask(FileWatchNotification notification, FileInfo file, string fullPath, List<DetectionEventRecord> detections)
    {
        if (notification.EventType != FileEventType.Created)
            return;

        if (!file.Extension.Equals(".xml", StringComparison.OrdinalIgnoreCase)
            && !file.Extension.Equals(".job", StringComparison.OrdinalIgnoreCase))
            return;

        if (fullPath.Contains(@"Windows\Tasks", StringComparison.OrdinalIgnoreCase)
            || fullPath.Contains(@"System32\Tasks", StringComparison.OrdinalIgnoreCase))
        {
            detections.Add(Create("beh-schtask", ThreatSeverity.High, 0.84m,
                $"Scheduled task file '{file.Name}' created in system tasks directory."));
        }
    }

    private static void CheckDllPlant(FileWatchNotification notification, FileInfo file, string fullPath, List<DetectionEventRecord> detections)
    {
        if (notification.EventType != FileEventType.Created)
            return;

        if (!file.Extension.Equals(".dll", StringComparison.OrdinalIgnoreCase))
            return;

        if (IsUserWritableDirectory(fullPath))
        {
            detections.Add(Create("beh-dll-plant", ThreatSeverity.Medium, 0.72m,
                $"DLL '{file.Name}' created in user-writable directory."));
        }
    }

    private static void CheckMassOpsRename(FileWatchNotification notification, FileInfo file, List<DetectionEventRecord> detections)
    {
        if (notification.EventType != FileEventType.Renamed)
            return;

        var newExt = file.Extension;
        if (string.IsNullOrEmpty(newExt))
            return;

        // Already covered by beh-ext-rename / beh-ransom
        if (s_ransomwareExtensions.Contains(newExt)
            || newExt.Contains("locked", StringComparison.OrdinalIgnoreCase))
            return;

        // If the new extension is uncommon and the previous path had a common extension
        if (!s_commonFileExtensions.Contains(newExt)
            && !string.IsNullOrEmpty(notification.PreviousPath))
        {
            var previousExt = Path.GetExtension(notification.PreviousPath);
            if (s_commonFileExtensions.Contains(previousExt))
            {
                detections.Add(Create("beh-mass-ops", ThreatSeverity.High, 0.87m,
                    $"File renamed from common extension '{previousExt}' to unusual extension '{newExt}'."));
            }
        }
    }

    private static bool IsUserWritableDirectory(string fullPath)
    {
        var normalized = fullPath.Replace('/', '\\');
        return normalized.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains(@"\Tmp\", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains(@"\AppData\", StringComparison.OrdinalIgnoreCase);
    }

    private static DetectionEventRecord Create(string ruleId, ThreatSeverity severity, decimal confidence, string summary) =>
        new()
        {
            RuleId = ruleId,
            EngineName = "Sentinel Behavior Engine",
            Source = ThreatSource.Behavior,
            Severity = severity,
            Confidence = confidence,
            Summary = summary
        };

    private static bool IsBenignSystemScript(FileInfo file)
    {
        var name = file.Name;

        if (name.StartsWith("__PSScriptPolicyTest_", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (name.StartsWith("tmp", StringComparison.OrdinalIgnoreCase)
            && name.EndsWith(".tmp.ps1", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }
}
