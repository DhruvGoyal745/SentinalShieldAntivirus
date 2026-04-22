namespace Antivirus.Domain;

public sealed class ProtectedFolder
{
    public string Path { get; init; } = string.Empty;
    public string Label { get; init; } = string.Empty;
    public bool IsEnabled { get; init; } = true;
}

public enum RansomwareAction
{
    Alert,
    Suspend,
    Kill
}

public sealed class RansomwareDetectionSignal
{
    public int ProcessId { get; init; }
    public string ProcessPath { get; init; } = string.Empty;
    public int AffectedFileCount { get; init; }
    public double MaxEntropyScore { get; init; }
    public int ExtensionChangeCount { get; init; }
    public RansomwareAction RecommendedAction { get; init; }
    public DateTimeOffset DetectedAt { get; init; } = DateTimeOffset.UtcNow;
    public string Summary { get; init; } = string.Empty;
}

public sealed class FileJournalEntry
{
    public long Id { get; init; }
    public string FolderPath { get; init; } = string.Empty;
    public string FilePath { get; init; } = string.Empty;
    public FileJournalOperation Operation { get; init; }
    public int? ProcessId { get; init; }
    public string? ProcessName { get; init; }
    public double? EntropyScore { get; init; }
    public DateTimeOffset OccurredAt { get; init; } = DateTimeOffset.UtcNow;
}

public enum FileJournalOperation
{
    Created,
    Modified,
    Renamed,
    Deleted
}

public sealed class RansomwareShieldPolicy
{
    public int FileWriteThresholdPerMinute { get; init; } = 50;
    public double EntropyThreshold { get; init; } = 7.0;
    public bool AutoKillEnabled { get; init; }
    public bool AutoSuspendEnabled { get; init; }
    public IReadOnlyCollection<ProtectedFolder> ProtectedFolders { get; init; } = [];
}
