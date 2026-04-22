using System.Collections.Concurrent;
using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
using Antivirus.Infrastructure.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Security;

public sealed class RansomwareShield : IRansomwareShield
{
    private readonly IOptions<AntivirusPlatformOptions> _options;
    private readonly IFeatureFlagService _featureFlags;
    private readonly ILogger<RansomwareShield> _logger;

    private readonly ConcurrentDictionary<string, ProcessFileWriteWindow> _windows = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<RansomwareDetectionSignal> _recentSignals = new();

    private readonly string[] _protectedFolders;
    private readonly int _thresholdPerMinute;
    private readonly double _entropyThreshold;
    private readonly bool _autoKillEnabled;
    private readonly bool _autoSuspendEnabled;

    public RansomwareShield(
        IOptions<AntivirusPlatformOptions> options,
        IFeatureFlagService featureFlags,
        ILogger<RansomwareShield> logger)
    {
        _options = options;
        _featureFlags = featureFlags;
        _logger = logger;

        var opts = options.Value;
        _thresholdPerMinute = opts.RansomwareFileWriteThresholdPerMinute;
        _entropyThreshold = opts.RansomwareEntropyThreshold;
        _autoKillEnabled = opts.RansomwareAutoKillEnabled;
        _autoSuspendEnabled = opts.RansomwareAutoSuspendEnabled;

        _protectedFolders = opts.ProtectedFolders.Length > 0
            ? opts.ProtectedFolders
            : GetDefaultProtectedFolders();
    }

    public async Task<RansomwareDetectionSignal?> RecordFileWriteAsync(
        FileWatchNotification notification, FileInfo file, CancellationToken ct = default)
    {
        if (!_featureFlags.IsEnabled("ransomware-shield"))
            return null;

        var filePath = file.FullName;
        if (!IsProtectedFolder(filePath))
            return null;

        // Compute entropy
        double? entropyScore = null;
        try
        {
            if (file.Exists && file.Length > 0)
            {
                var bytesToRead = (int)Math.Min(file.Length, 8192);
                var buffer = new byte[bytesToRead];
                using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                var bytesRead = await stream.ReadAsync(buffer.AsMemory(0, bytesToRead), ct);
                if (bytesRead > 0)
                {
                    entropyScore = CalculateShannonEntropy(buffer.AsSpan(0, bytesRead));
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // File locked or inaccessible — skip entropy
        }

        // Detect extension change
        bool isExtensionChange = false;
        if (notification.EventType == FileEventType.Renamed && !string.IsNullOrEmpty(notification.PreviousPath))
        {
            var oldExt = Path.GetExtension(notification.PreviousPath);
            var newExt = file.Extension;
            if (!string.Equals(oldExt, newExt, StringComparison.OrdinalIgnoreCase))
            {
                isExtensionChange = true;
            }
        }

        // Use file directory as a proxy key (we don't always have PID in file events)
        var processKey = Path.GetDirectoryName(filePath) ?? "unknown";

        var window = _windows.GetOrAdd(processKey, _ => new ProcessFileWriteWindow());

        var record = new FileWriteRecord
        {
            FilePath = filePath,
            Timestamp = DateTimeOffset.UtcNow,
            IsExtensionChange = isExtensionChange,
            EntropyScore = entropyScore
        };

        window.Writes.Enqueue(record);

        // Trim window to 60 seconds
        var cutoff = DateTimeOffset.UtcNow.AddSeconds(-60);
        while (window.Writes.TryPeek(out var oldest) && oldest.Timestamp < cutoff)
        {
            window.Writes.TryDequeue(out _);
        }

        // Count writes in window
        var writes = window.Writes.ToArray();
        var writeCount = writes.Length;
        var extensionChangeCount = writes.Count(w => w.IsExtensionChange);
        var maxEntropy = writes.Where(w => w.EntropyScore.HasValue).Select(w => w.EntropyScore!.Value).DefaultIfEmpty(0).Max();

        // Check primary threshold: mass writes
        if (writeCount >= _thresholdPerMinute)
        {
            var signal = BuildSignal(processKey, writeCount, maxEntropy, extensionChangeCount);
            StoreSignal(signal);
            _logger.LogWarning("Ransomware shield triggered: {WriteCount} writes in 60s by '{ProcessPath}'", writeCount, processKey);
            return signal;
        }

        // Check secondary threshold: high entropy + extension change + moderate writes
        if (entropyScore.HasValue && entropyScore.Value > _entropyThreshold
            && isExtensionChange && writeCount > 10)
        {
            var signal = BuildSignal(processKey, writeCount, maxEntropy, extensionChangeCount);
            StoreSignal(signal);
            _logger.LogWarning("Ransomware shield entropy-based trigger: entropy={Entropy:F2}, ext changes, {WriteCount} writes by '{ProcessPath}'",
                entropyScore.Value, writeCount, processKey);
            return signal;
        }

        return null;
    }

    public bool IsProtectedFolder(string path)
    {
        foreach (var folder in _protectedFolders)
        {
            if (path.StartsWith(folder, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    public IReadOnlyCollection<RansomwareDetectionSignal> GetRecentSignals(int maxCount = 20)
    {
        return _recentSignals.ToArray().TakeLast(maxCount).ToArray();
    }

    private RansomwareDetectionSignal BuildSignal(string processPath, int affectedFileCount, double maxEntropy, int extensionChangeCount)
    {
        var action = _autoKillEnabled ? RansomwareAction.Kill
            : _autoSuspendEnabled ? RansomwareAction.Suspend
            : RansomwareAction.Alert;

        return new RansomwareDetectionSignal
        {
            ProcessPath = processPath,
            AffectedFileCount = affectedFileCount,
            MaxEntropyScore = maxEntropy,
            ExtensionChangeCount = extensionChangeCount,
            RecommendedAction = action,
            DetectedAt = DateTimeOffset.UtcNow,
            Summary = $"Mass file-write detected: {affectedFileCount} files, entropy {maxEntropy:F2}, {extensionChangeCount} ext changes"
        };
    }

    private void StoreSignal(RansomwareDetectionSignal signal)
    {
        _recentSignals.Enqueue(signal);
        while (_recentSignals.Count > 100)
        {
            _recentSignals.TryDequeue(out _);
        }
    }

    private static double CalculateShannonEntropy(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
            return 0.0;

        Span<int> frequencies = stackalloc int[256];
        frequencies.Clear();

        for (int i = 0; i < data.Length; i++)
        {
            frequencies[data[i]]++;
        }

        double entropy = 0.0;
        double total = data.Length;

        for (int i = 0; i < 256; i++)
        {
            if (frequencies[i] == 0)
                continue;

            double p = frequencies[i] / total;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }

    private static string[] GetDefaultProtectedFolders()
    {
        var folders = new List<string>();

        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        if (!string.IsNullOrEmpty(documents)) folders.Add(documents);

        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        if (!string.IsNullOrEmpty(desktop)) folders.Add(desktop);

        var pictures = Environment.GetFolderPath(Environment.SpecialFolder.MyPictures);
        if (!string.IsNullOrEmpty(pictures)) folders.Add(pictures);

        return folders.ToArray();
    }

    private sealed class ProcessFileWriteWindow
    {
        public ConcurrentQueue<FileWriteRecord> Writes { get; } = new();
    }

    private sealed class FileWriteRecord
    {
        public required string FilePath { get; init; }
        public required DateTimeOffset Timestamp { get; init; }
        public required bool IsExtensionChange { get; init; }
        public double? EntropyScore { get; init; }
    }
}
