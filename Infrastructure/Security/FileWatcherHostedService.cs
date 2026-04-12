using System.Collections.Concurrent;
using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
using Antivirus.Infrastructure.Runtime;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Security;

public sealed class FileWatcherHostedService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly AntivirusPlatformOptions _options;
    private readonly ILogger<FileWatcherHostedService> _logger;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _recentEvents = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<FileSystemWatcher> _watchers = new();

    public FileWatcherHostedService(
        IServiceScopeFactory scopeFactory,
        IOptions<AntivirusPlatformOptions> options,
        ILogger<FileWatcherHostedService> logger)
    {
        _scopeFactory = scopeFactory;
        _options = options.Value;
        _logger = logger;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.RealtimeWatcherEnabled)
        {
            _logger.LogInformation("Realtime watcher is disabled by configuration.");
            return Task.CompletedTask;
        }

        foreach (var root in ResolveWatchRoots().Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(root))
            {
                _logger.LogWarning("Skipping watch root {Root} — directory does not exist.", root);
                continue;
            }

            var watcher = new FileSystemWatcher(root)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite | NotifyFilters.CreationTime | NotifyFilters.Size,
                Filter = "*"
            };

            watcher.Created += (_, args) => OnFileEvent(args.FullPath, FileEventType.Created, null, stoppingToken);
            watcher.Changed += (_, args) => OnFileEvent(args.FullPath, FileEventType.Changed, null, stoppingToken);
            watcher.Deleted += (_, args) => OnFileEvent(args.FullPath, FileEventType.Deleted, null, stoppingToken);
            watcher.Renamed += (_, args) => OnFileEvent(args.FullPath, FileEventType.Renamed, args.OldFullPath, stoppingToken);
            watcher.Error += (_, args) => _logger.LogWarning(args.GetException(), "FileSystemWatcher error on root {Root}.", root);
            watcher.EnableRaisingEvents = true;
            _watchers.Add(watcher);

            _logger.LogInformation("Watching filesystem root {Root}.", root);
        }

        // Periodic cleanup of the debounce dictionary to prevent unbounded memory growth
        _ = EvictStaleDebounceEntriesAsync(stoppingToken);

        stoppingToken.Register(() =>
        {
            foreach (var watcher in _watchers)
            {
                watcher.Dispose();
            }
        });

        return Task.Delay(Timeout.Infinite, stoppingToken);
    }

    private async Task EvictStaleDebounceEntriesAsync(CancellationToken stoppingToken)
    {
        var evictionInterval = TimeSpan.FromMinutes(5);
        var maxAge = TimeSpan.FromSeconds(_options.FileEventDebounceSeconds * 2);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(evictionInterval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            var cutoff = DateTimeOffset.UtcNow - maxAge;
            var keysToRemove = _recentEvents
                .Where(kvp => kvp.Value < cutoff)
                .Select(kvp => kvp.Key)
                .ToArray();

            foreach (var key in keysToRemove)
            {
                _recentEvents.TryRemove(key, out _);
            }

            if (keysToRemove.Length > 0)
            {
                _logger.LogDebug("Evicted {Count} stale debounce entries.", keysToRemove.Length);
            }
        }
    }

    private void OnFileEvent(string path, FileEventType eventType, string? previousPath, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        if (IsTransientSystemFile(path))
        {
            return;
        }

        var key = $"{eventType}:{path}";
        var now = DateTimeOffset.UtcNow;
        if (_recentEvents.TryGetValue(key, out var lastSeen)
            && now - lastSeen < TimeSpan.FromSeconds(_options.FileEventDebounceSeconds))
        {
            return;
        }

        _recentEvents[key] = now;

        _ = Task.Run(async () =>
        {
            try
            {
                using var scope = _scopeFactory.CreateScope();
                var realtimeProtectionService = scope.ServiceProvider.GetRequiredService<IRealtimeProtectionService>();
                await realtimeProtectionService.RegisterFileEventAsync(
                    new FileWatchNotification
                    {
                        FilePath = path,
                        EventType = eventType,
                        PreviousPath = previousPath,
                        ObservedAt = now
                    },
                    cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to register filesystem event {EventType} for {Path}.", eventType, path);
            }
        }, cancellationToken);
    }

    private IEnumerable<string> ResolveWatchRoots()
    {
        foreach (var root in SentinelRuntimePaths.ResolveWatchRoots(_options.WatchRoots))
        {
            yield return root;
        }
    }

    private static bool IsTransientSystemFile(string path)
    {
        var fileName = Path.GetFileName(path.AsSpan());

        if (fileName.StartsWith("__PSScriptPolicyTest_", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (fileName.StartsWith("tmp", StringComparison.OrdinalIgnoreCase)
            && fileName.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var extension = Path.GetExtension(fileName);
        if (extension.Equals(".edb", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".jrs", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".chk", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".log", StringComparison.OrdinalIgnoreCase)
            || extension.Equals(".etl", StringComparison.OrdinalIgnoreCase))
        {
            if (path.Contains("VSTelem", StringComparison.OrdinalIgnoreCase)
                || path.Contains("\\EDB", StringComparison.OrdinalIgnoreCase)
                || path.Contains("\\Diagnostics", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
