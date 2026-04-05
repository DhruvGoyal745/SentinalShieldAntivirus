using System.Collections.Concurrent;
using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
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
            watcher.EnableRaisingEvents = true;
            _watchers.Add(watcher);

            _logger.LogInformation("Watching filesystem root {Root}.", root);
        }

        stoppingToken.Register(() =>
        {
            foreach (var watcher in _watchers)
            {
                watcher.Dispose();
            }
        });

        return Task.Delay(Timeout.Infinite, stoppingToken);
    }

    private void OnFileEvent(string path, FileEventType eventType, string? previousPath, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(path))
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
        var configuredRoots = _options.WatchRoots.Length > 0
            ? _options.WatchRoots
            : new[]
            {
                "%USERPROFILE%\\Downloads",
                "%USERPROFILE%\\Desktop",
                "%USERPROFILE%\\Documents",
                "%TEMP%",
                "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
            };

        foreach (var root in configuredRoots)
        {
            yield return ExpandPathTokens(root);
        }
    }

    private static string ExpandPathTokens(string path)
    {
        return path
            .Replace("%USERPROFILE%", Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), StringComparison.OrdinalIgnoreCase)
            .Replace("%TEMP%", Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase)
            .Replace("%APPDATA%", Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), StringComparison.OrdinalIgnoreCase);
    }
}
