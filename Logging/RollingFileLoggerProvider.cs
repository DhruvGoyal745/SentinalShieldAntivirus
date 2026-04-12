using System.Collections.Concurrent;
using Microsoft.Extensions.Configuration;

namespace Antivirus.Logging;

public sealed class RollingFileLoggerProvider : ILoggerProvider
{
    private readonly string _logRoot;
    private readonly ConcurrentDictionary<string, RollingFileLogger> _loggers = new(StringComparer.OrdinalIgnoreCase);

    public RollingFileLoggerProvider(IConfiguration configuration)
    {
        _logRoot = ResolveLogsRoot(configuration);
        Directory.CreateDirectory(_logRoot);
    }

    public ILogger CreateLogger(string categoryName) =>
        _loggers.GetOrAdd(categoryName, name => new RollingFileLogger(name, _logRoot));

    public void Dispose() => _loggers.Clear();

    private sealed class RollingFileLogger : ILogger
    {
        private static readonly object Sync = new();

        private readonly string _categoryName;
        private readonly string _logRoot;

        public RollingFileLogger(string categoryName, string logRoot)
        {
            _categoryName = categoryName;
            _logRoot = logRoot;
        }

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            var message = formatter(state, exception);
            var timestamp = DateTimeOffset.Now;
            var line = $"{timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{logLevel}] {_categoryName}: {message}";
            if (exception is not null)
            {
                line = $"{line}{Environment.NewLine}{exception}";
            }

            var path = Path.Combine(_logRoot, $"sentinel-{timestamp:yyyyMMdd}.log");
            lock (Sync)
            {
                File.AppendAllText(path, line + Environment.NewLine);
            }
        }
    }

    private sealed class NullScope : IDisposable
    {
        public static readonly NullScope Instance = new();

        public void Dispose()
        {
        }
    }

    private static string ResolveLogsRoot(IConfiguration configuration)
    {
        var configuredLogsRoot = configuration["AntivirusPlatform:LogsRoot"];
        if (string.IsNullOrWhiteSpace(configuredLogsRoot))
        {
            configuredLogsRoot = Path.Combine("Data", "Logs");
        }

        if (Path.IsPathRooted(configuredLogsRoot))
        {
            return Path.GetFullPath(configuredLogsRoot);
        }

        var baseRoot = ResolveWritableBaseRoot(configuration["AntivirusPlatform:DataRoot"]);
        return Path.GetFullPath(Path.Combine(baseRoot, StripLeadingDataSegment(configuredLogsRoot)));
    }

    private static string ResolveWritableBaseRoot(string? configuredDataRoot)
    {
        if (!string.IsNullOrWhiteSpace(configuredDataRoot))
        {
            if (Path.IsPathRooted(configuredDataRoot))
            {
                return Path.GetFullPath(configuredDataRoot);
            }

            if (!LooksLikeInstalledApp())
            {
                return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, configuredDataRoot));
            }
        }

        if (LooksLikeInstalledApp())
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "SentinelShield");
        }

        return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, string.IsNullOrWhiteSpace(configuredDataRoot) ? "Data" : configuredDataRoot));
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
