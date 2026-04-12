using System.Collections.Concurrent;
using Antivirus.Configuration;
using Antivirus.Infrastructure.Runtime;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Logging;

public sealed class RollingFileLoggerProvider : ILoggerProvider
{
    private readonly string _logRoot;
    private readonly ConcurrentDictionary<string, RollingFileLogger> _loggers = new(StringComparer.OrdinalIgnoreCase);

    public RollingFileLoggerProvider(IOptions<AntivirusPlatformOptions> options)
    {
        _logRoot = SentinelRuntimePaths.ResolveLogsRoot(options.Value);
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
}
