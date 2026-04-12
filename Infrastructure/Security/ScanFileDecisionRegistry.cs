using System.Collections.Concurrent;
using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Security;

public sealed class ScanFileDecisionRegistry : IScanFileDecisionRegistry
{
    private readonly ConcurrentDictionary<int, PendingDecisionEntry> _pending = new();
    private readonly TimeSpan _timeout;

    public ScanFileDecisionRegistry(IOptions<AntivirusPlatformOptions> options)
    {
        _timeout = TimeSpan.FromSeconds(Math.Max(30, options.Value.FileDecisionTimeoutSeconds));
    }

    public async Task<ScanFileDecisionAction> WaitForDecisionAsync(
        int scanId,
        string filePath,
        string reason,
        CancellationToken cancellationToken)
    {
        var entry = new PendingDecisionEntry(filePath, reason);
        _pending[scanId] = entry;

        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(_timeout);
            using var registration = timeoutCts.Token.Register(() => entry.Complete(ScanFileDecisionAction.Skip));
            return await entry.Task;
        }
        finally
        {
            _pending.TryRemove(scanId, out _);
        }
    }

    public bool SubmitDecision(int scanId, string filePath, ScanFileDecisionAction action)
    {
        if (!_pending.TryGetValue(scanId, out var entry))
        {
            return false;
        }

        if (!string.Equals(entry.FilePath, filePath, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        entry.Complete(action);
        return true;
    }

    public PendingScanFilePrompt? GetPendingPrompt(int scanId)
    {
        if (!_pending.TryGetValue(scanId, out var entry))
        {
            return null;
        }

        return new PendingScanFilePrompt
        {
            ScanId = scanId,
            FilePath = entry.FilePath,
            Reason = entry.Reason,
            OccurredAt = entry.OccurredAt
        };
    }

    public void Clear(int scanId)
    {
        if (_pending.TryRemove(scanId, out var entry))
        {
            entry.Complete(ScanFileDecisionAction.Skip);
        }
    }

    private sealed class PendingDecisionEntry
    {
        private readonly TaskCompletionSource<ScanFileDecisionAction> _tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public PendingDecisionEntry(string filePath, string reason)
        {
            FilePath = filePath;
            Reason = reason;
            OccurredAt = DateTimeOffset.UtcNow;
        }

        public string FilePath { get; }
        public string Reason { get; }
        public DateTimeOffset OccurredAt { get; }
        public Task<ScanFileDecisionAction> Task => _tcs.Task;

        public void Complete(ScanFileDecisionAction action) => _tcs.TrySetResult(action);
    }
}
