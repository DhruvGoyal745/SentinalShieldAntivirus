using System.Collections.Concurrent;
using Antivirus.Application.Contracts;

namespace Antivirus.Infrastructure.Security;

public sealed class ScanCancellationRegistry : IScanCancellationRegistry
{
    private readonly ConcurrentDictionary<int, CancellationTokenSource> _activeExecutions = new();
    private readonly ConcurrentDictionary<int, byte> _pendingStops = new();

    public CancellationToken BeginExecution(int scanId, CancellationToken stoppingToken)
    {
        var cancellationSource = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        if (!_activeExecutions.TryAdd(scanId, cancellationSource))
        {
            cancellationSource.Dispose();
            cancellationSource = _activeExecutions[scanId];
        }

        if (_pendingStops.ContainsKey(scanId))
        {
            cancellationSource.Cancel();
        }

        return cancellationSource.Token;
    }

    public bool RequestStop(int scanId)
    {
        _pendingStops[scanId] = 0;
        if (_activeExecutions.TryGetValue(scanId, out var cancellationSource))
        {
            cancellationSource.Cancel();
        }

        return true;
    }

    public bool ConsumePendingStop(int scanId) => _pendingStops.TryRemove(scanId, out _);

    public bool IsStopRequested(int scanId) => _pendingStops.ContainsKey(scanId);

    public void Complete(int scanId)
    {
        _pendingStops.TryRemove(scanId, out _);
        if (_activeExecutions.TryRemove(scanId, out var cancellationSource))
        {
            cancellationSource.Dispose();
        }
    }
}
