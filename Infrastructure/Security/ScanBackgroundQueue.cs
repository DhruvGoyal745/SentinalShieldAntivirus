using System.Threading.Channels;
using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security;

public sealed class ScanBackgroundQueue : IScanBackgroundQueue
{
    private readonly Channel<QueuedScanWorkItem> _channel = Channel.CreateUnbounded<QueuedScanWorkItem>(
        new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });

    public ValueTask QueueAsync(QueuedScanWorkItem workItem, CancellationToken cancellationToken = default) =>
        _channel.Writer.WriteAsync(workItem, cancellationToken);

    public ValueTask<QueuedScanWorkItem> DequeueAsync(CancellationToken cancellationToken) =>
        _channel.Reader.ReadAsync(cancellationToken);
}
