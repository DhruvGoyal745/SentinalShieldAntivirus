using System.Threading.Channels;
using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security;

public sealed class FileEventBackgroundQueue : IFileEventBackgroundQueue
{
    private readonly Channel<QueuedFileEventWorkItem> _channel = Channel.CreateUnbounded<QueuedFileEventWorkItem>(
        new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });

    public ValueTask QueueAsync(QueuedFileEventWorkItem workItem, CancellationToken cancellationToken = default) =>
        _channel.Writer.WriteAsync(workItem, cancellationToken);

    public ValueTask<QueuedFileEventWorkItem> DequeueAsync(CancellationToken cancellationToken) =>
        _channel.Reader.ReadAsync(cancellationToken);
}
