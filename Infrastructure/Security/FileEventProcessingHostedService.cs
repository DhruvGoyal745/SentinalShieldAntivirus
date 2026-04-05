using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security;

public sealed class FileEventProcessingHostedService : BackgroundService
{
    private readonly IFileEventBackgroundQueue _fileEventBackgroundQueue;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<FileEventProcessingHostedService> _logger;

    public FileEventProcessingHostedService(
        IFileEventBackgroundQueue fileEventBackgroundQueue,
        IServiceScopeFactory scopeFactory,
        ILogger<FileEventProcessingHostedService> logger)
    {
        _fileEventBackgroundQueue = fileEventBackgroundQueue;
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            QueuedFileEventWorkItem workItem;
            try
            {
                workItem = await _fileEventBackgroundQueue.DequeueAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            try
            {
                using var scope = _scopeFactory.CreateScope();
                var realtimeProtectionService = scope.ServiceProvider.GetRequiredService<IRealtimeProtectionService>();
                await realtimeProtectionService.ProcessQueuedFileEventAsync(workItem, stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Realtime file event {FileEventId} failed.", workItem.FileEventId);
            }
        }
    }
}
