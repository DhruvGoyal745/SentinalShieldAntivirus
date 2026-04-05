using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security;

public sealed class ScanProcessingHostedService : BackgroundService
{
    private readonly IScanBackgroundQueue _scanBackgroundQueue;
    private readonly IScanCancellationRegistry _scanCancellationRegistry;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ISecurityRepository _securityRepository;
    private readonly ILogger<ScanProcessingHostedService> _logger;

    public ScanProcessingHostedService(
        IScanBackgroundQueue scanBackgroundQueue,
        IScanCancellationRegistry scanCancellationRegistry,
        IServiceScopeFactory scopeFactory,
        ISecurityRepository securityRepository,
        ILogger<ScanProcessingHostedService> logger)
    {
        _scanBackgroundQueue = scanBackgroundQueue;
        _scanCancellationRegistry = scanCancellationRegistry;
        _scopeFactory = scopeFactory;
        _securityRepository = securityRepository;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await ReconcileOrphanedScansAsync("Interrupted because the application host restarted before the scan could finish.", stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            QueuedScanWorkItem workItem;
            try
            {
                workItem = await _scanBackgroundQueue.DequeueAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            try
            {
                using var scope = _scopeFactory.CreateScope();
                var orchestrator = scope.ServiceProvider.GetRequiredService<ISecurityOrchestrator>();
                var executionToken = _scanCancellationRegistry.BeginExecution(workItem.ScanId, stoppingToken);
                try
                {
                    await orchestrator.ExecuteQueuedScanAsync(workItem, executionToken);
                }
                finally
                {
                    _scanCancellationRegistry.Complete(workItem.ScanId);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Background scan {ScanId} failed.", workItem.ScanId);
            }
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await ReconcileOrphanedScansAsync("Interrupted because the application host stopped before the scan could finish.", CancellationToken.None);
        await base.StopAsync(cancellationToken);
    }

    private async Task ReconcileOrphanedScansAsync(string note, CancellationToken stoppingToken)
    {
        var recoverableScans = await _securityRepository.GetRecoverableScansAsync(stoppingToken);
        foreach (var scan in recoverableScans)
        {
            await _securityRepository.UpdateScanStatusAsync(
                scan.Id,
                ScanStatus.Failed,
                ScanStage.Failed,
                scan.PercentComplete,
                scan.FilesScanned,
                scan.TotalFiles,
                scan.CurrentTarget ?? scan.TargetPath,
                scan.ThreatCount,
                note,
                scan.StartedAt ?? scan.CreatedAt,
                DateTimeOffset.UtcNow,
                stoppingToken);

            _logger.LogWarning("Marked orphaned scan {ScanId} with previous status {Status} as failed during host reconciliation.", scan.Id, scan.Status);
        }
    }
}
