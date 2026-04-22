using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security;

public sealed class ScanProcessingHostedService : BackgroundService
{
    private readonly IScanBackgroundQueue _scanBackgroundQueue;
    private readonly IScanCancellationRegistry _scanCancellationRegistry;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IScanRepository _securityRepository;
    private readonly ILogger<ScanProcessingHostedService> _logger;

    public ScanProcessingHostedService(
        IScanBackgroundQueue scanBackgroundQueue,
        IScanCancellationRegistry scanCancellationRegistry,
        IServiceScopeFactory scopeFactory,
        IScanRepository securityRepository,
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
            await _securityRepository.UpdateScanStatusAsync(scan.Id, new ScanStatusUpdate
            {
                Status = ScanStatus.Failed,
                Stage = ScanStage.Failed,
                PercentComplete = scan.PercentComplete,
                FilesScanned = scan.FilesScanned,
                TotalFiles = scan.TotalFiles,
                CurrentTarget = scan.CurrentTarget ?? scan.TargetPath,
                ThreatCount = scan.ThreatCount,
                Notes = note,
                StartedAt = scan.StartedAt ?? scan.CreatedAt,
                CompletedAt = DateTimeOffset.UtcNow
            }, stoppingToken);

            _logger.LogWarning("Marked orphaned scan {ScanId} with previous status {Status} as failed during host reconciliation.", scan.Id, scan.Status);
        }
    }
}
