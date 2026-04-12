using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Antivirus.Application.Services;

public sealed class SecurityOrchestrator : ISecurityOrchestrator
{
    private readonly ISecurityRepository _repository;
    private readonly IProprietaryProtectionEngine _proprietaryProtectionEngine;
    private readonly IScanBackgroundQueue _scanBackgroundQueue;
    private readonly IScanCancellationRegistry _scanCancellationRegistry;
    private readonly IScanFileDecisionRegistry _fileDecisionRegistry;
    private readonly AntivirusPlatformOptions _options;
    private readonly IWebHostEnvironment _environment;
    private readonly ILogger<SecurityOrchestrator> _logger;

    public SecurityOrchestrator(
        ISecurityRepository repository,
        IProprietaryProtectionEngine proprietaryProtectionEngine,
        IScanBackgroundQueue scanBackgroundQueue,
        IScanCancellationRegistry scanCancellationRegistry,
        IScanFileDecisionRegistry fileDecisionRegistry,
        IOptions<AntivirusPlatformOptions> options,
        IWebHostEnvironment environment,
        ILogger<SecurityOrchestrator> logger)
    {
        _repository = repository;
        _proprietaryProtectionEngine = proprietaryProtectionEngine;
        _scanBackgroundQueue = scanBackgroundQueue;
        _scanCancellationRegistry = scanCancellationRegistry;
        _fileDecisionRegistry = fileDecisionRegistry;
        _options = options.Value;
        _environment = environment;
        _logger = logger;
    }

    public async Task<ScanJob> QueueScanAsync(ScanRequest request, CancellationToken cancellationToken = default)
    {
        if (request.Mode == ScanMode.Custom && !string.IsNullOrWhiteSpace(request.TargetPath))
        {
            if (!File.Exists(request.TargetPath) && !Directory.Exists(request.TargetPath))
            {
                throw new InvalidOperationException($"Scan target '{request.TargetPath}' no longer exists.");
            }
        }

        var normalizedRequest = new ScanRequest
        {
            Mode = request.Mode,
            TargetPath = request.TargetPath,
            RunHeuristics = request.RunHeuristics,
            RequestedBy = string.IsNullOrWhiteSpace(request.RequestedBy) ? _options.DefaultRequestedBy : request.RequestedBy
        };

        var scanId = await _repository.CreateScanAsync(normalizedRequest, cancellationToken);
        await _repository.UpdateScanStatusAsync(scanId, new ScanStatusUpdate
        {
            Status = ScanStatus.Pending,
            Stage = ScanStage.Queued,
            Notes = "Scan queued and waiting for background execution."
        }, cancellationToken);

        await _scanBackgroundQueue.QueueAsync(
            new QueuedScanWorkItem
            {
                ScanId = scanId,
                Request = normalizedRequest
            },
            cancellationToken);

        return await _repository.GetScanByIdAsync(scanId, cancellationToken)
            ?? throw new InvalidOperationException($"Queued scan {scanId} was created but could not be reloaded.");
    }

    public async Task ExecuteQueuedScanAsync(QueuedScanWorkItem workItem, CancellationToken cancellationToken = default)
    {
        if (_scanCancellationRegistry.ConsumePendingStop(workItem.ScanId))
        {
            await MarkScanCancelledAsync(workItem.ScanId, "Scan stop requested before execution started.", cancellationToken);
            return;
        }

        var startedAt = DateTimeOffset.UtcNow;
        await _repository.UpdateScanStatusAsync(workItem.ScanId, new ScanStatusUpdate
        {
            Status = ScanStatus.Running,
            Stage = ScanStage.Observe,
            PercentComplete = 2,
            CurrentTarget = workItem.Request.TargetPath,
            Notes = "Running clean-room static, behavior, and reputation analysis.",
            StartedAt = startedAt
        }, cancellationToken);

        try
        {
            var proprietaryResult = await _proprietaryProtectionEngine.ScanRequestAsync(workItem.ScanId, workItem.Request, cancellationToken);

            var persistedThreats = proprietaryResult.Threats
                .Select(threat => new ThreatDetection
                {
                    ScanJobId = workItem.ScanId,
                    Name = threat.Name,
                    Category = threat.Category,
                    Severity = threat.Severity,
                    Source = threat.Source,
                    Resource = threat.Resource,
                    Description = threat.Description,
                    EngineName = threat.EngineName,
                    EvidenceJson = threat.EvidenceJson,
                    DetectedAt = threat.DetectedAt,
                    IsQuarantined = threat.IsQuarantined,
                    QuarantinePath = threat.QuarantinePath
                })
                .ToArray();

            await _repository.UpsertThreatsAsync(workItem.ScanId, persistedThreats, cancellationToken);

            await _repository.UpdateScanStatusAsync(workItem.ScanId, new ScanStatusUpdate
            {
                Status = ScanStatus.Completed,
                Stage = ScanStage.Completed,
                PercentComplete = 100,
                FilesScanned = proprietaryResult.FilesScanned,
                TotalFiles = proprietaryResult.TotalFiles,
                CurrentTarget = workItem.Request.TargetPath,
                ThreatCount = persistedThreats.Count(t => t.Severity is ThreatSeverity.High or ThreatSeverity.Critical),
                Notes = persistedThreats.Length > 0
                    ? $"Scan completed. {proprietaryResult.FilesScanned} file(s) scanned, {persistedThreats.Length} threat(s) detected."
                    : $"Scan completed. {proprietaryResult.FilesScanned} file(s) scanned. No threats detected.",
                StartedAt = startedAt,
                CompletedAt = DateTimeOffset.UtcNow
            }, cancellationToken);
        }
        catch (OperationCanceledException) when (_scanCancellationRegistry.IsStopRequested(workItem.ScanId) || cancellationToken.IsCancellationRequested)
        {
            await MarkScanCancelledAsync(workItem.ScanId, "Scan was stopped by the operator.", CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Scan execution failed for mode {Mode}.", workItem.Request.Mode);
            await _repository.UpdateScanStatusAsync(workItem.ScanId, new ScanStatusUpdate
            {
                Status = ScanStatus.Failed,
                Stage = ScanStage.Failed,
                PercentComplete = 100,
                CurrentTarget = workItem.Request.TargetPath,
                Notes = ex.Message,
                StartedAt = startedAt,
                CompletedAt = DateTimeOffset.UtcNow
            }, cancellationToken);
        }
    }

    public Task<IReadOnlyCollection<ScanJob>> GetRecentScansAsync(CancellationToken cancellationToken = default) =>
        _repository.GetRecentScansAsync(20, cancellationToken);

    public Task<IReadOnlyCollection<ScanProgressEvent>> GetScanProgressAsync(int scanId, CancellationToken cancellationToken = default) =>
        _repository.GetScanProgressEventsAsync(scanId, 100, cancellationToken);

    public async Task<ScanControlResult> StopScanAsync(int scanId, CancellationToken cancellationToken = default)
    {
        var scan = await _repository.GetScanByIdAsync(scanId, cancellationToken);
        if (scan is null)
        {
            return new ScanControlResult
            {
                Success = false,
                Status = ScanStatus.Failed,
                Message = "Scan record was not found."
            };
        }

        if (scan.Status is ScanStatus.Completed or ScanStatus.Failed or ScanStatus.Cancelled)
        {
            return new ScanControlResult
            {
                Success = false,
                Status = scan.Status,
                Message = $"Scan is already {scan.Status.ToString().ToLowerInvariant()}."
            };
        }

        _scanCancellationRegistry.RequestStop(scanId);
        await MarkScanCancelledAsync(scanId, "Stop requested by the operator.", cancellationToken);

        return new ScanControlResult
        {
            Success = true,
            Status = ScanStatus.Cancelled,
            Message = $"Stop requested for scan #{scanId}."
        };
    }

    public async Task<IReadOnlyCollection<ThreatDetection>> SyncThreatsAsync(CancellationToken cancellationToken = default)
    {
        return await _repository.GetThreatsAsync(activeOnly: false, cancellationToken);
    }

    public async Task<ScanFileDecisionResult> SubmitFileDecisionAsync(int scanId, ScanFileDecision decision, CancellationToken cancellationToken = default)
    {
        var scan = await _repository.GetScanByIdAsync(scanId, cancellationToken);
        if (scan is null)
        {
            return new ScanFileDecisionResult { Success = false, Message = "Scan not found." };
        }

        var submitted = _fileDecisionRegistry.SubmitDecision(scanId, decision.FilePath, decision.Action);
        if (!submitted)
        {
            return new ScanFileDecisionResult
            {
                Success = false,
                Message = "No pending file decision found for this scan. The scan may have already moved past this file."
            };
        }

        _logger.LogInformation(
            "File decision '{Action}' submitted for scan #{ScanId}, file {FilePath}.",
            decision.Action, scanId, decision.FilePath);

        return new ScanFileDecisionResult
        {
            Success = true,
            Message = $"Decision '{decision.Action}' applied for {Path.GetFileName(decision.FilePath)}."
        };
    }

    public async Task<QuarantineResult> QuarantineThreatAsync(int threatId, CancellationToken cancellationToken = default)
    {
        var threat = await _repository.GetThreatByIdAsync(threatId, cancellationToken);
        if (threat is null)
        {
            return new QuarantineResult
            {
                Success = false,
                Message = "Threat record was not found."
            };
        }

        if (threat.IsQuarantined)
        {
            return new QuarantineResult
            {
                Success = true,
                Message = "Threat is already marked as quarantined."
            };
        }

        var normalizedPath = NormalizeResourcePath(threat.Resource);
        if (string.IsNullOrWhiteSpace(normalizedPath) || !File.Exists(normalizedPath))
        {
            await _repository.MarkThreatQuarantinedAsync(threatId, null, cancellationToken);
            return new QuarantineResult
            {
                Success = true,
                Message = "Threat record marked as quarantined. The source file was not accessible, which usually means Defender already handled it."
            };
        }

        var quarantineDirectory = Path.GetFullPath(Path.Combine(_environment.ContentRootPath, _options.QuarantineRoot));
        Directory.CreateDirectory(quarantineDirectory);

        var invalidChars = Path.GetInvalidFileNameChars();
        var safeFileName = string.Concat(Path.GetFileName(normalizedPath).Select(character => invalidChars.Contains(character) ? '_' : character));
        var destination = Path.Combine(quarantineDirectory, $"{DateTimeOffset.UtcNow:yyyyMMddHHmmss}_{safeFileName}");

        File.Move(normalizedPath, destination, overwrite: true);
        await _repository.MarkThreatQuarantinedAsync(threatId, destination, cancellationToken);

        return new QuarantineResult
        {
            Success = true,
            Message = $"Threat moved to quarantine at {destination}."
        };
    }

    public async Task<DeviceHealthSnapshot> CaptureHealthAsync(CancellationToken cancellationToken = default)
    {
        var snapshot = await _proprietaryProtectionEngine.CaptureAgentHealthAsync(cancellationToken);
        await _repository.SaveHealthSnapshotAsync(snapshot, cancellationToken);
        return snapshot;
    }

    private static string? NormalizeResourcePath(string? resource)
    {
        if (string.IsNullOrWhiteSpace(resource))
        {
            return null;
        }

        var trimmed = resource.Trim();
        if (trimmed.StartsWith("file:", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed["file:".Length..];
        }

        trimmed = trimmed.Trim('"').Trim();
        return Path.IsPathRooted(trimmed) ? trimmed : null;
    }

    private async Task MarkScanCancelledAsync(int scanId, string message, CancellationToken cancellationToken)
    {
        var existingScan = await _repository.GetScanByIdAsync(scanId, cancellationToken);
        await _repository.UpdateScanStatusAsync(scanId, new ScanStatusUpdate
        {
            Status = ScanStatus.Cancelled,
            Stage = ScanStage.Cancelled,
            PercentComplete = existingScan?.PercentComplete ?? 0,
            FilesScanned = existingScan?.FilesScanned ?? 0,
            TotalFiles = existingScan?.TotalFiles,
            CurrentTarget = existingScan?.CurrentTarget ?? existingScan?.TargetPath,
            ThreatCount = existingScan?.ThreatCount ?? 0,
            Notes = message,
            StartedAt = existingScan?.StartedAt ?? existingScan?.CreatedAt,
            CompletedAt = DateTimeOffset.UtcNow
        }, cancellationToken);
    }
}
