using System.Security.Cryptography;
using System.Security;
using System.Text;
using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Security;

public sealed class RealtimeProtectionService : IRealtimeProtectionService
{
    private readonly ISecurityRepository _repository;
    private readonly IControlPlaneRepository _controlPlaneRepository;
    private readonly IFileEventBackgroundQueue _fileEventBackgroundQueue;
    private readonly IProprietaryProtectionEngine _proprietaryProtectionEngine;
    private readonly ISentinelShieldControlApi _controlService;
    private readonly AntivirusPlatformOptions _options;
    private readonly ILogger<RealtimeProtectionService> _logger;

    public RealtimeProtectionService(
        ISecurityRepository repository,
        IControlPlaneRepository controlPlaneRepository,
        IFileEventBackgroundQueue fileEventBackgroundQueue,
        IProprietaryProtectionEngine proprietaryProtectionEngine,
        ISentinelShieldControlApi controlService,
        IOptions<AntivirusPlatformOptions> options,
        ILogger<RealtimeProtectionService> logger)
    {
        _repository = repository;
        _controlPlaneRepository = controlPlaneRepository;
        _fileEventBackgroundQueue = fileEventBackgroundQueue;
        _proprietaryProtectionEngine = proprietaryProtectionEngine;
        _controlService = controlService;
        _options = options.Value;
        _logger = logger;
    }

    public async Task RegisterFileEventAsync(FileWatchNotification notification, CancellationToken cancellationToken = default)
    {
        var fileEventId = await _repository.CreateFileEventAsync(notification, scanJobId: null, cancellationToken);

        await _fileEventBackgroundQueue.QueueAsync(
            new QueuedFileEventWorkItem
            {
                FileEventId = fileEventId,
                Notification = notification
            },
            cancellationToken);
    }

    public Task<IReadOnlyCollection<FileSecurityEvent>> GetRecentFileEventsAsync(CancellationToken cancellationToken = default) =>
        _repository.GetRecentFileEventsAsync(25, cancellationToken);

    public async Task ProcessQueuedFileEventAsync(QueuedFileEventWorkItem workItem, CancellationToken cancellationToken = default)
    {
        if (_controlService.IsProtectionPaused)
        {
            await _repository.UpdateFileEventAsync(workItem.FileEventId, new FileEventUpdate
            {
                Status = FileEventStatus.Skipped,
                Notes = "Real-time protection is paused. File event was recorded but not scanned.",
                ProcessedAt = DateTimeOffset.UtcNow
            }, cancellationToken);
            return;
        }

        try
        {
            var path = workItem.Notification.FilePath;

            if (workItem.Notification.EventType == FileEventType.Deleted)
            {
                await _repository.UpdateFileEventAsync(workItem.FileEventId, new FileEventUpdate
                {
                    Status = FileEventStatus.Skipped,
                    Notes = "File was deleted before open-source analysis could run.",
                    ProcessedAt = DateTimeOffset.UtcNow
                }, cancellationToken);
                return;
            }

            if (!File.Exists(path))
            {
                await _repository.UpdateFileEventAsync(workItem.FileEventId, new FileEventUpdate
                {
                    Status = FileEventStatus.Skipped,
                    Notes = "File no longer exists.",
                    ProcessedAt = DateTimeOffset.UtcNow
                }, cancellationToken);
                return;
            }

            var fileInfo = new FileInfo(path);
            if (!fileInfo.Exists)
            {
                await _repository.UpdateFileEventAsync(workItem.FileEventId, new FileEventUpdate
                {
                    Status = FileEventStatus.Skipped,
                    Notes = "File was removed before scanning could begin.",
                    ProcessedAt = DateTimeOffset.UtcNow
                }, cancellationToken);
                return;
            }

            if ((fileInfo.Attributes & FileAttributes.Directory) == FileAttributes.Directory)
            {
                await _repository.UpdateFileEventAsync(workItem.FileEventId, new FileEventUpdate
                {
                    Status = FileEventStatus.Skipped,
                    Notes = "Directories are observed for telemetry but are not scanned.",
                    ProcessedAt = DateTimeOffset.UtcNow
                }, cancellationToken);
                return;
            }

            await _repository.UpdateFileEventAsync(workItem.FileEventId, new FileEventUpdate
            {
                Status = FileEventStatus.Processing,
                Notes = "Running proprietary engine analysis.",
                FileSizeBytes = fileInfo.Length
            }, cancellationToken);

            string? hashSha256 = null;
            if (fileInfo.Length <= _options.MaxFileScanBytes)
            {
                hashSha256 = await ComputeSha256Async(fileInfo, cancellationToken);
            }

            var primaryResult = await _proprietaryProtectionEngine.ScanFileAsync(
                null,
                workItem.Notification,
                fileInfo,
                _options.DefaultRequestedBy,
                cancellationToken);

            await _repository.SaveFileEngineResultsAsync(workItem.FileEventId, primaryResult.EngineResults, cancellationToken);

            var threatDetections = primaryResult.Threats.ToArray();

            if (threatDetections.Length > 0)
            {
                await _repository.UpsertThreatsAsync(null, threatDetections, cancellationToken);
            }

            var finalStatus = ResolveStatus(primaryResult.Verdict);
            var notes = BuildNotes(primaryResult.EngineResults, fileInfo.Length, primaryResult.Verdict);

            await _repository.UpdateFileEventAsync(workItem.FileEventId, new FileEventUpdate
            {
                Status = finalStatus,
                ThreatCount = threatDetections.Length,
                Notes = notes,
                HashSha256 = hashSha256,
                FileSizeBytes = fileInfo.Length,
                ProcessedAt = DateTimeOffset.UtcNow
            }, cancellationToken);
        }
        catch (Exception ex) when (IsSkippableAccessException(ex))
        {
            _logger.LogWarning(ex, "Skipping realtime file event {FileEventId} because the file could not be accessed.", workItem.FileEventId);
            await _repository.UpdateFileEventAsync(workItem.FileEventId, new FileEventUpdate
            {
                Status = FileEventStatus.Skipped,
                Notes = "File was skipped because it was locked, in use, or access was denied.",
                ProcessedAt = DateTimeOffset.UtcNow
            }, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Realtime processing failed for file event {FileEventId}.", workItem.FileEventId);
            await _repository.UpdateFileEventAsync(workItem.FileEventId, new FileEventUpdate
            {
                Status = FileEventStatus.Error,
                Notes = ex.Message,
                ProcessedAt = DateTimeOffset.UtcNow
            }, cancellationToken);
        }
    }

    private static FileEventStatus ResolveStatus(PipelineVerdict verdict)
    {
        return verdict switch
        {
            PipelineVerdict.Malicious => FileEventStatus.ThreatDetected,
            PipelineVerdict.Suspicious => FileEventStatus.Suspicious,
            _ => FileEventStatus.Clean
        };
    }

    private static string BuildNotes(IReadOnlyCollection<FileScannerEngineResult> results, long fileSizeBytes, PipelineVerdict verdict)
    {
        var summary = results.Count == 0
            ? "No scanners were available."
            : string.Join(
                " | ",
                results.Select(result =>
                    $"{result.EngineName}: {result.Status}{(string.IsNullOrWhiteSpace(result.SignatureName) ? string.Empty : $" ({result.SignatureName})")}"));

        return $"Size {fileSizeBytes} bytes. Primary verdict {verdict}. {summary}";
    }

    private static async Task<string> ComputeSha256Async(FileInfo fileInfo, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            fileInfo.FullName,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        using var sha256 = SHA256.Create();
        var hash = await sha256.ComputeHashAsync(stream, cancellationToken);
        return Convert.ToHexString(hash);
    }

    private static bool IsSkippableAccessException(Exception exception)
    {
        return exception switch
        {
            UnauthorizedAccessException => true,
            SecurityException => true,
            IOException => true,
            AggregateException aggregateException => aggregateException.InnerExceptions.Any(IsSkippableAccessException),
            _ when exception.InnerException is not null => IsSkippableAccessException(exception.InnerException),
            _ => false
        };
    }
}
