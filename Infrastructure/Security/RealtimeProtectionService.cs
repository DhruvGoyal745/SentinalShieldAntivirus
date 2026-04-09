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
    private readonly IReadOnlyCollection<IOpenSourceScannerEngine> _scannerEngines;
    private readonly ISentinelShieldControlApi _controlService;
    private readonly AntivirusPlatformOptions _options;
    private readonly ILogger<RealtimeProtectionService> _logger;

    public RealtimeProtectionService(
        ISecurityRepository repository,
        IControlPlaneRepository controlPlaneRepository,
        IFileEventBackgroundQueue fileEventBackgroundQueue,
        IProprietaryProtectionEngine proprietaryProtectionEngine,
        IEnumerable<IOpenSourceScannerEngine> scannerEngines,
        ISentinelShieldControlApi controlService,
        IOptions<AntivirusPlatformOptions> options,
        ILogger<RealtimeProtectionService> logger)
    {
        _repository = repository;
        _controlPlaneRepository = controlPlaneRepository;
        _fileEventBackgroundQueue = fileEventBackgroundQueue;
        _proprietaryProtectionEngine = proprietaryProtectionEngine;
        _scannerEngines = scannerEngines.ToArray();
        _controlService = controlService;
        _options = options.Value;
        _logger = logger;
    }

    public async Task RegisterFileEventAsync(FileWatchNotification notification, CancellationToken cancellationToken = default)
    {
        var fileEventId = await _repository.CreateFileEventAsync(notification, cancellationToken);

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
            await _repository.UpdateFileEventAsync(
                workItem.FileEventId,
                FileEventStatus.Skipped,
                0,
                "Real-time protection is paused. File event was recorded but not scanned.",
                null,
                null,
                DateTimeOffset.UtcNow,
                cancellationToken);
            return;
        }

        try
        {
            var path = workItem.Notification.FilePath;

            if (workItem.Notification.EventType == FileEventType.Deleted)
            {
                await _repository.UpdateFileEventAsync(
                    workItem.FileEventId,
                    FileEventStatus.Skipped,
                    0,
                    "File was deleted before open-source analysis could run.",
                    null,
                    null,
                    DateTimeOffset.UtcNow,
                    cancellationToken);
                return;
            }

            if (!File.Exists(path))
            {
                await _repository.UpdateFileEventAsync(
                    workItem.FileEventId,
                    FileEventStatus.Skipped,
                    0,
                    "File no longer exists.",
                    null,
                    null,
                    DateTimeOffset.UtcNow,
                    cancellationToken);
                return;
            }

            var fileInfo = new FileInfo(path);
            if ((fileInfo.Attributes & FileAttributes.Directory) == FileAttributes.Directory)
            {
                await _repository.UpdateFileEventAsync(
                    workItem.FileEventId,
                    FileEventStatus.Skipped,
                    0,
                    "Directories are observed for telemetry but are not scanned.",
                    null,
                    null,
                    DateTimeOffset.UtcNow,
                    cancellationToken);
                return;
            }

            await _repository.UpdateFileEventAsync(
                workItem.FileEventId,
                FileEventStatus.Processing,
                0,
                "Running proprietary engine analysis with legacy parity capture.",
                null,
                fileInfo.Length,
                null,
                cancellationToken);

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

            var results = new List<FileScannerEngineResult>(primaryResult.EngineResults);
            var legacyMatches = 0;
            if (_options.UseLegacyShadowMode && _options.UseInHouseScanners)
            {
                foreach (var scanner in _scannerEngines)
                {
                    try
                    {
                        var result = await scanner.ScanAsync(fileInfo, cancellationToken);
                        if (result.IsMatch)
                        {
                            legacyMatches++;
                        }

                        results.Add(new FileScannerEngineResult
                        {
                            EngineName = $"{result.EngineName} (shadow)",
                            Source = result.Source,
                            Status = result.Status,
                            IsMatch = result.IsMatch,
                            SignatureName = result.SignatureName,
                            Details = result.Details,
                            RawOutput = result.RawOutput,
                            ScannedAt = result.ScannedAt
                        });
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Open-source engine {Engine} failed for {Path}.", scanner.EngineName, fileInfo.FullName);
                        results.Add(new FileScannerEngineResult
                        {
                            EngineName = scanner.EngineName,
                            Source = scanner.Source,
                            Status = FileEngineResultStatus.Error,
                            Details = ex.Message,
                            RawOutput = ex.ToString()
                        });
                    }
                }

                await _controlPlaneRepository.SaveLegacyParitySnapshotAsync(
                    new LegacyParitySnapshot
                    {
                        DeviceId = $"{Environment.MachineName.ToLowerInvariant()}-agent",
                        OperatingSystem = OperatingSystemPlatform.Windows,
                        MalwareFamily = primaryResult.Threats.FirstOrDefault()?.Name ?? "Unknown",
                        DetectionRecallPercent = primaryResult.Threats.Count > 0 && legacyMatches > 0 ? 100m : primaryResult.Threats.Count == 0 && legacyMatches == 0 ? 100m : 50m,
                        FalsePositiveRatePercent = primaryResult.Threats.Count == 0 && legacyMatches > 0 ? 100m : 0m,
                        VerdictLatencyMilliseconds = 250m,
                        RemediationSuccessPercent = primaryResult.Quarantined || primaryResult.Verdict != PipelineVerdict.Malicious ? 100m : 0m,
                        CrashTamperRatePercent = 0m,
                        CreatedAt = DateTimeOffset.UtcNow
                    },
                    cancellationToken);
            }

            await _repository.SaveFileEngineResultsAsync(workItem.FileEventId, results, cancellationToken);

            var threatDetections = primaryResult.Threats.ToArray();

            if (threatDetections.Length > 0)
            {
                await _repository.UpsertThreatsAsync(null, threatDetections, cancellationToken);
            }

            var finalStatus = ResolveStatus(primaryResult.Verdict);
            var notes = BuildNotes(results, fileInfo.Length, primaryResult.Verdict, _options.UseLegacyShadowMode);

            await _repository.UpdateFileEventAsync(
                workItem.FileEventId,
                finalStatus,
                threatDetections.Length,
                notes,
                hashSha256,
                fileInfo.Length,
                DateTimeOffset.UtcNow,
                cancellationToken);
        }
        catch (Exception ex) when (IsSkippableAccessException(ex))
        {
            _logger.LogWarning(ex, "Skipping realtime file event {FileEventId} because the file could not be accessed.", workItem.FileEventId);
            await _repository.UpdateFileEventAsync(
                workItem.FileEventId,
                FileEventStatus.Skipped,
                0,
                "File was skipped because it was locked, in use, or access was denied.",
                null,
                null,
                DateTimeOffset.UtcNow,
                cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Realtime processing failed for file event {FileEventId}.", workItem.FileEventId);
            await _repository.UpdateFileEventAsync(
                workItem.FileEventId,
                FileEventStatus.Error,
                0,
                ex.Message,
                null,
                null,
                DateTimeOffset.UtcNow,
                cancellationToken);
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

    private static string BuildNotes(IReadOnlyCollection<FileScannerEngineResult> results, long fileSizeBytes, PipelineVerdict verdict, bool legacyShadowMode)
    {
        var summary = results.Count == 0
            ? "No scanners were available."
            : string.Join(
                " | ",
                results.Select(result =>
                    $"{result.EngineName}: {result.Status}{(string.IsNullOrWhiteSpace(result.SignatureName) ? string.Empty : $" ({result.SignatureName})")}"));

        var shadowText = legacyShadowMode ? " Legacy engines were run in shadow mode for parity capture." : string.Empty;
        return $"Size {fileSizeBytes} bytes. Primary verdict {verdict}. {summary}{shadowText}";
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
