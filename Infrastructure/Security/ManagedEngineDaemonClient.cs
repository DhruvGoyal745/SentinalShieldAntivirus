using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security;
using System.Text;
using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Security;

public sealed class ManagedEngineDaemonClient : IEngineDaemonClient
{
    private readonly IStaticFileScanner _staticFileScanner;
    private readonly IBehaviorMonitor _behaviorMonitor;
    private readonly IReputationClient _reputationClient;
    private readonly ISandboxSubmissionClient _sandboxSubmissionClient;
    private readonly IRemediationCoordinator _remediationCoordinator;
    private readonly IControlPlaneRepository _controlPlaneRepository;
    private readonly AntivirusPlatformOptions _options;
    private readonly ILogger<ManagedEngineDaemonClient> _logger;
    private readonly ConcurrentDictionary<int, ScanStatusSnapshot> _scanStatuses = new();
    private readonly ConcurrentDictionary<int, List<ScanProgressEvent>> _scanProgress = new();
    private readonly ConcurrentDictionary<int, List<EngineDetection>> _scanDetections = new();
    private ProprietarySignaturePack? _currentPack;

    public ManagedEngineDaemonClient(
        IStaticFileScanner staticFileScanner,
        IBehaviorMonitor behaviorMonitor,
        IReputationClient reputationClient,
        ISandboxSubmissionClient sandboxSubmissionClient,
        IRemediationCoordinator remediationCoordinator,
        IControlPlaneRepository controlPlaneRepository,
        IOptions<AntivirusPlatformOptions> options,
        ILogger<ManagedEngineDaemonClient> logger)
    {
        _staticFileScanner = staticFileScanner;
        _behaviorMonitor = behaviorMonitor;
        _reputationClient = reputationClient;
        _sandboxSubmissionClient = sandboxSubmissionClient;
        _remediationCoordinator = remediationCoordinator;
        _controlPlaneRepository = controlPlaneRepository;
        _options = options.Value;
        _logger = logger;
    }

    public Task<LoadSignaturePackResult> LoadSignaturePackAsync(ProprietarySignaturePack pack, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _currentPack = pack;

        return Task.FromResult(new LoadSignaturePackResult
        {
            Success = true,
            Version = pack.Manifest.Version,
            RuleCount = pack.Rules.Count,
            Message = "Managed clean-room engine pack loaded successfully."
        });
    }

    public async Task<ScanHandle> StartManualScanAsync(
        int scanJobId,
        ScanRequest request,
        Func<ScanProgressEvent, Task> onProgress,
        CancellationToken cancellationToken = default)
    {
        var pack = _currentPack ?? throw new InvalidOperationException("No signature pack is loaded.");
        var startedAt = DateTimeOffset.UtcNow;
        var detections = new ConcurrentBag<EngineDetection>();
        var progressEvents = new List<ScanProgressEvent>();
        var progressSync = new object();
        var scanInputs = ResolveRoots(request).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var discovered = DiscoverTargets(scanInputs, cancellationToken);
        var targets = discovered.Targets.ToArray();
        var skippedCandidates = discovered.SkippedCandidates;

        var totalFiles = targets.Length;
        var processedFiles = 0;
        var publishedFiles = 0;
        var lastPublishedPercent = -1;
        var lastPublishedStage = ScanStage.Queued;
        var lastPublishedAt = DateTimeOffset.MinValue;

        await PublishProgressAsync(
            scanJobId,
            startedAt,
            progressEvents,
            onProgress,
            ScanStage.Observe,
            4,
            0,
            totalFiles,
            scanInputs.FirstOrDefault(),
            0,
            cancellationToken);

        foreach (var skippedCandidate in skippedCandidates)
        {
            await MaybePublishManualProgressAsync(
                ScanStage.Observe,
                skippedCandidate.Path,
                0,
                force: true,
                isSkipped: true,
                detailMessage: skippedCandidate.Message,
                cancellationToken);
        }

        var parallelOptions = new ParallelOptions
        {
            CancellationToken = cancellationToken,
            MaxDegreeOfParallelism = Math.Max(1, _options.MaxParallelScanWorkers)
        };

        await Parallel.ForEachAsync(targets, parallelOptions, async (path, loopToken) =>
        {
            try
            {
                var file = new FileInfo(path);
                if (!file.Exists)
                {
                    Interlocked.Increment(ref processedFiles);
                    return;
                }

                var result = await ScanArtifactInternalAsync(
                    null,
                    new FileArtifact
                    {
                        FullPath = file.FullName,
                        FileName = file.Name,
                        SizeBytes = file.Length,
                        EventType = FileEventType.Changed,
                        ObservedAt = DateTimeOffset.UtcNow
                    },
                    request.RequestedBy,
                    pack,
                    persistOperationalArtifacts: false,
                    loopToken);

                foreach (var detection in result.Detections)
                {
                    detections.Add(detection);
                }

                var completedFiles = Interlocked.Increment(ref processedFiles);
                await MaybePublishManualProgressAsync(result.Stage, path, completedFiles, force: false, isSkipped: false, detailMessage: null, loopToken);
            }
            catch (Exception ex) when (IsSkippableAccessException(ex))
            {
                _logger.LogWarning(ex, "Skipping inaccessible file during scan {ScanId}: {Path}", scanJobId, path);
                var completedFiles = Interlocked.Increment(ref processedFiles);
                await MaybePublishManualProgressAsync(
                    ScanStage.Telemetry,
                    path,
                    completedFiles,
                    force: true,
                    isSkipped: true,
                    detailMessage: "File was skipped because it is locked, in use by another process, or access was denied.",
                    loopToken);
            }
        });

        if (totalFiles == 0)
        {
            await MaybePublishManualProgressAsync(ScanStage.Telemetry, scanInputs.FirstOrDefault(), 0, force: true, isSkipped: false, detailMessage: null, cancellationToken);
        }

        var completedAt = DateTimeOffset.UtcNow;
        var finalStage = ScanStage.Completed;
        var finalStatus = BuildStatusSnapshot(
            scanJobId,
            ScanStatus.Completed,
            finalStage,
            100,
            processedFiles,
            totalFiles,
            scanInputs.LastOrDefault(),
            detections.Count,
            startedAt,
            completedAt);
        _scanStatuses[scanJobId] = finalStatus;
        _scanDetections[scanJobId] = detections.ToList();

        await PublishProgressAsync(
            scanJobId,
            startedAt,
            progressEvents,
            onProgress,
            finalStage,
            100,
            processedFiles,
            totalFiles,
            scanInputs.LastOrDefault(),
            detections.Count,
            cancellationToken,
            completedAt);

        _scanProgress[scanJobId] = progressEvents.OrderBy(progressEvent => progressEvent.RecordedAt).ToList();

        return new ScanHandle
        {
            ScanJobId = scanJobId,
            EngineScanId = $"managed-{scanJobId}"
        };

        async Task MaybePublishManualProgressAsync(
            ScanStage stage,
            string? currentPath,
            int filesScanned,
            bool force,
            bool isSkipped,
            string? detailMessage,
            CancellationToken token)
        {
            var percent = totalFiles <= 0
                ? 100
                : Math.Min(98, 10 + (int)Math.Round((filesScanned / (double)totalFiles) * 88, MidpointRounding.AwayFromZero));
            var findingsCount = detections.Count;
            ScanProgressEvent? progressEvent = null;

            lock (progressSync)
            {
                var enoughFilesPassed = filesScanned - publishedFiles >= Math.Max(1, _options.ProgressPersistEveryFiles);
                var enoughTimePassed = DateTimeOffset.UtcNow - lastPublishedAt >= TimeSpan.FromMilliseconds(Math.Max(100, _options.ProgressPersistMinIntervalMs));
                var stageChanged = stage != lastPublishedStage;
                var percentChanged = percent > lastPublishedPercent;
                var shouldPublish = force
                    || filesScanned >= totalFiles
                    || filesScanned == 1
                    || stageChanged
                    || (enoughFilesPassed && percentChanged)
                    || (enoughTimePassed && percentChanged);

                if (!shouldPublish)
                {
                    return;
                }

                publishedFiles = filesScanned;
                lastPublishedPercent = percent;
                lastPublishedStage = stage;
                lastPublishedAt = DateTimeOffset.UtcNow;

                var snapshot = BuildStatusSnapshot(
                    scanJobId,
                    ScanStatus.Running,
                    stage,
                    percent,
                    filesScanned,
                    totalFiles,
                    currentPath,
                    findingsCount,
                    startedAt,
                    null);
                _scanStatuses[scanJobId] = snapshot;

                progressEvent = new ScanProgressEvent
                {
                    ScanJobId = scanJobId,
                    Stage = stage,
                    PercentComplete = percent,
                    CurrentPath = currentPath,
                    FilesScanned = filesScanned,
                    TotalFiles = totalFiles,
                    FindingsCount = findingsCount,
                    IsSkipped = isSkipped,
                    DetailMessage = detailMessage,
                    StartedAt = startedAt,
                    RecordedAt = DateTimeOffset.UtcNow
                };
            }

            if (progressEvent is not null)
            {
                await PublishProgressAsync(
                    scanJobId,
                    startedAt,
                    progressEvents,
                    onProgress,
                    progressEvent.Stage,
                    progressEvent.PercentComplete,
                    progressEvent.FilesScanned,
                    progressEvent.TotalFiles,
                    progressEvent.CurrentPath,
                    progressEvent.FindingsCount,
                    token,
                    progressEvent.CompletedAt);
            }
        }
    }

    public Task<ScanStatusSnapshot> GetScanStatusAsync(int scanJobId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (_scanStatuses.TryGetValue(scanJobId, out var snapshot))
        {
            return Task.FromResult(snapshot);
        }

        return Task.FromResult(new ScanStatusSnapshot
        {
            ScanJobId = scanJobId,
            Status = ScanStatus.Pending,
            Stage = ScanStage.Queued,
            PercentComplete = 0,
            FilesScanned = 0,
            FindingsCount = 0,
            StartedAt = DateTimeOffset.UtcNow
        });
    }

    public async IAsyncEnumerable<ScanProgressEvent> SubscribeScanProgressAsync(
        int scanJobId,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (_scanProgress.TryGetValue(scanJobId, out var events))
        {
            foreach (var progressEvent in events.OrderBy(progressEvent => progressEvent.RecordedAt))
            {
                cancellationToken.ThrowIfCancellationRequested();
                yield return progressEvent;
                await Task.Yield();
            }
        }
    }

    public async Task<(PipelineScanResult Result, RealtimeSubmissionResult Submission)> SubmitRealtimeFileEventAsync(
        int fileEventId,
        FileArtifact artifact,
        string requestedBy,
        CancellationToken cancellationToken = default)
    {
        var pack = _currentPack ?? throw new InvalidOperationException("No signature pack is loaded.");
        var scanResult = await ScanArtifactInternalAsync(fileEventId, artifact, requestedBy, pack, persistOperationalArtifacts: true, cancellationToken);
        return (scanResult.PipelineResult, new RealtimeSubmissionResult
        {
            FileEventId = fileEventId,
            EngineSubmissionId = $"realtime-{fileEventId}",
            Accepted = true,
            Message = "Realtime artifact processed by the managed clean-room daemon."
        });
    }

    public Task<IReadOnlyCollection<EngineDetection>> GetDetectionsForScanAsync(int scanJobId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_scanDetections.TryGetValue(scanJobId, out var detections))
        {
            return Task.FromResult<IReadOnlyCollection<EngineDetection>>(detections.ToArray());
        }

        return Task.FromResult<IReadOnlyCollection<EngineDetection>>(Array.Empty<EngineDetection>());
    }

    public async Task<QuarantineResult> QuarantineFileAsync(string path, CancellationToken cancellationToken = default)
    {
        var file = new FileInfo(path);
        var (quarantined, quarantinePath) = await _remediationCoordinator.QuarantineAsync(file, cancellationToken);
        return new QuarantineResult
        {
            Success = quarantined,
            Message = quarantined
                ? $"Artifact moved to quarantine at {quarantinePath}."
                : "Artifact could not be quarantined."
        };
    }

    public Task<EngineHealthSnapshot> GetEngineHealthAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var currentPack = _currentPack;
        return Task.FromResult(new EngineHealthSnapshot
        {
            EngineOnline = true,
            EngineVersion = _options.SignatureCompilerVersion,
            SignaturePackVersion = currentPack?.Manifest.Version ?? "unloaded",
            ParserCompatibilityVersion = currentPack?.ParserCompatibilityVersion ?? _options.ParserCompatibilityVersion,
            RealtimeMonitoringEnabled = _options.RealtimeWatcherEnabled,
            DaemonTransport = OperatingSystem.IsWindows() ? $"named-pipe:{_options.NativeEnginePipeName}" : $"unix-socket:{_options.NativeEngineSocketPath}",
            CapturedAt = DateTimeOffset.UtcNow
        });
    }

    private async Task<ManagedScanArtifactResult> ScanArtifactInternalAsync(
        int? fileEventId,
        FileArtifact artifact,
        string requestedBy,
        ProprietarySignaturePack pack,
        bool persistOperationalArtifacts,
        CancellationToken cancellationToken)
    {
        var file = new FileInfo(artifact.FullPath);
        if (!file.Exists)
        {
            return new ManagedScanArtifactResult(
                ScanStage.Telemetry,
                99,
                new PipelineScanResult
                {
                    Verdict = PipelineVerdict.Clean
                },
                Array.Empty<EngineDetection>());
        }

        var hash = artifact.HashSha256;
        if (string.IsNullOrWhiteSpace(hash) && file.Length <= _options.MaxHashComputationBytes)
        {
            hash = await ComputeSha256Async(file, cancellationToken);
        }

        var staticDetections = !string.IsNullOrWhiteSpace(hash)
            ? await _staticFileScanner.ScanAsync(file, hash, cancellationToken)
            : Array.Empty<DetectionEventRecord>();
        var behaviorDetections = await _behaviorMonitor.AnalyzeAsync(
            new FileWatchNotification
            {
                FilePath = file.FullName,
                EventType = artifact.EventType,
                ObservedAt = artifact.ObservedAt
            },
            file,
            cancellationToken);

        var allDetections = staticDetections.Concat(behaviorDetections).ToList();

        if (!string.IsNullOrWhiteSpace(hash))
        {
            var reputationDetection = await _reputationClient.EvaluateAsync(file, hash, cancellationToken);
            if (reputationDetection is not null)
            {
                allDetections.Add(reputationDetection);
            }
        }

        var verdict = ResolveVerdict(allDetections);
        var sandboxSubmission = persistOperationalArtifacts && !string.IsNullOrWhiteSpace(hash)
            ? await _sandboxSubmissionClient.SubmitIfNeededAsync(
                ResolveDeviceId(),
                file,
                hash!,
                verdict,
                allDetections,
                cancellationToken)
            : null;

        var (quarantined, quarantinePath) = verdict == PipelineVerdict.Malicious
            ? await _remediationCoordinator.QuarantineAsync(file, cancellationToken)
            : (false, null as string);

        var engineDetections = allDetections
            .Select(detection => new EngineDetection
            {
                RuleId = detection.RuleId,
                EngineName = detection.EngineName,
                Source = detection.Source,
                Severity = detection.Severity,
                Confidence = detection.Confidence,
                Summary = detection.Summary,
                ArtifactPath = artifact.FullPath,
                EvidenceJson = string.IsNullOrWhiteSpace(hash) ? null : $"{{\"sha256\":\"{hash}\"}}"
            })
            .ToArray();

        var incidentDetections = engineDetections
            .Where(IsThreatLevelIncidentDetection)
            .ToArray();

        if (persistOperationalArtifacts && verdict == PipelineVerdict.Malicious && incidentDetections.Length > 0)
        {
            var strongest = incidentDetections
                .OrderByDescending(detection => detection.Severity)
                .ThenByDescending(detection => detection.Confidence)
                .First();
            await _controlPlaneRepository.CreateIncidentAsync(new SecurityIncident
            {
                DeviceId = ResolveDeviceId(),
                Title = strongest.Summary,
                Severity = strongest.Severity,
                Status = quarantined ? IncidentStatus.Contained : IncidentStatus.Open,
                Source = strongest.Source.ToString(),
                PrimaryArtifact = artifact.FullPath,
                RuleId = strongest.RuleId,
                Confidence = strongest.Confidence,
                Summary = strongest.Summary,
                UpdatedAt = DateTimeOffset.UtcNow
            }, cancellationToken);
        }

        if (persistOperationalArtifacts && quarantined)
        {
            await _controlPlaneRepository.SaveRemediationActionAsync(new RemediationActionRecord
            {
                DeviceId = ResolveDeviceId(),
                ActionKind = RemediationActionKind.Quarantine,
                Status = RemediationStatus.Completed,
                RequestedBy = requestedBy,
                Notes = $"Artifact quarantined to {quarantinePath}.",
                CompletedAt = DateTimeOffset.UtcNow
            }, cancellationToken);
        }

        var threatDetections = engineDetections.Select(detection => new ThreatDetection
        {
            Name = detection.RuleId,
            Category = detection.Source.ToString(),
            Severity = detection.Severity,
            Source = detection.Source,
            Resource = detection.ArtifactPath,
            Description = detection.Summary,
            EngineName = detection.EngineName,
            EvidenceJson = detection.EvidenceJson,
            DetectedAt = DateTimeOffset.UtcNow,
            IsQuarantined = quarantined,
            QuarantinePath = quarantinePath
        }).ToArray();

        var engineResults = engineDetections.Select(detection => new FileScannerEngineResult
        {
            EngineName = detection.EngineName,
            Source = detection.Source,
            Status = detection.Severity is ThreatSeverity.High or ThreatSeverity.Critical
                ? FileEngineResultStatus.ThreatDetected
                : FileEngineResultStatus.Suspicious,
            IsMatch = true,
            SignatureName = detection.RuleId,
            Details = detection.Summary
        }).ToList();

        if (sandboxSubmission is not null)
        {
            engineResults.Add(new FileScannerEngineResult
            {
                EngineName = "Sentinel Sandbox Broker",
                Source = ThreatSource.Sandbox,
                Status = FileEngineResultStatus.Suspicious,
                IsMatch = true,
                SignatureName = sandboxSubmission.CorrelationId,
                Details = sandboxSubmission.BehaviorSummary
            });
        }

        return new ManagedScanArtifactResult(
            verdict == PipelineVerdict.Clean ? ScanStage.Telemetry : verdict == PipelineVerdict.Suspicious ? ScanStage.ReputationLookup : ScanStage.Response,
            verdict == PipelineVerdict.Clean ? 96 : verdict == PipelineVerdict.Suspicious ? 90 : 94,
            new PipelineScanResult
            {
                Verdict = verdict,
                EngineResults = engineResults,
                Threats = threatDetections,
                DetectionEvents = allDetections,
                Quarantined = quarantined,
                QuarantinePath = quarantinePath,
                SandboxSubmission = sandboxSubmission
            },
            engineDetections);
    }

    private static async Task<string> ComputeSha256Async(FileInfo file, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var sha256 = SHA256.Create();
        var hash = await sha256.ComputeHashAsync(stream, cancellationToken);
        return Convert.ToHexString(hash);
    }

    private IEnumerable<string> ResolveRoots(ScanRequest request)
    {
        if (request.Mode == ScanMode.Custom && !string.IsNullOrWhiteSpace(request.TargetPath))
        {
            yield return request.TargetPath;
            yield break;
        }

        foreach (var root in _options.WatchRoots)
        {
            yield return root
                .Replace("%USERPROFILE%", Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), StringComparison.OrdinalIgnoreCase)
                .Replace("%TEMP%", Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase)
                .Replace("%APPDATA%", Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), StringComparison.OrdinalIgnoreCase);
        }
    }

    private DiscoveryResult DiscoverTargets(IEnumerable<string> inputs, CancellationToken cancellationToken)
    {
        var targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var skippedCandidates = new List<SkippedCandidate>();

        foreach (var input in inputs)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (File.Exists(input))
            {
                targets.Add(input);
                continue;
            }

            if (Directory.Exists(input))
            {
                DiscoverDirectoryTargets(input, targets, skippedCandidates, cancellationToken);
                continue;
            }

            skippedCandidates.Add(new SkippedCandidate(
                input,
                "The path could not be scanned because it does not exist or is not accessible."));
        }

        return new DiscoveryResult(targets, skippedCandidates);
    }

    private void DiscoverDirectoryTargets(
        string root,
        HashSet<string> targets,
        List<SkippedCandidate> skippedCandidates,
        CancellationToken cancellationToken)
    {
        var pendingDirectories = new Stack<string>();
        pendingDirectories.Push(root);

        while (pendingDirectories.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = pendingDirectories.Pop();

            IEnumerable<string> entries;
            try
            {
                entries = Directory.EnumerateFileSystemEntries(current);
            }
            catch (Exception ex) when (IsSkippableAccessException(ex))
            {
                skippedCandidates.Add(new SkippedCandidate(
                    current,
                    "The antivirus skipped this location because access was denied or it was unavailable during enumeration."));
                continue;
            }

            foreach (var entry in entries)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    var attributes = File.GetAttributes(entry);
                    if ((attributes & FileAttributes.Directory) == FileAttributes.Directory)
                    {
                        pendingDirectories.Push(entry);
                    }
                    else
                    {
                        targets.Add(entry);
                    }
                }
                catch (Exception ex) when (IsSkippableAccessException(ex))
                {
                    skippedCandidates.Add(new SkippedCandidate(
                        entry,
                        "The antivirus skipped this file because access was denied or it was unavailable during discovery."));
                }
            }
        }
    }

    private static PipelineVerdict ResolveVerdict(IEnumerable<DetectionEventRecord> detections)
    {
        var materialized = detections.ToArray();
        if (materialized.Any(detection => detection.Severity is ThreatSeverity.High or ThreatSeverity.Critical || detection.Confidence >= 0.9m))
        {
            return PipelineVerdict.Malicious;
        }

        return materialized.Length > 0 ? PipelineVerdict.Suspicious : PipelineVerdict.Clean;
    }

    private async Task PublishProgressAsync(
        int scanJobId,
        DateTimeOffset startedAt,
        List<ScanProgressEvent> progressEvents,
        Func<ScanProgressEvent, Task> onProgress,
        ScanStage stage,
        int percentComplete,
        int filesScanned,
        int? totalFiles,
        string? currentPath,
        int findingsCount,
        CancellationToken cancellationToken,
        DateTimeOffset? completedAt = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var progressEvent = new ScanProgressEvent
        {
            ScanJobId = scanJobId,
            Stage = stage,
            PercentComplete = percentComplete,
            CurrentPath = currentPath,
            FilesScanned = filesScanned,
            TotalFiles = totalFiles,
            FindingsCount = findingsCount,
            StartedAt = startedAt,
            CompletedAt = completedAt,
            RecordedAt = DateTimeOffset.UtcNow
        };

        lock (progressEvents)
        {
            progressEvents.Add(progressEvent);
        }
        await onProgress(progressEvent);
    }

    private static ScanStatusSnapshot BuildStatusSnapshot(
        int scanJobId,
        ScanStatus status,
        ScanStage stage,
        int percentComplete,
        int filesScanned,
        int? totalFiles,
        string? currentTarget,
        int findingsCount,
        DateTimeOffset startedAt,
        DateTimeOffset? completedAt)
    {
        return new ScanStatusSnapshot
        {
            ScanJobId = scanJobId,
            Status = status,
            Stage = stage,
            PercentComplete = percentComplete,
            FilesScanned = filesScanned,
            TotalFiles = totalFiles,
            CurrentTarget = currentTarget,
            FindingsCount = findingsCount,
            StartedAt = startedAt,
            CompletedAt = completedAt
        };
    }

    private static int ComputePercent(int index, int total, int lowerBound, int upperBound)
    {
        if (total <= 0)
        {
            return upperBound;
        }

        var ratio = (index + 1d) / total;
        return lowerBound + (int)Math.Round((upperBound - lowerBound) * ratio, MidpointRounding.AwayFromZero);
    }

    private static string ResolveDeviceId() => $"{Environment.MachineName.ToLowerInvariant()}-agent";

    private static bool IsThreatLevelIncidentDetection(EngineDetection detection)
    {
        return detection.Severity is ThreatSeverity.High or ThreatSeverity.Critical
            || detection.Confidence >= 0.9m;
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

    private sealed record ManagedScanArtifactResult(
        ScanStage Stage,
        int PercentComplete,
        PipelineScanResult PipelineResult,
        IReadOnlyCollection<EngineDetection> Detections);

    private sealed record SkippedCandidate(string Path, string Message);

    private sealed record DiscoveryResult(
        IReadOnlyCollection<string> Targets,
        IReadOnlyCollection<SkippedCandidate> SkippedCandidates);
}
