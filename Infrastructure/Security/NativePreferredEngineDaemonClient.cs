using System.Collections.Concurrent;
using System.Text.Json;
using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
using Antivirus.Infrastructure.Runtime;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Security;

public sealed class NativePreferredEngineDaemonClient : IEngineDaemonClient
{
    private readonly ManagedEngineDaemonClient _managedFallback;
    private readonly IProcessCommandRunner _processCommandRunner;
    private readonly AntivirusPlatformOptions _options;
    private readonly ILogger<NativePreferredEngineDaemonClient> _logger;
    private readonly ConcurrentDictionary<int, ScanStatusSnapshot> _scanStatuses = new();
    private readonly ConcurrentDictionary<int, List<ScanProgressEvent>> _scanProgress = new();
    private readonly ConcurrentDictionary<int, List<EngineDetection>> _scanDetections = new();
    private ProprietarySignaturePack? _currentPack;

    public NativePreferredEngineDaemonClient(
        ManagedEngineDaemonClient managedFallback,
        IProcessCommandRunner processCommandRunner,
        IOptions<AntivirusPlatformOptions> options,
        ILogger<NativePreferredEngineDaemonClient> logger)
    {
        _managedFallback = managedFallback;
        _processCommandRunner = processCommandRunner;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<LoadSignaturePackResult> LoadSignaturePackAsync(
        ProprietarySignaturePack pack,
        CancellationToken cancellationToken = default)
    {
        _currentPack = pack;

        if (!CanUseNativeDaemon())
        {
            return await _managedFallback.LoadSignaturePackAsync(pack, cancellationToken);
        }

        return new LoadSignaturePackResult
        {
            Success = true,
            Version = pack.Manifest.Version,
            RuleCount = pack.Rules.Count,
            Message = "Native daemon pack staged successfully."
        };
    }

    public async Task<ScanHandle> StartManualScanAsync(
        int scanJobId,
        ScanRequest request,
        Func<ScanProgressEvent, Task> onProgress,
        CancellationToken cancellationToken = default)
    {
        if (!CanUseNativeDaemon())
        {
            return await _managedFallback.StartManualScanAsync(scanJobId, request, onProgress, cancellationToken);
        }

        var result = await TryRunNativeScanAsync(scanJobId, request, cancellationToken);
        if (result is null)
        {
            return await _managedFallback.StartManualScanAsync(scanJobId, request, onProgress, cancellationToken);
        }

        _scanStatuses[scanJobId] = result.Status;
        _scanDetections[scanJobId] = result.Detections.ToList();
        _scanProgress[scanJobId] = result.ProgressEvents.OrderBy(progress => progress.RecordedAt).ToList();

        foreach (var progressEvent in result.ProgressEvents.OrderBy(progress => progress.RecordedAt))
        {
            cancellationToken.ThrowIfCancellationRequested();
            await onProgress(progressEvent);
        }

        return new ScanHandle
        {
            ScanJobId = scanJobId,
            EngineScanId = $"native-{scanJobId}"
        };
    }

    public Task<ScanStatusSnapshot> GetScanStatusAsync(int scanJobId, CancellationToken cancellationToken = default)
    {
        if (_scanStatuses.TryGetValue(scanJobId, out var status))
        {
            return Task.FromResult(status);
        }

        return _managedFallback.GetScanStatusAsync(scanJobId, cancellationToken);
    }

    public async IAsyncEnumerable<ScanProgressEvent> SubscribeScanProgressAsync(
        int scanJobId,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (_scanProgress.TryGetValue(scanJobId, out var progressEvents))
        {
            foreach (var progressEvent in progressEvents.OrderBy(progress => progress.RecordedAt))
            {
                cancellationToken.ThrowIfCancellationRequested();
                yield return progressEvent;
                await Task.Yield();
            }

            yield break;
        }

        await foreach (var progressEvent in _managedFallback.SubscribeScanProgressAsync(scanJobId, cancellationToken))
        {
            yield return progressEvent;
        }
    }

    public async Task<(PipelineScanResult Result, RealtimeSubmissionResult Submission)> SubmitRealtimeFileEventAsync(
        int fileEventId,
        FileArtifact artifact,
        string requestedBy,
        CancellationToken cancellationToken = default)
    {
        if (!CanUseNativeDaemon())
        {
            return await _managedFallback.SubmitRealtimeFileEventAsync(fileEventId, artifact, requestedBy, cancellationToken);
        }

        var nativeResult = await TryRunNativeRealtimeAsync(fileEventId, artifact, requestedBy, cancellationToken);
        if (nativeResult is not null)
        {
            return nativeResult.Value;
        }

        return await _managedFallback.SubmitRealtimeFileEventAsync(fileEventId, artifact, requestedBy, cancellationToken);
    }

    public Task<IReadOnlyCollection<EngineDetection>> GetDetectionsForScanAsync(int scanJobId, CancellationToken cancellationToken = default)
    {
        if (_scanDetections.TryGetValue(scanJobId, out var detections))
        {
            return Task.FromResult<IReadOnlyCollection<EngineDetection>>(detections.ToArray());
        }

        return _managedFallback.GetDetectionsForScanAsync(scanJobId, cancellationToken);
    }

    public Task<QuarantineResult> QuarantineFileAsync(string path, CancellationToken cancellationToken = default) =>
        _managedFallback.QuarantineFileAsync(path, cancellationToken);

    public async Task<EngineHealthSnapshot> GetEngineHealthAsync(CancellationToken cancellationToken = default)
    {
        if (!CanUseNativeDaemon())
        {
            return await _managedFallback.GetEngineHealthAsync(cancellationToken);
        }

        var daemonPath = ResolveNativeDaemonPath();
        var result = await _processCommandRunner.RunAsync(
            daemonPath,
            BuildHealthArguments(),
            cancellationToken);

        if (result.ExitCode != 0)
        {
            _logger.LogWarning("Native daemon health probe failed: {Error}", result.StandardError);
            return await _managedFallback.GetEngineHealthAsync(cancellationToken);
        }

        try
        {
            var payload = JsonSerializer.Deserialize<NativeHealthPayload>(
                result.StandardOutput,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (payload is not null)
            {
                return new EngineHealthSnapshot
                {
                    EngineOnline = payload.EngineOnline,
                    EngineVersion = payload.EngineVersion ?? _options.ProprietaryEngineVersion,
                    SignaturePackVersion = payload.SignaturePackVersion ?? _currentPack?.Manifest.Version ?? "unloaded",
                    ParserCompatibilityVersion = payload.ParserCompatibilityVersion ?? _options.ParserCompatibilityVersion,
                    RealtimeMonitoringEnabled = payload.RealtimeMonitoringEnabled,
                    DaemonTransport = payload.DaemonTransport ?? $"native-process:{Path.GetFileName(daemonPath)}",
                    CapturedAt = payload.CapturedAt ?? DateTimeOffset.UtcNow
                };
            }
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "Failed to parse native daemon health payload.");
        }

        return await _managedFallback.GetEngineHealthAsync(cancellationToken);
    }

    private async Task<NativeScanExecutionResult?> TryRunNativeScanAsync(
        int scanJobId,
        ScanRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            var daemonPath = ResolveNativeDaemonPath();
            var packPath = ResolvePackPath();
            var result = await _processCommandRunner.RunAsync(
                daemonPath,
                BuildScanArguments(scanJobId, request, packPath),
                cancellationToken);

            if (result.ExitCode != 0)
            {
                _logger.LogWarning("Native daemon scan failed for scan {ScanId}: {Error}", scanJobId, result.StandardError);
                return null;
            }

            return ParseNativeScanResponse(result.StandardOutput, scanJobId);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Native daemon scan bridge failed for scan {ScanId}.", scanJobId);
            return null;
        }
    }

    private async Task<(PipelineScanResult Result, RealtimeSubmissionResult Submission)?> TryRunNativeRealtimeAsync(
        int fileEventId,
        FileArtifact artifact,
        string requestedBy,
        CancellationToken cancellationToken)
    {
        try
        {
            var daemonPath = ResolveNativeDaemonPath();
            var packPath = ResolvePackPath();
            var args = $"--realtime --file-event-id {fileEventId} --path {QuoteArg(artifact.FullPath)} --requested-by {QuoteArg(requestedBy)} --pack {QuoteArg(packPath)}";
            var result = await _processCommandRunner.RunAsync(daemonPath, args, cancellationToken);
            if (result.ExitCode != 0)
            {
                _logger.LogWarning("Native daemon realtime submission failed for event {FileEventId}: {Error}", fileEventId, result.StandardError);
                return null;
            }

            var response = ParseNativeScanResponse(result.StandardOutput, fileEventId);
            if (response is null)
            {
                return null;
            }

            return (
                BuildPipelineResult(response.Detections),
                new RealtimeSubmissionResult
                {
                    FileEventId = fileEventId,
                    Accepted = true,
                    EngineSubmissionId = $"native-realtime-{fileEventId}",
                    Message = "Realtime artifact processed by the native clean-room daemon."
                });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Native daemon realtime bridge failed for event {FileEventId}.", fileEventId);
            return null;
        }
    }

    private NativeScanExecutionResult? ParseNativeScanResponse(string output, int scanJobId)
    {
        try
        {
            var payload = JsonSerializer.Deserialize<NativeScanPayload>(
                output,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (payload is null)
            {
                return null;
            }

            var detections = (payload.Detections ?? [])
                .Select(detection => new EngineDetection
                {
                    RuleId = detection.RuleId ?? "native-rule",
                    EngineName = detection.EngineName ?? "Sentinel Native Static Engine",
                    Source = Enum.TryParse<ThreatSource>(detection.Source, true, out var source) ? source : ThreatSource.ProprietaryStatic,
                    Severity = Enum.TryParse<ThreatSeverity>(detection.Severity, true, out var severity) ? severity : ThreatSeverity.Medium,
                    Confidence = detection.Confidence ?? 0.75m,
                    Summary = detection.Summary ?? "Native engine match.",
                    ArtifactPath = detection.ArtifactPath,
                    EvidenceJson = detection.EvidenceJson
                })
                .ToArray();

            var progressEvents = (payload.ProgressEvents ?? [])
                .Select(progress => new ScanProgressEvent
                {
                    ScanJobId = scanJobId,
                    Stage = Enum.TryParse<ScanStage>(progress.Stage, true, out var stage) ? stage : ScanStage.Telemetry,
                    PercentComplete = progress.PercentComplete ?? 0,
                    CurrentPath = progress.CurrentPath,
                    FilesScanned = progress.FilesScanned ?? 0,
                    TotalFiles = progress.TotalFiles,
                    FindingsCount = progress.FindingsCount ?? detections.Length,
                    IsSkipped = progress.IsSkipped ?? false,
                    DetailMessage = progress.DetailMessage,
                    StartedAt = progress.StartedAt ?? DateTimeOffset.UtcNow,
                    CompletedAt = progress.CompletedAt,
                    RecordedAt = progress.RecordedAt ?? DateTimeOffset.UtcNow
                })
                .ToList();

            var finalStatus = new ScanStatusSnapshot
            {
                ScanJobId = scanJobId,
                Status = Enum.TryParse<ScanStatus>(payload.Status, true, out var status) ? status : ScanStatus.Completed,
                Stage = Enum.TryParse<ScanStage>(payload.Stage, true, out var stage) ? stage : ScanStage.Completed,
                PercentComplete = payload.PercentComplete ?? 100,
                FilesScanned = payload.FilesScanned ?? progressEvents.LastOrDefault()?.FilesScanned ?? 0,
                TotalFiles = payload.TotalFiles ?? progressEvents.LastOrDefault()?.TotalFiles,
                CurrentTarget = payload.CurrentTarget,
                FindingsCount = detections.Length,
                StartedAt = payload.StartedAt ?? DateTimeOffset.UtcNow,
                CompletedAt = payload.CompletedAt ?? DateTimeOffset.UtcNow
            };

            return new NativeScanExecutionResult(finalStatus, progressEvents, detections);
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "Failed to parse native scan response.");
            return null;
        }
    }

    private PipelineScanResult BuildPipelineResult(IReadOnlyCollection<EngineDetection> detections)
    {
        var threats = detections.Select(detection => new ThreatDetection
        {
            Name = detection.RuleId,
            Category = detection.Source.ToString(),
            Severity = detection.Severity,
            Source = detection.Source,
            Resource = detection.ArtifactPath,
            Description = detection.Summary,
            EngineName = detection.EngineName,
            EvidenceJson = detection.EvidenceJson,
            DetectedAt = DateTimeOffset.UtcNow
        }).ToArray();

        return new PipelineScanResult
        {
            Verdict = detections.Any(detection => detection.Severity is ThreatSeverity.High or ThreatSeverity.Critical)
                ? PipelineVerdict.Malicious
                : detections.Count > 0
                    ? PipelineVerdict.Suspicious
                    : PipelineVerdict.Clean,
            Threats = threats,
            DetectionEvents = detections.Select(detection => new DetectionEventRecord
            {
                RuleId = detection.RuleId,
                EngineName = detection.EngineName,
                Source = detection.Source,
                Severity = detection.Severity,
                Confidence = detection.Confidence,
                Summary = detection.Summary
            }).ToArray(),
            EngineResults = detections.Select(detection => new FileScannerEngineResult
            {
                EngineName = detection.EngineName,
                Source = detection.Source,
                Status = detection.Severity is ThreatSeverity.High or ThreatSeverity.Critical
                    ? FileEngineResultStatus.ThreatDetected
                    : FileEngineResultStatus.Suspicious,
                IsMatch = true,
                SignatureName = detection.RuleId,
                Details = detection.Summary
            }).ToArray()
        };
    }

    private bool CanUseNativeDaemon()
    {
        if (!_options.UseNativeEngineBridge)
        {
            return false;
        }

        return File.Exists(ResolveNativeDaemonPath());
    }

    private string ResolveNativeDaemonPath() =>
        Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, _options.NativeEngineDaemonPath));

    private string ResolvePackPath()
    {
        var pack = _currentPack ?? throw new InvalidOperationException("No signature pack is loaded.");
        return Path.GetFullPath(
            Path.Combine(
                SentinelRuntimePaths.ResolveSignaturePackRoot(_options),
                $"{pack.Manifest.Version}.sspack.json"));
    }

    private string BuildHealthArguments()
    {
        var currentPackVersion = _currentPack?.Manifest.Version ?? "unloaded";
        return $"--health --engine-version {QuoteArg(_options.ProprietaryEngineVersion)} --pack-version {QuoteArg(currentPackVersion)} --parser-version {QuoteArg(_options.ParserCompatibilityVersion)}";
    }

    private string BuildScanArguments(int scanJobId, ScanRequest request, string packPath)
    {
        var target = request.Mode == ScanMode.Custom && !string.IsNullOrWhiteSpace(request.TargetPath)
            ? request.TargetPath
            : string.Join(Path.PathSeparator, SentinelRuntimePaths.ResolveWatchRoots(_options.WatchRoots));

        return $"--scan --scan-id {scanJobId} --mode {QuoteArg(request.Mode.ToString())} --requested-by {QuoteArg(request.RequestedBy)} --target {QuoteArg(target ?? string.Empty)} --pack {QuoteArg(packPath)}";
    }

    private static string QuoteArg(string value) => $"\"{value.Replace("\"", "\\\"", StringComparison.Ordinal)}\"";

    private sealed record NativeScanExecutionResult(
        ScanStatusSnapshot Status,
        IReadOnlyCollection<ScanProgressEvent> ProgressEvents,
        IReadOnlyCollection<EngineDetection> Detections);

    private sealed class NativeHealthPayload
    {
        public bool EngineOnline { get; init; }

        public string? EngineVersion { get; init; }

        public string? SignaturePackVersion { get; init; }

        public string? ParserCompatibilityVersion { get; init; }

        public bool RealtimeMonitoringEnabled { get; init; }

        public string? DaemonTransport { get; init; }

        public DateTimeOffset? CapturedAt { get; init; }
    }

    private sealed class NativeScanPayload
    {
        public string? Status { get; init; }

        public string? Stage { get; init; }

        public int? PercentComplete { get; init; }

        public int? FilesScanned { get; init; }

        public int? TotalFiles { get; init; }

        public string? CurrentTarget { get; init; }

        public DateTimeOffset? StartedAt { get; init; }

        public DateTimeOffset? CompletedAt { get; init; }

        public NativeProgressPayload[]? ProgressEvents { get; init; }

        public NativeDetectionPayload[]? Detections { get; init; }
    }

    private sealed class NativeProgressPayload
    {
        public string? Stage { get; init; }

        public int? PercentComplete { get; init; }

        public string? CurrentPath { get; init; }

        public int? FilesScanned { get; init; }

        public int? TotalFiles { get; init; }

        public int? FindingsCount { get; init; }

        public bool? IsSkipped { get; init; }

        public string? DetailMessage { get; init; }

        public DateTimeOffset? StartedAt { get; init; }

        public DateTimeOffset? CompletedAt { get; init; }

        public DateTimeOffset? RecordedAt { get; init; }
    }

    private sealed class NativeDetectionPayload
    {
        public string? RuleId { get; init; }

        public string? EngineName { get; init; }

        public string? Source { get; init; }

        public string? Severity { get; init; }

        public decimal? Confidence { get; init; }

        public string? Summary { get; init; }

        public string? ArtifactPath { get; init; }

        public string? EvidenceJson { get; init; }
    }
}
