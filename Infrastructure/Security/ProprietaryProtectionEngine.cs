using System.Collections.Concurrent;
using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Security;

public sealed class ProprietaryProtectionEngine : IProprietaryProtectionEngine
{
    private readonly IEngineDaemonClient _engineDaemonClient;
    private readonly ISignaturePackProvider _signaturePackProvider;
    private readonly ISecurityRepository _securityRepository;
    private readonly AntivirusPlatformOptions _options;
    private readonly ConcurrentDictionary<int, ProgressWriteState> _progressWriteStates = new();

    public ProprietaryProtectionEngine(
        IEngineDaemonClient engineDaemonClient,
        ISignaturePackProvider signaturePackProvider,
        ISecurityRepository securityRepository,
        IOptions<AntivirusPlatformOptions> options)
    {
        _engineDaemonClient = engineDaemonClient;
        _signaturePackProvider = signaturePackProvider;
        _securityRepository = securityRepository;
        _options = options.Value;
    }

    public async Task<PipelineScanResult> ScanFileAsync(
        int? scanJobId,
        FileWatchNotification notification,
        FileInfo file,
        string requestedBy,
        CancellationToken cancellationToken = default)
    {
        var pack = await _signaturePackProvider.GetCompiledPackAsync(cancellationToken);
        await _engineDaemonClient.LoadSignaturePackAsync(pack, cancellationToken);

        var artifact = new FileArtifact
        {
            FullPath = file.FullName,
            FileName = file.Name,
            SizeBytes = file.Exists ? file.Length : 0,
            EventType = notification.EventType,
            ObservedAt = notification.ObservedAt
        };

        var (result, _) = await _engineDaemonClient.SubmitRealtimeFileEventAsync(
            scanJobId ?? 0,
            artifact,
            requestedBy,
            cancellationToken);

        return result;
    }

    public async Task<PipelineScanResult> ScanRequestAsync(int scanJobId, ScanRequest request, CancellationToken cancellationToken = default)
    {
        var pack = await _signaturePackProvider.GetCompiledPackAsync(cancellationToken);
        await _engineDaemonClient.LoadSignaturePackAsync(pack, cancellationToken);

        await _engineDaemonClient.StartManualScanAsync(
            scanJobId,
            request,
            progressEvent => PersistProgressAsync(scanJobId, progressEvent, cancellationToken),
            cancellationToken);

        var detections = await _engineDaemonClient.GetDetectionsForScanAsync(scanJobId, cancellationToken);
        var statusSnapshot = await _engineDaemonClient.GetScanStatusAsync(scanJobId, cancellationToken);

        var threats = detections.Select(detection => new ThreatDetection
        {
            ScanJobId = scanJobId,
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

        var engineResults = detections.Select(detection => new FileScannerEngineResult
        {
            EngineName = detection.EngineName,
            Source = detection.Source,
            Status = detection.Severity is ThreatSeverity.High or ThreatSeverity.Critical
                ? FileEngineResultStatus.ThreatDetected
                : FileEngineResultStatus.Suspicious,
            IsMatch = true,
            SignatureName = detection.RuleId,
            Details = detection.Summary
        }).ToArray();

        return new PipelineScanResult
        {
            Verdict = statusSnapshot.FindingsCount > 0 ? PipelineVerdict.Malicious : PipelineVerdict.Clean,
            EngineResults = engineResults,
            Threats = threats,
            FilesScanned = statusSnapshot.FilesScanned,
            TotalFiles = statusSnapshot.TotalFiles ?? statusSnapshot.FilesScanned,
            DetectionEvents = detections.Select(detection => new DetectionEventRecord
            {
                RuleId = detection.RuleId,
                EngineName = detection.EngineName,
                Source = detection.Source,
                Severity = detection.Severity,
                Confidence = detection.Confidence,
                Summary = detection.Summary
            }).ToArray(),
            Quarantined = threats.Any(threat => threat.IsQuarantined),
            QuarantinePath = threats.LastOrDefault(threat => threat.IsQuarantined)?.QuarantinePath
        };
    }

    public async Task<DeviceHealthSnapshot> CaptureAgentHealthAsync(CancellationToken cancellationToken = default)
    {
        var engineHealth = await _engineDaemonClient.GetEngineHealthAsync(cancellationToken);
        return new DeviceHealthSnapshot
        {
            CapturedAt = engineHealth.CapturedAt,
            AntivirusEnabled = engineHealth.EngineOnline,
            RealTimeProtectionEnabled = engineHealth.RealtimeMonitoringEnabled,
            IoavProtectionEnabled = true,
            NetworkInspectionEnabled = false,
            EngineServiceEnabled = engineHealth.EngineOnline,
            SignaturesOutOfDate = false,
            AntivirusSignatureVersion = engineHealth.SignaturePackVersion,
            AntivirusSignatureLastUpdated = engineHealth.CapturedAt,
            QuickScanAgeDays = null,
            FullScanAgeDays = null
        };
    }

    private async Task PersistProgressAsync(int scanJobId, ScanProgressEvent progressEvent, CancellationToken cancellationToken)
    {
        var shouldPersist = ShouldPersistProgress(scanJobId, progressEvent);
        if (!shouldPersist)
        {
            return;
        }

        var existingScan = await _securityRepository.GetScanByIdAsync(scanJobId, cancellationToken);
        if (existingScan?.Status == ScanStatus.Cancelled)
        {
            return;
        }

        await _securityRepository.AppendScanProgressAsync(progressEvent, cancellationToken);

        var status = progressEvent.CompletedAt.HasValue
            ? ScanStatus.Completed
            : ScanStatus.Running;

        await _securityRepository.UpdateScanStatusAsync(scanJobId, new ScanStatusUpdate
        {
            Status = status,
            Stage = progressEvent.Stage,
            PercentComplete = progressEvent.PercentComplete,
            FilesScanned = progressEvent.FilesScanned,
            TotalFiles = progressEvent.TotalFiles,
            CurrentTarget = progressEvent.CurrentPath,
            ThreatCount = progressEvent.FindingsCount,
            Notes = BuildProgressNote(progressEvent),
            StartedAt = progressEvent.StartedAt,
            CompletedAt = progressEvent.CompletedAt
        }, cancellationToken);

        if (progressEvent.CompletedAt.HasValue)
        {
            _progressWriteStates.TryRemove(scanJobId, out _);
        }
    }

    private static string BuildProgressNote(ScanProgressEvent progressEvent)
    {
        return progressEvent.Stage switch
        {
            ScanStage.Observe => "Enumerating configured scan roots.",
            ScanStage.Normalize => "Normalizing file metadata and preparing ingestion.",
            ScanStage.StaticAnalysis => "Applying clean-room static signatures.",
            ScanStage.HeuristicAnalysis => "Running behavioral and heuristic correlation.",
            ScanStage.ReputationLookup => "Checking reputation and optional sandbox enrichment.",
            ScanStage.Response => "Evaluating remediation and quarantine actions.",
            ScanStage.Telemetry => "Persisting telemetry and detections.",
            ScanStage.Completed => "Clean-room scan finished successfully.",
            ScanStage.Failed => "Clean-room scan failed before completion.",
            _ => "Clean-room daemon is processing the scan."
        };
    }

    private bool ShouldPersistProgress(int scanJobId, ScanProgressEvent progressEvent)
    {
        if (progressEvent.IsSkipped)
        {
            _progressWriteStates[scanJobId] = new ProgressWriteState(
                progressEvent.FilesScanned,
                progressEvent.Stage,
                progressEvent.RecordedAt,
                progressEvent.PercentComplete);
            return true;
        }

        if (progressEvent.CompletedAt.HasValue)
        {
            return true;
        }

        var now = progressEvent.RecordedAt;
        var currentState = _progressWriteStates.GetOrAdd(
            scanJobId,
            _ => new ProgressWriteState(0, progressEvent.Stage, DateTimeOffset.MinValue, -1));

        var enoughFilesPassed = progressEvent.FilesScanned - currentState.FilesScanned >= Math.Max(1, _options.ProgressPersistEveryFiles);
        var enoughTimePassed = now - currentState.RecordedAt >= TimeSpan.FromMilliseconds(Math.Max(100, _options.ProgressPersistMinIntervalMs));
        var stageChanged = progressEvent.Stage != currentState.Stage;
        var percentChanged = progressEvent.PercentComplete > currentState.PercentComplete;
        var shouldPersist = progressEvent.FilesScanned <= 1
            || stageChanged
            || (enoughFilesPassed && percentChanged)
            || (enoughTimePassed && percentChanged);

        if (shouldPersist)
        {
            _progressWriteStates[scanJobId] = new ProgressWriteState(
                progressEvent.FilesScanned,
                progressEvent.Stage,
                now,
                progressEvent.PercentComplete);
        }

        return shouldPersist;
    }

    private sealed record ProgressWriteState(
        int FilesScanned,
        ScanStage Stage,
        DateTimeOffset RecordedAt,
        int PercentComplete);
}
