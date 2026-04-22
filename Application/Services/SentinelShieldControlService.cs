using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Antivirus.Application.Services;

public sealed class SentinelShieldControlService : ISentinelShieldControlApi
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IScanRepository _scanRepository;
    private readonly IThreatRepository _threatRepository;
    private readonly IProprietaryProtectionEngine _engine;
    private readonly AntivirusPlatformOptions _options;
    private readonly ILogger<SentinelShieldControlService> _logger;

    private DateTimeOffset? _protectionPausedUntil;

    public SentinelShieldControlService(
        IServiceScopeFactory scopeFactory,
        IScanRepository scanRepository,
        IThreatRepository threatRepository,
        IProprietaryProtectionEngine engine,
        IOptions<AntivirusPlatformOptions> options,
        ILogger<SentinelShieldControlService> logger)
    {
        _scopeFactory = scopeFactory;
        _scanRepository = scanRepository;
        _threatRepository = threatRepository;
        _engine = engine;
        _options = options.Value;
        _logger = logger;
    }

    public bool IsProtectionPaused =>
        _protectionPausedUntil.HasValue && _protectionPausedUntil.Value > DateTimeOffset.UtcNow;

    public async Task<ServiceStatusDto> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        var health = await _engine.CaptureAgentHealthAsync(cancellationToken);
        var threats = await _threatRepository.GetThreatsAsync(activeOnly: true, cancellationToken);
        var recentScans = await _scanRepository.GetRecentScansAsync(1, cancellationToken);
        var lastScan = recentScans.FirstOrDefault();

        return new ServiceStatusDto
        {
            ServiceRunning = true,
            RealtimeProtectionEnabled = _options.RealtimeWatcherEnabled,
            RealtimeProtectionPaused = IsProtectionPaused,
            ProtectionPausedUntil = _protectionPausedUntil,
            EngineVersion = _options.ProprietaryEngineVersion,
            SignaturePackVersion = health.AntivirusSignatureVersion ?? _options.CurrentSignaturePackVersion,
            ActiveThreatCount = threats.Count,
            LastScan = lastScan is not null
                ? new ScanSummaryDto
                {
                    ScanId = lastScan.Id,
                    Mode = lastScan.Mode,
                    Status = lastScan.Status,
                    PercentComplete = lastScan.PercentComplete,
                    FilesScanned = lastScan.FilesScanned,
                    ThreatCount = lastScan.ThreatCount,
                    StartedAt = lastScan.StartedAt,
                    CompletedAt = lastScan.CompletedAt
                }
                : null
        };
    }

    public async Task<ScanSummaryDto> StartQuickScanAsync(string requestedBy, CancellationToken cancellationToken = default)
    {
        using var scope = _scopeFactory.CreateScope();
        var orchestrator = scope.ServiceProvider.GetRequiredService<ISecurityOrchestrator>();

        var scan = await orchestrator.QueueScanAsync(new ScanRequest
        {
            Mode = ScanMode.Quick,
            RequestedBy = requestedBy
        }, cancellationToken);

        _logger.LogInformation("Quick scan #{ScanId} queued by tray app for {RequestedBy}.", scan.Id, requestedBy);

        return new ScanSummaryDto
        {
            ScanId = scan.Id,
            Mode = scan.Mode,
            Status = scan.Status,
            PercentComplete = scan.PercentComplete,
            FilesScanned = scan.FilesScanned,
            ThreatCount = scan.ThreatCount,
            StartedAt = scan.StartedAt,
            CompletedAt = scan.CompletedAt
        };
    }

    public Task<ProtectionStatusDto> PauseProtectionAsync(TimeSpan duration, CancellationToken cancellationToken = default)
    {
        var maxPause = TimeSpan.FromHours(4);
        var effectiveDuration = duration > maxPause ? maxPause : duration;
        _protectionPausedUntil = DateTimeOffset.UtcNow.Add(effectiveDuration);

        _logger.LogWarning("Real-time protection paused until {PausedUntil}.", _protectionPausedUntil);

        return Task.FromResult(new ProtectionStatusDto
        {
            RealtimeProtectionEnabled = _options.RealtimeWatcherEnabled,
            Paused = true,
            PausedUntil = _protectionPausedUntil,
            Message = $"Protection paused for {effectiveDuration.TotalMinutes:0} minutes."
        });
    }

    public Task<ProtectionStatusDto> ResumeProtectionAsync(CancellationToken cancellationToken = default)
    {
        _protectionPausedUntil = null;
        _logger.LogInformation("Real-time protection resumed.");

        return Task.FromResult(new ProtectionStatusDto
        {
            RealtimeProtectionEnabled = _options.RealtimeWatcherEnabled,
            Paused = false,
            Message = "Protection resumed."
        });
    }

    public Task<UpdateStatusDto> CheckForUpdatesAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new UpdateStatusDto
        {
            UpdateAvailable = false,
            CurrentVersion = _options.CurrentSignaturePackVersion,
            Message = "Signature pack is up to date."
        });
    }
}
