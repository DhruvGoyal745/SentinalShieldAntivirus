using Antivirus.Domain;

namespace Antivirus.Application.Contracts;

public interface ISentinelShieldControlApi
{
    bool IsProtectionPaused { get; }

    Task<ServiceStatusDto> GetStatusAsync(CancellationToken cancellationToken = default);

    Task<ScanSummaryDto> StartQuickScanAsync(string requestedBy, CancellationToken cancellationToken = default);

    Task<ProtectionStatusDto> PauseProtectionAsync(TimeSpan duration, CancellationToken cancellationToken = default);

    Task<ProtectionStatusDto> ResumeProtectionAsync(CancellationToken cancellationToken = default);

    Task<UpdateStatusDto> CheckForUpdatesAsync(CancellationToken cancellationToken = default);
}

public sealed class ServiceStatusDto
{
    public required bool ServiceRunning { get; init; }

    public required bool RealtimeProtectionEnabled { get; init; }

    public required bool RealtimeProtectionPaused { get; init; }

    public DateTimeOffset? ProtectionPausedUntil { get; init; }

    public required string EngineVersion { get; init; }

    public required string SignaturePackVersion { get; init; }

    public required int ActiveThreatCount { get; init; }

    public ScanSummaryDto? LastScan { get; init; }

    public DateTimeOffset CapturedAt { get; init; } = DateTimeOffset.UtcNow;
}

public sealed class ProtectionStatusDto
{
    public required bool RealtimeProtectionEnabled { get; init; }

    public required bool Paused { get; init; }

    public DateTimeOffset? PausedUntil { get; init; }

    public required string Message { get; init; }
}

public sealed class ScanSummaryDto
{
    public int ScanId { get; init; }

    public ScanMode Mode { get; init; }

    public ScanStatus Status { get; init; }

    public int PercentComplete { get; init; }

    public int FilesScanned { get; init; }

    public int ThreatCount { get; init; }

    public DateTimeOffset? StartedAt { get; init; }

    public DateTimeOffset? CompletedAt { get; init; }
}

public sealed class UpdateStatusDto
{
    public required bool UpdateAvailable { get; init; }

    public required string CurrentVersion { get; init; }

    public string? AvailableVersion { get; init; }

    public required string Message { get; init; }
}

public sealed class TrayNotificationDto
{
    public required string Title { get; init; }

    public required string Message { get; init; }

    public required TrayNotificationLevel Level { get; init; }

    public string? ActionUrl { get; init; }

    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
}

public enum TrayNotificationLevel
{
    Info,
    Warning,
    Threat,
    ScanComplete
}
