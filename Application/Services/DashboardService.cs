using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Application.Services;

public sealed class DashboardService : IDashboardService
{
    private readonly IScanRepository _scanRepository;
    private readonly IThreatRepository _threatRepository;
    private readonly IFileEventRepository _fileEventRepository;
    private readonly ISecurityStatsRepository _statsRepository;
    private readonly ISecurityOrchestrator _orchestrator;

    public DashboardService(
        IScanRepository scanRepository,
        IThreatRepository threatRepository,
        IFileEventRepository fileEventRepository,
        ISecurityStatsRepository statsRepository,
        ISecurityOrchestrator orchestrator)
    {
        _scanRepository = scanRepository;
        _threatRepository = threatRepository;
        _fileEventRepository = fileEventRepository;
        _statsRepository = statsRepository;
        _orchestrator = orchestrator;
    }

    public async Task<DashboardSummary> GetDashboardAsync(CancellationToken cancellationToken = default)
    {
        var health = await _orchestrator.CaptureHealthAsync(cancellationToken);
        await _orchestrator.SyncThreatsAsync(cancellationToken);
        var recentScans = await _scanRepository.GetRecentScansAsync(10, cancellationToken);
        var threats = await _threatRepository.GetThreatsAsync(activeOnly: true, cancellationToken);
        var fileEvents = await _fileEventRepository.GetRecentFileEventsAsync(12, cancellationToken);
        var uniqueFileCount = await _statsRepository.GetDistinctFileCountAsync(cancellationToken);
        var uniqueThreatCount = await _statsRepository.GetDistinctThreatCountAsync(cancellationToken);

        return new DashboardSummary
        {
            Health = health,
            RecentScans = recentScans,
            ActiveThreats = threats,
            RecentFileEvents = fileEvents,
            UniqueFilesChecked = uniqueFileCount,
            UniqueThreatsFound = uniqueThreatCount
        };
    }
}
