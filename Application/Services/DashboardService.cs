using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Application.Services;

public sealed class DashboardService : IDashboardService
{
    private readonly ISecurityRepository _repository;
    private readonly ISecurityOrchestrator _orchestrator;

    public DashboardService(ISecurityRepository repository, ISecurityOrchestrator orchestrator)
    {
        _repository = repository;
        _orchestrator = orchestrator;
    }

    public async Task<DashboardSummary> GetDashboardAsync(CancellationToken cancellationToken = default)
    {
        var health = await _orchestrator.CaptureHealthAsync(cancellationToken);
        await _orchestrator.SyncThreatsAsync(cancellationToken);
        var recentScans = await _repository.GetRecentScansAsync(10, cancellationToken);
        var threats = await _repository.GetThreatsAsync(activeOnly: true, cancellationToken);
        var fileEvents = await _repository.GetRecentFileEventsAsync(12, cancellationToken);

        return new DashboardSummary
        {
            Health = health,
            RecentScans = recentScans,
            ActiveThreats = threats,
            RecentFileEvents = fileEvents
        };
    }
}
