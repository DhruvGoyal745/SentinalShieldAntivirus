using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Application.Services;

public sealed class EnterpriseDashboardService : IEnterpriseDashboardService
{
    private readonly ITenantRegistry _tenantRegistry;
    private readonly IControlPlaneRepository _controlPlaneRepository;
    private readonly IComplianceService _complianceService;

    public EnterpriseDashboardService(
        ITenantRegistry tenantRegistry,
        IControlPlaneRepository controlPlaneRepository,
        IComplianceService complianceService)
    {
        _tenantRegistry = tenantRegistry;
        _controlPlaneRepository = controlPlaneRepository;
        _complianceService = complianceService;
    }

    public async Task<EnterpriseDashboardSummary> GetSummaryAsync(CancellationToken cancellationToken = default)
    {
        var tenant = await _tenantRegistry.GetCurrentTenantAsync(cancellationToken);
        var devices = await _controlPlaneRepository.GetDevicesAsync(cancellationToken);
        var incidents = await _controlPlaneRepository.GetIncidentsAsync(cancellationToken);
        var packs = await _controlPlaneRepository.GetSignaturePacksAsync(cancellationToken);
        var reviews = await _controlPlaneRepository.GetFalsePositiveReviewsAsync(cancellationToken);
        var sandbox = await _controlPlaneRepository.GetSandboxSubmissionsAsync(cancellationToken);
        var complianceReports = await _controlPlaneRepository.GetComplianceReportsAsync(cancellationToken);
        if (complianceReports.Count == 0)
        {
            complianceReports = new[] { await _complianceService.CaptureAsync(cancellationToken) };
        }

        var latestCompliance = complianceReports
            .OrderByDescending(report => report.ReportDate)
            .ThenByDescending(report => report.CreatedAt)
            .First();
        var currentPack = packs.OrderByDescending(pack => pack.ReleasedAt ?? pack.CreatedAt).FirstOrDefault();

        var fleet = new FleetPostureSummary
        {
            TenantKey = tenant.TenantKey,
            DeviceCount = devices.Count,
            ActiveDeviceCount = devices.Count(device => device.EnrollmentStatus == DeviceEnrollmentStatus.Active),
            OpenIncidentCount = incidents.Count(incident => incident.Status != IncidentStatus.Resolved),
            CriticalThreatCount = incidents.Count(incident => incident.Severity is ThreatSeverity.Critical or ThreatSeverity.High && incident.Status != IncidentStatus.Resolved),
            AgentCoveragePercent = latestCompliance.AgentCoveragePercent,
            SignatureCurrencyPercent = latestCompliance.SignatureCurrencyPercent,
            PolicyCompliancePercent = latestCompliance.PolicyCompliancePercent,
            BaselineCoveragePercent = latestCompliance.BaselineScanCompletionPercent,
            SelfProtectionCoveragePercent = latestCompliance.SelfProtectionCoveragePercent,
            CurrentPackVersion = currentPack?.Version ?? "Unavailable"
        };

        return new EnterpriseDashboardSummary
        {
            Tenant = tenant,
            Fleet = fleet,
            Devices = devices,
            Incidents = incidents.Take(12).ToArray(),
            ComplianceReports = complianceReports.Take(6).ToArray(),
            SignaturePacks = packs.Take(6).ToArray(),
            SandboxSubmissions = sandbox.Take(8).ToArray(),
            FalsePositiveReviews = reviews.Take(8).ToArray()
        };
    }
}
