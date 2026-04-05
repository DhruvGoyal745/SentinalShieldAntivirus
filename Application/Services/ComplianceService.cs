using System.Text.Json;
using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Application.Services;

public sealed class ComplianceService : IComplianceService
{
    private readonly IControlPlaneRepository _controlPlaneRepository;
    private readonly ISecurityRepository _securityRepository;

    public ComplianceService(IControlPlaneRepository controlPlaneRepository, ISecurityRepository securityRepository)
    {
        _controlPlaneRepository = controlPlaneRepository;
        _securityRepository = securityRepository;
    }

    public async Task<ComplianceReport> CaptureAsync(CancellationToken cancellationToken = default)
    {
        var devices = await _controlPlaneRepository.GetDevicesAsync(cancellationToken);
        var incidents = await _controlPlaneRepository.GetIncidentsAsync(cancellationToken);
        var threats = await _securityRepository.GetThreatsAsync(activeOnly: false, cancellationToken);

        var deviceCount = devices.Count;
        var activeDeviceCount = devices.Count(device => device.EnrollmentStatus == DeviceEnrollmentStatus.Active);
        var baselineCount = devices.Count(device => device.BaselineScanCompleted);
        var selfProtectionCount = devices.Count(device =>
            device.SelfProtection.ProcessProtectionEnabled
            && device.SelfProtection.FileProtectionEnabled
            && device.SelfProtection.ServiceProtectionEnabled
            && device.SelfProtection.SignedUpdatesOnly);
        var currentPack = devices
            .Select(device => device.SignaturePackVersion)
            .Where(version => !string.IsNullOrWhiteSpace(version))
            .GroupBy(version => version, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(group => group.Count())
            .Select(group => group.Key)
            .FirstOrDefault() ?? string.Empty;
        var currentPackCount = devices.Count(device => string.Equals(device.SignaturePackVersion, currentPack, StringComparison.OrdinalIgnoreCase));

        var report = new ComplianceReport
        {
            ReportType = ComplianceReportType.Posture,
            ReportDate = DateTimeOffset.UtcNow,
            AgentCoveragePercent = ComputePercent(activeDeviceCount, deviceCount),
            SignatureCurrencyPercent = ComputePercent(currentPackCount, deviceCount),
            PolicyCompliancePercent = ComputePercent(devices.Count(device => !string.IsNullOrWhiteSpace(device.PolicyVersion)), deviceCount),
            BaselineScanCompletionPercent = ComputePercent(baselineCount, deviceCount),
            OpenCriticalIncidentCount = incidents.Count(incident => incident.Status != IncidentStatus.Resolved && incident.Severity is ThreatSeverity.Critical or ThreatSeverity.High),
            QuarantinedThreatCount = threats.Count(threat => threat.IsQuarantined),
            SelfProtectionCoveragePercent = ComputePercent(selfProtectionCount, deviceCount),
            AuditFindingCount = Math.Max(0, deviceCount - selfProtectionCount),
            ExportJson = JsonSerializer.Serialize(new
            {
                devices = deviceCount,
                activeDevices = activeDeviceCount,
                incidents = incidents.Count,
                threats = threats.Count
            })
        };

        return await _controlPlaneRepository.SaveComplianceReportAsync(report, cancellationToken);
    }

    private static decimal ComputePercent(int numerator, int denominator)
    {
        if (denominator == 0)
        {
            return 0m;
        }

        return Math.Round((decimal)numerator / denominator * 100m, 2);
    }
}
