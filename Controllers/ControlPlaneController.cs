using Antivirus.Application.Contracts;
using Antivirus.Domain;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Antivirus.Controllers;

[ApiController]
[Route("api/controlplane")]
[Authorize(Policy = "AdminOnly")]
public sealed class ControlPlaneController : ControllerBase
{
    private readonly ITenantRegistry _tenantRegistry;
    private readonly IEnterpriseDashboardService _enterpriseDashboardService;
    private readonly IControlPlaneRepository _controlPlaneRepository;
    private readonly IComplianceService _complianceService;

    public ControlPlaneController(
        ITenantRegistry tenantRegistry,
        IEnterpriseDashboardService enterpriseDashboardService,
        IControlPlaneRepository controlPlaneRepository,
        IComplianceService complianceService)
    {
        _tenantRegistry = tenantRegistry;
        _enterpriseDashboardService = enterpriseDashboardService;
        _controlPlaneRepository = controlPlaneRepository;
        _complianceService = complianceService;
    }

    [HttpGet("summary")]
    public async Task<ActionResult<EnterpriseDashboardSummary>> GetSummary(CancellationToken cancellationToken)
    {
        return Ok(await _enterpriseDashboardService.GetSummaryAsync(cancellationToken));
    }

    [HttpGet("tenants")]
    public async Task<ActionResult<IReadOnlyCollection<TenantSummary>>> GetTenants(CancellationToken cancellationToken)
    {
        return Ok(await _tenantRegistry.GetTenantsAsync(cancellationToken));
    }

    [HttpGet("packs")]
    public async Task<ActionResult<IReadOnlyCollection<SignaturePackManifest>>> GetPacks(CancellationToken cancellationToken)
    {
        return Ok(await _controlPlaneRepository.GetSignaturePacksAsync(cancellationToken));
    }

    [HttpGet("compliance")]
    public async Task<ActionResult<IReadOnlyCollection<ComplianceReport>>> GetCompliance(CancellationToken cancellationToken)
    {
        return Ok(await _controlPlaneRepository.GetComplianceReportsAsync(cancellationToken));
    }

    [HttpPost("compliance/capture")]
    public async Task<ActionResult<ComplianceReport>> CaptureCompliance(CancellationToken cancellationToken)
    {
        return Ok(await _complianceService.CaptureAsync(cancellationToken));
    }

    [HttpPost("incidents/{id:int}/resolve")]
    public async Task<IActionResult> ResolveIncident(int id, CancellationToken cancellationToken)
    {
        var resolved = await _controlPlaneRepository.ResolveIncidentAsync(id, "enterprise-operator", cancellationToken);
        return resolved ? NoContent() : NotFound();
    }
}
