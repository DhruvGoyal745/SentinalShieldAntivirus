using Antivirus.Application.Contracts;
using Antivirus.Domain;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Antivirus.Controllers;

[ApiController]
[Route("api/reputation")]
[Authorize]
public sealed class ReputationController : ControllerBase
{
    private readonly IReputationOrchestrator _orchestrator;
    private readonly IReputationLookupAuditRepository _auditRepository;
    private readonly ITenantRegistry _tenantRegistry;

    public ReputationController(
        IReputationOrchestrator orchestrator,
        IReputationLookupAuditRepository auditRepository,
        ITenantRegistry tenantRegistry)
    {
        _orchestrator = orchestrator;
        _auditRepository = auditRepository;
        _tenantRegistry = tenantRegistry;
    }

    [HttpPost("lookup")]
    public async Task<IActionResult> Lookup([FromBody] LookupRequest body, CancellationToken cancellationToken)
    {
        if (body is null || string.IsNullOrWhiteSpace(body.Value)) return BadRequest(new { error = "value is required" });
        if (!Enum.TryParse<ReputationLookupType>(body.Type, ignoreCase: true, out var type))
            return BadRequest(new { error = "invalid type", supported = Enum.GetNames<ReputationLookupType>() });

        var tenant = _tenantRegistry.GetCurrentTenantKey();
        var result = await _orchestrator.EvaluateAsync(new ReputationLookupRequest
        {
            TenantKey = tenant,
            LookupType = type,
            Value = body.Value,
            RequestedBy = User.Identity?.Name,
            CorrelationId = body.CorrelationId,
            AllowCloud = body.AllowCloud
        }, cancellationToken);
        return Ok(result);
    }

    [HttpGet("providers/health")]
    public async Task<IActionResult> ProviderHealth(CancellationToken cancellationToken)
    {
        var tenant = _tenantRegistry.GetCurrentTenantKey();
        return Ok(await _orchestrator.GetProviderHealthAsync(tenant, cancellationToken));
    }

    [HttpGet("audit")]
    [Authorize(Policy = "AdminOnly")]
    public async Task<IActionResult> Audit([FromQuery] int max = 100, CancellationToken cancellationToken = default)
    {
        var tenant = _tenantRegistry.GetCurrentTenantKey();
        return Ok(await _auditRepository.RecentAsync(tenant, max, cancellationToken));
    }

    public sealed class LookupRequest
    {
        public string Type { get; set; } = "Sha256";
        public string Value { get; set; } = string.Empty;
        public bool AllowCloud { get; set; } = true;
        public string? CorrelationId { get; set; }
    }
}
