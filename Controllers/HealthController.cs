using Antivirus.Application.Contracts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Antivirus.Controllers;

[ApiController]
[Route("api/health")]
public sealed class HealthController : ControllerBase
{
    private readonly ISecurityOrchestrator _securityOrchestrator;

    public HealthController(ISecurityOrchestrator securityOrchestrator)
    {
        _securityOrchestrator = securityOrchestrator;
    }

    [AllowAnonymous]
    [HttpGet("status")]
    public async Task<IActionResult> Get(CancellationToken cancellationToken)
    {
        var health = await _securityOrchestrator.CaptureHealthAsync(cancellationToken);
        return Ok(health);
    }
}
