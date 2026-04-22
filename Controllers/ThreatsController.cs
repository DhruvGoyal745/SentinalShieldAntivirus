using Antivirus.Application.Contracts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Antivirus.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public sealed class ThreatsController : ControllerBase
{
    private readonly ISecurityOrchestrator _securityOrchestrator;

    public ThreatsController(ISecurityOrchestrator securityOrchestrator)
    {
        _securityOrchestrator = securityOrchestrator;
    }

    [HttpGet]
    public async Task<IActionResult> Get(CancellationToken cancellationToken)
    {
        var threats = await _securityOrchestrator.SyncThreatsAsync(cancellationToken);
        return Ok(threats);
    }

    [HttpPost("{id:int}/quarantine")]
    public async Task<IActionResult> Quarantine(int id, CancellationToken cancellationToken)
    {
        var result = await _securityOrchestrator.QuarantineThreatAsync(id, cancellationToken);
        if (!result.Success)
        {
            return NotFound(result);
        }

        return Ok(result);
    }
}
