using Antivirus.Application.Contracts;
using Antivirus.Domain;
using Microsoft.AspNetCore.Mvc;

namespace Antivirus.Controllers;

[ApiController]
[Route("api/[controller]")]
public sealed class ScansController : ControllerBase
{
    private readonly ISecurityOrchestrator _securityOrchestrator;

    public ScansController(ISecurityOrchestrator securityOrchestrator)
    {
        _securityOrchestrator = securityOrchestrator;
    }

    [HttpGet]
    public async Task<IActionResult> Get(CancellationToken cancellationToken)
    {
        var scans = await _securityOrchestrator.GetRecentScansAsync(cancellationToken);
        return Ok(scans);
    }

    [HttpGet("{id:int}/progress")]
    public async Task<IActionResult> GetProgress(int id, CancellationToken cancellationToken)
    {
        var progress = await _securityOrchestrator.GetScanProgressAsync(id, cancellationToken);
        return Ok(progress);
    }

    [HttpPost]
    public async Task<IActionResult> Start([FromBody] ScanRequest request, CancellationToken cancellationToken)
    {
        var scan = await _securityOrchestrator.QueueScanAsync(request, cancellationToken);
        return Accepted(scan);
    }

    [HttpPost("{id:int}/stop")]
    public async Task<IActionResult> Stop(int id, CancellationToken cancellationToken)
    {
        var result = await _securityOrchestrator.StopScanAsync(id, cancellationToken);
        return result.Success ? Ok(result) : BadRequest(result);
    }

    [HttpPost("{id:int}/file-decision")]
    public async Task<IActionResult> FileDecision(int id, [FromBody] ScanFileDecision decision, CancellationToken cancellationToken)
    {
        var result = await _securityOrchestrator.SubmitFileDecisionAsync(id, decision, cancellationToken);
        return result.Success ? Ok(result) : BadRequest(result);
    }
}
