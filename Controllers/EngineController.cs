using Antivirus.Application.Contracts;
using Microsoft.AspNetCore.Mvc;

namespace Antivirus.Controllers;

[ApiController]
[Route("api/engine")]
public sealed class EngineController : ControllerBase
{
    private readonly IEngineDaemonClient _engineDaemonClient;

    public EngineController(IEngineDaemonClient engineDaemonClient)
    {
        _engineDaemonClient = engineDaemonClient;
    }

    [HttpGet("status")]
    public async Task<IActionResult> GetStatus(CancellationToken cancellationToken)
    {
        var snapshot = await _engineDaemonClient.GetEngineHealthAsync(cancellationToken);

        return Ok(new
        {
            online = snapshot.EngineOnline,
            capturedAt = snapshot.CapturedAt,
            engineVersion = snapshot.EngineVersion,
            signaturePackVersion = snapshot.SignaturePackVersion,
            realtimeMonitoringEnabled = snapshot.RealtimeMonitoringEnabled,
            daemonTransport = snapshot.DaemonTransport
        });
    }
}
