using Antivirus.Application.Contracts;
using Antivirus.Infrastructure.Platform;
using Microsoft.AspNetCore.Mvc;

namespace Antivirus.Controllers;

[ApiController]
[Route("api/service")]
public sealed class ServiceControlController : ControllerBase
{
    private readonly ISentinelShieldControlApi _controlApi;
    private readonly ILocalTrustBoundary _trustBoundary;

    public ServiceControlController(ISentinelShieldControlApi controlApi, ILocalTrustBoundary trustBoundary)
    {
        _controlApi = controlApi;
        _trustBoundary = trustBoundary;
    }

    /// <summary>
    /// Returns a session token that local callers (Tray, Desktop) must include in the
    /// X-Local-Token header for all subsequent /api/service/* calls.
    /// This endpoint itself is only accessible from localhost.
    /// </summary>
    [HttpPost("local-token")]
    public IActionResult GetLocalToken()
    {
        var remoteIp = HttpContext.Connection.RemoteIpAddress;
        if (remoteIp is null || !System.Net.IPAddress.IsLoopback(remoteIp))
        {
            return Forbid();
        }

        return Ok(new { token = _trustBoundary.GenerateLocalToken() });
    }

    [HttpGet("status")]
    public async Task<IActionResult> GetStatus(CancellationToken cancellationToken)
    {
        var status = await _controlApi.GetStatusAsync(cancellationToken);
        return Ok(status);
    }

    [HttpPost("scan/quick")]
    public async Task<IActionResult> StartQuickScan(CancellationToken cancellationToken)
    {
        var scan = await _controlApi.StartQuickScanAsync("tray-user", cancellationToken);
        return Accepted(scan);
    }

    [HttpPost("protection/pause")]
    public async Task<IActionResult> PauseProtection([FromQuery] int minutes = 30, CancellationToken cancellationToken = default)
    {
        var result = await _controlApi.PauseProtectionAsync(TimeSpan.FromMinutes(minutes), cancellationToken);
        return Ok(result);
    }

    [HttpPost("protection/resume")]
    public async Task<IActionResult> ResumeProtection(CancellationToken cancellationToken)
    {
        var result = await _controlApi.ResumeProtectionAsync(cancellationToken);
        return Ok(result);
    }

    [HttpPost("updates/check")]
    public async Task<IActionResult> CheckForUpdates(CancellationToken cancellationToken)
    {
        var result = await _controlApi.CheckForUpdatesAsync(cancellationToken);
        return Ok(result);
    }
}
