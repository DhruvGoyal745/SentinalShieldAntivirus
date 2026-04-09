using Antivirus.Application.Contracts;
using Microsoft.AspNetCore.Mvc;

namespace Antivirus.Controllers;

[ApiController]
[Route("api/service")]
public sealed class ServiceControlController : ControllerBase
{
    private readonly ISentinelShieldControlApi _controlApi;

    public ServiceControlController(ISentinelShieldControlApi controlApi)
    {
        _controlApi = controlApi;
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
