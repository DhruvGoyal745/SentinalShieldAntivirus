using Antivirus.Application.Contracts;
using Microsoft.AspNetCore.Mvc;

namespace Antivirus.Controllers;

[ApiController]
[Route("api/[controller]")]
public sealed class FileEventsController : ControllerBase
{
    private readonly IRealtimeProtectionService _realtimeProtectionService;

    public FileEventsController(IRealtimeProtectionService realtimeProtectionService)
    {
        _realtimeProtectionService = realtimeProtectionService;
    }

    [HttpGet]
    public async Task<IActionResult> Get(CancellationToken cancellationToken)
    {
        var events = await _realtimeProtectionService.GetRecentFileEventsAsync(cancellationToken);
        return Ok(events);
    }
}
