using Antivirus.Application.Contracts;
using Antivirus.Domain;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Antivirus.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public sealed class QuarantineController : ControllerBase
{
    private readonly IQuarantineVault _vault;

    public QuarantineController(IQuarantineVault vault)
    {
        _vault = vault;
    }

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] string? status, [FromQuery] string? threat,
        [FromQuery] int page = 1, [FromQuery] int pageSize = 50, CancellationToken cancellationToken = default)
    {
        var filter = new QuarantineListFilter
        {
            Status = Enum.TryParse<PurgeState>(status, true, out var ps) ? ps : null,
            ThreatName = threat,
            PageNumber = Math.Max(1, page),
            PageSize = Math.Clamp(pageSize, 1, 200)
        };

        var items = await _vault.ListAsync(filter, cancellationToken);
        return Ok(items);
    }

    [HttpGet("{id:guid}")]
    public async Task<IActionResult> Get(Guid id, CancellationToken cancellationToken)
    {
        var item = await _vault.GetItemAsync(id, cancellationToken);
        if (item is null)
            return NotFound();

        return Ok(item);
    }

    [HttpPost("{id:guid}/restore")]
    public async Task<IActionResult> Restore(Guid id, [FromBody] RestoreRequestDto? dto, CancellationToken cancellationToken)
    {
        var result = await _vault.RestoreAsync(id, dto?.RequestedBy ?? "desktop-user", dto?.RestoreToPath, cancellationToken);
        if (!result.Success)
            return BadRequest(result);

        return Ok(result);
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Purge(Guid id, CancellationToken cancellationToken)
    {
        var success = await _vault.PurgeAsync(id, cancellationToken);
        if (!success)
            return NotFound();

        return NoContent();
    }

    [HttpPost("purge-expired")]
    public async Task<IActionResult> PurgeExpired(CancellationToken cancellationToken)
    {
        var count = await _vault.PurgeExpiredAsync(cancellationToken);
        return Ok(new { purgedCount = count });
    }

    public sealed class RestoreRequestDto
    {
        public string? RequestedBy { get; init; }
        public string? RestoreToPath { get; init; }
    }
}
