using Antivirus.Application.Contracts;
using Antivirus.Domain;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Antivirus.Controllers;

[ApiController]
[Route("api/iocs")]
[Authorize]
public sealed class IocController : ControllerBase
{
    private readonly IIocRepository _repository;
    private readonly ITenantRegistry _tenantRegistry;

    public IocController(IIocRepository repository, ITenantRegistry tenantRegistry)
    {
        _repository = repository;
        _tenantRegistry = tenantRegistry;
    }

    [HttpGet]
    public async Task<IActionResult> Search([FromQuery] string? type, [FromQuery] string? source,
                                            [FromQuery] string? q, [FromQuery] bool? active,
                                            [FromQuery] int page = 1, [FromQuery] int pageSize = 50,
                                            CancellationToken cancellationToken = default)
    {
        IocType? typeEnum = null;
        if (!string.IsNullOrWhiteSpace(type))
        {
            if (!Enum.TryParse<IocType>(type, ignoreCase: true, out var parsed))
                return BadRequest(new { error = "invalid type", supported = Enum.GetNames<IocType>() });
            typeEnum = parsed;
        }
        var tenant = _tenantRegistry.GetCurrentTenantKey();
        var results = await _repository.SearchAsync(new IocSearchFilter
        {
            TenantKey = tenant,
            Type = typeEnum,
            Source = source,
            ValueContains = q,
            IsActive = active,
            PageNumber = page,
            PageSize = pageSize
        }, cancellationToken);
        return Ok(results);
    }

    [HttpGet("stats")]
    public async Task<IActionResult> Stats(CancellationToken cancellationToken)
    {
        var tenant = _tenantRegistry.GetCurrentTenantKey();
        return Ok(await _repository.GetStatsAsync(tenant, cancellationToken));
    }

    [HttpGet("{id:guid}")]
    public async Task<IActionResult> Get(Guid id, CancellationToken cancellationToken)
    {
        var ioc = await _repository.GetByIdAsync(id, cancellationToken);
        if (ioc is null) return NotFound();
        var tenant = _tenantRegistry.GetCurrentTenantKey();
        if (!string.Equals(ioc.TenantKey, tenant, StringComparison.OrdinalIgnoreCase)) return Forbid();
        return Ok(ioc);
    }

    [HttpPost]
    [Authorize(Policy = "AdminOnly")]
    public async Task<IActionResult> Create([FromBody] CreateIocRequest body, CancellationToken cancellationToken)
    {
        if (body is null || string.IsNullOrWhiteSpace(body.Value))
            return BadRequest(new { error = "value is required" });
        if (!Enum.TryParse<IocType>(body.Type, ignoreCase: true, out var type))
            return BadRequest(new { error = "invalid type", supported = Enum.GetNames<IocType>() });

        var tenant = _tenantRegistry.GetCurrentTenantKey();
        var indicator = new IocIndicator
        {
            TenantKey = tenant,
            Type = type,
            DisplayValue = body.Value,
            Source = string.IsNullOrWhiteSpace(body.Source) ? "manual" : body.Source!,
            Severity = body.Severity ?? ThreatSeverity.Medium,
            Confidence = body.Confidence ?? 0.7m,
            Tags = body.Tags ?? Array.Empty<string>(),
            Description = body.Description,
            ExpiresAt = body.ExpiresAt,
            IsActive = true
        };
        var saved = await _repository.AddAsync(indicator, cancellationToken);
        return CreatedAtAction(nameof(Get), new { id = saved.Id }, saved);
    }

    [HttpDelete("{id:guid}")]
    [Authorize(Policy = "AdminOnly")]
    public async Task<IActionResult> Delete(Guid id, CancellationToken cancellationToken)
    {
        var ioc = await _repository.GetByIdAsync(id, cancellationToken);
        if (ioc is null) return NotFound();
        var tenant = _tenantRegistry.GetCurrentTenantKey();
        if (!string.Equals(ioc.TenantKey, tenant, StringComparison.OrdinalIgnoreCase)) return Forbid();
        await _repository.DeleteAsync(id, cancellationToken);
        return NoContent();
    }

    public sealed class CreateIocRequest
    {
        public string Type { get; set; } = "Sha256";
        public string Value { get; set; } = string.Empty;
        public string? Source { get; set; }
        public ThreatSeverity? Severity { get; set; }
        public decimal? Confidence { get; set; }
        public string[]? Tags { get; set; }
        public string? Description { get; set; }
        public DateTimeOffset? ExpiresAt { get; set; }
    }
}
