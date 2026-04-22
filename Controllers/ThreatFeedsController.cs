using Antivirus.Application.Contracts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Antivirus.Controllers;

[ApiController]
[Route("api/threat-feeds")]
[Authorize(Policy = "AdminOnly")]
public sealed class ThreatFeedsController : ControllerBase
{
    private readonly IIocIngestionService _ingestion;
    private readonly IThreatIntelSettingsRepository _settingsRepository;
    private readonly ITenantRegistry _tenantRegistry;

    public ThreatFeedsController(IIocIngestionService ingestion, IThreatIntelSettingsRepository settingsRepository, ITenantRegistry tenantRegistry)
    {
        _ingestion = ingestion;
        _settingsRepository = settingsRepository;
        _tenantRegistry = tenantRegistry;
    }

    [HttpGet("settings")]
    public async Task<IActionResult> GetSettings(CancellationToken cancellationToken)
    {
        var tenant = _tenantRegistry.GetCurrentTenantKey();
        return Ok(await _settingsRepository.GetOrCreateAsync(tenant, cancellationToken));
    }

    [HttpPut("settings")]
    public async Task<IActionResult> UpdateSettings([FromBody] Domain.ThreatIntelSettings settings, CancellationToken cancellationToken)
    {
        if (settings is null) return BadRequest(new { error = "settings body is required" });
        var tenant = _tenantRegistry.GetCurrentTenantKey();
        // Force the tenant key — never trust the body.
        var sanitized = new Domain.ThreatIntelSettings
        {
            TenantKey = tenant,
            CloudReputationEnabled = settings.CloudReputationEnabled,
            Providers = settings.Providers ?? Array.Empty<Domain.ThreatIntelProviderSettings>(),
            Ttl = settings.Ttl ?? new Domain.ThreatIntelTtlSettings(),
            SyncWindowDays = settings.SyncWindowDays,
            MaxIndicatorsPerSync = settings.MaxIndicatorsPerSync,
            CloudFanoutTimeoutMs = settings.CloudFanoutTimeoutMs
        };
        await _settingsRepository.UpdateAsync(sanitized, cancellationToken);
        return Ok(sanitized);
    }

    [HttpPost("{provider}/sync")]
    public async Task<IActionResult> Sync(string provider, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(provider)) return BadRequest(new { error = "provider is required" });
        var tenant = _tenantRegistry.GetCurrentTenantKey();
        var run = await _ingestion.SyncProviderAsync(provider, tenant, cancellationToken);
        return run.Success ? Ok(run) : StatusCode(StatusCodes.Status502BadGateway, run);
    }

    [HttpGet("runs")]
    public async Task<IActionResult> RecentRuns([FromQuery] string? provider, [FromQuery] int max = 50, CancellationToken cancellationToken = default)
    {
        var tenant = _tenantRegistry.GetCurrentTenantKey();
        return Ok(await _ingestion.GetRecentSyncRunsAsync(provider, tenant, max, cancellationToken));
    }
}
