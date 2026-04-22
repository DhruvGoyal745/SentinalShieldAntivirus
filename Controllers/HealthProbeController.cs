using Antivirus.Application.Contracts;
using Antivirus.Infrastructure.Platform;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Antivirus.Controllers;

/// <summary>
/// Deep health probe that checks every infrastructure component.
/// Returns 200 with component-level detail when healthy, 503 when degraded.
/// </summary>
[ApiController]
[Route("api/health")]
public sealed class HealthProbeController : ControllerBase
{
    private readonly ITenantRegistry _tenantRegistry;
    private readonly IEngineDaemonClient _engineDaemon;
    private readonly ISignaturePackProvider _signaturePackProvider;
    private readonly IFeatureFlagService _featureFlags;
    private readonly SentinelMetrics _metrics;
    private readonly ILogger<HealthProbeController> _logger;

    public HealthProbeController(
        ITenantRegistry tenantRegistry,
        IEngineDaemonClient engineDaemon,
        ISignaturePackProvider signaturePackProvider,
        IFeatureFlagService featureFlags,
        SentinelMetrics metrics,
        ILogger<HealthProbeController> logger)
    {
        _tenantRegistry = tenantRegistry;
        _engineDaemon = engineDaemon;
        _signaturePackProvider = signaturePackProvider;
        _featureFlags = featureFlags;
        _metrics = metrics;
        _logger = logger;
    }

    [Authorize]
    [HttpGet("deep")]
    public async Task<IActionResult> DeepProbe(CancellationToken cancellationToken)
    {
        var components = new Dictionary<string, ComponentHealth>();
        var overallHealthy = true;

        // Database connectivity
        try
        {
            await _tenantRegistry.GetCurrentTenantAsync(cancellationToken);
            components["database"] = new ComponentHealth { Status = "healthy" };
        }
        catch (Exception ex)
        {
            components["database"] = new ComponentHealth { Status = "unhealthy", Detail = ex.Message };
            overallHealthy = false;
        }

        // Engine daemon
        try
        {
            var engineHealth = await _engineDaemon.GetEngineHealthAsync(cancellationToken);
            components["engine"] = new ComponentHealth
            {
                Status = engineHealth.EngineOnline ? "healthy" : "degraded",
                Detail = $"v{engineHealth.EngineVersion}, pack {engineHealth.SignaturePackVersion}"
            };
            if (!engineHealth.EngineOnline)
            {
                overallHealthy = false;
            }
        }
        catch (Exception ex)
        {
            components["engine"] = new ComponentHealth { Status = "unhealthy", Detail = ex.Message };
            overallHealthy = false;
        }

        // Signature pack
        try
        {
            var pack = await _signaturePackProvider.GetCurrentPackAsync(cancellationToken);
            components["signaturePack"] = new ComponentHealth
            {
                Status = "healthy",
                Detail = $"v{pack.Version}, {pack.SignatureCount} rules"
            };
        }
        catch (Exception ex)
        {
            components["signaturePack"] = new ComponentHealth { Status = "degraded", Detail = ex.Message };
        }

        // Feature flags
        components["featureFlags"] = new ComponentHealth
        {
            Status = "healthy",
            Detail = $"{_featureFlags.GetAllFlags().Count} flags registered"
        };

        var result = new
        {
            status = overallHealthy ? "healthy" : "degraded",
            timestamp = DateTimeOffset.UtcNow,
            components
        };

        return overallHealthy ? Ok(result) : StatusCode(503, result);
    }

    private sealed class ComponentHealth
    {
        public string Status { get; init; } = "unknown";

        public string? Detail { get; init; }
    }
}
