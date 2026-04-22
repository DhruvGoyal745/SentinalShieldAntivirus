using Antivirus.Infrastructure.Platform;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Antivirus.Controllers;

[ApiController]
[Route("api/platform")]
[Authorize(Policy = "AdminOnly")]
public sealed class PlatformController : ControllerBase
{
    private readonly IFeatureFlagService _featureFlags;
    private readonly IManifestSignatureValidator _signatureValidator;
    private readonly SentinelMetrics _metrics;

    public PlatformController(
        IFeatureFlagService featureFlags,
        IManifestSignatureValidator signatureValidator,
        SentinelMetrics metrics)
    {
        _featureFlags = featureFlags;
        _signatureValidator = signatureValidator;
        _metrics = metrics;
    }

    [HttpGet("flags")]
    public IActionResult GetFlags([FromQuery] string? tenant)
    {
        return Ok(_featureFlags.GetAllFlags(tenant));
    }

    [HttpPost("flags/{featureKey}")]
    public IActionResult SetFlag(string featureKey, [FromQuery] bool enabled, [FromQuery] string? tenant)
    {
        _featureFlags.SetOverride(featureKey, enabled, tenant);
        return Ok(new { featureKey, enabled, tenant });
    }

    [HttpDelete("flags/{featureKey}")]
    public IActionResult RemoveFlag(string featureKey, [FromQuery] string? tenant)
    {
        _featureFlags.RemoveOverride(featureKey, tenant);
        return Ok(new { featureKey, removed = true, tenant });
    }

    [HttpPost("validate-manifest")]
    public IActionResult ValidateManifest([FromBody] ManifestValidationRequest request)
    {
        var isValid = _signatureValidator.Validate(request.ManifestJson, request.SignatureBase64);
        return Ok(new { valid = isValid });
    }

    [HttpPost("sign-manifest")]
    public IActionResult SignManifest([FromBody] ManifestSignRequest request)
    {
        try
        {
            var signature = _signatureValidator.Sign(request.ManifestJson);
            return Ok(new { signature });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    public sealed class ManifestValidationRequest
    {
        public string ManifestJson { get; init; } = string.Empty;

        public string SignatureBase64 { get; init; } = string.Empty;
    }

    public sealed class ManifestSignRequest
    {
        public string ManifestJson { get; init; } = string.Empty;
    }
}
