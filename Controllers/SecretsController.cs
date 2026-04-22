using Antivirus.Application.Contracts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Antivirus.Controllers;

[ApiController]
[Route("api/secrets")]
[Authorize(Policy = "AdminOnly")]
public sealed class SecretsController : ControllerBase
{
    private readonly ISecretsVault _vault;
    private readonly ITenantRegistry _tenantRegistry;
    private readonly ILogger<SecretsController> _logger;

    public SecretsController(ISecretsVault vault, ITenantRegistry tenantRegistry, ILogger<SecretsController> logger)
    {
        _vault = vault;
        _tenantRegistry = tenantRegistry;
        _logger = logger;
    }

    /// <summary>List metadata only — never returns ciphertext or plaintext.</summary>
    [HttpGet]
    public async Task<IActionResult> List(CancellationToken cancellationToken)
    {
        var tenant = _tenantRegistry.GetCurrentTenantKey();
        return Ok(await _vault.ListMetadataAsync(tenant, cancellationToken));
    }

    [HttpPut("{provider}/{key}")]
    public async Task<IActionResult> Set(string provider, string key, [FromBody] SetSecretRequest body, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(provider) || string.IsNullOrWhiteSpace(key))
            return BadRequest(new { error = "provider and key are required" });
        if (body is null || string.IsNullOrWhiteSpace(body.Value))
            return BadRequest(new { error = "value is required" });

        var tenant = _tenantRegistry.GetCurrentTenantKey();
        await _vault.SetSecretAsync(tenant, provider, key, body.Value, cancellationToken);
        _logger.LogInformation("Secret stored for {Provider}/{Key} by {User}", provider, key, User.Identity?.Name);
        return NoContent();
    }

    [HttpDelete("{provider}/{key}")]
    public async Task<IActionResult> Delete(string provider, string key, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(provider) || string.IsNullOrWhiteSpace(key))
            return BadRequest(new { error = "provider and key are required" });
        var tenant = _tenantRegistry.GetCurrentTenantKey();
        var removed = await _vault.DeleteSecretAsync(tenant, provider, key, cancellationToken);
        return removed ? NoContent() : NotFound();
    }

    public sealed class SetSecretRequest
    {
        public string Value { get; set; } = string.Empty;
    }
}
