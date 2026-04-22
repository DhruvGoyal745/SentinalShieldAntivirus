using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
using Antivirus.Infrastructure.Platform;
using Antivirus.Infrastructure.Runtime;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Security;

public sealed class RemediationCoordinator : IRemediationCoordinator
{
    private readonly IWebHostEnvironment _environment;
    private readonly AntivirusPlatformOptions _options;
    private readonly IQuarantineVault _vault;
    private readonly IFeatureFlagService _featureFlags;
    private readonly ILogger<RemediationCoordinator> _logger;

    public RemediationCoordinator(
        IWebHostEnvironment environment,
        IOptions<AntivirusPlatformOptions> options,
        IQuarantineVault vault,
        IFeatureFlagService featureFlags,
        ILogger<RemediationCoordinator> logger)
    {
        _environment = environment;
        _options = options.Value;
        _vault = vault;
        _featureFlags = featureFlags;
        _logger = logger;
    }

    public async Task<(bool Quarantined, string? QuarantinePath)> QuarantineAsync(FileInfo file, CancellationToken cancellationToken = default)
    {
        if (!file.Exists)
        {
            return (false, null);
        }

        if (_featureFlags.IsEnabled("quarantine-encryption"))
        {
            var context = new QuarantineDetectionContext
            {
                ThreatName = "Unknown",
                ThreatSeverity = ThreatSeverity.Medium
            };

            var item = await _vault.QuarantineAsync(file, context, cancellationToken);
            return (true, item.VaultPath);
        }

        // Fallback: plain file move when encryption feature flag is off
        var quarantineDirectory = SentinelRuntimePaths.ResolveQuarantineRoot(_options);
        Directory.CreateDirectory(quarantineDirectory);
        var destination = Path.Combine(quarantineDirectory, $"{DateTimeOffset.UtcNow:yyyyMMddHHmmss}_{file.Name}");
        file.MoveTo(destination, overwrite: true);
        return (true, destination);
    }

    public async Task<(bool Quarantined, string? QuarantinePath)> QuarantineAsync(FileInfo file, QuarantineDetectionContext context, CancellationToken cancellationToken = default)
    {
        if (!file.Exists)
        {
            return (false, null);
        }

        if (_featureFlags.IsEnabled("quarantine-encryption"))
        {
            var item = await _vault.QuarantineAsync(file, context, cancellationToken);
            return (true, item.VaultPath);
        }

        // Fallback: plain file move when encryption feature flag is off
        var quarantineDirectory = SentinelRuntimePaths.ResolveQuarantineRoot(_options);
        Directory.CreateDirectory(quarantineDirectory);
        var destination = Path.Combine(quarantineDirectory, $"{DateTimeOffset.UtcNow:yyyyMMddHHmmss}_{file.Name}");
        file.MoveTo(destination, overwrite: true);
        return (true, destination);
    }
}
