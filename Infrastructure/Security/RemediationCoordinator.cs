using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Infrastructure.Runtime;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Security;

public sealed class RemediationCoordinator : IRemediationCoordinator
{
    private readonly IWebHostEnvironment _environment;
    private readonly AntivirusPlatformOptions _options;

    public RemediationCoordinator(IWebHostEnvironment environment, IOptions<AntivirusPlatformOptions> options)
    {
        _environment = environment;
        _options = options.Value;
    }

    public Task<(bool Quarantined, string? QuarantinePath)> QuarantineAsync(FileInfo file, CancellationToken cancellationToken = default)
    {
        if (!file.Exists)
        {
            return Task.FromResult((false, (string?)null));
        }

        var quarantineDirectory = SentinelRuntimePaths.ResolveQuarantineRoot(_options);
        Directory.CreateDirectory(quarantineDirectory);
        var destination = Path.Combine(quarantineDirectory, $"{DateTimeOffset.UtcNow:yyyyMMddHHmmss}_{file.Name}");
        file.MoveTo(destination, overwrite: true);
        return Task.FromResult((true, (string?)destination));
    }
}
