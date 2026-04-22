using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
using Antivirus.Infrastructure.Platform;
using Antivirus.Infrastructure.Runtime;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Security;

public sealed class SignaturePackProvider : ISignaturePackProvider
{
    private readonly IPolicyRepository _policyRepository;
    private readonly ISignaturePackCompiler _signaturePackCompiler;
    private readonly IManifestSignatureValidator _signatureValidator;
    private readonly AntivirusPlatformOptions _options;
    private readonly ILogger<SignaturePackProvider> _logger;
    private ProprietarySignaturePack? _cachedPack;
    private string? _cachedVersion;

    public SignaturePackProvider(
        IPolicyRepository policyRepository,
        ISignaturePackCompiler signaturePackCompiler,
        IManifestSignatureValidator signatureValidator,
        IOptions<AntivirusPlatformOptions> options,
        ILogger<SignaturePackProvider> logger)
    {
        _policyRepository = policyRepository;
        _signaturePackCompiler = signaturePackCompiler;
        _signatureValidator = signatureValidator;
        _options = options.Value;
        _logger = logger;
    }

    public Task<SignaturePackManifest> GetCurrentPackAsync(CancellationToken cancellationToken = default) =>
        _policyRepository.GetCurrentSignaturePackAsync(cancellationToken);

    public async Task<ProprietarySignaturePack> GetCompiledPackAsync(CancellationToken cancellationToken = default)
    {
        var manifest = await _policyRepository.GetCurrentSignaturePackAsync(cancellationToken);
        if (_cachedPack is not null
            && string.Equals(_cachedVersion, manifest.Version, StringComparison.OrdinalIgnoreCase))
        {
            return _cachedPack;
        }

        if (_options.RequireSignedManifests)
        {
            ValidateManifestSignature(manifest);
        }

        var rules = await _policyRepository.GetEnabledSignatureRulesAsync(cancellationToken);
        var compiled = await _signaturePackCompiler.CompileAsync(manifest, rules, cancellationToken);
        PersistPackArtifact(compiled);
        _cachedPack = compiled;
        _cachedVersion = compiled.Manifest.Version;
        return compiled;
    }

    private void ValidateManifestSignature(SignaturePackManifest manifest)
    {
        var manifestJson = System.Text.Json.JsonSerializer.Serialize(new
        {
            manifest.Version,
            manifest.Channel,
            manifest.SignatureCount,
            manifest.Sha256,
            manifest.MinAgentVersion
        });

        if (!_signatureValidator.Validate(manifestJson, manifest.Sha256))
        {
            _logger.LogError("Signature pack {Version} failed signature validation. Rejecting tampered manifest.", manifest.Version);
            throw new InvalidOperationException(
                $"Signature pack '{manifest.Version}' failed cryptographic validation. " +
                "The manifest may have been tampered with. Update rejected.");
        }

        _logger.LogInformation("Signature pack {Version} passed signature validation.", manifest.Version);
    }

    private void PersistPackArtifact(ProprietarySignaturePack pack)
    {
        if (string.IsNullOrWhiteSpace(_options.SignaturePackRoot))
        {
            return;
        }

        var root = SentinelRuntimePaths.ResolveSignaturePackRoot(_options);
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, $"{pack.Manifest.Version}.sspack.json");
        File.WriteAllBytes(path, pack.SerializedBytes);
    }
}
