using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Security;

public sealed class SignaturePackProvider : ISignaturePackProvider
{
    private readonly IControlPlaneRepository _controlPlaneRepository;
    private readonly ISignaturePackCompiler _signaturePackCompiler;
    private readonly AntivirusPlatformOptions _options;
    private ProprietarySignaturePack? _cachedPack;
    private string? _cachedVersion;

    public SignaturePackProvider(
        IControlPlaneRepository controlPlaneRepository,
        ISignaturePackCompiler signaturePackCompiler,
        IOptions<AntivirusPlatformOptions> options)
    {
        _controlPlaneRepository = controlPlaneRepository;
        _signaturePackCompiler = signaturePackCompiler;
        _options = options.Value;
    }

    public Task<SignaturePackManifest> GetCurrentPackAsync(CancellationToken cancellationToken = default) =>
        _controlPlaneRepository.GetCurrentSignaturePackAsync(cancellationToken);

    public async Task<ProprietarySignaturePack> GetCompiledPackAsync(CancellationToken cancellationToken = default)
    {
        var manifest = await _controlPlaneRepository.GetCurrentSignaturePackAsync(cancellationToken);
        if (_cachedPack is not null
            && string.Equals(_cachedVersion, manifest.Version, StringComparison.OrdinalIgnoreCase))
        {
            return _cachedPack;
        }

        var rules = await _controlPlaneRepository.GetEnabledSignatureRulesAsync(cancellationToken);
        var compiled = await _signaturePackCompiler.CompileAsync(manifest, rules, cancellationToken);
        PersistPackArtifact(compiled);
        _cachedPack = compiled;
        _cachedVersion = compiled.Manifest.Version;
        return compiled;
    }

    private void PersistPackArtifact(ProprietarySignaturePack pack)
    {
        if (string.IsNullOrWhiteSpace(_options.SignaturePackRoot))
        {
            return;
        }

        var root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, _options.SignaturePackRoot));
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, $"{pack.Manifest.Version}.sspack.json");
        File.WriteAllBytes(path, pack.SerializedBytes);
    }
}
