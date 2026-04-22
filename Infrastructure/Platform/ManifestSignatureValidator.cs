using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Antivirus.Infrastructure.Platform;

/// <summary>
/// Validates cryptographic signatures on signature pack manifests, product update manifests,
/// and policy bundles before they are applied. Prevents tampered payloads from being loaded.
/// </summary>
public interface IManifestSignatureValidator
{
    bool Validate(string manifestJson, string signatureBase64);

    string Sign(string manifestJson);
}

public sealed class ManifestSignatureValidator : IManifestSignatureValidator
{
    private readonly RSA _publicKey;
    private readonly RSA? _privateKey;

    /// <summary>
    /// In production the public key is baked into the agent binary and the private key lives in a secure build pipeline.
    /// For development both are generated in-process.
    /// </summary>
    public ManifestSignatureValidator()
    {
        var rsa = RSA.Create(2048);
        _publicKey = rsa;
        _privateKey = rsa;
    }

    public ManifestSignatureValidator(RSA publicKey)
    {
        _publicKey = publicKey;
    }

    public ManifestSignatureValidator(RSA publicKey, RSA privateKey)
    {
        _publicKey = publicKey;
        _privateKey = privateKey;
    }

    public bool Validate(string manifestJson, string signatureBase64)
    {
        if (string.IsNullOrWhiteSpace(manifestJson) || string.IsNullOrWhiteSpace(signatureBase64))
        {
            return false;
        }

        try
        {
            var data = Encoding.UTF8.GetBytes(manifestJson);
            var signature = Convert.FromBase64String(signatureBase64);
            return _publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch
        {
            return false;
        }
    }

    public string Sign(string manifestJson)
    {
        if (_privateKey is null)
        {
            throw new InvalidOperationException("Signing requires a private key. This instance was initialized with a public key only.");
        }

        var data = Encoding.UTF8.GetBytes(manifestJson);
        var signature = _privateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return Convert.ToBase64String(signature);
    }
}
