using System.Security.Cryptography;

namespace Antivirus.Infrastructure.Platform.Secrets;

/// <summary>
/// AES-256-GCM fallback for non-Windows dev/test. Bootstrap key MUST come
/// from the environment variable <c>SENTINEL_SECRETS_KEY</c> (base64-encoded
/// 32 bytes) or from secure config. NEVER from a UI request — that would
/// allow an attacker to swap the key.
/// </summary>
public sealed class AesSecretEncryptor : ISecretEncryptor
{
    private const string EnvVarName = "SENTINEL_SECRETS_KEY";
    private readonly byte[] _key;

    public AesSecretEncryptor(IConfiguration configuration)
    {
        var keyBase64 = Environment.GetEnvironmentVariable(EnvVarName)
            ?? configuration[$"AntivirusPlatform:{EnvVarName}"];

        if (string.IsNullOrWhiteSpace(keyBase64))
        {
            // Derive a stable per-machine key as last-resort dev fallback. WARNING:
            // this is NOT secure for production. The only supported production
            // path is DPAPI (Windows) or an explicit env var.
            using var sha = SHA256.Create();
            var seed = Environment.MachineName + "|" + Environment.OSVersion.Platform;
            _key = sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(seed));
        }
        else
        {
            _key = Convert.FromBase64String(keyBase64);
            if (_key.Length != 32)
            {
                throw new InvalidOperationException($"{EnvVarName} must decode to 32 bytes (AES-256). Got {_key.Length}.");
            }
        }
    }

    public string Algorithm => "aes-256-gcm";

    public byte[] Encrypt(byte[] plaintext)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var ciphertext = new byte[plaintext.Length];

        using var aes = new AesGcm(_key, tag.Length);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        // Layout: [12-byte nonce][16-byte tag][ciphertext]
        var output = new byte[nonce.Length + tag.Length + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, output, 0, nonce.Length);
        Buffer.BlockCopy(tag, 0, output, nonce.Length, tag.Length);
        Buffer.BlockCopy(ciphertext, 0, output, nonce.Length + tag.Length, ciphertext.Length);
        return output;
    }

    public byte[] Decrypt(byte[] ciphertext)
    {
        if (ciphertext.Length < 12 + 16) throw new CryptographicException("Ciphertext too short.");

        var nonce = ciphertext.AsSpan(0, 12);
        var tag = ciphertext.AsSpan(12, 16);
        var payload = ciphertext.AsSpan(28);
        var plaintext = new byte[payload.Length];

        using var aes = new AesGcm(_key, tag.Length);
        aes.Decrypt(nonce, payload, tag, plaintext);
        return plaintext;
    }
}
