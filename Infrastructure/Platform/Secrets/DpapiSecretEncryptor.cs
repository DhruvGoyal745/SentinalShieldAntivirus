using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Antivirus.Infrastructure.Platform.Secrets;

/// <summary>
/// Windows DPAPI machine-scoped encryption. Production path on Windows.
/// Throws on non-Windows hosts; selection happens at DI time so this
/// type is never instantiated when running on Linux/macOS.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiSecretEncryptor : ISecretEncryptor
{
    private static readonly byte[] Entropy = "SentinelShield.ThreatIntel.v1"u8.ToArray();

    public string Algorithm => "dpapi-machine";

    public byte[] Encrypt(byte[] plaintext)
        => ProtectedData.Protect(plaintext, Entropy, DataProtectionScope.LocalMachine);

    public byte[] Decrypt(byte[] ciphertext)
        => ProtectedData.Unprotect(ciphertext, Entropy, DataProtectionScope.LocalMachine);
}
