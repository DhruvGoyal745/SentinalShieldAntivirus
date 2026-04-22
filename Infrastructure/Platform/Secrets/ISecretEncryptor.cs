namespace Antivirus.Infrastructure.Platform.Secrets;

/// <summary>
/// Internal Phase 3 contract for secret encryption/decryption. Concrete
/// implementations (DPAPI on Windows, AES elsewhere) are selected at DI
/// registration time. Plaintext NEVER crosses an HTTP boundary.
/// </summary>
public interface ISecretEncryptor
{
    string Algorithm { get; }
    byte[] Encrypt(byte[] plaintext);
    byte[] Decrypt(byte[] ciphertext);
}
