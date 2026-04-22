using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.Reputation;

internal static class IndicatorNormalization
{
    public static string Normalize(ReputationLookupType type, string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        var trimmed = value.Trim();
        return type switch
        {
            ReputationLookupType.Sha256 or ReputationLookupType.Sha1 or ReputationLookupType.Md5 => trimmed.ToLowerInvariant(),
            ReputationLookupType.Domain => trimmed.ToLowerInvariant().TrimEnd('.'),
            ReputationLookupType.Ip => trimmed.ToLowerInvariant(),
            ReputationLookupType.Url => trimmed,
            _ => trimmed
        };
    }

    public static string NormalizeIoc(IocType type, string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        var trimmed = value.Trim();
        return type switch
        {
            IocType.Sha256 or IocType.Sha1 or IocType.Md5 => trimmed.ToLowerInvariant(),
            IocType.Domain => trimmed.ToLowerInvariant().TrimEnd('.'),
            IocType.Ip => trimmed.ToLowerInvariant(),
            IocType.Url => trimmed,
            IocType.PathGlob => trimmed.Replace('/', '\\'),
            _ => trimmed
        };
    }

    /// <summary>Audit-safe redaction. Hashes and IPs/domains pass through; URLs and file-like values are SHA-256 truncated.</summary>
    public static string RedactForAudit(ReputationLookupType type, string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        return type switch
        {
            ReputationLookupType.Sha256 or ReputationLookupType.Sha1 or ReputationLookupType.Md5 or ReputationLookupType.Ip or ReputationLookupType.Domain
                => value.Length <= 256 ? value : value[..256],
            _ => "sha256:" + Hex(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value))).Substring(0, 32)
        };
    }

    private static string Hex(byte[] bytes)
    {
        var sb = new System.Text.StringBuilder(bytes.Length * 2);
        foreach (var b in bytes) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }
}
