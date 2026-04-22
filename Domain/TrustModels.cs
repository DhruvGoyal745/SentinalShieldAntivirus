namespace Antivirus.Domain;

public enum TrustAction
{
    Allow,
    ReduceSeverity,
    Block
}

public enum TrustScope
{
    Global,
    Tenant,
    Device
}

public enum TrustOverrideType
{
    Signer,
    Path,
    Hash,
    Process
}

public enum SignerTrustLevel
{
    Trusted,
    Neutral,
    Blocked
}

public sealed class TrustOverride
{
    public int Id { get; init; }
    public TrustOverrideType Type { get; init; }
    public string Pattern { get; init; } = string.Empty;
    public TrustAction Action { get; init; }
    public TrustScope Scope { get; init; }
    public string? TenantKey { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
}

public sealed class SignerTrustEntry
{
    public int Id { get; init; }
    public string CommonName { get; init; } = string.Empty;
    public string? Thumbprint { get; init; }
    public SignerTrustLevel TrustLevel { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
}
