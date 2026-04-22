using Antivirus.Domain;

namespace Antivirus.Application.Contracts;

// ── Phase 3: Threat Intel Settings + Secrets Vault Contracts ────────

/// <summary>
/// Per-tenant operator state for the threat-intel subsystem. Distinct
/// from feature flags (which are runtime kill switches): settings persist
/// configuration like provider toggles, TTLs, sync windows, and rate
/// limits. Always retrieve through <see cref="GetOrCreateAsync"/> so a
/// tenant gets seeded defaults on first access.
/// </summary>
public interface IThreatIntelSettingsRepository
{
    Task<ThreatIntelSettings> GetOrCreateAsync(string tenantKey, CancellationToken cancellationToken = default);
    Task<ThreatIntelSettings> UpdateAsync(ThreatIntelSettings settings, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ThreatIntelSettings>> ListAllAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Encrypted secrets store for cloud provider credentials. Keys are
/// (tenantKey, provider, key). Plaintext is NEVER returned outside the
/// vault: <see cref="GetSecretAsync"/> is used by provider implementations
/// only and routes through the same DI scope as the orchestrator.
/// HTTP layers must use <see cref="ListMetadataAsync"/>.
/// </summary>
public interface ISecretsVault
{
    Task SetSecretAsync(string tenantKey, string provider, string key, string plaintext, CancellationToken cancellationToken = default);
    Task<string?> GetSecretAsync(string tenantKey, string provider, string key, CancellationToken cancellationToken = default);
    Task<bool> DeleteSecretAsync(string tenantKey, string provider, string key, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<SecretMetadata>> ListMetadataAsync(string tenantKey, CancellationToken cancellationToken = default);
}

/// <summary>Persists provider health snapshots produced by the orchestrator and background sync service.</summary>
public interface IProviderHealthRepository
{
    Task UpsertAsync(ProviderHealth health, string tenantKey, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ProviderHealth>> ListAsync(string tenantKey, CancellationToken cancellationToken = default);
}

/// <summary>Persists redacted audit rows for every reputation lookup (scan-path + API).</summary>
public interface IReputationLookupAuditRepository
{
    Task RecordAsync(ReputationLookupAuditEntry entry, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<ReputationLookupAuditEntry>> RecentAsync(string tenantKey, int maxCount, CancellationToken cancellationToken = default);
}
