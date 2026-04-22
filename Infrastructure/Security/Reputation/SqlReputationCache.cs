using System.Text.Json;
using Antivirus.Application.Contracts;
using Antivirus.Domain;
using Microsoft.Data.SqlClient;

namespace Antivirus.Infrastructure.Security.Reputation;

public sealed class SqlReputationCache : IReputationCache
{
    private readonly ITenantRegistry _tenantRegistry;
    private readonly ILogger<SqlReputationCache> _logger;

    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    public SqlReputationCache(ITenantRegistry tenantRegistry, ILogger<SqlReputationCache> logger)
    {
        _tenantRegistry = tenantRegistry;
        _logger = logger;
    }

    public async Task<ProviderVerdict?> TryGetAsync(string tenantKey, string provider, ReputationLookupType type, string normalizedValue, CancellationToken cancellationToken = default)
    {
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        const string sql = """
            SELECT VerdictJson, ExpiresAt FROM dbo.ReputationCache
            WHERE TenantKey = @TenantKey AND Provider = @Provider AND LookupType = @LookupType AND NormalizedValue = @NormalizedValue
            """;
        await using var cmd = new SqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("@TenantKey", tenantKey);
        cmd.Parameters.AddWithValue("@Provider", provider);
        cmd.Parameters.AddWithValue("@LookupType", type.ToString());
        cmd.Parameters.AddWithValue("@NormalizedValue", normalizedValue);
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;

        var json = reader.GetString(0);
        var expires = reader.GetDateTimeOffset(1);
        if (expires <= DateTimeOffset.UtcNow) return null;

        try
        {
            var verdict = JsonSerializer.Deserialize<ProviderVerdict>(json, JsonOpts);
            if (verdict is null) return null;
            return new ProviderVerdict
            {
                Provider = verdict.Provider,
                Verdict = verdict.Verdict,
                Confidence = verdict.Confidence,
                ReasonCodes = verdict.ReasonCodes,
                EvidenceSummary = verdict.EvidenceSummary,
                Evidence = verdict.Evidence,
                FromCache = true,
                TimedOut = false,
                RateLimited = false,
                LatencyMs = 0
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Cached verdict deserialize failed for {Provider}/{Type}", provider, type);
            return null;
        }
    }

    public async Task SetAsync(string tenantKey, string provider, ReputationLookupType type, string normalizedValue, ProviderVerdict verdict, TimeSpan ttl, CancellationToken cancellationToken = default)
    {
        var json = JsonSerializer.Serialize(verdict, JsonOpts);
        var expiresAt = DateTimeOffset.UtcNow.Add(ttl);

        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        const string sql = """
            MERGE dbo.ReputationCache AS target
            USING (SELECT @TenantKey AS TenantKey, @Provider AS Provider, @LookupType AS LookupType, @NormalizedValue AS NormalizedValue) AS src
              ON target.TenantKey = src.TenantKey AND target.Provider = src.Provider AND target.LookupType = src.LookupType AND target.NormalizedValue = src.NormalizedValue
            WHEN MATCHED THEN
              UPDATE SET VerdictJson = @VerdictJson, Verdict = @Verdict, Confidence = @Confidence, ExpiresAt = @ExpiresAt, CreatedAt = SYSUTCDATETIME()
            WHEN NOT MATCHED THEN
              INSERT (TenantKey, Provider, LookupType, NormalizedValue, VerdictJson, Verdict, Confidence, ExpiresAt)
              VALUES (@TenantKey, @Provider, @LookupType, @NormalizedValue, @VerdictJson, @Verdict, @Confidence, @ExpiresAt);
            """;
        await using var cmd = new SqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("@TenantKey", tenantKey);
        cmd.Parameters.AddWithValue("@Provider", provider);
        cmd.Parameters.AddWithValue("@LookupType", type.ToString());
        cmd.Parameters.AddWithValue("@NormalizedValue", normalizedValue);
        cmd.Parameters.AddWithValue("@VerdictJson", json);
        cmd.Parameters.AddWithValue("@Verdict", verdict.Verdict.ToString());
        cmd.Parameters.AddWithValue("@Confidence", verdict.Confidence);
        cmd.Parameters.AddWithValue("@ExpiresAt", expiresAt);
        await cmd.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task EvictExpiredAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        const string sql = "DELETE FROM dbo.ReputationCache WHERE ExpiresAt < SYSUTCDATETIME()";
        await using var cmd = new SqlCommand(sql, connection);
        var rows = await cmd.ExecuteNonQueryAsync(cancellationToken);
        if (rows > 0) _logger.LogInformation("Evicted {Rows} expired reputation cache rows", rows);
    }
}
