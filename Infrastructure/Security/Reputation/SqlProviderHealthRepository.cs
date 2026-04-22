using Antivirus.Application.Contracts;
using Antivirus.Domain;
using Microsoft.Data.SqlClient;

namespace Antivirus.Infrastructure.Security.Reputation;

public sealed class SqlProviderHealthRepository : IProviderHealthRepository
{
    private readonly ITenantRegistry _tenantRegistry;
    private readonly ILogger<SqlProviderHealthRepository> _logger;

    public SqlProviderHealthRepository(ITenantRegistry tenantRegistry, ILogger<SqlProviderHealthRepository> logger)
    {
        _tenantRegistry = tenantRegistry;
        _logger = logger;
    }

    public async Task UpsertAsync(ProviderHealth health, string tenantKey, CancellationToken cancellationToken = default)
    {
        try
        {
            await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
            const string sql = """
                MERGE dbo.ProviderHealthSnapshots AS target
                USING (SELECT @TenantKey AS TenantKey, @Provider AS Provider) AS src
                  ON target.TenantKey = src.TenantKey AND target.Provider = src.Provider
                WHEN MATCHED THEN UPDATE SET
                    Enabled = @Enabled,
                    LastSuccessAt = @LastSuccessAt,
                    LastFailureAt = @LastFailureAt,
                    LastFailureReason = @LastFailureReason,
                    CircuitState = @CircuitState,
                    RateLimitTokensRemaining = @RateLimitTokensRemaining,
                    LastSyncDurationMs = @LastSyncDurationMs,
                    LastSyncCount = @LastSyncCount,
                    LastSyncAt = @LastSyncAt,
                    UpdatedAt = SYSUTCDATETIME()
                WHEN NOT MATCHED THEN INSERT
                    (TenantKey, Provider, Enabled, LastSuccessAt, LastFailureAt, LastFailureReason,
                     CircuitState, RateLimitTokensRemaining, LastSyncDurationMs, LastSyncCount, LastSyncAt)
                  VALUES
                    (@TenantKey, @Provider, @Enabled, @LastSuccessAt, @LastFailureAt, @LastFailureReason,
                     @CircuitState, @RateLimitTokensRemaining, @LastSyncDurationMs, @LastSyncCount, @LastSyncAt);
                """;
            await using var cmd = new SqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("@TenantKey", tenantKey);
            cmd.Parameters.AddWithValue("@Provider", health.Provider);
            cmd.Parameters.AddWithValue("@Enabled", health.Enabled);
            cmd.Parameters.AddWithValue("@LastSuccessAt", (object?)health.LastSuccessAt ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@LastFailureAt", (object?)health.LastFailureAt ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@LastFailureReason", (object?)health.LastFailureReason ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@CircuitState", health.CircuitState.ToString());
            cmd.Parameters.AddWithValue("@RateLimitTokensRemaining", health.RateLimitTokensRemaining);
            cmd.Parameters.AddWithValue("@LastSyncDurationMs", health.LastSyncDurationMs);
            cmd.Parameters.AddWithValue("@LastSyncCount", health.LastSyncCount);
            cmd.Parameters.AddWithValue("@LastSyncAt", (object?)health.LastSyncAt ?? DBNull.Value);
            await cmd.ExecuteNonQueryAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to upsert provider health for {Provider}", health.Provider);
        }
    }

    public async Task<IReadOnlyList<ProviderHealth>> ListAsync(string tenantKey, CancellationToken cancellationToken = default)
    {
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        const string sql = """
            SELECT Provider, Enabled, LastSuccessAt, LastFailureAt, LastFailureReason,
                   CircuitState, RateLimitTokensRemaining, LastSyncDurationMs, LastSyncCount, LastSyncAt
            FROM dbo.ProviderHealthSnapshots
            WHERE TenantKey = @TenantKey
            ORDER BY Provider
            """;
        await using var cmd = new SqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("@TenantKey", tenantKey);
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        var list = new List<ProviderHealth>();
        while (await reader.ReadAsync(cancellationToken))
        {
            list.Add(new ProviderHealth
            {
                Provider = reader.GetString(0),
                Enabled = reader.GetBoolean(1),
                LastSuccessAt = reader.IsDBNull(2) ? null : reader.GetDateTimeOffset(2),
                LastFailureAt = reader.IsDBNull(3) ? null : reader.GetDateTimeOffset(3),
                LastFailureReason = reader.IsDBNull(4) ? null : reader.GetString(4),
                CircuitState = Enum.Parse<ProviderCircuitState>(reader.GetString(5)),
                RateLimitTokensRemaining = reader.GetInt32(6),
                LastSyncDurationMs = reader.GetInt32(7),
                LastSyncCount = reader.GetInt32(8),
                LastSyncAt = reader.IsDBNull(9) ? null : reader.GetDateTimeOffset(9)
            });
        }
        return list;
    }
}
