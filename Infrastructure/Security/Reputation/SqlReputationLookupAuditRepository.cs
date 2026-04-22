using Antivirus.Application.Contracts;
using Antivirus.Domain;
using Microsoft.Data.SqlClient;

namespace Antivirus.Infrastructure.Security.Reputation;

public sealed class SqlReputationLookupAuditRepository : IReputationLookupAuditRepository
{
    private readonly ITenantRegistry _tenantRegistry;
    private readonly ILogger<SqlReputationLookupAuditRepository> _logger;

    public SqlReputationLookupAuditRepository(ITenantRegistry tenantRegistry, ILogger<SqlReputationLookupAuditRepository> logger)
    {
        _tenantRegistry = tenantRegistry;
        _logger = logger;
    }

    public async Task RecordAsync(ReputationLookupAuditEntry entry, CancellationToken cancellationToken = default)
    {
        try
        {
            await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
            const string sql = """
                INSERT INTO dbo.ReputationLookupAudit
                    (TenantKey, CallerUser, LookupType, RedactedValue, ProvidersAttempted,
                     CacheHit, LocalIocHit, LatencyMs, FinalVerdict, FailureReason, CorrelationId)
                VALUES
                    (@TenantKey, @CallerUser, @LookupType, @RedactedValue, @ProvidersAttempted,
                     @CacheHit, @LocalIocHit, @LatencyMs, @FinalVerdict, @FailureReason, @CorrelationId)
                """;
            await using var cmd = new SqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("@TenantKey", entry.TenantKey);
            cmd.Parameters.AddWithValue("@CallerUser", (object?)entry.CallerUser ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@LookupType", entry.LookupType.ToString());
            cmd.Parameters.AddWithValue("@RedactedValue", entry.RedactedValue);
            cmd.Parameters.AddWithValue("@ProvidersAttempted", entry.ProvidersAttempted);
            cmd.Parameters.AddWithValue("@CacheHit", entry.CacheHit);
            cmd.Parameters.AddWithValue("@LocalIocHit", entry.LocalIocHit);
            cmd.Parameters.AddWithValue("@LatencyMs", entry.LatencyMs);
            cmd.Parameters.AddWithValue("@FinalVerdict", entry.FinalVerdict.ToString());
            cmd.Parameters.AddWithValue("@FailureReason", (object?)entry.FailureReason ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@CorrelationId", (object?)entry.CorrelationId ?? DBNull.Value);
            await cmd.ExecuteNonQueryAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to record reputation lookup audit");
        }
    }

    public async Task<IReadOnlyList<ReputationLookupAuditEntry>> RecentAsync(string tenantKey, int maxCount, CancellationToken cancellationToken = default)
    {
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        var sql = $"""
            SELECT TOP ({Math.Clamp(maxCount, 1, 500)})
                Id, TenantKey, CallerUser, LookupType, RedactedValue, ProvidersAttempted,
                CacheHit, LocalIocHit, LatencyMs, FinalVerdict, FailureReason, CorrelationId, CreatedAt
            FROM dbo.ReputationLookupAudit
            WHERE TenantKey = @TenantKey
            ORDER BY CreatedAt DESC
            """;
        await using var cmd = new SqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("@TenantKey", tenantKey);
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        var list = new List<ReputationLookupAuditEntry>();
        while (await reader.ReadAsync(cancellationToken))
        {
            list.Add(new ReputationLookupAuditEntry
            {
                Id = reader.GetInt64(0),
                TenantKey = reader.GetString(1),
                CallerUser = reader.IsDBNull(2) ? null : reader.GetString(2),
                LookupType = Enum.Parse<ReputationLookupType>(reader.GetString(3)),
                RedactedValue = reader.GetString(4),
                ProvidersAttempted = reader.GetString(5),
                CacheHit = reader.GetBoolean(6),
                LocalIocHit = reader.GetBoolean(7),
                LatencyMs = reader.GetInt32(8),
                FinalVerdict = Enum.Parse<ReputationVerdict>(reader.GetString(9)),
                FailureReason = reader.IsDBNull(10) ? null : reader.GetString(10),
                CorrelationId = reader.IsDBNull(11) ? null : reader.GetString(11),
                CreatedAt = reader.GetDateTimeOffset(12)
            });
        }
        return list;
    }
}
