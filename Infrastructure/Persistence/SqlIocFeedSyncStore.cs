using Antivirus.Application.Contracts;
using Antivirus.Domain;
using Microsoft.Data.SqlClient;

namespace Antivirus.Infrastructure.Persistence;

/// <summary>SQL-backed store for IOC feed sync run history and per-source cursors.</summary>
public interface IIocFeedSyncStore
{
    Task<IocSource?> GetSourceAsync(string tenantKey, string provider, CancellationToken cancellationToken);
    Task UpsertSourceAsync(IocSource source, CancellationToken cancellationToken);
    Task<long> RecordRunAsync(IocFeedSyncRun run, CancellationToken cancellationToken);
    Task<IReadOnlyList<IocFeedSyncRun>> RecentAsync(string? provider, string? tenantKey, int maxCount, CancellationToken cancellationToken);
}

public sealed class SqlIocFeedSyncStore : IIocFeedSyncStore
{
    private readonly ITenantRegistry _tenantRegistry;

    public SqlIocFeedSyncStore(ITenantRegistry tenantRegistry) => _tenantRegistry = tenantRegistry;

    public async Task<IocSource?> GetSourceAsync(string tenantKey, string provider, CancellationToken cancellationToken)
    {
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        const string sql = "SELECT TenantKey, Provider, LastSyncAt, LastCursor, Enabled FROM dbo.IocSources WHERE TenantKey=@TenantKey AND Provider=@Provider";
        await using var cmd = new SqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("@TenantKey", tenantKey);
        cmd.Parameters.AddWithValue("@Provider", provider);
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        return new IocSource
        {
            TenantKey = reader.GetString(0),
            Provider = reader.GetString(1),
            LastSyncAt = reader.IsDBNull(2) ? null : reader.GetDateTimeOffset(2),
            LastCursor = reader.IsDBNull(3) ? null : reader.GetString(3),
            Enabled = reader.GetBoolean(4)
        };
    }

    public async Task UpsertSourceAsync(IocSource source, CancellationToken cancellationToken)
    {
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        const string sql = """
            MERGE dbo.IocSources AS target
            USING (SELECT @TenantKey AS TenantKey, @Provider AS Provider) AS src
              ON target.TenantKey = src.TenantKey AND target.Provider = src.Provider
            WHEN MATCHED THEN UPDATE SET LastSyncAt=@LastSyncAt, LastCursor=@LastCursor, Enabled=@Enabled
            WHEN NOT MATCHED THEN INSERT (TenantKey, Provider, LastSyncAt, LastCursor, Enabled)
              VALUES (@TenantKey, @Provider, @LastSyncAt, @LastCursor, @Enabled);
            """;
        await using var cmd = new SqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("@TenantKey", source.TenantKey);
        cmd.Parameters.AddWithValue("@Provider", source.Provider);
        cmd.Parameters.AddWithValue("@LastSyncAt", (object?)source.LastSyncAt ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@LastCursor", (object?)source.LastCursor ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@Enabled", source.Enabled);
        await cmd.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<long> RecordRunAsync(IocFeedSyncRun run, CancellationToken cancellationToken)
    {
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        const string sql = """
            INSERT INTO dbo.IocFeedSyncRuns
                (TenantKey, Provider, StartedAt, CompletedAt, IndicatorsImported, IndicatorsSkipped, Success, FailureReason, CursorAfter)
            OUTPUT INSERTED.Id
            VALUES
                (@TenantKey, @Provider, @StartedAt, @CompletedAt, @IndicatorsImported, @IndicatorsSkipped, @Success, @FailureReason, @CursorAfter)
            """;
        await using var cmd = new SqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("@TenantKey", run.TenantKey);
        cmd.Parameters.AddWithValue("@Provider", run.Provider);
        cmd.Parameters.AddWithValue("@StartedAt", run.StartedAt);
        cmd.Parameters.AddWithValue("@CompletedAt", (object?)run.CompletedAt ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@IndicatorsImported", run.IndicatorsImported);
        cmd.Parameters.AddWithValue("@IndicatorsSkipped", run.IndicatorsSkipped);
        cmd.Parameters.AddWithValue("@Success", run.Success);
        cmd.Parameters.AddWithValue("@FailureReason", (object?)run.FailureReason ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@CursorAfter", (object?)run.CursorAfter ?? DBNull.Value);
        var id = await cmd.ExecuteScalarAsync(cancellationToken);
        return Convert.ToInt64(id);
    }

    public async Task<IReadOnlyList<IocFeedSyncRun>> RecentAsync(string? provider, string? tenantKey, int maxCount, CancellationToken cancellationToken)
    {
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        var clamped = Math.Clamp(maxCount, 1, 200);
        var sql = $"""
            SELECT TOP ({clamped})
                Id, TenantKey, Provider, StartedAt, CompletedAt, IndicatorsImported, IndicatorsSkipped, Success, FailureReason, CursorAfter
            FROM dbo.IocFeedSyncRuns
            WHERE (@TenantKey IS NULL OR TenantKey=@TenantKey)
              AND (@Provider IS NULL OR Provider=@Provider)
            ORDER BY StartedAt DESC
            """;
        await using var cmd = new SqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("@TenantKey", (object?)tenantKey ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@Provider", (object?)provider ?? DBNull.Value);
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        var list = new List<IocFeedSyncRun>();
        while (await reader.ReadAsync(cancellationToken))
        {
            list.Add(new IocFeedSyncRun
            {
                Id = reader.GetInt64(0),
                TenantKey = reader.GetString(1),
                Provider = reader.GetString(2),
                StartedAt = reader.GetDateTimeOffset(3),
                CompletedAt = reader.IsDBNull(4) ? null : reader.GetDateTimeOffset(4),
                IndicatorsImported = reader.GetInt32(5),
                IndicatorsSkipped = reader.GetInt32(6),
                Success = reader.GetBoolean(7),
                FailureReason = reader.IsDBNull(8) ? null : reader.GetString(8),
                CursorAfter = reader.IsDBNull(9) ? null : reader.GetString(9)
            });
        }
        return list;
    }
}
