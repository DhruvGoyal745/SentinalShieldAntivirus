using Antivirus.Application.Contracts;
using Antivirus.Domain;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Logging;

namespace Antivirus.Infrastructure.Persistence;

public sealed class SqlQuarantineRepository : IQuarantineRepository
{
    private readonly ITenantRegistry _tenantRegistry;
    private readonly ILogger<SqlQuarantineRepository> _logger;

    public SqlQuarantineRepository(ITenantRegistry tenantRegistry, ILogger<SqlQuarantineRepository> logger)
    {
        _tenantRegistry = tenantRegistry;
        _logger = logger;
    }

    public async Task InsertAsync(QuarantineVaultItem item, CancellationToken ct = default)
    {
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(ct);
        const string sql = """
            INSERT INTO dbo.QuarantineItems
                (Id, OriginalPath, OriginalFileName, VaultPath, HashSha256, FileSizeBytes,
                 EncryptionKeyId, EncryptionIV, ThreatName, ThreatSeverity, ThreatSource,
                 DetectionContextJson, PurgeState, CreatedAt, RetentionExpiresAt, RestoredAt, PurgedAt, RestoredBy)
            VALUES
                (@Id, @OriginalPath, @OriginalFileName, @VaultPath, @HashSha256, @FileSizeBytes,
                 @EncryptionKeyId, @EncryptionIV, @ThreatName, @ThreatSeverity, @ThreatSource,
                 @DetectionContextJson, @PurgeState, @CreatedAt, @RetentionExpiresAt, @RestoredAt, @PurgedAt, @RestoredBy)
            """;

        await using var cmd = new SqlCommand(sql, connection);
        AddParameters(cmd, item);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task UpdateAsync(QuarantineVaultItem item, CancellationToken ct = default)
    {
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(ct);
        const string sql = """
            UPDATE dbo.QuarantineItems
            SET PurgeState = @PurgeState,
                RestoredAt = @RestoredAt,
                PurgedAt = @PurgedAt,
                RestoredBy = @RestoredBy
            WHERE Id = @Id
            """;

        await using var cmd = new SqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("@Id", item.Id);
        cmd.Parameters.AddWithValue("@PurgeState", (int)item.PurgeState);
        cmd.Parameters.AddWithValue("@RestoredAt", (object?)item.RestoredAt?.UtcDateTime ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@PurgedAt", (object?)item.PurgedAt?.UtcDateTime ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@RestoredBy", (object?)item.RestoredBy ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<QuarantineVaultItem?> GetByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(ct);
        const string sql = "SELECT * FROM dbo.QuarantineItems WHERE Id = @Id";

        await using var cmd = new SqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("@Id", id);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (await reader.ReadAsync(ct))
            return MapItem(reader);

        return null;
    }

    public async Task<IReadOnlyCollection<QuarantineVaultItem>> ListAsync(QuarantineListFilter filter, CancellationToken ct = default)
    {
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(ct);

        var conditions = new List<string>();
        var parameters = new List<SqlParameter>();

        if (filter.Status.HasValue)
        {
            conditions.Add("PurgeState = @Status");
            parameters.Add(new SqlParameter("@Status", (int)filter.Status.Value));
        }

        if (!string.IsNullOrEmpty(filter.ThreatName))
        {
            conditions.Add("ThreatName LIKE @ThreatName");
            parameters.Add(new SqlParameter("@ThreatName", $"%{filter.ThreatName}%"));
        }

        if (filter.FromDate.HasValue)
        {
            conditions.Add("CreatedAt >= @FromDate");
            parameters.Add(new SqlParameter("@FromDate", filter.FromDate.Value.UtcDateTime));
        }

        if (filter.ToDate.HasValue)
        {
            conditions.Add("CreatedAt <= @ToDate");
            parameters.Add(new SqlParameter("@ToDate", filter.ToDate.Value.UtcDateTime));
        }

        var whereClause = conditions.Count > 0 ? "WHERE " + string.Join(" AND ", conditions) : string.Empty;
        var offset = (filter.PageNumber - 1) * filter.PageSize;

        var sql = $"""
            SELECT * FROM dbo.QuarantineItems
            {whereClause}
            ORDER BY CreatedAt DESC
            OFFSET @Offset ROWS FETCH NEXT @PageSize ROWS ONLY
            """;

        await using var cmd = new SqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("@Offset", offset);
        cmd.Parameters.AddWithValue("@PageSize", filter.PageSize);
        foreach (var p in parameters)
            cmd.Parameters.Add(p);

        var items = new List<QuarantineVaultItem>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            items.Add(MapItem(reader));

        return items;
    }

    public async Task<IReadOnlyCollection<QuarantineVaultItem>> GetExpiredActiveItemsAsync(CancellationToken ct = default)
    {
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(ct);
        const string sql = """
            SELECT * FROM dbo.QuarantineItems
            WHERE PurgeState = @ActiveState AND RetentionExpiresAt < @Now
            ORDER BY RetentionExpiresAt ASC
            """;

        await using var cmd = new SqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("@ActiveState", (int)PurgeState.Active);
        cmd.Parameters.AddWithValue("@Now", DateTimeOffset.UtcNow.UtcDateTime);

        var items = new List<QuarantineVaultItem>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            items.Add(MapItem(reader));

        return items;
    }

    private static void AddParameters(SqlCommand cmd, QuarantineVaultItem item)
    {
        cmd.Parameters.AddWithValue("@Id", item.Id);
        cmd.Parameters.AddWithValue("@OriginalPath", item.OriginalPath);
        cmd.Parameters.AddWithValue("@OriginalFileName", item.OriginalFileName);
        cmd.Parameters.AddWithValue("@VaultPath", item.VaultPath);
        cmd.Parameters.AddWithValue("@HashSha256", item.HashSha256);
        cmd.Parameters.AddWithValue("@FileSizeBytes", item.FileSizeBytes);
        cmd.Parameters.AddWithValue("@EncryptionKeyId", item.EncryptionKeyId);
        cmd.Parameters.AddWithValue("@EncryptionIV", item.EncryptionIV.Length > 0 ? item.EncryptionIV : DBNull.Value);
        cmd.Parameters.AddWithValue("@ThreatName", (object?)item.ThreatName ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@ThreatSeverity", (int)item.ThreatSeverity);
        cmd.Parameters.AddWithValue("@ThreatSource", (object?)item.ThreatSource ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@DetectionContextJson", (object?)item.DetectionContextJson ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@PurgeState", (int)item.PurgeState);
        cmd.Parameters.AddWithValue("@CreatedAt", item.CreatedAt.UtcDateTime);
        cmd.Parameters.AddWithValue("@RetentionExpiresAt", item.RetentionExpiresAt.UtcDateTime);
        cmd.Parameters.AddWithValue("@RestoredAt", (object?)item.RestoredAt?.UtcDateTime ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@PurgedAt", (object?)item.PurgedAt?.UtcDateTime ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@RestoredBy", (object?)item.RestoredBy ?? DBNull.Value);
    }

    private static QuarantineVaultItem MapItem(SqlDataReader reader)
    {
        return new QuarantineVaultItem
        {
            Id = reader.GetGuid(reader.GetOrdinal("Id")),
            OriginalPath = reader.GetString(reader.GetOrdinal("OriginalPath")),
            OriginalFileName = reader.GetString(reader.GetOrdinal("OriginalFileName")),
            VaultPath = reader.GetString(reader.GetOrdinal("VaultPath")),
            HashSha256 = reader.GetString(reader.GetOrdinal("HashSha256")),
            FileSizeBytes = reader.GetInt64(reader.GetOrdinal("FileSizeBytes")),
            EncryptionKeyId = reader.GetString(reader.GetOrdinal("EncryptionKeyId")),
            EncryptionIV = reader.IsDBNull(reader.GetOrdinal("EncryptionIV"))
                ? Array.Empty<byte>()
                : (byte[])reader["EncryptionIV"],
            ThreatName = reader.IsDBNull(reader.GetOrdinal("ThreatName")) ? null : reader.GetString(reader.GetOrdinal("ThreatName")),
            ThreatSeverity = (ThreatSeverity)reader.GetInt32(reader.GetOrdinal("ThreatSeverity")),
            ThreatSource = reader.IsDBNull(reader.GetOrdinal("ThreatSource")) ? null : reader.GetString(reader.GetOrdinal("ThreatSource")),
            DetectionContextJson = reader.IsDBNull(reader.GetOrdinal("DetectionContextJson")) ? null : reader.GetString(reader.GetOrdinal("DetectionContextJson")),
            PurgeState = (PurgeState)reader.GetInt32(reader.GetOrdinal("PurgeState")),
            CreatedAt = new DateTimeOffset(reader.GetDateTime(reader.GetOrdinal("CreatedAt")), TimeSpan.Zero),
            RetentionExpiresAt = new DateTimeOffset(reader.GetDateTime(reader.GetOrdinal("RetentionExpiresAt")), TimeSpan.Zero),
            RestoredAt = reader.IsDBNull(reader.GetOrdinal("RestoredAt")) ? null : new DateTimeOffset(reader.GetDateTime(reader.GetOrdinal("RestoredAt")), TimeSpan.Zero),
            PurgedAt = reader.IsDBNull(reader.GetOrdinal("PurgedAt")) ? null : new DateTimeOffset(reader.GetDateTime(reader.GetOrdinal("PurgedAt")), TimeSpan.Zero),
            RestoredBy = reader.IsDBNull(reader.GetOrdinal("RestoredBy")) ? null : reader.GetString(reader.GetOrdinal("RestoredBy"))
        };
    }
}
