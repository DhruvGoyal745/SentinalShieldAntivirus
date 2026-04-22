using System.Text;
using System.Text.Json;
using Antivirus.Application.Contracts;
using Antivirus.Domain;
using Antivirus.Infrastructure.Security.Reputation;
using Microsoft.Data.SqlClient;

namespace Antivirus.Infrastructure.Persistence;

public sealed class SqlIocRepository : IIocRepository
{
    private readonly ITenantRegistry _tenantRegistry;
    private readonly ILogger<SqlIocRepository> _logger;

    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    public SqlIocRepository(ITenantRegistry tenantRegistry, ILogger<SqlIocRepository> logger)
    {
        _tenantRegistry = tenantRegistry;
        _logger = logger;
    }

    public async Task<IocIndicator> AddAsync(IocIndicator indicator, CancellationToken cancellationToken = default)
    {
        var prepared = Prepare(indicator);
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        const string sql = """
            MERGE dbo.IocIndicators AS target
            USING (SELECT @TenantKey AS TenantKey, @IocType AS IocType, @NormalizedValue AS NormalizedValue, @Source AS Source) AS src
              ON target.TenantKey = src.TenantKey AND target.IocType = src.IocType AND target.NormalizedValue = src.NormalizedValue AND target.Source = src.Source
            WHEN MATCHED THEN UPDATE SET
                DisplayValue = @DisplayValue, Severity = @Severity, Confidence = @Confidence,
                TagsJson = @TagsJson, Description = @Description, ExpiresAt = @ExpiresAt, IsActive = @IsActive
            WHEN NOT MATCHED THEN INSERT
                (Id, TenantKey, IocType, NormalizedValue, DisplayValue, Source, Severity, Confidence, TagsJson, Description, CreatedAt, ExpiresAt, IsActive)
              VALUES
                (@Id, @TenantKey, @IocType, @NormalizedValue, @DisplayValue, @Source, @Severity, @Confidence, @TagsJson, @Description, @CreatedAt, @ExpiresAt, @IsActive);
            """;
        await using var cmd = new SqlCommand(sql, connection);
        Bind(cmd, prepared);
        await cmd.ExecuteNonQueryAsync(cancellationToken);
        return prepared;
    }

    public async Task<int> BulkUpsertAsync(IReadOnlyCollection<IocIndicator> indicators, CancellationToken cancellationToken = default)
    {
        if (indicators.Count == 0) return 0;
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        await using var tx = (SqlTransaction)await connection.BeginTransactionAsync(cancellationToken);
        var rows = 0;
        try
        {
            const string sql = """
                MERGE dbo.IocIndicators AS target
                USING (SELECT @TenantKey AS TenantKey, @IocType AS IocType, @NormalizedValue AS NormalizedValue, @Source AS Source) AS src
                  ON target.TenantKey = src.TenantKey AND target.IocType = src.IocType AND target.NormalizedValue = src.NormalizedValue AND target.Source = src.Source
                WHEN MATCHED THEN UPDATE SET
                    DisplayValue = @DisplayValue, Severity = @Severity, Confidence = @Confidence,
                    TagsJson = @TagsJson, Description = @Description, ExpiresAt = @ExpiresAt, IsActive = @IsActive
                WHEN NOT MATCHED THEN INSERT
                    (Id, TenantKey, IocType, NormalizedValue, DisplayValue, Source, Severity, Confidence, TagsJson, Description, CreatedAt, ExpiresAt, IsActive)
                  VALUES
                    (@Id, @TenantKey, @IocType, @NormalizedValue, @DisplayValue, @Source, @Severity, @Confidence, @TagsJson, @Description, @CreatedAt, @ExpiresAt, @IsActive);
                """;
            foreach (var indicator in indicators)
            {
                var prepared = Prepare(indicator);
                await using var cmd = new SqlCommand(sql, connection, tx);
                Bind(cmd, prepared);
                rows += await cmd.ExecuteNonQueryAsync(cancellationToken);
            }
            await tx.CommitAsync(cancellationToken);
        }
        catch
        {
            await tx.RollbackAsync(cancellationToken);
            throw;
        }
        return rows;
    }

    public async Task<IocIndicator?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        const string sql = "SELECT " + SelectColumns + " FROM dbo.IocIndicators WHERE Id = @Id";
        await using var cmd = new SqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("@Id", id);
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        return Map(reader);
    }

    public async Task<IocIndicator?> GetByValueAsync(string tenantKey, IocType type, string normalizedValue, CancellationToken cancellationToken = default)
    {
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        const string sql = "SELECT TOP 1 " + SelectColumns +
                           " FROM dbo.IocIndicators WHERE TenantKey=@TenantKey AND IocType=@IocType AND NormalizedValue=@NormalizedValue AND IsActive=1 ORDER BY Confidence DESC";
        await using var cmd = new SqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("@TenantKey", tenantKey);
        cmd.Parameters.AddWithValue("@IocType", type.ToString());
        cmd.Parameters.AddWithValue("@NormalizedValue", normalizedValue);
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        return Map(reader);
    }

    public async Task<IReadOnlyList<IocIndicator>> SearchAsync(IocSearchFilter filter, CancellationToken cancellationToken = default)
    {
        var pageSize = Math.Clamp(filter.PageSize, 1, 500);
        var pageNumber = Math.Max(1, filter.PageNumber);
        var sb = new StringBuilder("SELECT " + SelectColumns + " FROM dbo.IocIndicators WHERE 1=1");
        if (!string.IsNullOrWhiteSpace(filter.TenantKey)) sb.Append(" AND TenantKey=@TenantKey");
        if (filter.Type is not null) sb.Append(" AND IocType=@IocType");
        if (!string.IsNullOrWhiteSpace(filter.Source)) sb.Append(" AND Source=@Source");
        if (filter.IsActive is not null) sb.Append(" AND IsActive=@IsActive");
        if (!string.IsNullOrWhiteSpace(filter.ValueContains)) sb.Append(" AND (NormalizedValue LIKE @ValueLike OR DisplayValue LIKE @ValueLike)");
        sb.Append(" ORDER BY CreatedAt DESC OFFSET @Offset ROWS FETCH NEXT @PageSize ROWS ONLY");

        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        await using var cmd = new SqlCommand(sb.ToString(), connection);
        if (!string.IsNullOrWhiteSpace(filter.TenantKey)) cmd.Parameters.AddWithValue("@TenantKey", filter.TenantKey);
        if (filter.Type is not null) cmd.Parameters.AddWithValue("@IocType", filter.Type.Value.ToString());
        if (!string.IsNullOrWhiteSpace(filter.Source)) cmd.Parameters.AddWithValue("@Source", filter.Source);
        if (filter.IsActive is not null) cmd.Parameters.AddWithValue("@IsActive", filter.IsActive.Value);
        if (!string.IsNullOrWhiteSpace(filter.ValueContains)) cmd.Parameters.AddWithValue("@ValueLike", "%" + filter.ValueContains + "%");
        cmd.Parameters.AddWithValue("@Offset", (pageNumber - 1) * pageSize);
        cmd.Parameters.AddWithValue("@PageSize", pageSize);

        var list = new List<IocIndicator>();
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) list.Add(Map(reader));
        return list;
    }

    public async Task<IocStats> GetStatsAsync(string tenantKey, CancellationToken cancellationToken = default)
    {
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        const string sql = """
            SELECT COUNT_BIG(*) AS Total, SUM(CAST(IsActive AS INT)) AS Active FROM dbo.IocIndicators WHERE TenantKey=@TenantKey;
            SELECT IocType, COUNT_BIG(*) AS Cnt FROM dbo.IocIndicators WHERE TenantKey=@TenantKey AND IsActive=1 GROUP BY IocType;
            SELECT Source, COUNT_BIG(*) AS Cnt FROM dbo.IocIndicators WHERE TenantKey=@TenantKey AND IsActive=1 GROUP BY Source;
            """;
        await using var cmd = new SqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("@TenantKey", tenantKey);
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);

        int total = 0, active = 0;
        if (await reader.ReadAsync(cancellationToken))
        {
            total = (int)reader.GetInt64(0);
            active = reader.IsDBNull(1) ? 0 : reader.GetInt32(1);
        }
        var byType = new Dictionary<IocType, int>();
        if (await reader.NextResultAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                if (Enum.TryParse<IocType>(reader.GetString(0), out var t)) byType[t] = (int)reader.GetInt64(1);
            }
        }
        var bySource = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        if (await reader.NextResultAsync(cancellationToken))
        {
            while (await reader.ReadAsync(cancellationToken))
            {
                bySource[reader.GetString(0)] = (int)reader.GetInt64(1);
            }
        }
        return new IocStats { Total = total, Active = active, ByType = byType, BySource = bySource };
    }

    public async Task<bool> DeleteAsync(Guid id, CancellationToken cancellationToken = default)
    {
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        const string sql = "DELETE FROM dbo.IocIndicators WHERE Id=@Id";
        await using var cmd = new SqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("@Id", id);
        return await cmd.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    public async Task<int> ExpireOldAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        const string sql = "UPDATE dbo.IocIndicators SET IsActive=0 WHERE IsActive=1 AND ExpiresAt IS NOT NULL AND ExpiresAt < SYSUTCDATETIME()";
        await using var cmd = new SqlCommand(sql, connection);
        var rows = await cmd.ExecuteNonQueryAsync(cancellationToken);
        if (rows > 0) _logger.LogInformation("Expired {Rows} stale IOC indicators", rows);
        return rows;
    }

    private const string SelectColumns =
        "Id, TenantKey, IocType, NormalizedValue, DisplayValue, Source, Severity, Confidence, TagsJson, Description, CreatedAt, ExpiresAt, IsActive";

    private static IocIndicator Prepare(IocIndicator indicator) => new()
    {
        Id = indicator.Id == Guid.Empty ? Guid.NewGuid() : indicator.Id,
        TenantKey = indicator.TenantKey,
        Type = indicator.Type,
        NormalizedValue = string.IsNullOrWhiteSpace(indicator.NormalizedValue)
            ? IndicatorNormalization.NormalizeIoc(indicator.Type, indicator.DisplayValue)
            : indicator.NormalizedValue,
        DisplayValue = string.IsNullOrWhiteSpace(indicator.DisplayValue) ? indicator.NormalizedValue : indicator.DisplayValue,
        Source = string.IsNullOrWhiteSpace(indicator.Source) ? "manual" : indicator.Source,
        Severity = indicator.Severity == default ? ThreatSeverity.Medium : indicator.Severity,
        Confidence = indicator.Confidence == 0m ? 0.7m : indicator.Confidence,
        Tags = indicator.Tags,
        Description = indicator.Description,
        CreatedAt = indicator.CreatedAt == default ? DateTimeOffset.UtcNow : indicator.CreatedAt,
        ExpiresAt = indicator.ExpiresAt,
        IsActive = indicator.IsActive
    };

    private static void Bind(SqlCommand cmd, IocIndicator indicator)
    {
        cmd.Parameters.AddWithValue("@Id", indicator.Id);
        cmd.Parameters.AddWithValue("@TenantKey", indicator.TenantKey);
        cmd.Parameters.AddWithValue("@IocType", indicator.Type.ToString());
        cmd.Parameters.AddWithValue("@NormalizedValue", indicator.NormalizedValue);
        cmd.Parameters.AddWithValue("@DisplayValue", indicator.DisplayValue);
        cmd.Parameters.AddWithValue("@Source", indicator.Source);
        cmd.Parameters.AddWithValue("@Severity", indicator.Severity.ToString());
        cmd.Parameters.AddWithValue("@Confidence", indicator.Confidence);
        cmd.Parameters.AddWithValue("@TagsJson", (object?)(indicator.Tags?.Count > 0 ? JsonSerializer.Serialize(indicator.Tags, JsonOpts) : null) ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@Description", (object?)indicator.Description ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@CreatedAt", indicator.CreatedAt);
        cmd.Parameters.AddWithValue("@ExpiresAt", (object?)indicator.ExpiresAt ?? DBNull.Value);
        cmd.Parameters.AddWithValue("@IsActive", indicator.IsActive);
    }

    private static IocIndicator Map(SqlDataReader reader) => new()
    {
        Id = reader.GetGuid(0),
        TenantKey = reader.GetString(1),
        Type = Enum.Parse<IocType>(reader.GetString(2)),
        NormalizedValue = reader.GetString(3),
        DisplayValue = reader.GetString(4),
        Source = reader.GetString(5),
        Severity = Enum.Parse<ThreatSeverity>(reader.GetString(6)),
        Confidence = reader.GetDecimal(7),
        Tags = reader.IsDBNull(8) ? Array.Empty<string>() : (JsonSerializer.Deserialize<List<string>>(reader.GetString(8), JsonOpts) ?? new List<string>()),
        Description = reader.IsDBNull(9) ? null : reader.GetString(9),
        CreatedAt = reader.GetDateTimeOffset(10),
        ExpiresAt = reader.IsDBNull(11) ? null : reader.GetDateTimeOffset(11),
        IsActive = reader.GetBoolean(12)
    };
}
