using System.Text.Json;
using Antivirus.Application.Contracts;
using Antivirus.Domain;
using Microsoft.Data.SqlClient;

namespace Antivirus.Infrastructure.Persistence;

public sealed class SqlThreatIntelSettingsRepository : IThreatIntelSettingsRepository
{
    private readonly ITenantRegistry _tenantRegistry;
    private readonly ILogger<SqlThreatIntelSettingsRepository> _logger;

    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    public SqlThreatIntelSettingsRepository(ITenantRegistry tenantRegistry, ILogger<SqlThreatIntelSettingsRepository> logger)
    {
        _tenantRegistry = tenantRegistry;
        _logger = logger;
    }

    public async Task<ThreatIntelSettings> GetOrCreateAsync(string tenantKey, CancellationToken cancellationToken = default)
    {
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        const string select = "SELECT SettingsJson, UpdatedAt FROM dbo.ThreatIntelSettings WHERE TenantKey = @TenantKey";
        await using var cmd = new SqlCommand(select, connection);
        cmd.Parameters.AddWithValue("@TenantKey", tenantKey);
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);

        if (await reader.ReadAsync(cancellationToken))
        {
            var json = reader.GetString(0);
            var updated = reader.GetDateTimeOffset(1);
            await reader.CloseAsync();
            try
            {
                var parsed = JsonSerializer.Deserialize<ThreatIntelSettings>(json, JsonOpts) ?? CreateDefault(tenantKey);
                parsed.TenantKey = tenantKey;
                parsed.UpdatedAt = updated;
                return parsed;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to parse ThreatIntelSettings JSON for {Tenant}; resetting to defaults", tenantKey);
            }
        }
        else
        {
            await reader.CloseAsync();
        }

        var seeded = CreateDefault(tenantKey);
        await UpsertAsync(connection, seeded, cancellationToken);
        return seeded;
    }

    public async Task<ThreatIntelSettings> UpdateAsync(ThreatIntelSettings settings, CancellationToken cancellationToken = default)
    {
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        settings.UpdatedAt = DateTimeOffset.UtcNow;
        await UpsertAsync(connection, settings, cancellationToken);
        return settings;
    }

    public async Task<IReadOnlyList<ThreatIntelSettings>> ListAllAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        const string sql = "SELECT TenantKey, SettingsJson, UpdatedAt FROM dbo.ThreatIntelSettings";
        await using var cmd = new SqlCommand(sql, connection);
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        var list = new List<ThreatIntelSettings>();
        while (await reader.ReadAsync(cancellationToken))
        {
            try
            {
                var json = reader.GetString(1);
                var parsed = JsonSerializer.Deserialize<ThreatIntelSettings>(json, JsonOpts) ?? CreateDefault(reader.GetString(0));
                parsed.TenantKey = reader.GetString(0);
                parsed.UpdatedAt = reader.GetDateTimeOffset(2);
                list.Add(parsed);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Skipping unreadable ThreatIntelSettings row");
            }
        }
        return list;
    }

    private static async Task UpsertAsync(SqlConnection connection, ThreatIntelSettings settings, CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(settings, JsonOpts);
        const string sql = """
            MERGE dbo.ThreatIntelSettings AS target
            USING (SELECT @TenantKey AS TenantKey) AS src ON target.TenantKey = src.TenantKey
            WHEN MATCHED THEN UPDATE SET SettingsJson = @SettingsJson, UpdatedAt = SYSUTCDATETIME()
            WHEN NOT MATCHED THEN INSERT (TenantKey, SettingsJson) VALUES (@TenantKey, @SettingsJson);
            """;
        await using var cmd = new SqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("@TenantKey", settings.TenantKey);
        cmd.Parameters.AddWithValue("@SettingsJson", json);
        await cmd.ExecuteNonQueryAsync(cancellationToken);
    }

    public static ThreatIntelSettings CreateDefault(string tenantKey) => new()
    {
        TenantKey = tenantKey,
        CloudReputationEnabled = true,
        Providers = new List<ThreatIntelProviderSettings>
        {
            new() { Provider = "mock", Enabled = true, TrustWeight = 0.0m, RateLimitPerMinute = 1000 },
            new() { Provider = "virustotal", Enabled = false, TrustWeight = 0.9m, RateLimitPerMinute = 4 },
            new() { Provider = "hybridanalysis", Enabled = false, TrustWeight = 0.85m, RateLimitPerMinute = 10 },
            new() { Provider = "misp", Enabled = false, TrustWeight = 0.7m, RateLimitPerMinute = 60 },
            new() { Provider = "otx", Enabled = false, TrustWeight = 0.6m, RateLimitPerMinute = 30 },
        },
        Ttl = new ThreatIntelTtlSettings(),
        SyncWindowDays = 7,
        MaxIndicatorsPerSync = 10000,
        CloudFanoutTimeoutMs = 1500,
        UpdatedAt = DateTimeOffset.UtcNow
    };
}
