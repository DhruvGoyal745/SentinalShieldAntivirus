using System.Collections.Concurrent;
using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Persistence;

public sealed class SqlTenantRegistry : ITenantRegistry
{
    private readonly ISqlConnectionFactory _connectionFactory;
    private readonly IWebHostEnvironment _environment;
    private readonly AntivirusPlatformOptions _options;
    private readonly ITenantContextAccessor _tenantContextAccessor;
    private readonly ILogger<SqlTenantRegistry> _logger;
    private readonly ConcurrentDictionary<string, TenantSummary> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _gate = new(1, 1);

    public SqlTenantRegistry(
        ISqlConnectionFactory connectionFactory,
        IWebHostEnvironment environment,
        IOptions<AntivirusPlatformOptions> options,
        ITenantContextAccessor tenantContextAccessor,
        ILogger<SqlTenantRegistry> logger)
    {
        _connectionFactory = connectionFactory;
        _environment = environment;
        _options = options.Value;
        _tenantContextAccessor = tenantContextAccessor;
        _logger = logger;
    }

    public string GetCurrentTenantKey()
    {
        var requested = _tenantContextAccessor.CurrentTenantKey;
        return NormalizeTenantKey(string.IsNullOrWhiteSpace(requested) ? _options.DefaultTenantKey : requested);
    }

    public async Task<TenantSummary> GetCurrentTenantAsync(CancellationToken cancellationToken = default)
    {
        return await EnsureTenantAsync(GetCurrentTenantKey(), cancellationToken);
    }

    public async Task<IReadOnlyCollection<TenantSummary>> GetTenantsAsync(CancellationToken cancellationToken = default)
    {
        const string sql = """
            SELECT Id, TenantKey, DisplayName, DatabaseName, IsActive, CreatedAt
            FROM dbo.Tenants
            ORDER BY DisplayName;
            """;

        var tenants = new List<TenantSummary>();
        await using var connection = await OpenPlatformConnectionAsync(cancellationToken);
        await using var command = new SqlCommand(sql, connection);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);

        while (await reader.ReadAsync(cancellationToken))
        {
            tenants.Add(new TenantSummary
            {
                Id = reader.GetInt32(0),
                TenantKey = reader.GetString(1),
                DisplayName = reader.GetString(2),
                DatabaseName = reader.GetString(3),
                IsActive = reader.GetBoolean(4),
                CreatedAt = reader.GetDateTimeOffset(5)
            });
        }

        foreach (var tenant in tenants)
        {
            _cache[tenant.TenantKey] = tenant;
        }

        return tenants;
    }

    public async Task<SqlConnection> OpenTenantConnectionAsync(CancellationToken cancellationToken = default)
    {
        var tenant = await GetCurrentTenantAsync(cancellationToken);
        var builder = new SqlConnectionStringBuilder(_connectionFactory.PlatformConnectionString)
        {
            InitialCatalog = tenant.DatabaseName
        };

        var connection = new SqlConnection(builder.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    public async Task<SqlConnection> OpenPlatformConnectionAsync(CancellationToken cancellationToken = default)
    {
        var connection = new SqlConnection(_connectionFactory.PlatformConnectionString);
        await connection.OpenAsync(cancellationToken);
        return connection;
    }

    public async Task<TenantSummary> EnsureTenantAsync(string tenantKey, CancellationToken cancellationToken = default)
    {
        var normalizedTenantKey = NormalizeTenantKey(tenantKey);
        if (_cache.TryGetValue(normalizedTenantKey, out var cached))
        {
            return cached;
        }

        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (_cache.TryGetValue(normalizedTenantKey, out cached))
            {
                return cached;
            }

            await using var connection = await OpenPlatformConnectionAsync(cancellationToken);
            var tenant = await TryLoadTenantAsync(connection, normalizedTenantKey, cancellationToken);
            if (tenant is null)
            {
                var databaseName = $"{_options.TenantDatabasePrefix}{normalizedTenantKey.Replace('-', '_')}";
                await EnsureDatabaseExistsAsync(databaseName, cancellationToken);
                await EnsureTenantSchemaAsync(databaseName, cancellationToken);

                tenant = await InsertTenantAsync(connection, normalizedTenantKey, databaseName, cancellationToken);
                _logger.LogInformation("Provisioned tenant {TenantKey} with database {DatabaseName}.", normalizedTenantKey, databaseName);
            }
            else
            {
                await EnsureDatabaseExistsAsync(tenant.DatabaseName, cancellationToken);
                await EnsureTenantSchemaAsync(tenant.DatabaseName, cancellationToken);
            }

            _cache[normalizedTenantKey] = tenant;
            return tenant;
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<TenantSummary?> TryLoadTenantAsync(SqlConnection connection, string tenantKey, CancellationToken cancellationToken)
    {
        const string sql = """
            SELECT TOP (1) Id, TenantKey, DisplayName, DatabaseName, IsActive, CreatedAt
            FROM dbo.Tenants
            WHERE TenantKey = @TenantKey;
            """;

        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@TenantKey", tenantKey);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new TenantSummary
        {
            Id = reader.GetInt32(0),
            TenantKey = reader.GetString(1),
            DisplayName = reader.GetString(2),
            DatabaseName = reader.GetString(3),
            IsActive = reader.GetBoolean(4),
            CreatedAt = reader.GetDateTimeOffset(5)
        };
    }

    private async Task<TenantSummary> InsertTenantAsync(SqlConnection connection, string tenantKey, string databaseName, CancellationToken cancellationToken)
    {
        const string sql = """
            INSERT INTO dbo.Tenants (TenantKey, DisplayName, DatabaseName, IsActive, CreatedAt)
            OUTPUT INSERTED.Id, INSERTED.TenantKey, INSERTED.DisplayName, INSERTED.DatabaseName, INSERTED.IsActive, INSERTED.CreatedAt
            VALUES (@TenantKey, @DisplayName, @DatabaseName, 1, SYSUTCDATETIME());
            """;

        await using var command = new SqlCommand(sql, connection);
        command.Parameters.AddWithValue("@TenantKey", tenantKey);
        command.Parameters.AddWithValue("@DisplayName", BuildDisplayName(tenantKey));
        command.Parameters.AddWithValue("@DatabaseName", databaseName);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        await reader.ReadAsync(cancellationToken);

        return new TenantSummary
        {
            Id = reader.GetInt32(0),
            TenantKey = reader.GetString(1),
            DisplayName = reader.GetString(2),
            DatabaseName = reader.GetString(3),
            IsActive = reader.GetBoolean(4),
            CreatedAt = reader.GetDateTimeOffset(5)
        };
    }

    private async Task EnsureDatabaseExistsAsync(string databaseName, CancellationToken cancellationToken)
    {
        await using var connection = new SqlConnection(_connectionFactory.MasterConnectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = """
            IF DB_ID(@databaseName) IS NULL
            BEGIN
                DECLARE @sql nvarchar(max) = N'CREATE DATABASE [' + REPLACE(@databaseName, ']', ']]') + N']';
                EXEC(@sql);
            END
            """;
        command.Parameters.AddWithValue("@databaseName", databaseName);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task EnsureTenantSchemaAsync(string databaseName, CancellationToken cancellationToken)
    {
        var schemaPath = Path.Combine(_environment.ContentRootPath, "Database", "schema.sql");
        var schema = await File.ReadAllTextAsync(schemaPath, cancellationToken);
        var builder = new SqlConnectionStringBuilder(_connectionFactory.PlatformConnectionString)
        {
            InitialCatalog = databaseName
        };

        await using var connection = new SqlConnection(builder.ConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = schema;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static string NormalizeTenantKey(string tenantKey)
    {
        var normalized = new string(tenantKey
            .Trim()
            .ToLowerInvariant()
            .Select(character => char.IsLetterOrDigit(character) ? character : '-')
            .ToArray())
            .Trim('-');

        return string.IsNullOrWhiteSpace(normalized) ? "default" : normalized;
    }

    private static string BuildDisplayName(string tenantKey)
    {
        return string.Join(
            ' ',
            tenantKey
                .Split('-', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(part => char.ToUpperInvariant(part[0]) + part[1..]));
    }
}
