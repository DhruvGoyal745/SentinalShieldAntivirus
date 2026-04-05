using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Persistence;

public sealed class DatabaseBootstrapper : IDatabaseBootstrapper
{
    private readonly ISqlConnectionFactory _connectionFactory;
    private readonly ITenantRegistry _tenantRegistry;
    private readonly IWebHostEnvironment _environment;
    private readonly AntivirusPlatformOptions _options;
    private readonly ILogger<DatabaseBootstrapper> _logger;

    public DatabaseBootstrapper(
        ISqlConnectionFactory connectionFactory,
        ITenantRegistry tenantRegistry,
        IWebHostEnvironment environment,
        IOptions<AntivirusPlatformOptions> options,
        ILogger<DatabaseBootstrapper> logger)
    {
        _connectionFactory = connectionFactory;
        _tenantRegistry = tenantRegistry;
        _environment = environment;
        _options = options.Value;
        _logger = logger;
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        var platformBuilder = new SqlConnectionStringBuilder(_connectionFactory.PlatformConnectionString);
        if (string.IsNullOrWhiteSpace(platformBuilder.InitialCatalog))
        {
            throw new InvalidOperationException("The PlatformDb connection string must define an Initial Catalog.");
        }

        await EnsureDatabaseExistsAsync(platformBuilder.InitialCatalog, cancellationToken);
        await EnsureSharedSchemaAsync(cancellationToken);
        await _tenantRegistry.EnsureTenantAsync(_options.DefaultTenantKey, cancellationToken);

        var quarantinePath = Path.GetFullPath(Path.Combine(_environment.ContentRootPath, _options.QuarantineRoot));
        Directory.CreateDirectory(quarantinePath);
        _logger.LogInformation("Database and quarantine storage are ready.");
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

    private async Task EnsureSharedSchemaAsync(CancellationToken cancellationToken)
    {
        var schemaPath = Path.Combine(_environment.ContentRootPath, "Database", "shared-schema.sql");
        var schema = await File.ReadAllTextAsync(schemaPath, cancellationToken);

        await using var connection = new SqlConnection(_connectionFactory.PlatformConnectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = schema;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
