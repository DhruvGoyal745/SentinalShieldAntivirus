using Antivirus.Application.Contracts;
using Microsoft.Data.SqlClient;

namespace Antivirus.Infrastructure.Persistence;

public sealed class SqlConnectionFactory : ISqlConnectionFactory
{
    private static readonly string[] CandidateServers =
    [
        ".\\SQLEXPRESS",
        "(localdb)\\MSSQLLocalDB",
        ".",
        "localhost"
    ];

    public SqlConnectionFactory(IConfiguration configuration, ILogger<SqlConnectionFactory> logger)
    {
        var configuredConnectionString = configuration.GetConnectionString("PlatformDb")
            ?? throw new InvalidOperationException("Connection string 'PlatformDb' is missing.");

        PlatformConnectionString = ResolveConnectionString(configuredConnectionString, logger);

        var builder = new SqlConnectionStringBuilder(PlatformConnectionString)
        {
            InitialCatalog = "master"
        };

        MasterConnectionString = builder.ConnectionString;
    }

    public string PlatformConnectionString { get; }

    public string MasterConnectionString { get; }

    private static string ResolveConnectionString(string configuredConnectionString, ILogger logger)
    {
        var builder = new SqlConnectionStringBuilder(configuredConnectionString);

        if (TryConnect(builder.ConnectionString))
        {
            logger.LogInformation("Connected to SQL Server: {Server}", builder.DataSource);
            return configuredConnectionString;
        }

        logger.LogWarning("Configured SQL Server '{Server}' is not reachable. Probing alternatives...", builder.DataSource);

        var originalCatalog = builder.InitialCatalog;

        foreach (var server in CandidateServers)
        {
            builder.DataSource = server;
            builder.InitialCatalog = "master";
            builder.ConnectTimeout = 5;

            if (TryConnect(builder.ConnectionString))
            {
                builder.InitialCatalog = originalCatalog;
                logger.LogInformation("Auto-detected SQL Server: {Server}", server);
                return builder.ConnectionString;
            }
        }

        logger.LogError("No SQL Server instance could be found. The service will attempt to use the configured connection string.");
        return configuredConnectionString;
    }

    private static bool TryConnect(string connectionString)
    {
        try
        {
            using var connection = new SqlConnection(connectionString);
            connection.Open();
            return true;
        }
        catch
        {
            return false;
        }
    }
}
