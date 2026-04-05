using Antivirus.Application.Contracts;
using Microsoft.Data.SqlClient;

namespace Antivirus.Infrastructure.Persistence;

public sealed class SqlConnectionFactory : ISqlConnectionFactory
{
    public SqlConnectionFactory(IConfiguration configuration)
    {
        PlatformConnectionString = configuration.GetConnectionString("PlatformDb")
            ?? throw new InvalidOperationException("Connection string 'PlatformDb' is missing.");

        var builder = new SqlConnectionStringBuilder(PlatformConnectionString)
        {
            InitialCatalog = "master"
        };

        MasterConnectionString = builder.ConnectionString;
    }

    public string PlatformConnectionString { get; }

    public string MasterConnectionString { get; }
}
