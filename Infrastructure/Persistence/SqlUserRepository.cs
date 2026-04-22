using Antivirus.Application.Contracts;
using Antivirus.Domain;
using Microsoft.Data.SqlClient;

namespace Antivirus.Infrastructure.Persistence;

public sealed class SqlUserRepository : IUserRepository
{
    private readonly ISqlConnectionFactory _connectionFactory;
    private readonly ILogger<SqlUserRepository> _logger;

    public SqlUserRepository(ISqlConnectionFactory connectionFactory, ILogger<SqlUserRepository> logger)
    {
        _connectionFactory = connectionFactory;
        _logger = logger;
    }

    public async Task<AppUser?> GetByUsernameAsync(string username, CancellationToken cancellationToken = default)
    {
        await using var connection = new SqlConnection(_connectionFactory.PlatformConnectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT Id, Username, PasswordHash, Role, IsActive, CreatedAt, LastLoginAt
            FROM dbo.Users
            WHERE Username = @username
            """;
        command.Parameters.AddWithValue("@username", username);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new AppUser
        {
            Id = reader.GetInt32(0),
            Username = reader.GetString(1),
            PasswordHash = reader.GetString(2),
            Role = Enum.Parse<UserRole>(reader.GetString(3)),
            IsActive = reader.GetBoolean(4),
            CreatedAt = reader.GetDateTimeOffset(5),
            LastLoginAt = reader.IsDBNull(6) ? null : reader.GetDateTimeOffset(6)
        };
    }

    public async Task<AppUser> CreateUserAsync(string username, string passwordHash, UserRole role, CancellationToken cancellationToken = default)
    {
        await using var connection = new SqlConnection(_connectionFactory.PlatformConnectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO dbo.Users (Username, PasswordHash, Role, IsActive, CreatedAt)
            OUTPUT INSERTED.Id
            VALUES (@username, @passwordHash, @role, 1, SYSUTCDATETIME())
            """;
        command.Parameters.AddWithValue("@username", username);
        command.Parameters.AddWithValue("@passwordHash", passwordHash);
        command.Parameters.AddWithValue("@role", role.ToString());

        var id = (int)(await command.ExecuteScalarAsync(cancellationToken))!;

        return new AppUser
        {
            Id = id,
            Username = username,
            PasswordHash = passwordHash,
            Role = role,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow
        };
    }

    public async Task UpdateLastLoginAsync(string username, CancellationToken cancellationToken = default)
    {
        await using var connection = new SqlConnection(_connectionFactory.PlatformConnectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE dbo.Users SET LastLoginAt = SYSUTCDATETIME() WHERE Username = @username";
        command.Parameters.AddWithValue("@username", username);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<bool> AnyUsersExistAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = new SqlConnection(_connectionFactory.PlatformConnectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT CASE WHEN EXISTS (SELECT 1 FROM dbo.Users) THEN 1 ELSE 0 END";
        return (int)(await command.ExecuteScalarAsync(cancellationToken))! == 1;
    }
}
