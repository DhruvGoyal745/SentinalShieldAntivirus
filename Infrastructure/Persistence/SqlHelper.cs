using Microsoft.Data.SqlClient;

namespace Antivirus.Infrastructure.Persistence;

/// <summary>
/// Lightweight ADO.NET helper that eliminates repetitive connection/command/reader boilerplate.
/// Each method follows the Template Method pattern: open connection → build command → execute → map results.
/// </summary>
internal static class SqlHelper
{
    private const int DefaultCommandTimeoutSeconds = 120;

    public static async Task<T?> QuerySingleOrDefaultAsync<T>(
        this SqlConnection connection,
        string sql,
        Action<SqlParameterCollection> addParameters,
        Func<SqlDataReader, T> map,
        CancellationToken cancellationToken = default)
    {
        await using var command = new SqlCommand(sql, connection) { CommandTimeout = DefaultCommandTimeoutSeconds };
        addParameters(command.Parameters);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? map(reader) : default;
    }

    public static async Task<List<T>> QueryAsync<T>(
        this SqlConnection connection,
        string sql,
        Action<SqlParameterCollection> addParameters,
        Func<SqlDataReader, T> map,
        CancellationToken cancellationToken = default)
    {
        var results = new List<T>();
        await using var command = new SqlCommand(sql, connection) { CommandTimeout = DefaultCommandTimeoutSeconds };
        addParameters(command.Parameters);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);

        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(map(reader));
        }

        return results;
    }

    public static async Task<int> ExecuteNonQueryAsync(
        this SqlConnection connection,
        string sql,
        Action<SqlParameterCollection> addParameters,
        CancellationToken cancellationToken = default)
    {
        await using var command = new SqlCommand(sql, connection) { CommandTimeout = DefaultCommandTimeoutSeconds };
        addParameters(command.Parameters);
        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public static async Task<int> ExecuteNonQueryAsync(
        this SqlConnection connection,
        string sql,
        Action<SqlParameterCollection> addParameters,
        SqlTransaction transaction,
        CancellationToken cancellationToken = default)
    {
        await using var command = new SqlCommand(sql, connection, transaction) { CommandTimeout = DefaultCommandTimeoutSeconds };
        addParameters(command.Parameters);
        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public static async Task<int> ExecuteScalarIntAsync(
        this SqlConnection connection,
        string sql,
        Action<SqlParameterCollection> addParameters,
        CancellationToken cancellationToken = default)
    {
        await using var command = new SqlCommand(sql, connection) { CommandTimeout = DefaultCommandTimeoutSeconds };
        addParameters(command.Parameters);
        return Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken));
    }

    /// <summary>
    /// Adds a parameter that maps null to <see cref="DBNull.Value"/>.
    /// Eliminates the verbose <c>(object?)value ?? DBNull.Value</c> pattern.
    /// </summary>
    public static SqlParameter AddNullable(this SqlParameterCollection parameters, string name, object? value)
    {
        return parameters.AddWithValue(name, value ?? DBNull.Value);
    }
}
    