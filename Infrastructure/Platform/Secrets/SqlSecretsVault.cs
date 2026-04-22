using System.Text;
using Antivirus.Application.Contracts;
using Antivirus.Domain;
using Microsoft.Data.SqlClient;

namespace Antivirus.Infrastructure.Platform.Secrets;

/// <summary>
/// SQL-backed implementation of <see cref="ISecretsVault"/>. Plaintext is
/// encrypted via the injected <see cref="ISecretEncryptor"/> before storage
/// and decrypted only inside <see cref="GetSecretAsync"/>. Metadata listings
/// never expose ciphertext or values.
/// </summary>
public sealed class SqlSecretsVault : ISecretsVault
{
    private readonly ITenantRegistry _tenantRegistry;
    private readonly ISecretEncryptor _encryptor;
    private readonly ILogger<SqlSecretsVault> _logger;

    public SqlSecretsVault(ITenantRegistry tenantRegistry, ISecretEncryptor encryptor, ILogger<SqlSecretsVault> logger)
    {
        _tenantRegistry = tenantRegistry;
        _encryptor = encryptor;
        _logger = logger;
    }

    public async Task SetSecretAsync(string tenantKey, string provider, string key, string plaintext, CancellationToken cancellationToken = default)
    {
        var cipher = _encryptor.Encrypt(Encoding.UTF8.GetBytes(plaintext));
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);

        const string sql = """
            MERGE dbo.EncryptedSecrets AS target
            USING (SELECT @TenantKey AS TenantKey, @Provider AS Provider, @SecretKey AS SecretKey) AS src
              ON target.TenantKey = src.TenantKey AND target.Provider = src.Provider AND target.SecretKey = src.SecretKey
            WHEN MATCHED THEN
              UPDATE SET CipherText = @CipherText, Algorithm = @Algorithm, UpdatedAt = SYSUTCDATETIME()
            WHEN NOT MATCHED THEN
              INSERT (TenantKey, Provider, SecretKey, CipherText, Algorithm)
              VALUES (@TenantKey, @Provider, @SecretKey, @CipherText, @Algorithm);
            """;

        await using var cmd = new SqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("@TenantKey", tenantKey);
        cmd.Parameters.AddWithValue("@Provider", provider);
        cmd.Parameters.AddWithValue("@SecretKey", key);
        cmd.Parameters.Add("@CipherText", System.Data.SqlDbType.VarBinary, -1).Value = cipher;
        cmd.Parameters.AddWithValue("@Algorithm", _encryptor.Algorithm);
        await cmd.ExecuteNonQueryAsync(cancellationToken);
        _logger.LogInformation("Stored secret tenant={Tenant} provider={Provider} key={Key}", tenantKey, provider, key);
    }

    public async Task<string?> GetSecretAsync(string tenantKey, string provider, string key, CancellationToken cancellationToken = default)
    {
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        const string sql = "SELECT CipherText, Algorithm FROM dbo.EncryptedSecrets WHERE TenantKey = @TenantKey AND Provider = @Provider AND SecretKey = @SecretKey";
        await using var cmd = new SqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("@TenantKey", tenantKey);
        cmd.Parameters.AddWithValue("@Provider", provider);
        cmd.Parameters.AddWithValue("@SecretKey", key);
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;

        var cipher = (byte[])reader[0];
        var algorithm = reader.GetString(1);
        if (!string.Equals(algorithm, _encryptor.Algorithm, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Secret algorithm mismatch tenant={Tenant} provider={Provider} key={Key} stored={Stored} active={Active}",
                tenantKey, provider, key, algorithm, _encryptor.Algorithm);
            return null;
        }

        var plaintext = _encryptor.Decrypt(cipher);
        return Encoding.UTF8.GetString(plaintext);
    }

    public async Task<bool> DeleteSecretAsync(string tenantKey, string provider, string key, CancellationToken cancellationToken = default)
    {
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        const string sql = "DELETE FROM dbo.EncryptedSecrets WHERE TenantKey = @TenantKey AND Provider = @Provider AND SecretKey = @SecretKey";
        await using var cmd = new SqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("@TenantKey", tenantKey);
        cmd.Parameters.AddWithValue("@Provider", provider);
        cmd.Parameters.AddWithValue("@SecretKey", key);
        var rows = await cmd.ExecuteNonQueryAsync(cancellationToken);
        return rows > 0;
    }

    public async Task<IReadOnlyList<SecretMetadata>> ListMetadataAsync(string tenantKey, CancellationToken cancellationToken = default)
    {
        await using var connection = await _tenantRegistry.OpenTenantConnectionAsync(cancellationToken);
        const string sql = "SELECT Provider, SecretKey, CreatedAt, UpdatedAt FROM dbo.EncryptedSecrets WHERE TenantKey = @TenantKey ORDER BY Provider, SecretKey";
        await using var cmd = new SqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("@TenantKey", tenantKey);
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        var list = new List<SecretMetadata>();
        while (await reader.ReadAsync(cancellationToken))
        {
            list.Add(new SecretMetadata
            {
                TenantKey = tenantKey,
                Provider = reader.GetString(0),
                Key = reader.GetString(1),
                CreatedAt = reader.GetDateTimeOffset(2),
                UpdatedAt = reader.GetDateTimeOffset(3),
                HasValue = true
            });
        }
        return list;
    }
}
