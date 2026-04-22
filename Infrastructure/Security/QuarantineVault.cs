using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
using Antivirus.Infrastructure.Platform;
using Antivirus.Infrastructure.Runtime;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Security;

public sealed class QuarantineVault : IQuarantineVault
{
    private readonly IQuarantineRepository _repository;
    private readonly AntivirusPlatformOptions _options;
    private readonly IWebHostEnvironment _environment;
    private readonly ILogger<QuarantineVault> _logger;
    private readonly IFeatureFlagService _featureFlags;
    private readonly byte[] _encryptionKey;
    private readonly string _encryptionKeyId;

    public QuarantineVault(
        IQuarantineRepository repository,
        IOptions<AntivirusPlatformOptions> options,
        IWebHostEnvironment environment,
        ILogger<QuarantineVault> logger,
        IFeatureFlagService featureFlags)
    {
        _repository = repository;
        _options = options.Value;
        _environment = environment;
        _logger = logger;
        _featureFlags = featureFlags;

        (_encryptionKey, _encryptionKeyId) = DeriveEncryptionKey();
    }

    public async Task<QuarantineVaultItem> QuarantineAsync(FileInfo file, QuarantineDetectionContext context, CancellationToken ct = default)
    {
        if (!file.Exists)
            throw new FileNotFoundException("File to quarantine does not exist.", file.FullName);

        var quarantineRoot = ResolveQuarantineRoot();
        Directory.CreateDirectory(quarantineRoot);

        var itemId = Guid.NewGuid();
        var vaultFileName = $"{itemId:N}.vault";
        var vaultPath = Path.Combine(quarantineRoot, vaultFileName);

        // Compute SHA-256 of original file
        var hash = await ComputeFileHashAsync(file.FullName, ct);
        var fileSize = file.Length;

        // Generate random IV
        var iv = RandomNumberGenerator.GetBytes(16);

        // Encrypt file
        var encryptionEnabled = _featureFlags.IsEnabled("quarantine-encryption");
        if (encryptionEnabled)
        {
            await EncryptFileAsync(file.FullName, vaultPath, iv, ct);
        }
        else
        {
            File.Copy(file.FullName, vaultPath, overwrite: true);
        }

        // Delete original file
        try
        {
            file.Delete();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to delete original file {Path} after quarantine", file.FullName);
        }

        var contextJson = JsonSerializer.Serialize(context);

        var item = new QuarantineVaultItem
        {
            Id = itemId,
            OriginalPath = file.FullName,
            OriginalFileName = file.Name,
            VaultPath = vaultPath,
            HashSha256 = hash,
            FileSizeBytes = fileSize,
            EncryptionKeyId = encryptionEnabled ? _encryptionKeyId : string.Empty,
            EncryptionIV = encryptionEnabled ? iv : Array.Empty<byte>(),
            ThreatName = context.ThreatName,
            ThreatSeverity = context.ThreatSeverity,
            ThreatSource = context.ThreatSource,
            DetectionContextJson = contextJson,
            PurgeState = PurgeState.Active,
            CreatedAt = DateTimeOffset.UtcNow,
            RetentionExpiresAt = DateTimeOffset.UtcNow.AddDays(_options.QuarantineRetentionDays)
        };

        await _repository.InsertAsync(item, ct);

        _logger.LogInformation("Quarantined file {FileName} as {ItemId} (encrypted={Encrypted})",
            file.Name, itemId, encryptionEnabled);

        return item;
    }

    public async Task<RestoreResult> RestoreAsync(Guid itemId, string requestedBy, string? restoreToPath = null, CancellationToken ct = default)
    {
        var item = await _repository.GetByIdAsync(itemId, ct);
        if (item is null)
            return new RestoreResult { Success = false, Message = "Quarantine item not found." };

        if (item.PurgeState != PurgeState.Active)
            return new RestoreResult { Success = false, Message = $"Cannot restore item in state '{item.PurgeState}'." };

        if (!File.Exists(item.VaultPath))
            return new RestoreResult { Success = false, Message = "Vault file is missing from disk." };

        var destination = restoreToPath ?? item.OriginalPath;
        var destinationDir = Path.GetDirectoryName(destination);
        if (!string.IsNullOrEmpty(destinationDir))
            Directory.CreateDirectory(destinationDir);

        try
        {
            var encryptionEnabled = !string.IsNullOrEmpty(item.EncryptionKeyId);
            if (encryptionEnabled)
            {
                await DecryptFileAsync(item.VaultPath, destination, item.EncryptionIV, ct);
            }
            else
            {
                File.Copy(item.VaultPath, destination, overwrite: true);
            }

            // Verify hash integrity
            var restoredHash = await ComputeFileHashAsync(destination, ct);
            if (!string.Equals(restoredHash, item.HashSha256, StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(destination);
                return new RestoreResult { Success = false, Message = "Integrity check failed: SHA-256 mismatch after decryption." };
            }

            item.PurgeState = PurgeState.Restored;
            item.RestoredAt = DateTimeOffset.UtcNow;
            item.RestoredBy = requestedBy;
            await _repository.UpdateAsync(item, ct);

            _logger.LogInformation("Restored quarantine item {ItemId} to {Path} by {User}",
                itemId, destination, requestedBy);

            return new RestoreResult { Success = true, Message = "File restored successfully.", RestoredPath = destination };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to restore quarantine item {ItemId}", itemId);
            return new RestoreResult { Success = false, Message = $"Restore failed: {ex.Message}" };
        }
    }

    public async Task<bool> PurgeAsync(Guid itemId, CancellationToken ct = default)
    {
        var item = await _repository.GetByIdAsync(itemId, ct);
        if (item is null)
            return false;

        if (item.PurgeState is not (PurgeState.Active or PurgeState.Expired))
            return false;

        // Secure delete: overwrite with random bytes
        if (File.Exists(item.VaultPath))
        {
            await SecureDeleteFileAsync(item.VaultPath, _options.SecureDeletePasses, ct);
        }

        item.PurgeState = PurgeState.Purged;
        item.PurgedAt = DateTimeOffset.UtcNow;
        await _repository.UpdateAsync(item, ct);

        _logger.LogInformation("Purged quarantine item {ItemId} with {Passes} overwrite passes",
            itemId, _options.SecureDeletePasses);

        return true;
    }

    public async Task<int> PurgeExpiredAsync(CancellationToken ct = default)
    {
        var expiredItems = await _repository.GetExpiredActiveItemsAsync(ct);
        var purgedCount = 0;

        foreach (var item in expiredItems)
        {
            if (await PurgeAsync(item.Id, ct))
                purgedCount++;
        }

        if (purgedCount > 0)
            _logger.LogInformation("Purged {Count} expired quarantine items", purgedCount);

        return purgedCount;
    }

    public Task<QuarantineVaultItem?> GetItemAsync(Guid itemId, CancellationToken ct = default)
        => _repository.GetByIdAsync(itemId, ct);

    public Task<IReadOnlyCollection<QuarantineVaultItem>> ListAsync(QuarantineListFilter filter, CancellationToken ct = default)
        => _repository.ListAsync(filter, ct);

    private async Task EncryptFileAsync(string sourcePath, string destinationPath, byte[] iv, CancellationToken ct)
    {
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = _encryptionKey;
        aes.IV = iv;

        await using var sourceStream = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);
        await using var destStream = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true);
        await using var cryptoStream = new CryptoStream(destStream, aes.CreateEncryptor(), CryptoStreamMode.Write);

        await sourceStream.CopyToAsync(cryptoStream, ct);
    }

    private async Task DecryptFileAsync(string sourcePath, string destinationPath, byte[] iv, CancellationToken ct)
    {
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = _encryptionKey;
        aes.IV = iv;

        await using var sourceStream = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);
        await using var destStream = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true);
        await using var cryptoStream = new CryptoStream(sourceStream, aes.CreateDecryptor(), CryptoStreamMode.Read);

        await cryptoStream.CopyToAsync(destStream, ct);
    }

    private static async Task<string> ComputeFileHashAsync(string filePath, CancellationToken ct)
    {
        await using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);
        var hashBytes = await SHA256.HashDataAsync(stream, ct);
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    private static async Task SecureDeleteFileAsync(string filePath, int passes, CancellationToken ct)
    {
        var fileInfo = new FileInfo(filePath);
        var length = fileInfo.Length;

        for (var i = 0; i < passes; i++)
        {
            ct.ThrowIfCancellationRequested();
            var randomBytes = RandomNumberGenerator.GetBytes((int)Math.Min(length, int.MaxValue));
            await File.WriteAllBytesAsync(filePath, randomBytes, ct);
        }

        File.Delete(filePath);
    }

    private (byte[] Key, string KeyId) DeriveEncryptionKey()
    {
        var machineName = Environment.MachineName;
        var contentRoot = _environment.ContentRootPath;
        var salt = Encoding.UTF8.GetBytes($"SentinelShield-Quarantine-{machineName}-{contentRoot}");

        var password = $"{machineName}:{contentRoot}";

        var key = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations: 600_000,
            HashAlgorithmName.SHA256,
            outputLength: 32); // 256 bits

        // Compute stable key ID: SHA-256 of derivation inputs, first 16 hex chars
        var keyIdInput = Encoding.UTF8.GetBytes($"{machineName}|{contentRoot}|{Convert.ToBase64String(salt)}");
        var keyIdHash = SHA256.HashData(keyIdInput);
        var keyId = Convert.ToHexString(keyIdHash)[..16].ToLowerInvariant();

        return (key, keyId);
    }

    private string ResolveQuarantineRoot()
    {
        return Path.GetFullPath(Path.Combine(_environment.ContentRootPath, _options.QuarantineRoot));
    }
}
