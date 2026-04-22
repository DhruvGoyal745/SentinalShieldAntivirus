using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
using Antivirus.Infrastructure.Platform;
using Antivirus.Infrastructure.Security;
using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;

namespace Antivirus.Tests.Unit;

public sealed class QuarantineVaultTests : IDisposable
{
    private readonly string _tempDir;
    private readonly string _quarantineDir;
    private readonly Mock<IQuarantineRepository> _repoMock = new();
    private readonly Mock<IFeatureFlagService> _flagsMock = new();
    private readonly Mock<IWebHostEnvironment> _envMock = new();
    private readonly QuarantineVault _sut;

    public QuarantineVaultTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"sentinel-vault-test-{Guid.NewGuid():N}");
        _quarantineDir = Path.Combine(_tempDir, "quarantine");
        Directory.CreateDirectory(_tempDir);

        _envMock.SetupGet(e => e.ContentRootPath).Returns(_tempDir);
        _flagsMock.Setup(f => f.IsEnabled("quarantine-encryption", null)).Returns(true);

        var options = Options.Create(new AntivirusPlatformOptions
        {
            QuarantineRoot = "quarantine",
            QuarantineRetentionDays = 30,
            SecureDeletePasses = 1
        });

        _sut = new QuarantineVault(
            _repoMock.Object,
            options,
            _envMock.Object,
            NullLogger<QuarantineVault>.Instance,
            _flagsMock.Object);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    [Fact]
    public async Task QuarantineAsync_EncryptsFileAndDeletesOriginal()
    {
        var filePath = Path.Combine(_tempDir, "malware.exe");
        var content = "This is test malware content for encryption verification"u8.ToArray();
        await File.WriteAllBytesAsync(filePath, content);

        var context = new QuarantineDetectionContext
        {
            ThreatName = "Trojan.Test",
            ThreatSeverity = ThreatSeverity.High
        };

        var result = await _sut.QuarantineAsync(new FileInfo(filePath), context);

        result.Should().NotBeNull();
        result.OriginalFileName.Should().Be("malware.exe");
        result.ThreatName.Should().Be("Trojan.Test");
        result.FileSizeBytes.Should().Be(content.Length);
        result.EncryptionIV.Should().HaveCount(16);
        result.VaultPath.Should().EndWith(".vault");
        File.Exists(filePath).Should().BeFalse("original file should be deleted after quarantine");
        File.Exists(result.VaultPath).Should().BeTrue("vault file should exist");

        // Encrypted content should differ from original
        var vaultBytes = await File.ReadAllBytesAsync(result.VaultPath);
        vaultBytes.Should().NotBeEquivalentTo(content, "content should be encrypted");

        _repoMock.Verify(r => r.InsertAsync(It.IsAny<QuarantineVaultItem>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task QuarantineAsync_NonExistentFile_Throws()
    {
        var filePath = Path.Combine(_tempDir, "nonexistent.exe");
        var context = new QuarantineDetectionContext();

        var act = () => _sut.QuarantineAsync(new FileInfo(filePath), context);

        await act.Should().ThrowAsync<FileNotFoundException>();
    }

    [Fact]
    public async Task RestoreAsync_DecryptsAndVerifiesHash()
    {
        // First quarantine a file
        var filePath = Path.Combine(_tempDir, "restore-test.txt");
        var content = "Important document content for restore test"u8.ToArray();
        await File.WriteAllBytesAsync(filePath, content);

        var context = new QuarantineDetectionContext { ThreatName = "FP.Test" };
        var item = await _sut.QuarantineAsync(new FileInfo(filePath), context);

        // Setup repo to return the item
        _repoMock.Setup(r => r.GetByIdAsync(item.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(item);

        var restorePath = Path.Combine(_tempDir, "restored.txt");
        var result = await _sut.RestoreAsync(item.Id, "test-user", restorePath);

        result.Success.Should().BeTrue();
        result.RestoredPath.Should().Be(restorePath);
        File.Exists(restorePath).Should().BeTrue();

        var restoredContent = await File.ReadAllBytesAsync(restorePath);
        restoredContent.Should().BeEquivalentTo(content, "restored content should match original");
    }

    [Fact]
    public async Task PurgeAsync_SecureDeletesVaultFile()
    {
        var filePath = Path.Combine(_tempDir, "purge-test.dll");
        await File.WriteAllBytesAsync(filePath, new byte[1024]);

        var context = new QuarantineDetectionContext { ThreatName = "Malware.Purge" };
        var item = await _sut.QuarantineAsync(new FileInfo(filePath), context);

        _repoMock.Setup(r => r.GetByIdAsync(item.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(item);

        var result = await _sut.PurgeAsync(item.Id);

        result.Should().BeTrue();
        File.Exists(item.VaultPath).Should().BeFalse("vault file should be securely deleted");
        _repoMock.Verify(r => r.UpdateAsync(It.Is<QuarantineVaultItem>(i => i.PurgeState == PurgeState.Purged), It.IsAny<CancellationToken>()), Times.Once);
    }
}

public sealed class RansomwareShieldTests : IDisposable
{
    private readonly string _tempDir;
    private readonly Mock<IFeatureFlagService> _flagsMock = new();
    private readonly RansomwareShield _sut;

    public RansomwareShieldTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"sentinel-rs-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);

        _flagsMock.Setup(f => f.IsEnabled("ransomware-shield", null)).Returns(true);

        var options = Options.Create(new AntivirusPlatformOptions
        {
            ProtectedFolders = [_tempDir],
            RansomwareFileWriteThresholdPerMinute = 5,
            RansomwareEntropyThreshold = 7.0,
            RansomwareAutoKillEnabled = false,
            RansomwareAutoSuspendEnabled = false
        });

        _sut = new RansomwareShield(options, _flagsMock.Object, NullLogger<RansomwareShield>.Instance);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    [Fact]
    public void IsProtectedFolder_MatchesConfiguredPaths()
    {
        _sut.IsProtectedFolder(Path.Combine(_tempDir, "subdir", "file.txt")).Should().BeTrue();
        _sut.IsProtectedFolder(@"C:\SomeOtherPath\file.txt").Should().BeFalse();
    }

    [Fact]
    public async Task RecordFileWrite_BelowThreshold_ReturnsNull()
    {
        var filePath = Path.Combine(_tempDir, "safe.txt");
        await File.WriteAllTextAsync(filePath, "safe content");
        var notification = MakeNotification(FileEventType.Created, filePath);

        var result = await _sut.RecordFileWriteAsync(notification, new FileInfo(filePath));

        result.Should().BeNull();
    }

    [Fact]
    public async Task RecordFileWrite_ExceedsThreshold_ReturnsSignal()
    {
        // Threshold is 5 writes per minute
        for (int i = 0; i < 6; i++)
        {
            var filePath = Path.Combine(_tempDir, $"file{i}.txt");
            await File.WriteAllTextAsync(filePath, $"content {i}");
            var notification = MakeNotification(FileEventType.Created, filePath);
            var signal = await _sut.RecordFileWriteAsync(notification, new FileInfo(filePath));

            if (i < 4)
                signal.Should().BeNull($"write {i} should be below threshold");
        }

        // The 5th or 6th write should trigger
        var lastPath = Path.Combine(_tempDir, "file_trigger.txt");
        await File.WriteAllTextAsync(lastPath, "trigger content");
        var triggerNotification = MakeNotification(FileEventType.Created, lastPath);
        var triggerSignal = await _sut.RecordFileWriteAsync(triggerNotification, new FileInfo(lastPath));

        // At this point we've recorded at least 6-7 writes, exceeding threshold of 5
        // The signal may have been returned on an earlier iteration
        var recentSignals = _sut.GetRecentSignals();
        recentSignals.Should().NotBeEmpty("threshold should have been breached");
    }

    [Fact]
    public async Task RecordFileWrite_FeatureFlagDisabled_ReturnsNull()
    {
        _flagsMock.Setup(f => f.IsEnabled("ransomware-shield", null)).Returns(false);

        var filePath = Path.Combine(_tempDir, "ignored.txt");
        await File.WriteAllTextAsync(filePath, "content");
        var notification = MakeNotification(FileEventType.Created, filePath);

        var result = await _sut.RecordFileWriteAsync(notification, new FileInfo(filePath));

        result.Should().BeNull();
    }

    [Fact]
    public async Task RecordFileWrite_OutsideProtectedFolder_ReturnsNull()
    {
        var filePath = @"C:\Windows\Temp\outside.txt";
        var notification = MakeNotification(FileEventType.Created, filePath);

        var result = await _sut.RecordFileWriteAsync(notification, new FileInfo(filePath));

        result.Should().BeNull();
    }

    [Fact]
    public void GetRecentSignals_ReturnsUpToMaxCount()
    {
        var signals = _sut.GetRecentSignals(10);
        signals.Should().NotBeNull();
        signals.Count.Should().BeLessThanOrEqualTo(10);
    }

    private static FileWatchNotification MakeNotification(FileEventType eventType, string filePath, string? previousPath = null) =>
        new()
        {
            FilePath = filePath,
            EventType = eventType,
            PreviousPath = previousPath,
            ObservedAt = DateTimeOffset.UtcNow
        };
}

public sealed class ProcessRemediatorTests
{
    private readonly ProcessRemediator _sut = new(NullLogger<ProcessRemediator>.Instance);

    [Fact]
    public void KillProcess_InvalidPid_ReturnsFalse()
    {
        var result = _sut.KillProcess(-1);
        result.Should().BeFalse();
    }

    [Fact]
    public void SuspendProcess_InvalidPid_ReturnsFalse()
    {
        var result = _sut.SuspendProcess(-1);
        result.Should().BeFalse();
    }
}

public sealed class RemediationCoordinatorTests : IDisposable
{
    private readonly string _tempDir;
    private readonly Mock<IQuarantineVault> _vaultMock = new();
    private readonly Mock<IFeatureFlagService> _flagsMock = new();
    private readonly Mock<IWebHostEnvironment> _envMock = new();
    private readonly RemediationCoordinator _sut;

    public RemediationCoordinatorTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"sentinel-rem-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);

        _envMock.SetupGet(e => e.ContentRootPath).Returns(_tempDir);
        _flagsMock.Setup(f => f.IsEnabled("quarantine-encryption", null)).Returns(true);

        var options = Options.Create(new AntivirusPlatformOptions
        {
            QuarantineRoot = "quarantine"
        });

        _sut = new RemediationCoordinator(
            _envMock.Object,
            options,
            _vaultMock.Object,
            _flagsMock.Object,
            NullLogger<RemediationCoordinator>.Instance);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    [Fact]
    public async Task QuarantineAsync_WhenEncryptionEnabled_DelegatesToVault()
    {
        var filePath = Path.Combine(_tempDir, "test.exe");
        await File.WriteAllBytesAsync(filePath, new byte[64]);

        var vaultItem = new QuarantineVaultItem
        {
            VaultPath = Path.Combine(_tempDir, "quarantine", "test.vault")
        };

        _vaultMock.Setup(v => v.QuarantineAsync(It.IsAny<FileInfo>(), It.IsAny<QuarantineDetectionContext>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(vaultItem);

        var (quarantined, path) = await _sut.QuarantineAsync(new FileInfo(filePath));

        quarantined.Should().BeTrue();
        path.Should().EndWith(".vault");
        _vaultMock.Verify(v => v.QuarantineAsync(It.IsAny<FileInfo>(), It.IsAny<QuarantineDetectionContext>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task QuarantineAsync_WhenEncryptionDisabled_PlainMoves()
    {
        _flagsMock.Setup(f => f.IsEnabled("quarantine-encryption", null)).Returns(false);

        var filePath = Path.Combine(_tempDir, "test.exe");
        await File.WriteAllBytesAsync(filePath, new byte[64]);

        var (quarantined, path) = await _sut.QuarantineAsync(new FileInfo(filePath));

        quarantined.Should().BeTrue();
        path.Should().Contain("quarantine");
        File.Exists(filePath).Should().BeFalse();
    }

    [Fact]
    public async Task QuarantineAsync_NonExistentFile_ReturnsFalse()
    {
        var (quarantined, path) = await _sut.QuarantineAsync(new FileInfo(Path.Combine(_tempDir, "nope.exe")));

        quarantined.Should().BeFalse();
        path.Should().BeNull();
    }
}
