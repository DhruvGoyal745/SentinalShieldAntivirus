using Antivirus.Domain;
using Antivirus.Infrastructure.Security;
using FluentAssertions;

namespace Antivirus.Tests.Unit;

public sealed class BehaviorMonitorTests
{
    private readonly BehaviorMonitor _sut = new();

    private static FileWatchNotification MakeNotification(FileEventType eventType, string filePath, string? previousPath = null) =>
        new()
        {
            FilePath = filePath,
            EventType = eventType,
            PreviousPath = previousPath,
            ObservedAt = DateTimeOffset.UtcNow
        };

    // --- Original rules ---

    [Fact]
    public async Task StartupPath_DetectsBehStartup()
    {
        var notification = MakeNotification(FileEventType.Created, @"C:\Users\Test\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.exe");
        var file = new FileInfo(notification.FilePath);

        var results = await _sut.AnalyzeAsync(notification, file);

        results.Should().Contain(d => d.RuleId == "beh-startup");
    }

    [Fact]
    public async Task RunOncePath_DetectsBehStartup()
    {
        var notification = MakeNotification(FileEventType.Changed, @"C:\Windows\CurrentVersion\RunOnce\payload.reg");
        var file = new FileInfo(notification.FilePath);

        var results = await _sut.AnalyzeAsync(notification, file);

        results.Should().Contain(d => d.RuleId == "beh-startup");
    }

    [Fact]
    public async Task RansomwareRename_DetectsBehRansom()
    {
        var notification = MakeNotification(FileEventType.Renamed, @"C:\Users\Test\Documents\file.locked_by_attacker");
        var file = new FileInfo(notification.FilePath);

        var results = await _sut.AnalyzeAsync(notification, file);

        results.Should().Contain(d => d.RuleId == "beh-ransom");
    }

    // --- New rules ---

    [Theory]
    [InlineData(".encrypted")]
    [InlineData(".crypted")]
    [InlineData(".locky")]
    [InlineData(".zzz")]
    public async Task RansomwareExtension_DetectsBehExtRename(string extension)
    {
        var notification = MakeNotification(FileEventType.Renamed, $@"C:\Users\Test\Documents\report{extension}");
        var file = new FileInfo(notification.FilePath);

        var results = await _sut.AnalyzeAsync(notification, file);

        results.Should().Contain(d => d.RuleId == "beh-ext-rename");
        results.First(d => d.RuleId == "beh-ext-rename").Severity.Should().Be(ThreatSeverity.Critical);
        results.First(d => d.RuleId == "beh-ext-rename").Confidence.Should().Be(0.93m);
    }

    [Fact]
    public async Task LOLBinInNonSystemDir_DetectsBehLolbin()
    {
        var notification = MakeNotification(FileEventType.Created, @"C:\Users\Test\Downloads\certutil.exe");
        var file = new FileInfo(notification.FilePath);

        var results = await _sut.AnalyzeAsync(notification, file);

        results.Should().Contain(d => d.RuleId == "beh-lolbin");
        results.First(d => d.RuleId == "beh-lolbin").Severity.Should().Be(ThreatSeverity.High);
    }

    [Fact]
    public async Task LOLBinInSystemDir_NotDetected()
    {
        var systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var notification = MakeNotification(FileEventType.Created, Path.Combine(systemRoot, "System32", "certutil.exe"));
        var file = new FileInfo(notification.FilePath);

        var results = await _sut.AnalyzeAsync(notification, file);

        results.Should().NotContain(d => d.RuleId == "beh-lolbin");
    }

    [Fact]
    public async Task ScriptInDownloads_DetectsBehDownloadScript()
    {
        var notification = MakeNotification(FileEventType.Created, @"C:\Users\Test\Downloads\payload.hta");
        var file = new FileInfo(notification.FilePath);

        var results = await _sut.AnalyzeAsync(notification, file);

        results.Should().Contain(d => d.RuleId == "beh-download-script");
        results.First(d => d.RuleId == "beh-download-script").Severity.Should().Be(ThreatSeverity.Medium);
    }

    [Fact]
    public async Task ScheduledTaskXml_DetectsBehSchtask()
    {
        var notification = MakeNotification(FileEventType.Created, @"C:\Windows\System32\Tasks\EvilTask.xml");
        var file = new FileInfo(notification.FilePath);

        var results = await _sut.AnalyzeAsync(notification, file);

        results.Should().Contain(d => d.RuleId == "beh-schtask");
        results.First(d => d.RuleId == "beh-schtask").Severity.Should().Be(ThreatSeverity.High);
    }

    [Fact]
    public async Task DllInTempDir_DetectsBehDllPlant()
    {
        var notification = MakeNotification(FileEventType.Created, @"C:\Users\Test\AppData\Local\Temp\evil.dll");
        var file = new FileInfo(notification.FilePath);

        var results = await _sut.AnalyzeAsync(notification, file);

        results.Should().Contain(d => d.RuleId == "beh-dll-plant");
        results.First(d => d.RuleId == "beh-dll-plant").Severity.Should().Be(ThreatSeverity.Medium);
    }

    [Fact]
    public async Task MassOpsRename_CommonToUncommonExtension_DetectsBehMassOps()
    {
        var notification = MakeNotification(FileEventType.Renamed, @"C:\Users\Test\Documents\report.xyz123", @"C:\Users\Test\Documents\report.docx");
        var file = new FileInfo(notification.FilePath);

        var results = await _sut.AnalyzeAsync(notification, file);

        results.Should().Contain(d => d.RuleId == "beh-mass-ops");
        results.First(d => d.RuleId == "beh-mass-ops").Severity.Should().Be(ThreatSeverity.High);
    }

    [Fact]
    public async Task MassOpsRename_CommonToCommonExtension_NotDetected()
    {
        var notification = MakeNotification(FileEventType.Renamed, @"C:\Users\Test\Documents\report.pdf", @"C:\Users\Test\Documents\report.docx");
        var file = new FileInfo(notification.FilePath);

        var results = await _sut.AnalyzeAsync(notification, file);

        results.Should().NotContain(d => d.RuleId == "beh-mass-ops");
    }

    [Fact]
    public async Task NormalFile_NoDetections()
    {
        var notification = MakeNotification(FileEventType.Created, @"C:\Users\Test\Documents\report.docx");
        var file = new FileInfo(notification.FilePath);

        var results = await _sut.AnalyzeAsync(notification, file);

        results.Should().BeEmpty();
    }

    [Fact]
    public async Task AllDetectionsUseCorrectEngineAndSource()
    {
        var notification = MakeNotification(FileEventType.Renamed, @"C:\Users\Test\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\file.encrypted",
            @"C:\Users\Test\Documents\file.docx");
        var file = new FileInfo(notification.FilePath);

        var results = await _sut.AnalyzeAsync(notification, file);

        results.Should().NotBeEmpty();
        results.Should().AllSatisfy(d =>
        {
            d.EngineName.Should().Be("Sentinel Behavior Engine");
            d.Source.Should().Be(ThreatSource.Behavior);
        });
    }

    [Fact]
    public async Task BenignSystemScript_NotDetected()
    {
        var notification = MakeNotification(FileEventType.Created, @"C:\Users\Test\Documents\__PSScriptPolicyTest_abc.ps1");
        var file = new FileInfo(notification.FilePath);

        var results = await _sut.AnalyzeAsync(notification, file);

        results.Should().NotContain(d => d.RuleId == "beh-scriptdrop");
    }
}
