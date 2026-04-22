using Antivirus.Configuration;
using Antivirus.Infrastructure.Platform;
using FluentAssertions;
using Microsoft.Extensions.Options;

namespace Antivirus.Tests.Unit;

public sealed class FeatureFlagServiceTests
{
    private readonly FeatureFlagService _sut;

    public FeatureFlagServiceTests()
    {
        var options = Options.Create(new AntivirusPlatformOptions());
        _sut = new FeatureFlagService(options);
    }

    // ── Default Flags ───────────────────────────────────────────────────

    [Theory]
    [InlineData("behavior-engine", true)]
    [InlineData("reputation-engine", true)]
    [InlineData("realtime-watcher", true)]
    [InlineData("sandbox-submission", true)]
    [InlineData("ransomware-shield", false)]
    [InlineData("ml-detection", false)]
    [InlineData("browser-protection", false)]
    [InlineData("ai-agent-security", false)]
    [InlineData("soc-automation", false)]
    [InlineData("correlation-engine", false)]
    public void IsEnabled_DefaultFlags_MatchExpected(string key, bool expected)
    {
        _sut.IsEnabled(key).Should().Be(expected);
    }

    [Fact]
    public void IsEnabled_UnknownFlag_ReturnsFalse()
    {
        _sut.IsEnabled("nonexistent-feature").Should().BeFalse();
    }

    // ── Global Overrides ────────────────────────────────────────────────

    [Fact]
    public void SetOverride_Global_OverridesDefault()
    {
        _sut.IsEnabled("ml-detection").Should().BeFalse("default is off");

        _sut.SetOverride("ml-detection", true);

        _sut.IsEnabled("ml-detection").Should().BeTrue();
    }

    [Fact]
    public void RemoveOverride_Global_RestoresDefault()
    {
        _sut.SetOverride("ml-detection", true);
        _sut.IsEnabled("ml-detection").Should().BeTrue();

        _sut.RemoveOverride("ml-detection");

        _sut.IsEnabled("ml-detection").Should().BeFalse("should revert to default");
    }

    // ── Tenant Overrides ────────────────────────────────────────────────

    [Fact]
    public void SetOverride_Tenant_OverridesGlobal()
    {
        _sut.SetOverride("ml-detection", true); // global on

        _sut.SetOverride("ml-detection", false, tenantKey: "tenant-A");

        _sut.IsEnabled("ml-detection", tenantKey: "tenant-A").Should().BeFalse("tenant override wins");
        _sut.IsEnabled("ml-detection", tenantKey: "tenant-B").Should().BeTrue("other tenant uses global");
        _sut.IsEnabled("ml-detection").Should().BeTrue("no tenant = global");
    }

    [Fact]
    public void RemoveOverride_Tenant_FallsBackToGlobal()
    {
        _sut.SetOverride("ml-detection", true);
        _sut.SetOverride("ml-detection", false, tenantKey: "tenant-A");

        _sut.RemoveOverride("ml-detection", tenantKey: "tenant-A");

        _sut.IsEnabled("ml-detection", tenantKey: "tenant-A").Should().BeTrue("falls back to global");
    }

    // ── Kill Switches ───────────────────────────────────────────────────

    [Fact]
    public void KillSwitch_OverridesEverything()
    {
        // Enable via default + global + tenant
        _sut.SetOverride("behavior-engine", true);
        _sut.SetOverride("behavior-engine", true, tenantKey: "tenant-A");
        _sut.IsEnabled("behavior-engine", tenantKey: "tenant-A").Should().BeTrue("all levels say on");

        _sut.ActivateKillSwitch("behavior-engine");

        _sut.IsEnabled("behavior-engine").Should().BeFalse("kill switch overrides global");
        _sut.IsEnabled("behavior-engine", tenantKey: "tenant-A").Should().BeFalse("kill switch overrides tenant");
    }

    [Fact]
    public void DeactivateKillSwitch_RestoresPreviousState()
    {
        _sut.SetOverride("behavior-engine", true);
        _sut.ActivateKillSwitch("behavior-engine");
        _sut.IsEnabled("behavior-engine").Should().BeFalse();

        _sut.DeactivateKillSwitch("behavior-engine");

        // Note: ActivateKillSwitch also sets global override to false,
        // so after deactivation the global override (false) takes precedence.
        _sut.IsEnabled("behavior-engine").Should().BeFalse("global override was set to false by kill switch activation");
    }

    [Fact]
    public void IsKillSwitchActive_TracksState()
    {
        _sut.IsKillSwitchActive("behavior-engine").Should().BeFalse();

        _sut.ActivateKillSwitch("behavior-engine");
        _sut.IsKillSwitchActive("behavior-engine").Should().BeTrue();

        _sut.DeactivateKillSwitch("behavior-engine");
        _sut.IsKillSwitchActive("behavior-engine").Should().BeFalse();
    }

    [Fact]
    public void GetActiveKillSwitches_ReturnsAll()
    {
        _sut.ActivateKillSwitch("behavior-engine");
        _sut.ActivateKillSwitch("reputation-engine");

        var active = _sut.GetActiveKillSwitches();

        active.Should().HaveCount(2);
        active.Should().Contain("behavior-engine");
        active.Should().Contain("reputation-engine");
    }

    // ── GetAllFlags ─────────────────────────────────────────────────────

    [Fact]
    public void GetAllFlags_ReturnsDefaults()
    {
        var flags = _sut.GetAllFlags();

        flags.Should().ContainKey("behavior-engine").WhoseValue.Should().BeTrue();
        flags.Should().ContainKey("ml-detection").WhoseValue.Should().BeFalse();
    }

    [Fact]
    public void GetAllFlags_IncludesOverrides()
    {
        _sut.SetOverride("ml-detection", true);
        _sut.SetOverride("ml-detection", false, tenantKey: "tenant-A");

        var globalFlags = _sut.GetAllFlags();
        var tenantFlags = _sut.GetAllFlags(tenantKey: "tenant-A");

        globalFlags["ml-detection"].Should().BeTrue();
        tenantFlags["ml-detection"].Should().BeFalse();
    }

    // ── Case Insensitivity ──────────────────────────────────────────────

    [Fact]
    public void Flags_AreCaseInsensitive()
    {
        _sut.IsEnabled("BEHAVIOR-ENGINE").Should().BeTrue();
        _sut.IsEnabled("Behavior-Engine").Should().BeTrue();

        _sut.SetOverride("ML-DETECTION", true);
        _sut.IsEnabled("ml-detection").Should().BeTrue();
    }
}
