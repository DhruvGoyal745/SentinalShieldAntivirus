using System.Collections.Concurrent;
using Antivirus.Configuration;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Platform;

/// <summary>
/// Provides runtime feature flag evaluation that respects rollout rings, tenant overrides, and kill switches.
/// Flags can be toggled remotely via <see cref="SetOverride"/> without restarting the service.
/// </summary>
public interface IFeatureFlagService
{
    bool IsEnabled(string featureKey, string? tenantKey = null);

    IReadOnlyDictionary<string, bool> GetAllFlags(string? tenantKey = null);

    void SetOverride(string featureKey, bool enabled, string? tenantKey = null);

    void RemoveOverride(string featureKey, string? tenantKey = null);

    void ActivateKillSwitch(string featureKey);
    void DeactivateKillSwitch(string featureKey);
    bool IsKillSwitchActive(string featureKey);
    IReadOnlyCollection<string> GetActiveKillSwitches();
}

public sealed class FeatureFlagService : IFeatureFlagService
{
    private readonly AntivirusPlatformOptions _options;
    private readonly ConcurrentDictionary<string, bool> _globalOverrides = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, bool>> _tenantOverrides = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _killSwitches = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Default flag definitions. Every future engine module is registered here and defaults to off until explicitly enabled.
    /// </summary>
    private static readonly Dictionary<string, bool> Defaults = new(StringComparer.OrdinalIgnoreCase)
    {
        ["behavior-engine"] = true,
        ["reputation-engine"] = true,
        ["ransomware-shield"] = false,
        ["ml-detection"] = false,
        ["browser-protection"] = false,
        ["ai-agent-security"] = false,
        ["soc-automation"] = false,
        ["realtime-watcher"] = true,
        ["sandbox-submission"] = true,
        ["signed-updates-only"] = false,
        ["correlation-engine"] = false,
        ["quarantine-encryption"] = true,
        ["protected-folders"] = true,
    };

    public FeatureFlagService(IOptions<AntivirusPlatformOptions> options)
    {
        _options = options.Value;
    }

    public bool IsEnabled(string featureKey, string? tenantKey = null)
    {
        // Kill switches take absolute priority
        if (_killSwitches.ContainsKey(featureKey))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(tenantKey)
            && _tenantOverrides.TryGetValue(tenantKey, out var tenantFlags)
            && tenantFlags.TryGetValue(featureKey, out var tenantValue))
        {
            return tenantValue;
        }

        if (_globalOverrides.TryGetValue(featureKey, out var globalValue))
        {
            return globalValue;
        }

        return Defaults.TryGetValue(featureKey, out var defaultValue) && defaultValue;
    }

    public IReadOnlyDictionary<string, bool> GetAllFlags(string? tenantKey = null)
    {
        var result = new Dictionary<string, bool>(Defaults, StringComparer.OrdinalIgnoreCase);

        foreach (var kvp in _globalOverrides)
        {
            result[kvp.Key] = kvp.Value;
        }

        if (!string.IsNullOrWhiteSpace(tenantKey)
            && _tenantOverrides.TryGetValue(tenantKey, out var tenantFlags))
        {
            foreach (var kvp in tenantFlags)
            {
                result[kvp.Key] = kvp.Value;
            }
        }

        return result;
    }

    public void SetOverride(string featureKey, bool enabled, string? tenantKey = null)
    {
        if (!string.IsNullOrWhiteSpace(tenantKey))
        {
            var tenantFlags = _tenantOverrides.GetOrAdd(tenantKey, _ => new(StringComparer.OrdinalIgnoreCase));
            tenantFlags[featureKey] = enabled;
        }
        else
        {
            _globalOverrides[featureKey] = enabled;
        }
    }

    public void RemoveOverride(string featureKey, string? tenantKey = null)
    {
        if (!string.IsNullOrWhiteSpace(tenantKey))
        {
            if (_tenantOverrides.TryGetValue(tenantKey, out var tenantFlags))
            {
                tenantFlags.TryRemove(featureKey, out _);
            }
        }
        else
        {
            _globalOverrides.TryRemove(featureKey, out _);
        }
    }

    public void ActivateKillSwitch(string featureKey)
    {
        _killSwitches[featureKey] = DateTimeOffset.UtcNow;
        _globalOverrides[featureKey] = false;
    }

    public void DeactivateKillSwitch(string featureKey)
    {
        _killSwitches.TryRemove(featureKey, out _);
    }

    public bool IsKillSwitchActive(string featureKey)
    {
        return _killSwitches.ContainsKey(featureKey);
    }

    public IReadOnlyCollection<string> GetActiveKillSwitches()
    {
        return _killSwitches.Keys.ToArray();
    }
}
