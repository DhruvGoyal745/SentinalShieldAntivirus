namespace SentinelShield.Desktop.Models;

public sealed class DesktopActivationRequest
{
    public static DesktopActivationRequest Empty { get; } = new();

    public string? ScanTarget { get; init; }

    public static DesktopActivationRequest FromArgs(string[] args)
    {
        if (args is null || args.Length == 0)
        {
            return Empty;
        }

        for (var index = 0; index < args.Length; index++)
        {
            var current = args[index];
            if (string.Equals(current, "--scan-target", StringComparison.OrdinalIgnoreCase))
            {
                var target = index + 1 < args.Length ? args[index + 1] : null;
                return string.IsNullOrWhiteSpace(target)
                    ? Empty
                    : new DesktopActivationRequest { ScanTarget = target };
            }

            const string prefix = "--scan-target=";
            if (current.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                var target = current[prefix.Length..].Trim();
                return string.IsNullOrWhiteSpace(target)
                    ? Empty
                    : new DesktopActivationRequest { ScanTarget = target };
            }
        }

        return Empty;
    }
}
