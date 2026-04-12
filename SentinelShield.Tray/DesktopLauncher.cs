using System.Diagnostics;

namespace SentinelShield.Tray;

internal static class DesktopLauncher
{
    private const string DesktopExecutableName = "SentinelShieldDesktop.exe";
    private const string DashboardUrl = "http://127.0.0.1:5100";

    public static bool OpenDashboard(string? scanTarget = null)
    {
        try
        {
            var desktopExecutablePath = Path.Combine(AppContext.BaseDirectory, DesktopExecutableName);
            if (File.Exists(desktopExecutablePath))
            {
                var startInfo = new ProcessStartInfo(desktopExecutablePath)
                {
                    UseShellExecute = true
                };

                if (!string.IsNullOrWhiteSpace(scanTarget))
                {
                    startInfo.ArgumentList.Add("--scan-target");
                    startInfo.ArgumentList.Add(scanTarget);
                }

                Process.Start(startInfo);
                return true;
            }

            Process.Start(new ProcessStartInfo(DashboardUrl) { UseShellExecute = true });
            return true;
        }
        catch
        {
            return false;
        }
    }
}
