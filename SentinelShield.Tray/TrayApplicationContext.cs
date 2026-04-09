using System.Diagnostics;

namespace SentinelShield.Tray;

public sealed class TrayApplicationContext : ApplicationContext
{
    private const string DashboardUrl = "http://127.0.0.1:5100";
    private const int StatusPollIntervalMs = 5000;

    private readonly NotifyIcon _notifyIcon;
    private readonly ServiceApiClient _serviceClient;
    private readonly System.Windows.Forms.Timer _statusTimer;

    private ToolStripMenuItem _statusItem = null!;
    private ToolStripMenuItem _protectionItem = null!;
    private ToolStripMenuItem _scanItem = null!;
    private ToolStripMenuItem _updateItem = null!;

    private bool _lastKnownOnline;
    private int _lastThreatCount;

    public TrayApplicationContext()
    {
        _serviceClient = new ServiceApiClient(DashboardUrl);

        _notifyIcon = new NotifyIcon
        {
            Icon = CreateShieldIcon(Color.Gray),
            Text = "Sentinel Shield — Connecting...",
            Visible = true,
            ContextMenuStrip = BuildContextMenu()
        };

        _notifyIcon.DoubleClick += OnOpenDashboard;

        _statusTimer = new System.Windows.Forms.Timer { Interval = StatusPollIntervalMs };
        _statusTimer.Tick += async (_, _) => await PollStatusAsync();
        _statusTimer.Start();

        _ = InitializeAsync();
    }

    private async Task InitializeAsync()
    {
        // Wait briefly for the service to be ready, then open the dashboard
        for (var i = 0; i < 6; i++)
        {
            var status = await _serviceClient.GetStatusAsync();
            if (status is not null)
            {
                await PollStatusAsync();
                OnOpenDashboard(this, EventArgs.Empty);
                return;
            }
            await Task.Delay(2000);
        }

        // Service didn't respond — still poll normally, user can open manually
        await PollStatusAsync();
    }

    private ContextMenuStrip BuildContextMenu()
    {
        var menu = new ContextMenuStrip();

        _statusItem = new ToolStripMenuItem("Connecting to service...")
        {
            Enabled = false
        };

        _protectionItem = new ToolStripMenuItem("Pause Protection (30 min)");
        _protectionItem.Click += OnToggleProtection;

        _scanItem = new ToolStripMenuItem("Quick Scan");
        _scanItem.Click += OnQuickScan;

        _updateItem = new ToolStripMenuItem("Check for Updates");
        _updateItem.Click += OnCheckUpdates;

        var openItem = new ToolStripMenuItem("Open Dashboard");
        openItem.Click += OnOpenDashboard;
        openItem.Font = new Font(openItem.Font, FontStyle.Bold);

        var exitItem = new ToolStripMenuItem("Exit Tray");
        exitItem.Click += OnExit;

        menu.Items.Add(_statusItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(openItem);
        menu.Items.Add(_scanItem);
        menu.Items.Add(_protectionItem);
        menu.Items.Add(_updateItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(exitItem);

        return menu;
    }

    private async Task PollStatusAsync()
    {
        var status = await _serviceClient.GetStatusAsync();

        if (status is null)
        {
            _notifyIcon.Icon = CreateShieldIcon(Color.Gray);
            _notifyIcon.Text = "Sentinel Shield — Service offline";
            _statusItem.Text = "Service: Offline";
            _scanItem.Enabled = false;
            _protectionItem.Enabled = false;
            _updateItem.Enabled = false;

            if (_lastKnownOnline)
            {
                _notifyIcon.ShowBalloonTip(
                    3000,
                    "Sentinel Shield",
                    "Protection service is offline.",
                    ToolTipIcon.Warning);
            }

            _lastKnownOnline = false;
            return;
        }

        _scanItem.Enabled = true;
        _protectionItem.Enabled = true;
        _updateItem.Enabled = true;
        _lastKnownOnline = true;

        if (status.ActiveThreatCount > 0)
        {
            _notifyIcon.Icon = CreateShieldIcon(Color.FromArgb(239, 68, 68));
            _notifyIcon.Text = $"Sentinel Shield — {status.ActiveThreatCount} threat(s) detected";
            _statusItem.Text = $"⚠ {status.ActiveThreatCount} active threat(s)";

            if (status.ActiveThreatCount > _lastThreatCount)
            {
                _notifyIcon.ShowBalloonTip(
                    5000,
                    "Threat Detected",
                    $"{status.ActiveThreatCount} active threat(s) found. Open the dashboard to review.",
                    ToolTipIcon.Error);
            }
        }
        else if (status.RealtimeProtectionPaused)
        {
            _notifyIcon.Icon = CreateShieldIcon(Color.FromArgb(245, 158, 11));
            _notifyIcon.Text = "Sentinel Shield — Protection paused";
            _statusItem.Text = "Protection: Paused";
        }
        else if (!status.RealtimeProtectionEnabled)
        {
            _notifyIcon.Icon = CreateShieldIcon(Color.FromArgb(245, 158, 11));
            _notifyIcon.Text = "Sentinel Shield — Real-time protection disabled";
            _statusItem.Text = "Protection: Disabled";
        }
        else
        {
            _notifyIcon.Icon = CreateShieldIcon(Color.FromArgb(34, 197, 94));
            _notifyIcon.Text = "Sentinel Shield — Protected";
            _statusItem.Text = "Protected — No threats";
        }

        _lastThreatCount = status.ActiveThreatCount;

        _protectionItem.Text = status.RealtimeProtectionPaused
            ? "Resume Protection"
            : "Pause Protection (30 min)";
    }

    private void OnOpenDashboard(object? sender, EventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo(DashboardUrl) { UseShellExecute = true });
        }
        catch
        {
            // Browser not available
        }
    }

    private async void OnQuickScan(object? sender, EventArgs e)
    {
        _scanItem.Enabled = false;
        _scanItem.Text = "Scanning...";

        var success = await _serviceClient.StartQuickScanAsync();

        _scanItem.Enabled = true;
        _scanItem.Text = "Quick Scan";

        _notifyIcon.ShowBalloonTip(
            3000,
            "Sentinel Shield",
            success ? "Quick scan started." : "Failed to start scan. Is the service running?",
            success ? ToolTipIcon.Info : ToolTipIcon.Warning);
    }

    private async void OnToggleProtection(object? sender, EventArgs e)
    {
        var status = await _serviceClient.GetStatusAsync();

        if (status?.RealtimeProtectionPaused == true)
        {
            await _serviceClient.ResumeProtectionAsync();
        }
        else
        {
            var result = MessageBox.Show(
                "Pausing protection leaves your system vulnerable for 30 minutes.\n\nAre you sure?",
                "Sentinel Shield",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);

            if (result == DialogResult.Yes)
            {
                await _serviceClient.PauseProtectionAsync(30);
            }
        }

        await PollStatusAsync();
    }

    private async void OnCheckUpdates(object? sender, EventArgs e)
    {
        var success = await _serviceClient.CheckForUpdatesAsync();

        _notifyIcon.ShowBalloonTip(
            3000,
            "Sentinel Shield",
            success ? "Signatures are up to date." : "Could not check for updates.",
            success ? ToolTipIcon.Info : ToolTipIcon.Warning);
    }

    private void OnExit(object? sender, EventArgs e)
    {
        var result = MessageBox.Show(
            "This will close the tray icon only. The protection service will continue running in the background.\n\nClose tray?",
            "Sentinel Shield",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);

        if (result == DialogResult.Yes)
        {
            _statusTimer.Stop();
            _notifyIcon.Visible = false;
            _serviceClient.Dispose();
            Application.Exit();
        }
    }

    private static Icon CreateShieldIcon(Color color)
    {
        var bitmap = new Bitmap(16, 16);
        using var g = Graphics.FromImage(bitmap);
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        g.Clear(Color.Transparent);

        using var brush = new SolidBrush(color);
        var shieldPoints = new Point[]
        {
            new(8, 1), new(14, 4), new(14, 9),
            new(8, 15), new(2, 9), new(2, 4)
        };
        g.FillPolygon(brush, shieldPoints);

        using var pen = new Pen(Color.FromArgb(180, Color.White), 1f);
        g.DrawLines(pen, new Point[] { new(5, 8), new(7, 10), new(11, 5) });

        return Icon.FromHandle(bitmap.GetHicon());
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _statusTimer.Dispose();
            _notifyIcon.Dispose();
            _serviceClient.Dispose();
        }

        base.Dispose(disposing);
    }
}
