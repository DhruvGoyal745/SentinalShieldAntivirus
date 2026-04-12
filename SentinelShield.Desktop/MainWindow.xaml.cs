using System.Diagnostics;
using System.IO;
using System.Windows;
using Microsoft.Web.WebView2.Core;
using SentinelShield.Desktop.Interop;
using SentinelShield.Desktop.Models;
using SentinelShield.Desktop.Services;

namespace SentinelShield.Desktop;

public partial class MainWindow : Window
{
    private readonly DashboardClient _dashboardClient;
    private readonly SemaphoreSlim _activationGate = new(1, 1);

    private DesktopActivationRequest _lastActivationRequest = DesktopActivationRequest.Empty;
    private bool _webViewInitialized;

    public MainWindow(string serviceBaseUrl)
    {
        InitializeComponent();
        _dashboardClient = new DashboardClient(serviceBaseUrl);
        DashboardWebView.NavigationCompleted += DashboardWebView_OnNavigationCompleted;
        Closed += (_, _) =>
        {
            _dashboardClient.Dispose();
            _activationGate.Dispose();
        };
    }

    public async Task HandleActivationAsync(DesktopActivationRequest request)
    {
        await _activationGate.WaitAsync();

        try
        {
            _lastActivationRequest = request;
            BringToForeground();

            if (request.ScanTarget is not null &&
                !File.Exists(request.ScanTarget) &&
                !Directory.Exists(request.ScanTarget))
            {
                ShowUnavailable(
                    "The requested scan target could not be found.",
                    $"Sentinel Shield could not find '{request.ScanTarget}'. Check that the file or folder still exists.");
                return;
            }

            ShowLoading(
                "Loading Sentinel Shield",
                "Preparing the security dashboard.");

            await EnsureWebViewReadyAsync();

            if (request.ScanTarget is not null)
            {
                ShowLoading(
                    "Submitting custom scan",
                    $"Preparing a custom scan for '{request.ScanTarget}'.");

                var scanId = await _dashboardClient.StartCustomScanAsync(request.ScanTarget, CancellationToken.None);
                if (scanId is null)
                {
                    ShowUnavailable(
                        "The custom scan could not be started.",
                        "The service is online, but the scan request failed. Review the service logs and retry.");
                    return;
                }

                DashboardWebView.Source = _dashboardClient.BuildDashboardUri("home", scanId);
                return;
            }

            var dashboardUri = _dashboardClient.BuildDashboardUri("home");
            if (IsDashboardAlreadyLoaded(dashboardUri))
            {
                ShowDashboard();
            }
            else
            {
                DashboardWebView.Source = dashboardUri;
            }
        }
        catch (Exception ex)
        {
            ShowUnavailable(
                "The desktop dashboard hit an unexpected error.",
                ex.Message);
        }
        finally
        {
            _activationGate.Release();
        }
    }

    private bool IsDashboardAlreadyLoaded(Uri targetUri)
    {
        var currentUri = DashboardWebView.Source;
        if (currentUri is null)
        {
            return false;
        }

        return string.Equals(currentUri.GetLeftPart(UriPartial.Path), targetUri.GetLeftPart(UriPartial.Path), StringComparison.OrdinalIgnoreCase);
    }

    private async Task EnsureWebViewReadyAsync()
    {
        if (_webViewInitialized)
        {
            return;
        }

        var userDataFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SentinelShield",
            "WebView2");

        Directory.CreateDirectory(userDataFolder);

        var environment = await CoreWebView2Environment.CreateAsync(
            browserExecutableFolder: null,
            userDataFolder: userDataFolder);

        await DashboardWebView.EnsureCoreWebView2Async(environment);
        DashboardWebView.DefaultBackgroundColor = System.Drawing.Color.FromArgb(255, 8, 17, 32);
        DashboardWebView.CoreWebView2.Settings.AreDefaultContextMenusEnabled = true;
        DashboardWebView.CoreWebView2.Settings.AreDevToolsEnabled = true;
        DashboardWebView.CoreWebView2.Settings.IsStatusBarEnabled = false;
        DashboardWebView.CoreWebView2.Settings.IsZoomControlEnabled = true;
        _webViewInitialized = true;
    }

    private void DashboardWebView_OnNavigationCompleted(object? sender, Microsoft.Web.WebView2.Core.CoreWebView2NavigationCompletedEventArgs e)
    {
        var currentUrl = DashboardWebView.Source?.AbsoluteUri;
        if (string.IsNullOrEmpty(currentUrl) || currentUrl == "about:blank")
        {
            return;
        }

        if (e.IsSuccess)
        {
            ShowDashboard();
            return;
        }

        ShowUnavailable(
            "The dashboard failed to load.",
            $"WebView2 could not render the local dashboard (0x{e.WebErrorStatus:X}).");
    }

    private async void RetryButton_OnClick(object sender, RoutedEventArgs e)
    {
        await HandleActivationAsync(_lastActivationRequest);
    }

    private void OpenLogsButton_OnClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var logsPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "SentinelShield",
                "Logs");

            Directory.CreateDirectory(logsPath);
            Process.Start(new ProcessStartInfo(logsPath) { UseShellExecute = true });
        }
        catch
        {
            MessageBox.Show(
                this,
                "Sentinel Shield could not open the logs folder automatically.",
                "Sentinel Shield",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
    }

    private void ShowLoading(string title, string message)
    {
        LoadingTitle.Text = title;
        LoadingMessage.Text = message;
        LoadingView.Visibility = Visibility.Visible;
        UnavailableView.Visibility = Visibility.Collapsed;
        DashboardViewHost.Visibility = Visibility.Collapsed;
    }

    private void ShowUnavailable(string message, string details)
    {
        UnavailableMessage.Text = message;
        UnavailableDetails.Text = details;
        LoadingView.Visibility = Visibility.Collapsed;
        UnavailableView.Visibility = Visibility.Visible;
        DashboardViewHost.Visibility = Visibility.Collapsed;
    }

    private void ShowDashboard()
    {
        LoadingView.Visibility = Visibility.Collapsed;
        UnavailableView.Visibility = Visibility.Collapsed;
        DashboardViewHost.Visibility = Visibility.Visible;
    }

    private void BringToForeground()
    {
        if (WindowState == WindowState.Minimized)
        {
            WindowState = WindowState.Normal;
        }

        Show();
        Activate();

        var windowHandle = new System.Windows.Interop.WindowInteropHelper(this).Handle;
        NativeMethods.ShowWindow(windowHandle, NativeMethods.SW_RESTORE);
        NativeMethods.SetForegroundWindow(windowHandle);
    }
}
