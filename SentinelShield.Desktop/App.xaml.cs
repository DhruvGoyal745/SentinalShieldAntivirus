using System.Windows;
using System.Windows.Threading;
using SentinelShield.Desktop.Models;
using SentinelShield.Desktop.Services;

namespace SentinelShield.Desktop;

public partial class App : Application
{
    private SingleInstanceCoordinator? _singleInstanceCoordinator;
    private CancellationTokenSource? _activationLoopCancellation;
    private EmbeddedServiceHost? _serviceHost;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var activationRequest = DesktopActivationRequest.FromArgs(e.Args);
        _singleInstanceCoordinator = new SingleInstanceCoordinator();

        if (!_singleInstanceCoordinator.TryAcquirePrimaryInstance())
        {
            await _singleInstanceCoordinator.ForwardActivationAsync(activationRequest, CancellationToken.None);
            Shutdown();
            return;
        }

        _activationLoopCancellation = new CancellationTokenSource();
        _serviceHost = new EmbeddedServiceHost();

        var serviceReady = await _serviceHost.EnsureRunningAsync(CancellationToken.None);
        if (!serviceReady)
        {
            MessageBox.Show(
                "Sentinel Shield could not start the protection service.\n\n" +
                "Make sure SentinelShieldAntivirus.exe is in the same folder, " +
                "or that the Windows Service is installed and running.",
                "Sentinel Shield",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Shutdown();
            return;
        }

        var mainWindow = new MainWindow(_serviceHost.BaseUrl);
        MainWindow = mainWindow;

        _singleInstanceCoordinator.ActivationReceived += request =>
            Dispatcher.InvokeAsync(() => mainWindow.HandleActivationAsync(request), DispatcherPriority.Normal).Task.Unwrap();

        _singleInstanceCoordinator.StartListening(_activationLoopCancellation.Token);

        mainWindow.Show();
        _ = mainWindow.HandleActivationAsync(activationRequest);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _activationLoopCancellation?.Cancel();
        _singleInstanceCoordinator?.Dispose();
        _activationLoopCancellation?.Dispose();
        _serviceHost?.Dispose();
        base.OnExit(e);
    }
}
