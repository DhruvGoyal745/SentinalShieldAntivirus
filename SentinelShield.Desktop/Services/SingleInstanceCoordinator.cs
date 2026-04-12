using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using SentinelShield.Desktop.Models;

namespace SentinelShield.Desktop.Services;

internal sealed class SingleInstanceCoordinator : IDisposable
{
    private const string MutexName = "SentinelShieldDesktop_SingleInstance";
    private const string PipeName = "SentinelShieldDesktop_Activation";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private Mutex? _instanceMutex;
    private Task? _listenerLoopTask;

    public event Func<DesktopActivationRequest, Task>? ActivationReceived;

    public bool TryAcquirePrimaryInstance()
    {
        _instanceMutex = new Mutex(true, MutexName, out var createdNew);
        return createdNew;
    }

    public void StartListening(CancellationToken cancellationToken)
    {
        _listenerLoopTask = Task.Run(() => ListenLoopAsync(cancellationToken), cancellationToken);
    }

    public async Task ForwardActivationAsync(DesktopActivationRequest request, CancellationToken cancellationToken)
    {
        var payload = JsonSerializer.Serialize(request, JsonOptions);

        for (var attempt = 0; attempt < 20; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                using var client = new NamedPipeClientStream(".", PipeName, PipeDirection.Out, PipeOptions.Asynchronous);
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeoutCts.CancelAfter(TimeSpan.FromMilliseconds(500));
                await client.ConnectAsync(timeoutCts.Token);

                await using var writer = new StreamWriter(client, Encoding.UTF8, 1024, leaveOpen: false);
                await writer.WriteAsync(payload);
                await writer.FlushAsync();
                return;
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                await Task.Delay(250, cancellationToken);
            }
            catch (IOException)
            {
                await Task.Delay(250, cancellationToken);
            }
        }
    }

    private async Task ListenLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                using var server = new NamedPipeServerStream(
                    PipeName,
                    PipeDirection.In,
                    1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                await server.WaitForConnectionAsync(cancellationToken);

                using var reader = new StreamReader(server, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: false);
                var payload = await reader.ReadToEndAsync(cancellationToken);
                if (string.IsNullOrWhiteSpace(payload))
                {
                    continue;
                }

                var activationRequest = JsonSerializer.Deserialize<DesktopActivationRequest>(payload, JsonOptions)
                    ?? DesktopActivationRequest.Empty;

                if (ActivationReceived is not null)
                {
                    await ActivationReceived.Invoke(activationRequest);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                await Task.Delay(250, cancellationToken);
            }
        }
    }

    public void Dispose()
    {
        _instanceMutex?.Dispose();
    }
}
