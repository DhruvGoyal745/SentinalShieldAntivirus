using Antivirus.Application.Contracts;
using System.Diagnostics;
using System.Text;

namespace Antivirus.Infrastructure.Security;

public sealed class PowerShellRunner : IPowerShellRunner
{
    public async Task<PowerShellCommandResult> RunAsync(string command, CancellationToken cancellationToken = default)
    {
        var encodedCommand = Convert.ToBase64String(Encoding.Unicode.GetBytes(command));
        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encodedCommand}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = new Process { StartInfo = startInfo };
        process.Start();

        var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);

        await process.WaitForExitAsync(cancellationToken);

        return new PowerShellCommandResult(
            process.ExitCode,
            await outputTask,
            await errorTask);
    }
}
