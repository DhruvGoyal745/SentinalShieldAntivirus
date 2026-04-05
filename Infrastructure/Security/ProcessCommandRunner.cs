using System.Diagnostics;
using Antivirus.Application.Contracts;

namespace Antivirus.Infrastructure.Security;

public sealed class ProcessCommandRunner : IProcessCommandRunner
{
    public async Task<ProcessCommandResult> RunAsync(string fileName, string arguments, CancellationToken cancellationToken = default)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
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

        return new ProcessCommandResult(
            process.ExitCode,
            await outputTask,
            await errorTask);
    }
}
