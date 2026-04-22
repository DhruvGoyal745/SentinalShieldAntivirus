using System.Diagnostics;
using System.Runtime.InteropServices;
using Antivirus.Application.Contracts;
using Microsoft.Extensions.Logging;

namespace Antivirus.Infrastructure.Security;

public sealed class ProcessRemediator : IProcessRemediator
{
    private readonly ILogger<ProcessRemediator> _logger;

    public ProcessRemediator(ILogger<ProcessRemediator> logger)
    {
        _logger = logger;
    }

    public bool KillProcess(int processId)
    {
        try
        {
            var process = Process.GetProcessById(processId);
            var processName = process.ProcessName;
            process.Kill(entireProcessTree: true);
            _logger.LogWarning("Killed process {ProcessId} ({ProcessName}) via ransomware shield remediation",
                processId, processName);
            return true;
        }
        catch (ArgumentException)
        {
            _logger.LogWarning("Cannot kill process {ProcessId}: process not found", processId);
            return false;
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning(ex, "Cannot kill process {ProcessId}: process has already exited", processId);
            return false;
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            _logger.LogWarning(ex, "Cannot kill process {ProcessId}: access denied", processId);
            return false;
        }
    }

    public bool SuspendProcess(int processId)
    {
        IntPtr handle = IntPtr.Zero;
        try
        {
            handle = OpenProcess(ProcessAccessFlags.SuspendResume, false, processId);
            if (handle == IntPtr.Zero)
            {
                _logger.LogWarning("Cannot suspend process {ProcessId}: unable to open process handle", processId);
                return false;
            }

            int status = NtSuspendProcess(handle);
            if (status == 0)
            {
                _logger.LogWarning("Suspended process {ProcessId} via ransomware shield remediation", processId);
                return true;
            }

            _logger.LogWarning("Cannot suspend process {ProcessId}: NtSuspendProcess returned status {Status}",
                processId, status);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Cannot suspend process {ProcessId}: unexpected error", processId);
            return false;
        }
        finally
        {
            if (handle != IntPtr.Zero)
            {
                CloseHandle(handle);
            }
        }
    }

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtSuspendProcess(IntPtr processHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(ProcessAccessFlags desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [Flags]
    private enum ProcessAccessFlags : uint
    {
        SuspendResume = 0x0800
    }
}
