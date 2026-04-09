using System.Text;
using System.Text.RegularExpressions;
using Antivirus.Configuration;
using Antivirus.Domain;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Security.StaticAnalysis;

public sealed class SuspiciousStringExtractionEnricher : IStaticArtifactEnricher
{
    private readonly AntivirusPlatformOptions _options;

    private static readonly Regex UrlPattern = new(
        @"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,}",
        RegexOptions.Compiled | RegexOptions.IgnoreCase,
        TimeSpan.FromSeconds(2));

    private static readonly Regex IpV4Pattern = new(
        @"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        RegexOptions.Compiled,
        TimeSpan.FromSeconds(2));

    private static readonly string[] SuspiciousTlds =
        [".onion", ".bit", ".tk", ".top", ".xyz", ".pw", ".cc", ".ws"];

    private static readonly string[] SuspiciousCommands =
    [
        "cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "wscript.exe",
        "cscript.exe", "certutil.exe", "bitsadmin.exe", "regsvr32.exe",
        "rundll32.exe", "msiexec.exe", "schtasks.exe", "net.exe",
        "whoami", "ipconfig", "tasklist", "systeminfo", "netstat"
    ];

    private static readonly string[] SuspiciousApiNames =
    [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtUnmapViewOfSection", "SetWindowsHookEx", "GetAsyncKeyState",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "AdjustTokenPrivileges", "OpenProcessToken",
        "MiniDumpWriteDump", "LsaRetrievePrivateData"
    ];

    public SuspiciousStringExtractionEnricher(IOptions<AntivirusPlatformOptions> options)
    {
        _options = options.Value;
    }

    public async Task<IReadOnlyCollection<DetectionEventRecord>> EnrichAsync(
        StaticScanArtifact artifact,
        CancellationToken cancellationToken = default)
    {
        if (!artifact.File.Exists || artifact.File.Length < 64)
        {
            return Array.Empty<DetectionEventRecord>();
        }

        byte[] buffer;
        try
        {
            await using var stream = new FileStream(
                artifact.File.FullName,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            var readLength = (int)Math.Min(stream.Length, _options.MaxContentInspectionBytes);
            buffer = new byte[readLength];
            _ = await stream.ReadAsync(buffer.AsMemory(0, readLength), cancellationToken);
        }
        catch
        {
            return Array.Empty<DetectionEventRecord>();
        }

        var strings = ExtractPrintableStrings(buffer, minLength: 6);
        var joined = string.Join('\n', strings);

        var detections = new List<DetectionEventRecord>();

        var urls = ExtractUrls(joined);
        if (urls.Count > 0)
        {
            var suspiciousTldUrls = urls
                .Where(url => SuspiciousTlds.Any(tld => url.Contains(tld, StringComparison.OrdinalIgnoreCase)))
                .ToArray();

            artifact.SetProperty("strings.urlCount", urls.Count.ToString());

            if (suspiciousTldUrls.Length > 0)
            {
                detections.Add(new DetectionEventRecord
                {
                    RuleId = "heur-strings-suspicious-tld",
                    EngineName = "Sentinel String Analyzer",
                    Source = ThreatSource.ProprietaryStatic,
                    Severity = ThreatSeverity.High,
                    Confidence = 0.82m,
                    Summary = $"File contains {suspiciousTldUrls.Length} URL(s) with suspicious TLDs commonly associated with malware C2 infrastructure."
                });
            }
            else if (urls.Count >= 5 && artifact.Classification is "PE" or "ELF")
            {
                detections.Add(new DetectionEventRecord
                {
                    RuleId = "heur-strings-many-urls-in-binary",
                    EngineName = "Sentinel String Analyzer",
                    Source = ThreatSource.ProprietaryStatic,
                    Severity = ThreatSeverity.Medium,
                    Confidence = 0.58m,
                    Summary = $"Binary file contains {urls.Count} embedded URLs, which is unusual for legitimate executables."
                });
            }
        }

        var rawIps = ExtractRawIpAddresses(joined);
        var externalIps = rawIps.Where(ip => !IsPrivateOrLoopback(ip)).ToArray();
        if (externalIps.Length >= 3 && artifact.Classification is "PE" or "ELF" or "SCRIPT")
        {
            artifact.SetProperty("strings.externalIpCount", externalIps.Length.ToString());
            detections.Add(new DetectionEventRecord
            {
                RuleId = "heur-strings-hardcoded-ips",
                EngineName = "Sentinel String Analyzer",
                Source = ThreatSource.ProprietaryStatic,
                Severity = ThreatSeverity.Medium,
                Confidence = 0.66m,
                Summary = $"File contains {externalIps.Length} hardcoded external IP addresses, suggesting network communication capability."
            });
        }

        var commandHits = SuspiciousCommands
            .Where(cmd => joined.Contains(cmd, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (commandHits.Length >= 3)
        {
            artifact.SetProperty("strings.suspiciousCommandCount", commandHits.Length.ToString());
            detections.Add(new DetectionEventRecord
            {
                RuleId = "heur-strings-recon-commands",
                EngineName = "Sentinel String Analyzer",
                Source = ThreatSource.ProprietaryStatic,
                Severity = ThreatSeverity.High,
                Confidence = 0.80m,
                Summary = $"File references {commandHits.Length} system reconnaissance or execution commands: {string.Join(", ", commandHits.Take(5))}."
            });
        }

        if (artifact.Classification == "PE")
        {
            var apiHits = SuspiciousApiNames
                .Where(api => joined.Contains(api, StringComparison.Ordinal))
                .ToArray();
            if (apiHits.Length >= 2)
            {
                artifact.SetProperty("strings.suspiciousApiCount", apiHits.Length.ToString());
                detections.Add(new DetectionEventRecord
                {
                    RuleId = "heur-strings-suspicious-api-imports",
                    EngineName = "Sentinel String Analyzer",
                    Source = ThreatSource.ProprietaryStatic,
                    Severity = ThreatSeverity.High,
                    Confidence = 0.85m,
                    Summary = $"PE file references {apiHits.Length} suspicious Windows APIs used for process injection, credential theft, or anti-debugging: {string.Join(", ", apiHits.Take(4))}."
                });
            }
        }

        return detections;
    }

    private static List<string> ExtractPrintableStrings(byte[] data, int minLength)
    {
        var results = new List<string>();
        var current = new StringBuilder();

        foreach (var b in data)
        {
            if (b is >= 0x20 and < 0x7F)
            {
                current.Append((char)b);
            }
            else
            {
                if (current.Length >= minLength)
                {
                    results.Add(current.ToString());
                }

                current.Clear();
            }
        }

        if (current.Length >= minLength)
        {
            results.Add(current.ToString());
        }

        return results;
    }

    private static List<string> ExtractUrls(string text)
    {
        try
        {
            return UrlPattern.Matches(text)
                .Select(match => match.Value)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch (RegexMatchTimeoutException)
        {
            return [];
        }
    }

    private static List<string> ExtractRawIpAddresses(string text)
    {
        try
        {
            return IpV4Pattern.Matches(text)
                .Select(match => match.Value)
                .Distinct()
                .ToList();
        }
        catch (RegexMatchTimeoutException)
        {
            return [];
        }
    }

    private static bool IsPrivateOrLoopback(string ip)
    {
        if (!System.Net.IPAddress.TryParse(ip, out var address))
        {
            return true;
        }

        var bytes = address.GetAddressBytes();
        return bytes[0] == 127
            || bytes[0] == 10
            || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            || (bytes[0] == 192 && bytes[1] == 168)
            || (bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0);
    }
}
