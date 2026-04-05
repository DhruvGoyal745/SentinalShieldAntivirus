using System.Text.Json;
using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security;

public sealed class WindowsDefenderClient : IWindowsDefenderClient
{
    private readonly IPowerShellRunner _powerShellRunner;

    public WindowsDefenderClient(IPowerShellRunner powerShellRunner)
    {
        _powerShellRunner = powerShellRunner;
    }

    public async Task<DeviceHealthSnapshot> GetHealthAsync(CancellationToken cancellationToken = default)
    {
        const string command = """
            Get-MpComputerStatus |
            Select-Object AntivirusEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled, NISEnabled, AMServiceEnabled, DefenderSignaturesOutOfDate, AntivirusSignatureVersion, AntivirusSignatureLastUpdated, QuickScanAge, FullScanAge |
            ConvertTo-Json -Depth 4
            """;

        var result = await _powerShellRunner.RunAsync(command, cancellationToken);
        EnsureSuccess(result, "Unable to read Windows Defender health.");

        using var document = JsonDocument.Parse(result.StandardOutput);
        var payload = document.RootElement;

        return new DeviceHealthSnapshot
        {
            CapturedAt = DateTimeOffset.UtcNow,
            AntivirusEnabled = GetBoolean(payload, "AntivirusEnabled"),
            RealTimeProtectionEnabled = GetBoolean(payload, "RealTimeProtectionEnabled"),
            IoavProtectionEnabled = GetBoolean(payload, "IoavProtectionEnabled"),
            NetworkInspectionEnabled = GetBoolean(payload, "NISEnabled"),
            EngineServiceEnabled = GetBoolean(payload, "AMServiceEnabled"),
            SignaturesOutOfDate = GetBoolean(payload, "DefenderSignaturesOutOfDate"),
            AntivirusSignatureVersion = GetString(payload, "AntivirusSignatureVersion"),
            AntivirusSignatureLastUpdated = ParseDateTimeOffset(GetString(payload, "AntivirusSignatureLastUpdated")),
            QuickScanAgeDays = GetInt32(payload, "QuickScanAge"),
            FullScanAgeDays = GetInt32(payload, "FullScanAge")
        };
    }

    public async Task<IReadOnlyCollection<ThreatDetection>> GetActiveThreatsAsync(CancellationToken cancellationToken = default)
    {
        const string command = """
            @(Get-MpThreatDetection |
            Select-Object ThreatID, ThreatName, InitialDetectionTime, Resources, ProcessName, DomainUser, SeverityID) |
            ConvertTo-Json -Depth 5
            """;

        var result = await _powerShellRunner.RunAsync(command, cancellationToken);
        EnsureSuccess(result, "Unable to read active Windows Defender threats.");

        return DeserializeArray(result.StandardOutput)
            .Select(MapThreat)
            .ToArray();
    }

    public async Task<DefenderScanResult> StartScanAsync(ScanRequest request, CancellationToken cancellationToken = default)
    {
        var command = request.Mode switch
        {
            ScanMode.Quick => "Start-MpScan -ScanType QuickScan",
            ScanMode.Full => "Start-MpScan -ScanType FullScan",
            ScanMode.Custom when !string.IsNullOrWhiteSpace(request.TargetPath)
                => $"Start-MpScan -ScanType CustomScan -ScanPath '{request.TargetPath!.Replace("'", "''")}'",
            ScanMode.Custom => throw new InvalidOperationException("Custom scans require a target path."),
            _ => throw new ArgumentOutOfRangeException(nameof(request.Mode), request.Mode, "Unsupported scan mode.")
        };

        var result = await _powerShellRunner.RunAsync(command, cancellationToken);
        if (result.ExitCode != 0 && !IsScanAlreadyRunning(result.StandardError))
        {
            EnsureSuccess(result, "Windows Defender scan request failed.");
        }

        var threats = await GetActiveThreatsAsync(cancellationToken);
        return new DefenderScanResult
        {
            Output = IsScanAlreadyRunning(result.StandardError)
                ? "Windows Defender already has a scan in progress on this device."
                : string.IsNullOrWhiteSpace(result.StandardOutput)
                    ? "Windows Defender accepted the scan request."
                    : result.StandardOutput,
            Threats = threats
        };
    }

    private static IReadOnlyCollection<JsonElement> DeserializeArray(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return Array.Empty<JsonElement>();
        }

        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind == JsonValueKind.Array)
        {
            return document.RootElement.EnumerateArray().Select(element => element.Clone()).ToArray();
        }

        return new[] { document.RootElement.Clone() };
    }

    private static ThreatDetection MapThreat(JsonElement projection)
    {
        var severityId = GetInt32(projection, "SeverityID") ?? 0;
        var resources = GetStringArray(projection, "Resources");

        return new ThreatDetection
        {
            Name = string.IsNullOrWhiteSpace(GetString(projection, "ThreatName")) ? "Windows Defender Threat" : GetString(projection, "ThreatName")!,
            Category = "Malware",
            Severity = severityId switch
            {
                >= 5 => ThreatSeverity.Critical,
                4 => ThreatSeverity.High,
                3 => ThreatSeverity.Medium,
                2 => ThreatSeverity.Low,
                _ => ThreatSeverity.Informational
            },
            Source = ThreatSource.WindowsDefender,
            Resource = resources.FirstOrDefault(),
            Description = $"Detected for user {GetString(projection, "DomainUser") ?? "unknown"} in process {GetString(projection, "ProcessName") ?? "unknown"}.",
            EngineName = "Windows Defender",
            EvidenceJson = projection.GetRawText(),
            DetectedAt = ParseDateTimeOffset(GetString(projection, "InitialDetectionTime")) ?? DateTimeOffset.UtcNow
        };
    }

    private static bool GetBoolean(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property))
        {
            return false;
        }

        if (property.ValueKind == JsonValueKind.True)
        {
            return true;
        }

        if (property.ValueKind == JsonValueKind.False)
        {
            return false;
        }

        return bool.TryParse(property.ToString(), out var parsed) && parsed;
    }

    private static int? GetInt32(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property))
        {
            return null;
        }

        if (property.ValueKind == JsonValueKind.Number && property.TryGetInt32(out var number))
        {
            return number;
        }

        return int.TryParse(property.ToString(), out var parsed) ? parsed : null;
    }

    private static string? GetString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property) || property.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        return property.ValueKind == JsonValueKind.String ? property.GetString() : property.ToString();
    }

    private static IReadOnlyCollection<string> GetStringArray(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property) || property.ValueKind == JsonValueKind.Null)
        {
            return Array.Empty<string>();
        }

        if (property.ValueKind == JsonValueKind.Array)
        {
            return property.EnumerateArray()
                .Select(item => item.ValueKind == JsonValueKind.String ? item.GetString() : item.ToString())
                .Where(item => !string.IsNullOrWhiteSpace(item))
                .Cast<string>()
                .ToArray();
        }

        var value = property.ValueKind == JsonValueKind.String ? property.GetString() : property.ToString();
        return string.IsNullOrWhiteSpace(value) ? Array.Empty<string>() : new[] { value };
    }

    private static DateTimeOffset? ParseDateTimeOffset(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (DateTimeOffset.TryParse(value, out var parsedOffset))
        {
            return parsedOffset;
        }

        if (DateTime.TryParse(value, out var parsedDateTime))
        {
            return new DateTimeOffset(parsedDateTime);
        }

        return null;
    }

    private static void EnsureSuccess(PowerShellCommandResult result, string message)
    {
        if (result.ExitCode == 0)
        {
            return;
        }

        throw new InvalidOperationException($"{message} {result.StandardError}".Trim());
    }

    private static bool IsScanAlreadyRunning(string? error) =>
        !string.IsNullOrWhiteSpace(error)
        && error.Contains("scan is already in progress", StringComparison.OrdinalIgnoreCase);
}
