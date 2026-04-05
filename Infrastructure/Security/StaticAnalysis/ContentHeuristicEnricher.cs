using System.Text;
using Antivirus.Configuration;
using Antivirus.Domain;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Security.StaticAnalysis;

public sealed class ContentHeuristicEnricher : IStaticArtifactEnricher
{
    private static readonly string[] ScriptLikeExtensions =
    [
        ".ps1", ".vbs", ".js", ".cmd", ".bat", ".sh", ".py", ".rb", ".txt", ".hta", ".psm1"
    ];

    private readonly AntivirusPlatformOptions _options;

    public ContentHeuristicEnricher(IOptions<AntivirusPlatformOptions> options)
    {
        _options = options.Value;
    }

    public async Task<IReadOnlyCollection<DetectionEventRecord>> EnrichAsync(
        StaticScanArtifact artifact,
        CancellationToken cancellationToken = default)
    {
        if (!ShouldInspect(artifact.File))
        {
            return Array.Empty<DetectionEventRecord>();
        }

        string? content;
        try
        {
            await using var stream = new FileStream(
                artifact.File.FullName,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            var buffer = new byte[(int)Math.Min(_options.MaxContentInspectionBytes, stream.Length)];
            var bytesRead = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);
            content = DecodeBestEffort(buffer.AsSpan(0, bytesRead));
        }
        catch
        {
            return Array.Empty<DetectionEventRecord>();
        }

        artifact.TextContent = content;
        if (string.IsNullOrWhiteSpace(content))
        {
            return Array.Empty<DetectionEventRecord>();
        }

        var detections = new List<DetectionEventRecord>();
        if (ContainsAny(content, "EncodedCommand", "FromBase64String(", "Invoke-Expression", "IEX("))
        {
            detections.Add(CreateDetection(
                "heur-script-obfuscated-loader",
                ThreatSeverity.High,
                0.87m,
                "Script content contains obfuscation or loader patterns that often precede malicious execution."));
        }

        if (ContainsAny(content, "AutoOpen(", "Document_Open(", "Workbook_Open(", "CreateObject(\"WScript.Shell\")"))
        {
            detections.Add(CreateDetection(
                "heur-macro-autoexec",
                ThreatSeverity.High,
                0.84m,
                "Document or script content contains auto-execution markers or shell automation behavior."));
        }

        if (ContainsAny(content, "schtasks", "RunOnce", "Startup", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"))
        {
            detections.Add(CreateDetection(
                "heur-persistence-bootstrap",
                ThreatSeverity.Medium,
                0.73m,
                "Content includes persistence-oriented commands or autorun references."));
        }

        return detections;
    }

    private static DetectionEventRecord CreateDetection(string ruleId, ThreatSeverity severity, decimal confidence, string summary)
    {
        return new DetectionEventRecord
        {
            RuleId = ruleId,
            EngineName = "Sentinel Content Inspector",
            Source = ThreatSource.ProprietaryStatic,
            Severity = severity,
            Confidence = confidence,
            Summary = summary
        };
    }

    private static bool ContainsAny(string content, params string[] markers)
    {
        return markers.Any(marker => content.Contains(marker, StringComparison.OrdinalIgnoreCase));
    }

    private static bool ShouldInspect(FileInfo file)
    {
        return ScriptLikeExtensions.Contains(file.Extension, StringComparer.OrdinalIgnoreCase)
            || file.Length <= 128 * 1024;
    }

    private static string DecodeBestEffort(ReadOnlySpan<byte> bytes)
    {
        try
        {
            return Encoding.UTF8.GetString(bytes);
        }
        catch
        {
            return Encoding.Latin1.GetString(bytes);
        }
    }
}
