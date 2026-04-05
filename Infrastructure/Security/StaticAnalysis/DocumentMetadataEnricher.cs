using System.IO.Compression;
using System.Text;
using Antivirus.Configuration;
using Antivirus.Domain;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Security.StaticAnalysis;

public sealed class DocumentMetadataEnricher : IStaticArtifactEnricher
{
    private static readonly HashSet<string> OpenXmlExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"
    };

    private static readonly HashSet<string> LegacyOfficeExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".doc", ".dot", ".xls", ".xlt", ".ppt", ".pot"
    };

    private readonly AntivirusPlatformOptions _options;

    public DocumentMetadataEnricher(IOptions<AntivirusPlatformOptions> options)
    {
        _options = options.Value;
    }

    public async Task<IReadOnlyCollection<DetectionEventRecord>> EnrichAsync(
        StaticScanArtifact artifact,
        CancellationToken cancellationToken = default)
    {
        var extension = artifact.File.Extension;
        if (extension.Equals(".pdf", StringComparison.OrdinalIgnoreCase))
        {
            return await InspectPdfAsync(artifact, cancellationToken);
        }

        if (OpenXmlExtensions.Contains(extension))
        {
            return await InspectOpenXmlAsync(artifact, cancellationToken);
        }

        if (LegacyOfficeExtensions.Contains(extension))
        {
            return await InspectLegacyOfficeAsync(artifact, cancellationToken);
        }

        return Array.Empty<DetectionEventRecord>();
    }

    private async Task<IReadOnlyCollection<DetectionEventRecord>> InspectPdfAsync(
        StaticScanArtifact artifact,
        CancellationToken cancellationToken)
    {
        string content;
        try
        {
            await using var stream = new FileStream(
                artifact.File.FullName,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            var buffer = new byte[(int)Math.Min(_options.MaxContentInspectionBytes, stream.Length)];
            var bytesRead = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);
            content = Encoding.Latin1.GetString(buffer, 0, bytesRead);
        }
        catch
        {
            return Array.Empty<DetectionEventRecord>();
        }

        if (!content.Contains("%PDF-", StringComparison.OrdinalIgnoreCase))
        {
            return Array.Empty<DetectionEventRecord>();
        }

        artifact.Classification = "DOCUMENT";
        artifact.SetProperty("doc.type", "PDF");
        artifact.SetProperty("doc.hasJavaScript", ContainsAny(content, "/JavaScript", "/JS").ToString().ToLowerInvariant());
        artifact.SetProperty("doc.hasOpenAction", ContainsAny(content, "/OpenAction", "/AA").ToString().ToLowerInvariant());
        artifact.SetProperty("doc.hasLaunchAction", content.Contains("/Launch", StringComparison.OrdinalIgnoreCase).ToString().ToLowerInvariant());
        artifact.SetProperty("doc.hasEmbeddedFiles", content.Contains("/EmbeddedFile", StringComparison.OrdinalIgnoreCase).ToString().ToLowerInvariant());

        var detections = new List<DetectionEventRecord>();
        if (ContainsAny(content, "/JavaScript", "/JS"))
        {
            detections.Add(CreateDetection(
                "heur-pdf-javascript",
                ThreatSeverity.High,
                0.88m,
                "PDF contains JavaScript markers often abused for staged document execution."));
        }

        if (ContainsAny(content, "/OpenAction", "/AA", "/Launch"))
        {
            detections.Add(CreateDetection(
                "heur-pdf-active-action",
                ThreatSeverity.High,
                0.84m,
                "PDF contains automatic action or launch markers that warrant deeper review."));
        }

        if (content.Contains("/EmbeddedFile", StringComparison.OrdinalIgnoreCase))
        {
            detections.Add(CreateDetection(
                "heur-pdf-embedded-file",
                ThreatSeverity.Medium,
                0.72m,
                "PDF contains embedded file markers and may package secondary payloads."));
        }

        return detections;
    }

    private async Task<IReadOnlyCollection<DetectionEventRecord>> InspectOpenXmlAsync(
        StaticScanArtifact artifact,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var stream = new FileStream(
                artifact.File.FullName,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false);

            var hasMacros = false;
            var hasExternalRelationships = false;
            var embeddedCount = 0;
            var templateInjection = false;

            foreach (var entry in archive.Entries.Take(300))
            {
                cancellationToken.ThrowIfCancellationRequested();
                artifact.AddArchiveEntry(entry.FullName);

                if (entry.FullName.Contains("vbaProject", StringComparison.OrdinalIgnoreCase))
                {
                    hasMacros = true;
                }

                if (entry.FullName.EndsWith(".rels", StringComparison.OrdinalIgnoreCase))
                {
                    using var reader = new StreamReader(entry.Open(), Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: false);
                    var relContent = await reader.ReadToEndAsync(cancellationToken);
                    if (relContent.Contains("TargetMode=\"External\"", StringComparison.OrdinalIgnoreCase))
                    {
                        hasExternalRelationships = true;
                    }

                    if (relContent.Contains("attachedTemplate", StringComparison.OrdinalIgnoreCase)
                        || relContent.Contains("template", StringComparison.OrdinalIgnoreCase)
                        || relContent.Contains("mhtml", StringComparison.OrdinalIgnoreCase))
                    {
                        templateInjection = true;
                    }
                }

                if (entry.FullName.Contains("embeddings/", StringComparison.OrdinalIgnoreCase)
                    || entry.FullName.Contains("activeX/", StringComparison.OrdinalIgnoreCase)
                    || entry.FullName.Contains("oleObject", StringComparison.OrdinalIgnoreCase))
                {
                    embeddedCount++;
                }
            }

            artifact.Classification = "DOCUMENT";
            artifact.SetProperty("doc.type", $"OOXML-{artifact.File.Extension.Trim('.').ToUpperInvariant()}");
            artifact.SetProperty("doc.hasMacros", hasMacros.ToString().ToLowerInvariant());
            artifact.SetProperty("doc.hasExternalRelationships", hasExternalRelationships.ToString().ToLowerInvariant());
            artifact.SetProperty("doc.embeddedObjectCount", embeddedCount.ToString());
            artifact.SetProperty("doc.templateInjection", templateInjection.ToString().ToLowerInvariant());

            var detections = new List<DetectionEventRecord>();
            if (hasMacros)
            {
                detections.Add(CreateDetection(
                    "heur-ooxml-macro-project",
                    ThreatSeverity.High,
                    0.9m,
                    "Open XML document contains a VBA macro project and should be treated as high-risk content."));
            }

            if (hasExternalRelationships || templateInjection)
            {
                detections.Add(CreateDetection(
                    "heur-ooxml-external-template",
                    ThreatSeverity.High,
                    0.85m,
                    "Open XML document references external relationships or templates that may retrieve remote payloads."));
            }

            if (embeddedCount > 0)
            {
                detections.Add(CreateDetection(
                    "heur-ooxml-embedded-objects",
                    ThreatSeverity.Medium,
                    0.74m,
                    "Open XML document contains embedded objects or ActiveX content."));
            }

            return detections;
        }
        catch
        {
            return Array.Empty<DetectionEventRecord>();
        }
    }

    private async Task<IReadOnlyCollection<DetectionEventRecord>> InspectLegacyOfficeAsync(
        StaticScanArtifact artifact,
        CancellationToken cancellationToken)
    {
        string content;
        try
        {
            await using var stream = new FileStream(
                artifact.File.FullName,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            var buffer = new byte[(int)Math.Min(256 * 1024, stream.Length)];
            var bytesRead = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);
            if (bytesRead < 8
                || buffer[0] != 0xD0
                || buffer[1] != 0xCF
                || buffer[2] != 0x11
                || buffer[3] != 0xE0)
            {
                return Array.Empty<DetectionEventRecord>();
            }

            content = Encoding.Latin1.GetString(buffer, 0, bytesRead);
        }
        catch
        {
            return Array.Empty<DetectionEventRecord>();
        }

        var hasVba = ContainsAny(content, "VBA", "Macros", "PROJECT", "dir");
        var hasAutoExec = ContainsAny(content, "AutoOpen", "Document_Open", "Workbook_Open", "Auto_Close");
        var hasShellAbuse = ContainsAny(content, "Shell", "URLDownloadToFile", "PowerShell", "WScript.Shell");

        artifact.Classification = "DOCUMENT";
        artifact.SetProperty("doc.type", $"OLE-{artifact.File.Extension.Trim('.').ToUpperInvariant()}");
        artifact.SetProperty("doc.hasMacros", hasVba.ToString().ToLowerInvariant());
        artifact.SetProperty("doc.hasAutoExec", hasAutoExec.ToString().ToLowerInvariant());
        artifact.SetProperty("doc.hasShellAbuse", hasShellAbuse.ToString().ToLowerInvariant());

        var detections = new List<DetectionEventRecord>();
        if (hasVba && hasAutoExec)
        {
            detections.Add(CreateDetection(
                "heur-ole-autoexec-macro",
                ThreatSeverity.High,
                0.87m,
                "Legacy Office document contains macro storage and auto-execution markers."));
        }

        if (hasShellAbuse)
        {
            detections.Add(CreateDetection(
                "heur-ole-shell-abuse",
                ThreatSeverity.High,
                0.82m,
                "Legacy Office document content references shelling or downloader behavior."));
        }

        return detections;
    }

    private static bool ContainsAny(string content, params string[] markers)
    {
        return markers.Any(marker => content.Contains(marker, StringComparison.OrdinalIgnoreCase));
    }

    private static DetectionEventRecord CreateDetection(
        string ruleId,
        ThreatSeverity severity,
        decimal confidence,
        string summary)
    {
        return new DetectionEventRecord
        {
            RuleId = ruleId,
            EngineName = "Sentinel Document Inspector",
            Source = ThreatSource.ProprietaryStatic,
            Severity = severity,
            Confidence = confidence,
            Summary = summary
        };
    }
}
