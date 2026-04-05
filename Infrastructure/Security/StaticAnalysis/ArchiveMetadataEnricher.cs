using System.Formats.Tar;
using System.IO.Compression;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.StaticAnalysis;

public sealed class ArchiveMetadataEnricher : IStaticArtifactEnricher
{
    public async Task<IReadOnlyCollection<DetectionEventRecord>> EnrichAsync(
        StaticScanArtifact artifact,
        CancellationToken cancellationToken = default)
    {
        if (artifact.File.Extension.Equals(".zip", StringComparison.OrdinalIgnoreCase))
        {
            return await InspectZipAsync(artifact, cancellationToken);
        }

        if (artifact.File.Extension.Equals(".tar", StringComparison.OrdinalIgnoreCase))
        {
            return await InspectTarAsync(artifact, cancellationToken);
        }

        if (artifact.File.Extension.Equals(".gz", StringComparison.OrdinalIgnoreCase))
        {
            return await InspectGzipAsync(artifact, cancellationToken);
        }

        return EvaluateUnsupportedArchiveHeuristics(artifact);
    }

    private static async Task<IReadOnlyCollection<DetectionEventRecord>> InspectZipAsync(
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

            long compressedBytes = 0;
            long expandedBytes = 0;
            foreach (var entry in archive.Entries.Take(500))
            {
                cancellationToken.ThrowIfCancellationRequested();
                artifact.AddArchiveEntry(entry.FullName);
                compressedBytes += entry.CompressedLength;
                expandedBytes += entry.Length;
            }

            artifact.Classification = "ARCHIVE";
            artifact.ArchiveEntryCount = archive.Entries.Count;
            artifact.ArchiveCompressedBytes = compressedBytes;
            artifact.ArchiveExpandedBytes = expandedBytes;
            artifact.SetProperty("archive.type", "ZIP");
            artifact.SetProperty("archive.entryCount", archive.Entries.Count.ToString());
            artifact.SetProperty(
                "archive.expansionRatio",
                compressedBytes > 0
                    ? Math.Round(expandedBytes / (double)compressedBytes, 2).ToString("0.##", System.Globalization.CultureInfo.InvariantCulture)
                    : "0");

            return EvaluateArchiveDetections(artifact, archive.Entries.Count, compressedBytes, expandedBytes);
        }
        catch
        {
            return EvaluateUnsupportedArchiveHeuristics(artifact);
        }
    }

    private static async Task<IReadOnlyCollection<DetectionEventRecord>> InspectTarAsync(
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
            using var reader = new TarReader(stream, leaveOpen: false);

            var entryCount = 0;
            long expandedBytes = 0;
            TarEntry? entry;
            while ((entry = reader.GetNextEntry(copyData: false)) is not null && entryCount < 500)
            {
                cancellationToken.ThrowIfCancellationRequested();
                entryCount++;
                artifact.AddArchiveEntry(entry.Name);
                expandedBytes += entry.Length;
            }

            artifact.Classification = "ARCHIVE";
            artifact.ArchiveEntryCount = entryCount;
            artifact.ArchiveExpandedBytes = expandedBytes;
            artifact.ArchiveCompressedBytes = artifact.File.Length;
            artifact.SetProperty("archive.type", "TAR");
            artifact.SetProperty("archive.entryCount", entryCount.ToString());
            artifact.SetProperty(
                "archive.expansionRatio",
                artifact.File.Length > 0
                    ? Math.Round(expandedBytes / (double)artifact.File.Length, 2).ToString("0.##", System.Globalization.CultureInfo.InvariantCulture)
                    : "0");

            return EvaluateArchiveDetections(artifact, entryCount, artifact.File.Length, expandedBytes);
        }
        catch
        {
            return EvaluateUnsupportedArchiveHeuristics(artifact);
        }
    }

    private static async Task<IReadOnlyCollection<DetectionEventRecord>> InspectGzipAsync(
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
            using var gzip = new GZipStream(stream, CompressionMode.Decompress, leaveOpen: false);

            var buffer = new byte[8192];
            long expandedBytes = 0;
            int bytesRead;
            while ((bytesRead = await gzip.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)) > 0
                   && expandedBytes < 128L * 1024 * 1024)
            {
                expandedBytes += bytesRead;
            }

            artifact.Classification = "ARCHIVE";
            artifact.ArchiveEntryCount = 1;
            artifact.ArchiveCompressedBytes = artifact.File.Length;
            artifact.ArchiveExpandedBytes = expandedBytes;
            artifact.SetProperty("archive.type", "GZIP");
            artifact.SetProperty("archive.entryCount", "1");
            artifact.SetProperty(
                "archive.expansionRatio",
                artifact.File.Length > 0
                    ? Math.Round(expandedBytes / (double)artifact.File.Length, 2).ToString("0.##", System.Globalization.CultureInfo.InvariantCulture)
                    : "0");

            return EvaluateArchiveDetections(artifact, 1, artifact.File.Length, expandedBytes);
        }
        catch
        {
            return EvaluateUnsupportedArchiveHeuristics(artifact);
        }
    }

    private static IReadOnlyCollection<DetectionEventRecord> EvaluateArchiveDetections(
        StaticScanArtifact artifact,
        int entryCount,
        long compressedBytes,
        long expandedBytes)
    {
        var detections = new List<DetectionEventRecord>();
        if (entryCount > 750 || (compressedBytes > 0 && expandedBytes / (double)compressedBytes > 40d && expandedBytes > 128L * 1024 * 1024))
        {
            detections.Add(new DetectionEventRecord
            {
                RuleId = "heur-archive-expansion-anomaly",
                EngineName = "Sentinel Archive Inspector",
                Source = ThreatSource.ProprietaryStatic,
                Severity = ThreatSeverity.High,
                Confidence = 0.86m,
                Summary = "Archive expansion characteristics suggest compression abuse or archive-bomb behavior."
            });
        }

        if (artifact.ArchiveEntries.Any(entry =>
                entry.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                || entry.EndsWith(".js", StringComparison.OrdinalIgnoreCase)
                || entry.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                || entry.Contains(".pdf.exe", StringComparison.OrdinalIgnoreCase)
                || entry.Contains("AppData/", StringComparison.OrdinalIgnoreCase)
                || entry.Contains("Startup/", StringComparison.OrdinalIgnoreCase)))
        {
            detections.Add(new DetectionEventRecord
            {
                RuleId = "heur-archive-executable-payload",
                EngineName = "Sentinel Archive Inspector",
                Source = ThreatSource.ProprietaryStatic,
                Severity = ThreatSeverity.Medium,
                Confidence = 0.75m,
                Summary = "Archive contains executable, script-like, or persistence-oriented payload members."
            });
        }

        return detections;
    }

    private static IReadOnlyCollection<DetectionEventRecord> EvaluateUnsupportedArchiveHeuristics(StaticScanArtifact artifact)
    {
        if (artifact.Classification != "ARCHIVE")
        {
            return Array.Empty<DetectionEventRecord>();
        }

        var detections = new List<DetectionEventRecord>();
        if (artifact.File.Length > 256L * 1024 * 1024)
        {
            detections.Add(new DetectionEventRecord
            {
                RuleId = "heur-archive-oversized",
                EngineName = "Sentinel Archive Inspector",
                Source = ThreatSource.ProprietaryStatic,
                Severity = ThreatSeverity.High,
                Confidence = 0.82m,
                Summary = "Archive exceeds clean-room guardrail limits and may indicate resource-exhaustion abuse."
            });
        }

        if (artifact.File.Name.Count(character => character == '.') >= 3)
        {
            detections.Add(new DetectionEventRecord
            {
                RuleId = "heur-archive-disguised-name",
                EngineName = "Sentinel Archive Inspector",
                Source = ThreatSource.ProprietaryStatic,
                Severity = ThreatSeverity.Medium,
                Confidence = 0.66m,
                Summary = "Archive naming pattern suggests layered or disguised payload packaging."
            });
        }

        return detections;
    }
}
