using System.Buffers.Binary;
using System.Text;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.StaticAnalysis;

public sealed class PortableExecutableMetadataEnricher : IStaticArtifactEnricher
{
    private static readonly IReadOnlyDictionary<ushort, string> MachineMap = new Dictionary<ushort, string>
    {
        [0x014c] = "I386",
        [0x8664] = "AMD64",
        [0x01c4] = "ARMNT",
        [0xAA64] = "ARM64"
    };

    public async Task<IReadOnlyCollection<DetectionEventRecord>> EnrichAsync(
        StaticScanArtifact artifact,
        CancellationToken cancellationToken = default)
    {
        var detections = new List<DetectionEventRecord>();
        byte[] buffer;
        try
        {
            await using var stream = new FileStream(
                artifact.File.FullName,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            buffer = new byte[(int)Math.Min(stream.Length, 8192)];
            var bytesRead = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);
            if (bytesRead < 256)
            {
                return Array.Empty<DetectionEventRecord>();
            }

            Array.Resize(ref buffer, bytesRead);
        }
        catch
        {
            return Array.Empty<DetectionEventRecord>();
        }

        if (!buffer.AsSpan().StartsWith("MZ"u8))
        {
            return Array.Empty<DetectionEventRecord>();
        }

        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(buffer.AsSpan(0x3c, 4));
        if (peOffset < 0 || peOffset + 24 > buffer.Length || !buffer.AsSpan(peOffset, 4).SequenceEqual("PE\0\0"u8))
        {
            return Array.Empty<DetectionEventRecord>();
        }

        artifact.Classification = "PE";

        var fileHeaderOffset = peOffset + 4;
        var machine = BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(fileHeaderOffset, 2));
        var numberOfSections = BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(fileHeaderOffset + 2, 2));
        var characteristics = BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(fileHeaderOffset + 18, 2));
        var sizeOfOptionalHeader = BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(fileHeaderOffset + 16, 2));

        artifact.SetProperty("pe.machine", MachineMap.TryGetValue(machine, out var machineName) ? machineName : $"0x{machine:x4}");
        artifact.SetProperty("pe.sectionCount", numberOfSections.ToString());
        artifact.SetProperty("pe.isDll", ((characteristics & 0x2000) != 0).ToString().ToLowerInvariant());
        artifact.SetProperty("pe.isExecutable", ((characteristics & 0x0002) != 0).ToString().ToLowerInvariant());

        var sectionOffset = fileHeaderOffset + 20 + sizeOfOptionalHeader;
        for (var i = 0; i < numberOfSections && sectionOffset + 40 <= buffer.Length; i++, sectionOffset += 40)
        {
            var rawName = Encoding.ASCII.GetString(buffer, sectionOffset, 8).TrimEnd('\0', ' ');
            if (string.IsNullOrWhiteSpace(rawName))
            {
                continue;
            }

            artifact.AddSection(rawName);
            artifact.SetProperty($"pe.section.{rawName}", "true");
        }

        if (artifact.Sections.Any(section => section.StartsWith("UPX", StringComparison.OrdinalIgnoreCase)))
        {
            detections.Add(new DetectionEventRecord
            {
                RuleId = "heur-pe-packed-upx",
                EngineName = "Sentinel PE Inspector",
                Source = ThreatSource.ProprietaryStatic,
                Severity = ThreatSeverity.Medium,
                Confidence = 0.69m,
                Summary = "Portable executable contains UPX-style section names and may be packed or staged."
            });
        }

        if (artifact.File.DirectoryName?.Contains("temp", StringComparison.OrdinalIgnoreCase) == true
            && artifact.File.Extension.Equals(".exe", StringComparison.OrdinalIgnoreCase))
        {
            detections.Add(new DetectionEventRecord
            {
                RuleId = "heur-pe-temp-execution-surface",
                EngineName = "Sentinel PE Inspector",
                Source = ThreatSource.ProprietaryStatic,
                Severity = ThreatSeverity.Medium,
                Confidence = 0.63m,
                Summary = "Executable is positioned in a temporary location often abused for drop-and-run behavior."
            });
        }

        return detections;
    }
}
