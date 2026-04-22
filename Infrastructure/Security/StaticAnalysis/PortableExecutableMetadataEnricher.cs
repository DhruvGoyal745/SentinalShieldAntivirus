using System.Buffers.Binary;
using System.Text;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.StaticAnalysis;

public sealed class PortableExecutableMetadataEnricher : IStaticArtifactEnricher
{
    private static readonly HashSet<string> StandardSectionNames = new(StringComparer.Ordinal)
    {
        ".text", ".data", ".rdata", ".rsrc", ".reloc", ".bss",
        ".idata", ".edata", ".pdata", ".tls", ".CRT", ".debug"
    };

    private static readonly string[] SuspiciousImportNames =
    [
        "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
        "NtUnmapViewOfSection", "VirtualProtect", "IsDebuggerPresent", "LoadLibraryA"
    ];

    private static readonly HashSet<string> CommercialPackerSections = new(StringComparer.OrdinalIgnoreCase)
    {
        ".themida", ".vmp0", ".vmp1", "ENIGMA"
    };

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

        // Shannon entropy analysis
        var entropy = CalculateShannonEntropy(buffer);
        artifact.SetProperty("pe.entropy", entropy.ToString("F2"));

        if (entropy > 7.0)
        {
            detections.Add(new DetectionEventRecord
            {
                RuleId = "heur-pe-high-entropy-section",
                EngineName = "Sentinel PE Inspector",
                Source = ThreatSource.ProprietaryStatic,
                Severity = ThreatSeverity.Medium,
                Confidence = 0.71m,
                Summary = $"PE buffer Shannon entropy is {entropy:F2}, suggesting packed or encrypted content."
            });
        }

        // Non-standard / anomalous section names
        foreach (var section in artifact.Sections)
        {
            if (!StandardSectionNames.Contains(section) && !section.StartsWith('.'))
            {
                detections.Add(new DetectionEventRecord
                {
                    RuleId = "heur-pe-anomalous-section",
                    EngineName = "Sentinel PE Inspector",
                    Source = ThreatSource.ProprietaryStatic,
                    Severity = ThreatSeverity.Low,
                    Confidence = 0.55m,
                    Summary = $"PE contains non-standard section name '{section}' that does not follow typical conventions."
                });
                break;
            }
        }

        // Suspicious import string analysis
        var asciiContent = Encoding.ASCII.GetString(buffer);
        var suspiciousImportCount = SuspiciousImportNames
            .Count(name => asciiContent.Contains(name, StringComparison.Ordinal));
        artifact.SetProperty("pe.suspiciousImportCount", suspiciousImportCount.ToString());

        if (suspiciousImportCount >= 3)
        {
            detections.Add(new DetectionEventRecord
            {
                RuleId = "heur-pe-suspicious-imports",
                EngineName = "Sentinel PE Inspector",
                Source = ThreatSource.ProprietaryStatic,
                Severity = ThreatSeverity.Medium,
                Confidence = 0.67m,
                Summary = $"PE contains {suspiciousImportCount} suspicious import API references commonly associated with process injection or evasion."
            });
        }

        // Themida / VMProtect / commercial packer detection
        if (artifact.Sections.Any(s => CommercialPackerSections.Contains(s)))
        {
            detections.Add(new DetectionEventRecord
            {
                RuleId = "heur-pe-packed-commercial",
                EngineName = "Sentinel PE Inspector",
                Source = ThreatSource.ProprietaryStatic,
                Severity = ThreatSeverity.Medium,
                Confidence = 0.73m,
                Summary = "PE contains section names associated with commercial packers (Themida, VMProtect, or Enigma)."
            });
        }

        return detections;
    }

    private static double CalculateShannonEntropy(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return 0.0;
        }

        Span<int> frequency = stackalloc int[256];
        frequency.Clear();

        for (var i = 0; i < data.Length; i++)
        {
            frequency[data[i]]++;
        }

        var entropy = 0.0;
        var length = (double)data.Length;

        for (var i = 0; i < 256; i++)
        {
            if (frequency[i] == 0)
            {
                continue;
            }

            var p = frequency[i] / length;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }
}
