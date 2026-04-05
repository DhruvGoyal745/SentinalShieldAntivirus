using System.Buffers.Binary;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.StaticAnalysis;

public sealed class ElfMetadataEnricher : IStaticArtifactEnricher
{
    private static readonly IReadOnlyDictionary<ushort, string> MachineMap = new Dictionary<ushort, string>
    {
        [0x03] = "X86",
        [0x3e] = "X86_64",
        [0x28] = "ARM",
        [0xb7] = "AARCH64"
    };

    public async Task<IReadOnlyCollection<DetectionEventRecord>> EnrichAsync(
        StaticScanArtifact artifact,
        CancellationToken cancellationToken = default)
    {
        byte[] header;
        try
        {
            await using var stream = new FileStream(
                artifact.File.FullName,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            header = new byte[(int)Math.Min(stream.Length, 256)];
            var bytesRead = await stream.ReadAsync(header.AsMemory(0, header.Length), cancellationToken);
            if (bytesRead < 24)
            {
                return Array.Empty<DetectionEventRecord>();
            }

            Array.Resize(ref header, bytesRead);
        }
        catch
        {
            return Array.Empty<DetectionEventRecord>();
        }

        if (!(header[0] == 0x7f && header[1] == (byte)'E' && header[2] == (byte)'L' && header[3] == (byte)'F'))
        {
            return Array.Empty<DetectionEventRecord>();
        }

        artifact.Classification = "ELF";
        artifact.SetProperty("elf.class", header[4] switch
        {
            1 => "ELF32",
            2 => "ELF64",
            _ => "UNKNOWN"
        });
        artifact.SetProperty("elf.endianness", header[5] switch
        {
            1 => "LITTLE",
            2 => "BIG",
            _ => "UNKNOWN"
        });

        if (header[5] == 1 && header.Length >= 20)
        {
            var machine = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(18, 2));
            artifact.SetProperty("elf.machine", MachineMap.TryGetValue(machine, out var machineName) ? machineName : $"0x{machine:x4}");
        }

        if (artifact.File.FullName.Contains("/tmp/", StringComparison.OrdinalIgnoreCase)
            || artifact.File.FullName.Contains("\\temp\\", StringComparison.OrdinalIgnoreCase))
        {
            return
            [
                new DetectionEventRecord
                {
                    RuleId = "heur-elf-temp-staging",
                    EngineName = "Sentinel ELF Inspector",
                    Source = ThreatSource.ProprietaryStatic,
                    Severity = ThreatSeverity.Medium,
                    Confidence = 0.62m,
                    Summary = "ELF artifact appears to be staged from a temporary path."
                }
            ];
        }

        return Array.Empty<DetectionEventRecord>();
    }
}
