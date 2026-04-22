using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.Rules;

public sealed class HighEntropySectionRule : IHeuristicRule
{
    private const double EntropyThreshold = 7.0;

    private static readonly HashSet<string> PeExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys"
    };

    public ThreatDetection? Evaluate(FileScanContext context)
    {
        if (!PeExtensions.Contains(context.File.Extension))
        {
            return null;
        }

        double entropy;
        try
        {
            using var stream = new FileStream(
                context.File.FullName,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            var buffer = new byte[(int)Math.Min(stream.Length, 8192)];
            var bytesRead = stream.Read(buffer, 0, buffer.Length);
            if (bytesRead == 0)
            {
                return null;
            }

            entropy = CalculateShannonEntropy(buffer.AsSpan(0, bytesRead));
        }
        catch
        {
            return null;
        }

        if (entropy <= EntropyThreshold)
        {
            return null;
        }

        return new ThreatDetection
        {
            Name = "High entropy PE file detected",
            Category = "Packing",
            Severity = ThreatSeverity.Medium,
            Source = ThreatSource.Heuristic,
            Resource = context.File.FullName,
            Description = $"PE file '{context.File.Name}' has Shannon entropy of {entropy:F2} (threshold: {EntropyThreshold:F1}). High entropy suggests the file may be packed, encrypted, or compressed to evade analysis.",
            EngineName = "Sentinel Shield Heuristics",
            DetectedAt = DateTimeOffset.UtcNow
        };
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
