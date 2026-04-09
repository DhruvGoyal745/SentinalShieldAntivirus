using System.Security.Cryptography;
using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Security;

public sealed class SignatureHashScannerEngine : IOpenSourceScannerEngine
{
    private readonly AntivirusPlatformOptions _options;
    private readonly ILogger<SignatureHashScannerEngine> _logger;

    private static readonly Dictionary<string, string> KnownMaliciousHashes = new(StringComparer.OrdinalIgnoreCase)
    {
        ["275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F"] = "EICAR-Test-File",
        ["131F95C51CC819465FA1797F6CCACF9D494AAAFF46FA3EAC73AE63FFBDFD8267"] = "EICAR-Test-File (trailing newline)"
    };

    private static readonly ByteSignature[] ByteSignatures = BuildByteSignatures();

    public SignatureHashScannerEngine(
        IOptions<AntivirusPlatformOptions> options,
        ILogger<SignatureHashScannerEngine> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public string EngineName => "Sentinel Signature Engine";

    public ThreatSource Source => ThreatSource.SignatureHash;

    public async Task<FileScannerEngineResult> ScanAsync(FileInfo file, CancellationToken cancellationToken = default)
    {
        if (!file.Exists)
        {
            return Clean("File does not exist.");
        }

        if (file.Length == 0)
        {
            return Clean("Empty file.");
        }

        byte[] header;
        string? hash = null;

        try
        {
            await using var stream = new FileStream(
                file.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

            header = new byte[(int)Math.Min(8192, file.Length)];
            _ = await stream.ReadAsync(header, cancellationToken);

            if (file.Length <= _options.MaxHashComputationBytes)
            {
                stream.Position = 0;
                using var sha256 = SHA256.Create();
                var hashBytes = await sha256.ComputeHashAsync(stream, cancellationToken);
                hash = Convert.ToHexString(hashBytes);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new FileScannerEngineResult
            {
                EngineName = EngineName,
                Source = Source,
                Status = FileEngineResultStatus.Error,
                Details = $"Could not read file: {ex.Message}"
            };
        }

        if (hash is not null && KnownMaliciousHashes.TryGetValue(hash, out var hashMatch))
        {
            return new FileScannerEngineResult
            {
                EngineName = EngineName,
                Source = Source,
                Status = FileEngineResultStatus.ThreatDetected,
                IsMatch = true,
                SignatureName = hashMatch,
                Details = $"SHA-256 hash matched known malicious signature: {hashMatch}.",
                RawOutput = $"SHA256:{hash} -> {hashMatch}"
            };
        }

        foreach (var signature in ByteSignatures)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (header.Length < signature.Offset + signature.Bytes.Length)
            {
                continue;
            }

            if (header.AsSpan(signature.Offset, signature.Bytes.Length).SequenceEqual(signature.Bytes))
            {
                if (!signature.IsSuspicious)
                {
                    continue;
                }

                return new FileScannerEngineResult
                {
                    EngineName = EngineName,
                    Source = Source,
                    Status = FileEngineResultStatus.Suspicious,
                    IsMatch = true,
                    SignatureName = signature.Name,
                    Details = signature.Description,
                    RawOutput = $"Byte signature at offset {signature.Offset}: {signature.Name}"
                };
            }
        }

        if (file.Length >= 256)
        {
            var entropy = ComputeEntropy(header);
            if (entropy >= 7.5)
            {
                return new FileScannerEngineResult
                {
                    EngineName = EngineName,
                    Source = Source,
                    Status = FileEngineResultStatus.Suspicious,
                    IsMatch = true,
                    SignatureName = "Sentinel.HighEntropy.PackedBinary",
                    Details = $"File header entropy is {entropy:F2}/8.00, suggesting packed, encrypted, or obfuscated content.",
                    RawOutput = $"Entropy: {entropy:F4}"
                };
            }
        }

        return Clean("No signatures matched.");
    }

    private FileScannerEngineResult Clean(string details) =>
        new()
        {
            EngineName = EngineName,
            Source = Source,
            Status = FileEngineResultStatus.Clean,
            Details = details
        };

    private static double ComputeEntropy(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
        {
            return 0;
        }

        Span<int> frequency = stackalloc int[256];
        frequency.Clear();

        foreach (var b in data)
        {
            frequency[b]++;
        }

        var entropy = 0.0;
        var length = (double)data.Length;

        for (var i = 0; i < 256; i++)
        {
            if (frequency[i] == 0)
            {
                continue;
            }

            var probability = frequency[i] / length;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }

    private static ByteSignature[] BuildByteSignatures() =>
    [
        new ByteSignature
        {
            Name = "Sentinel.PE.UPXPacked",
            Bytes = "UPX!"u8.ToArray(),
            Offset = 0,
            IsSuspicious = true,
            Description = "File begins with the UPX packer signature — commonly used to pack malware."
        },
        new ByteSignature
        {
            Name = "Sentinel.PE.Executable",
            Bytes = [0x4D, 0x5A],
            Offset = 0,
            IsSuspicious = false,
            Description = "MZ header — standard Windows PE executable."
        },
        new ByteSignature
        {
            Name = "Sentinel.ELF.Executable",
            Bytes = [0x7F, 0x45, 0x4C, 0x46],
            Offset = 0,
            IsSuspicious = false,
            Description = "ELF header — Linux/Unix executable."
        },
        new ByteSignature
        {
            Name = "Sentinel.PDF.EmbeddedJS",
            Bytes = "/JavaScript"u8.ToArray(),
            Offset = 0,
            IsSuspicious = true,
            Description = "PDF contains an embedded JavaScript action — commonly exploited for drive-by downloads."
        },
        new ByteSignature
        {
            Name = "Sentinel.PDF.AutoOpen",
            Bytes = "/OpenAction"u8.ToArray(),
            Offset = 0,
            IsSuspicious = true,
            Description = "PDF contains an auto-open action that runs automatically when the document is opened."
        },
        new ByteSignature
        {
            Name = "Sentinel.OLE.MacroDocument",
            Bytes = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
            Offset = 0,
            IsSuspicious = true,
            Description = "OLE Compound Document (legacy Office format) — often contains VBA macros used for malware delivery."
        },
        new ByteSignature
        {
            Name = "Sentinel.Script.ShebangExec",
            Bytes = "#!/"u8.ToArray(),
            Offset = 0,
            IsSuspicious = false,
            Description = "Unix shebang — script file with an interpreter directive."
        }
    ];

    private sealed class ByteSignature
    {
        public string Name { get; init; } = string.Empty;
        public byte[] Bytes { get; init; } = [];
        public int Offset { get; init; }
        public bool IsSuspicious { get; init; }
        public string Description { get; init; } = string.Empty;
    }
}
