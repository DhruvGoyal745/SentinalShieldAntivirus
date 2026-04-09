using System.Text;
using System.Text.RegularExpressions;
using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Security;

public sealed class PatternRuleScannerEngine : IOpenSourceScannerEngine
{
    private readonly AntivirusPlatformOptions _options;
    private readonly ILogger<PatternRuleScannerEngine> _logger;
    private static readonly PatternRule[] Rules = BuildRules();

    public PatternRuleScannerEngine(
        IOptions<AntivirusPlatformOptions> options,
        ILogger<PatternRuleScannerEngine> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public string EngineName => "Sentinel Pattern Engine";

    public ThreatSource Source => ThreatSource.PatternRule;

    public async Task<FileScannerEngineResult> ScanAsync(FileInfo file, CancellationToken cancellationToken = default)
    {
        if (!file.Exists)
        {
            return Clean("File does not exist.");
        }

        if (file.Length > _options.MaxContentInspectionBytes)
        {
            return Clean("File exceeds the pattern engine inspection limit.");
        }

        byte[] content;
        try
        {
            content = await ReadFileBytesAsync(file, cancellationToken);
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

        var text = Encoding.UTF8.GetString(content);
        var matches = new List<string>();

        foreach (var rule in Rules)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var matched = rule.Kind switch
            {
                PatternRuleKind.LiteralBytes => ContainsBytes(content, rule.LiteralBytes!),
                PatternRuleKind.LiteralString => text.Contains(rule.LiteralString!, rule.Comparison),
                PatternRuleKind.Regex => rule.CompiledRegex!.IsMatch(text),
                _ => false
            };

            if (matched)
            {
                matches.Add(rule.Name);
            }
        }

        if (matches.Count == 0)
        {
            return Clean("No pattern rules matched.");
        }

        return new FileScannerEngineResult
        {
            EngineName = EngineName,
            Source = Source,
            Status = FileEngineResultStatus.ThreatDetected,
            IsMatch = true,
            SignatureName = matches[0],
            Details = $"{matches.Count} pattern rule(s) matched: {string.Join(", ", matches)}.",
            RawOutput = string.Join(Environment.NewLine, matches)
        };
    }

    private FileScannerEngineResult Clean(string details) =>
        new()
        {
            EngineName = EngineName,
            Source = Source,
            Status = FileEngineResultStatus.Clean,
            Details = details
        };

    private static async Task<byte[]> ReadFileBytesAsync(FileInfo file, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            file.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var buffer = new byte[file.Length];
        _ = await stream.ReadAsync(buffer, cancellationToken);
        return buffer;
    }

    private static bool ContainsBytes(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0 || needle.Length > haystack.Length)
        {
            return false;
        }

        for (var i = 0; i <= haystack.Length - needle.Length; i++)
        {
            if (haystack.AsSpan(i, needle.Length).SequenceEqual(needle))
            {
                return true;
            }
        }

        return false;
    }

    private static PatternRule[] BuildRules() =>
    [
        new PatternRule
        {
            Name = "Sentinel.Eicar.TestFile",
            Kind = PatternRuleKind.LiteralString,
            LiteralString = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
            Comparison = StringComparison.Ordinal
        },
        new PatternRule
        {
            Name = "Sentinel.EncodedPowerShell.Command",
            Kind = PatternRuleKind.Regex,
            CompiledRegex = new Regex(
                @"-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{20,}",
                RegexOptions.IgnoreCase | RegexOptions.Compiled,
                TimeSpan.FromSeconds(2))
        },
        new PatternRule
        {
            Name = "Sentinel.PowerShell.DownloadCradle",
            Kind = PatternRuleKind.Regex,
            CompiledRegex = new Regex(
                @"(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm|wget|curl|Net\.WebClient|DownloadString|DownloadFile)\s*[\(\s].*https?://",
                RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline,
                TimeSpan.FromSeconds(2))
        },
        new PatternRule
        {
            Name = "Sentinel.PowerShell.InvokeExpression",
            Kind = PatternRuleKind.Regex,
            CompiledRegex = new Regex(
                @"(?:Invoke-Expression|iex)\s*[\(\s].*(?:DownloadString|Net\.WebClient|FromBase64String)",
                RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline,
                TimeSpan.FromSeconds(2))
        },
        new PatternRule
        {
            Name = "Sentinel.Script.HiddenWindowExec",
            Kind = PatternRuleKind.Regex,
            CompiledRegex = new Regex(
                @"-(?:w(?:indowstyle)?)\s+hidden",
                RegexOptions.IgnoreCase | RegexOptions.Compiled,
                TimeSpan.FromSeconds(2))
        },
        new PatternRule
        {
            Name = "Sentinel.VBScript.ShellExecute",
            Kind = PatternRuleKind.Regex,
            CompiledRegex = new Regex(
                @"(?:WScript\.Shell|Shell\.Application).*\.(?:Run|Exec|ShellExecute)\s*\(",
                RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline,
                TimeSpan.FromSeconds(2))
        },
        new PatternRule
        {
            Name = "Sentinel.Batch.DisableDefender",
            Kind = PatternRuleKind.Regex,
            CompiledRegex = new Regex(
                @"Set-MpPreference\s+-Disable(?:RealtimeMonitoring|IOAVProtection|BehaviorMonitoring)\s+\$?true",
                RegexOptions.IgnoreCase | RegexOptions.Compiled,
                TimeSpan.FromSeconds(2))
        },
        new PatternRule
        {
            Name = "Sentinel.Script.Base64Payload",
            Kind = PatternRuleKind.Regex,
            CompiledRegex = new Regex(
                @"(?:FromBase64String|atob|base64_decode)\s*\(\s*[""'][A-Za-z0-9+/=]{40,}[""']",
                RegexOptions.IgnoreCase | RegexOptions.Compiled,
                TimeSpan.FromSeconds(2))
        },
        new PatternRule
        {
            Name = "Sentinel.PE.MZHeader.InScript",
            Kind = PatternRuleKind.LiteralBytes,
            LiteralBytes = "MZ"u8.ToArray()
        }
    ];

    private enum PatternRuleKind
    {
        LiteralString,
        LiteralBytes,
        Regex
    }

    private sealed class PatternRule
    {
        public string Name { get; init; } = string.Empty;
        public PatternRuleKind Kind { get; init; }
        public string? LiteralString { get; init; }
        public byte[]? LiteralBytes { get; init; }
        public Regex? CompiledRegex { get; init; }
        public StringComparison Comparison { get; init; } = StringComparison.OrdinalIgnoreCase;
    }
}
