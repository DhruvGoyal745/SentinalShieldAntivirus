using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Security;

public sealed class SignaturePackCompiler : ISignaturePackCompiler
{
    private readonly AntivirusPlatformOptions _options;

    public SignaturePackCompiler(IOptions<AntivirusPlatformOptions> options)
    {
        _options = options.Value;
    }

    public Task<ProprietarySignaturePack> CompileAsync(
        SignaturePackManifest manifest,
        IReadOnlyCollection<SignatureRuleDefinition> rules,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var compiledRules = rules
            .Select(rule => new CompiledSignatureRule
            {
                RuleId = $"sig-{rule.Id}",
                RuleName = rule.RuleName,
                RuleKind = InferKind(rule.Pattern),
                Pattern = NormalizePattern(rule.Pattern),
                Severity = rule.Severity
            })
            .ToArray();

        var serializedModel = new
        {
            manifest.Version,
            ParserCompatibilityVersion = _options.ParserCompatibilityVersion,
            SignatureCompilerVersion = _options.SignatureCompilerVersion,
            Rules = compiledRules.Select(rule => new
            {
                rule.RuleId,
                rule.RuleName,
                RuleKind = rule.RuleKind.ToString(),
                rule.Pattern,
                Severity = rule.Severity.ToString()
            })
        };

        var serializedBytes = JsonSerializer.SerializeToUtf8Bytes(
            serializedModel,
            new JsonSerializerOptions { WriteIndented = true });

        var sha256 = Convert.ToHexString(SHA256.HashData(serializedBytes));

        return Task.FromResult(new ProprietarySignaturePack
        {
            Manifest = manifest,
            ParserCompatibilityVersion = _options.ParserCompatibilityVersion,
            SigningMetadata = $"sha256:{sha256};compiler:{_options.SignatureCompilerVersion}",
            Rules = compiledRules,
            SerializedBytes = serializedBytes
        });
    }

    private static SignatureRuleKind InferKind(string? pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern))
        {
            return SignatureRuleKind.ContentLiteral;
        }

        var normalized = pattern.Trim();
        if (normalized.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase))
        {
            return SignatureRuleKind.Hash;
        }

        if (normalized.StartsWith("name:", StringComparison.OrdinalIgnoreCase))
        {
            return SignatureRuleKind.FileName;
        }

        if (normalized.StartsWith("path:", StringComparison.OrdinalIgnoreCase))
        {
            return SignatureRuleKind.PathFragment;
        }

        if (normalized.StartsWith("content:", StringComparison.OrdinalIgnoreCase))
        {
            return SignatureRuleKind.ContentLiteral;
        }

        if (normalized.StartsWith("pe:", StringComparison.OrdinalIgnoreCase))
        {
            return SignatureRuleKind.PeMetadata;
        }

        if (normalized.StartsWith("elf:", StringComparison.OrdinalIgnoreCase))
        {
            return SignatureRuleKind.ElfMetadata;
        }

        if (normalized.StartsWith("archive:", StringComparison.OrdinalIgnoreCase))
        {
            return SignatureRuleKind.ArchiveMemberName;
        }

        if (normalized.StartsWith("doc:", StringComparison.OrdinalIgnoreCase))
        {
            return SignatureRuleKind.DocumentMetadata;
        }

        return SignatureRuleKind.ContentLiteral;
    }

    private static string NormalizePattern(string? pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern))
        {
            return string.Empty;
        }

        var normalized = pattern.Trim();
        var separatorIndex = normalized.IndexOf(':');
        if (separatorIndex > 0)
        {
            return normalized[(separatorIndex + 1)..].Trim();
        }

        return normalized;
    }
}
