using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.StaticAnalysis;

public sealed class StaticRuleEvaluator : IStaticRuleEvaluator
{
    public IReadOnlyCollection<DetectionEventRecord> Evaluate(
        StaticScanArtifact artifact,
        IReadOnlyCollection<CompiledSignatureRule> rules)
    {
        var detections = new List<DetectionEventRecord>();
        foreach (var rule in rules)
        {
            if (!Matches(rule, artifact))
            {
                continue;
            }

            detections.Add(new DetectionEventRecord
            {
                RuleId = rule.RuleId,
                EngineName = "Sentinel Clean-Room Static Engine",
                Source = ThreatSource.ProprietaryStatic,
                Severity = rule.Severity,
                Confidence = rule.Severity is ThreatSeverity.High or ThreatSeverity.Critical ? 0.96m : 0.74m,
                Summary = $"Matched proprietary {rule.RuleKind} rule '{rule.RuleName}'."
            });
        }

        return detections;
    }

    private static bool Matches(CompiledSignatureRule rule, StaticScanArtifact artifact)
    {
        return rule.RuleKind switch
        {
            SignatureRuleKind.Hash => string.Equals(artifact.HashSha256, rule.Pattern, StringComparison.OrdinalIgnoreCase),
            SignatureRuleKind.FileName => artifact.File.Name.Contains(rule.Pattern, StringComparison.OrdinalIgnoreCase),
            SignatureRuleKind.PathFragment => artifact.File.FullName.Contains(rule.Pattern, StringComparison.OrdinalIgnoreCase),
            SignatureRuleKind.ContentLiteral => !string.IsNullOrWhiteSpace(artifact.TextContent)
                && artifact.TextContent.Contains(rule.Pattern, StringComparison.OrdinalIgnoreCase),
            SignatureRuleKind.PeMetadata => artifact.Classification == "PE" && MatchesMetadataPattern(artifact, "pe", rule.Pattern),
            SignatureRuleKind.ElfMetadata => artifact.Classification == "ELF" && MatchesMetadataPattern(artifact, "elf", rule.Pattern),
            SignatureRuleKind.ArchiveMemberName => artifact.Classification == "ARCHIVE" && MatchesArchivePattern(artifact, rule.Pattern),
            SignatureRuleKind.DocumentMetadata => artifact.Classification == "DOCUMENT" && MatchesDocumentPattern(artifact, rule.Pattern),
            _ => false
        };
    }

    private static bool MatchesMetadataPattern(StaticScanArtifact artifact, string prefix, string pattern)
    {
        if (TrySplitPattern(pattern, out var key, out var value))
        {
            var namespacedKey = key.StartsWith($"{prefix}.", StringComparison.OrdinalIgnoreCase)
                ? key
                : $"{prefix}.{key}";

            if (namespacedKey.EndsWith(".section", StringComparison.OrdinalIgnoreCase))
            {
                return artifact.Sections.Any(section => section.Contains(value, StringComparison.OrdinalIgnoreCase));
            }

            return artifact.Properties.TryGetValue(namespacedKey, out var propertyValue)
                && propertyValue.Contains(value, StringComparison.OrdinalIgnoreCase);
        }

        return artifact.File.Name.Contains(pattern, StringComparison.OrdinalIgnoreCase)
            || artifact.Properties.Any(property => property.Key.StartsWith($"{prefix}.", StringComparison.OrdinalIgnoreCase)
                && property.Value.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            || artifact.Sections.Any(section => section.Contains(pattern, StringComparison.OrdinalIgnoreCase));
    }

    private static bool MatchesArchivePattern(StaticScanArtifact artifact, string pattern)
    {
        if (TrySplitPattern(pattern, out var key, out var value))
        {
            return key.ToLowerInvariant() switch
            {
                "member" => artifact.ArchiveEntries.Any(entry => entry.Contains(value, StringComparison.OrdinalIgnoreCase)),
                "type" => artifact.Properties.TryGetValue("archive.type", out var archiveType)
                    && archiveType.Contains(value, StringComparison.OrdinalIgnoreCase),
                _ => false
            };
        }

        return artifact.ArchiveEntries.Any(entry => entry.Contains(pattern, StringComparison.OrdinalIgnoreCase));
    }

    private static bool MatchesDocumentPattern(StaticScanArtifact artifact, string pattern)
    {
        if (TrySplitPattern(pattern, out var key, out var value))
        {
            var namespacedKey = key.StartsWith("doc.", StringComparison.OrdinalIgnoreCase)
                ? key
                : $"doc.{key}";

            return artifact.Properties.TryGetValue(namespacedKey, out var propertyValue)
                && propertyValue.Contains(value, StringComparison.OrdinalIgnoreCase);
        }

        return artifact.Properties.Any(property =>
                   property.Key.StartsWith("doc.", StringComparison.OrdinalIgnoreCase)
                   && property.Value.Contains(pattern, StringComparison.OrdinalIgnoreCase))
               || artifact.File.Name.Contains(pattern, StringComparison.OrdinalIgnoreCase);
    }

    private static bool TrySplitPattern(string pattern, out string key, out string value)
    {
        var separatorIndex = pattern.IndexOf('=');
        if (separatorIndex <= 0 || separatorIndex == pattern.Length - 1)
        {
            key = string.Empty;
            value = string.Empty;
            return false;
        }

        key = pattern[..separatorIndex].Trim();
        value = pattern[(separatorIndex + 1)..].Trim();
        return !string.IsNullOrWhiteSpace(key) && !string.IsNullOrWhiteSpace(value);
    }
}
