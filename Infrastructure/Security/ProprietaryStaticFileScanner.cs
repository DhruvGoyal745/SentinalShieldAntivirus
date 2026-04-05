using Antivirus.Application.Contracts;
using Antivirus.Domain;
using Antivirus.Infrastructure.Security.StaticAnalysis;

namespace Antivirus.Infrastructure.Security;

public sealed class ProprietaryStaticFileScanner : IStaticFileScanner
{
    private readonly ISignaturePackProvider _signaturePackProvider;
    private readonly IReadOnlyCollection<IStaticArtifactEnricher> _artifactEnrichers;
    private readonly IStaticRuleEvaluator _staticRuleEvaluator;

    public ProprietaryStaticFileScanner(
        ISignaturePackProvider signaturePackProvider,
        IEnumerable<IStaticArtifactEnricher> artifactEnrichers,
        IStaticRuleEvaluator staticRuleEvaluator)
    {
        _signaturePackProvider = signaturePackProvider;
        _artifactEnrichers = artifactEnrichers.ToArray();
        _staticRuleEvaluator = staticRuleEvaluator;
    }

    public async Task<IReadOnlyCollection<DetectionEventRecord>> ScanAsync(
        FileInfo file,
        string hashSha256,
        CancellationToken cancellationToken = default)
    {
        var artifact = new StaticScanArtifact(file, hashSha256);
        var pack = await _signaturePackProvider.GetCompiledPackAsync(cancellationToken);
        var detections = new List<DetectionEventRecord>();

        foreach (var enricher in _artifactEnrichers)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var enrichedDetections = await enricher.EnrichAsync(artifact, cancellationToken);
            detections.AddRange(enrichedDetections);
        }

        detections.AddRange(_staticRuleEvaluator.Evaluate(artifact, pack.Rules));
        return detections
            .GroupBy(detection => new { detection.RuleId, detection.EngineName, detection.Summary })
            .Select(group => group.First())
            .ToArray();
    }
}
