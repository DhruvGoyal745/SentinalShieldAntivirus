using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security.StaticAnalysis;

public interface IStaticRuleEvaluator
{
    IReadOnlyCollection<DetectionEventRecord> Evaluate(
        StaticScanArtifact artifact,
        IReadOnlyCollection<CompiledSignatureRule> rules);
}
