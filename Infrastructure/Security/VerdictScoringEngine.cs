using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security;

public sealed class VerdictScoringEngine : IVerdictScoringEngine
{
    public DetectionVerdict ComputeVerdict(
        IReadOnlyCollection<DetectionEventRecord> detectionEvents,
        ScoringThresholds? thresholds = null,
        ScoringWeights? weights = null)
    {
        thresholds ??= new ScoringThresholds();
        weights ??= new ScoringWeights();

        if (detectionEvents.Count == 0)
        {
            return new DetectionVerdict
            {
                FinalScore = 0m,
                Verdict = PipelineVerdict.Clean,
                RecommendedAction = "Allow",
                Contributions = [],
                ReasonCodes = []
            };
        }

        var sourceGroups = detectionEvents.GroupBy(d => d.Source);
        var contributions = new List<SourceContribution>();
        var allReasonCodes = new HashSet<string>();

        foreach (var group in sourceGroups)
        {
            var weight = GetWeight(group.Key, weights);
            var rawScore = group.Max(d => d.Confidence);
            var weightedScore = weight * rawScore;
            var ruleIds = group.Select(d => d.RuleId).Where(r => !string.IsNullOrEmpty(r)).Distinct().ToArray();

            foreach (var ruleId in ruleIds)
            {
                allReasonCodes.Add(ruleId);
            }

            contributions.Add(new SourceContribution
            {
                SourceName = group.Key.ToString(),
                Weight = weight,
                RawScore = rawScore,
                WeightedScore = weightedScore,
                TopRuleIds = ruleIds
            });
        }

        var finalScore = Math.Clamp(contributions.Sum(c => c.WeightedScore), 0m, 1m);

        var verdict = finalScore >= thresholds.BlockThreshold
            ? PipelineVerdict.Malicious
            : finalScore >= thresholds.AlertThreshold
                ? PipelineVerdict.Suspicious
                : PipelineVerdict.Clean;

        var recommendedAction = verdict switch
        {
            PipelineVerdict.Malicious => "Quarantine",
            PipelineVerdict.Suspicious => "Alert",
            _ => "Allow"
        };

        return new DetectionVerdict
        {
            FinalScore = finalScore,
            Verdict = verdict,
            RecommendedAction = recommendedAction,
            Contributions = contributions,
            ReasonCodes = allReasonCodes.ToArray()
        };
    }

    private static decimal GetWeight(ThreatSource source, ScoringWeights weights) => source switch
    {
        ThreatSource.ProprietaryStatic => weights.ProprietaryStatic,
        ThreatSource.PatternRule => weights.ProprietaryStatic,
        ThreatSource.SignatureHash => weights.ProprietaryStatic,
        ThreatSource.Heuristic => weights.Heuristic,
        ThreatSource.Behavior => weights.Behavior,
        ThreatSource.Reputation => weights.Reputation,
        ThreatSource.Sandbox => weights.Sandbox,
        ThreatSource.WindowsDefender => weights.ProprietaryStatic,
        _ => weights.ProprietaryStatic
    };
}
