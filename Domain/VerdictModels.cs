namespace Antivirus.Domain;

/// <summary>
/// Composite verdict produced by the scoring engine from all detection sources.
/// </summary>
public sealed class DetectionVerdict
{
    public decimal FinalScore { get; init; }

    public PipelineVerdict Verdict { get; init; }

    public string RecommendedAction { get; init; } = "Allow"; // Allow, Alert, Block, Quarantine

    public IReadOnlyCollection<SourceContribution> Contributions { get; init; } = [];

    public IReadOnlyCollection<string> ReasonCodes { get; init; } = [];
}

public sealed class SourceContribution
{
    public string SourceName { get; init; } = string.Empty;

    public decimal Weight { get; init; }

    public decimal RawScore { get; init; }

    public decimal WeightedScore { get; init; }

    public IReadOnlyCollection<string> TopRuleIds { get; init; } = [];
}

public sealed class ScoringThresholds
{
    public decimal BlockThreshold { get; init; } = 0.85m;

    public decimal AlertThreshold { get; init; } = 0.50m;

    public decimal LogThreshold { get; init; } = 0.20m;
}

public sealed class ScoringWeights
{
    public decimal ProprietaryStatic { get; init; } = 0.40m;

    public decimal Heuristic { get; init; } = 0.15m;

    public decimal Behavior { get; init; } = 0.25m;

    public decimal Reputation { get; init; } = 0.15m;

    public decimal Sandbox { get; init; } = 0.05m;
}
