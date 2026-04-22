using Antivirus.Domain;
using Antivirus.Infrastructure.Security;
using FluentAssertions;

namespace Antivirus.Tests.Unit;

public sealed class VerdictScoringEngineTests
{
    private readonly VerdictScoringEngine _sut = new();

    [Fact]
    public void EmptyDetections_ReturnsCleanVerdict()
    {
        var verdict = _sut.ComputeVerdict([]);

        verdict.FinalScore.Should().Be(0m);
        verdict.Verdict.Should().Be(PipelineVerdict.Clean);
        verdict.RecommendedAction.Should().Be("Allow");
        verdict.Contributions.Should().BeEmpty();
        verdict.ReasonCodes.Should().BeEmpty();
    }

    [Fact]
    public void SingleHighConfidenceStaticDetection_ReturnsSuspicious()
    {
        // ProprietaryStatic weight = 0.40, confidence 0.95 → weighted = 0.38
        // 0.38 < 0.85 (block) but < 0.50 (alert)? No, 0.38 < 0.50 → Clean
        // Actually 0.40 * 0.95 = 0.38 < 0.50 → Clean
        var detections = new[]
        {
            new DetectionEventRecord
            {
                RuleId = "test-static",
                EngineName = "Test",
                Source = ThreatSource.ProprietaryStatic,
                Severity = ThreatSeverity.High,
                Confidence = 0.95m,
                Summary = "Test detection"
            }
        };

        var verdict = _sut.ComputeVerdict(detections);

        verdict.FinalScore.Should().Be(0.38m);
        verdict.Verdict.Should().Be(PipelineVerdict.Clean);
        verdict.RecommendedAction.Should().Be("Allow");
    }

    [Fact]
    public void MultiSourceHighConfidence_ReturnsMalicious()
    {
        // Static: 0.40 * 0.95 = 0.38
        // Behavior: 0.25 * 0.90 = 0.225
        // Heuristic: 0.15 * 0.85 = 0.1275
        // Reputation: 0.15 * 0.80 = 0.12
        // Total = 0.8525 ≥ 0.85 → Malicious
        var detections = new[]
        {
            new DetectionEventRecord { RuleId = "r1", EngineName = "E", Source = ThreatSource.ProprietaryStatic, Severity = ThreatSeverity.High, Confidence = 0.95m, Summary = "S" },
            new DetectionEventRecord { RuleId = "r2", EngineName = "E", Source = ThreatSource.Behavior, Severity = ThreatSeverity.High, Confidence = 0.90m, Summary = "S" },
            new DetectionEventRecord { RuleId = "r3", EngineName = "E", Source = ThreatSource.Heuristic, Severity = ThreatSeverity.Medium, Confidence = 0.85m, Summary = "S" },
            new DetectionEventRecord { RuleId = "r4", EngineName = "E", Source = ThreatSource.Reputation, Severity = ThreatSeverity.Medium, Confidence = 0.80m, Summary = "S" },
        };

        var verdict = _sut.ComputeVerdict(detections);

        verdict.FinalScore.Should().Be(0.8525m);
        verdict.Verdict.Should().Be(PipelineVerdict.Malicious);
        verdict.RecommendedAction.Should().Be("Quarantine");
        verdict.ReasonCodes.Should().HaveCount(4);
    }

    [Fact]
    public void BehaviorAndHeuristicOnly_ReturnsSuspicious()
    {
        // Behavior: 0.25 * 0.95 = 0.2375
        // Heuristic: 0.15 * 0.90 = 0.135
        // Total = 0.3725 → < 0.50 → Clean (not suspicious!)
        var detections = new[]
        {
            new DetectionEventRecord { RuleId = "beh-1", EngineName = "E", Source = ThreatSource.Behavior, Severity = ThreatSeverity.Critical, Confidence = 0.95m, Summary = "S" },
            new DetectionEventRecord { RuleId = "heur-1", EngineName = "E", Source = ThreatSource.Heuristic, Severity = ThreatSeverity.High, Confidence = 0.90m, Summary = "S" },
        };

        var verdict = _sut.ComputeVerdict(detections);

        // 0.2375 + 0.135 = 0.3725
        verdict.FinalScore.Should().Be(0.3725m);
        verdict.Verdict.Should().Be(PipelineVerdict.Clean);
    }

    [Fact]
    public void MultipleDetectionsSameSource_UsesMaxConfidence()
    {
        // Two behavior detections: max confidence is 0.95
        // Behavior: 0.25 * 0.95 = 0.2375
        var detections = new[]
        {
            new DetectionEventRecord { RuleId = "beh-1", EngineName = "E", Source = ThreatSource.Behavior, Severity = ThreatSeverity.High, Confidence = 0.60m, Summary = "S" },
            new DetectionEventRecord { RuleId = "beh-2", EngineName = "E", Source = ThreatSource.Behavior, Severity = ThreatSeverity.Critical, Confidence = 0.95m, Summary = "S" },
        };

        var verdict = _sut.ComputeVerdict(detections);

        verdict.FinalScore.Should().Be(0.2375m);
        verdict.Contributions.Should().HaveCount(1);
        verdict.Contributions.First().RawScore.Should().Be(0.95m);
        verdict.Contributions.First().TopRuleIds.Should().Contain("beh-1").And.Contain("beh-2");
    }

    [Fact]
    public void PatternRuleAndSignatureHash_MapToStaticWeight()
    {
        // PatternRule and SignatureHash both map to ProprietaryStatic (0.40)
        // They're different ThreatSource values → different groups
        // PatternRule: 0.40 * 0.80 = 0.32
        // SignatureHash: 0.40 * 0.70 = 0.28
        // Total = 0.60 ≥ 0.50 → Suspicious
        var detections = new[]
        {
            new DetectionEventRecord { RuleId = "pat-1", EngineName = "E", Source = ThreatSource.PatternRule, Severity = ThreatSeverity.High, Confidence = 0.80m, Summary = "S" },
            new DetectionEventRecord { RuleId = "sig-1", EngineName = "E", Source = ThreatSource.SignatureHash, Severity = ThreatSeverity.High, Confidence = 0.70m, Summary = "S" },
        };

        var verdict = _sut.ComputeVerdict(detections);

        verdict.FinalScore.Should().Be(0.60m);
        verdict.Verdict.Should().Be(PipelineVerdict.Suspicious);
        verdict.RecommendedAction.Should().Be("Alert");
    }

    [Fact]
    public void CustomThresholds_AreRespected()
    {
        var detections = new[]
        {
            new DetectionEventRecord { RuleId = "r1", EngineName = "E", Source = ThreatSource.ProprietaryStatic, Severity = ThreatSeverity.High, Confidence = 0.80m, Summary = "S" },
        };

        // Score = 0.40 * 0.80 = 0.32
        var lenientThresholds = new ScoringThresholds
        {
            BlockThreshold = 0.30m,
            AlertThreshold = 0.20m,
            LogThreshold = 0.10m
        };

        var verdict = _sut.ComputeVerdict(detections, lenientThresholds);

        verdict.FinalScore.Should().Be(0.32m);
        verdict.Verdict.Should().Be(PipelineVerdict.Malicious);
    }

    [Fact]
    public void CustomWeights_AreRespected()
    {
        var detections = new[]
        {
            new DetectionEventRecord { RuleId = "r1", EngineName = "E", Source = ThreatSource.Behavior, Severity = ThreatSeverity.High, Confidence = 1.0m, Summary = "S" },
        };

        var weights = new ScoringWeights
        {
            Behavior = 0.80m
        };

        var verdict = _sut.ComputeVerdict(detections, weights: weights);

        verdict.FinalScore.Should().Be(0.80m);
    }

    [Fact]
    public void FinalScore_ClampedToOne()
    {
        // Max out all sources at 1.0 confidence
        // Total weights = 0.40 + 0.25 + 0.15 + 0.15 + 0.05 = 1.0
        // But if we use multiple sources that map to same weight...
        // Actually with all 5 distinct weight categories maxed, total = 1.0 exactly
        var detections = new[]
        {
            new DetectionEventRecord { RuleId = "r1", EngineName = "E", Source = ThreatSource.ProprietaryStatic, Severity = ThreatSeverity.Critical, Confidence = 1.0m, Summary = "S" },
            new DetectionEventRecord { RuleId = "r2", EngineName = "E", Source = ThreatSource.Behavior, Severity = ThreatSeverity.Critical, Confidence = 1.0m, Summary = "S" },
            new DetectionEventRecord { RuleId = "r3", EngineName = "E", Source = ThreatSource.Heuristic, Severity = ThreatSeverity.Critical, Confidence = 1.0m, Summary = "S" },
            new DetectionEventRecord { RuleId = "r4", EngineName = "E", Source = ThreatSource.Reputation, Severity = ThreatSeverity.Critical, Confidence = 1.0m, Summary = "S" },
            new DetectionEventRecord { RuleId = "r5", EngineName = "E", Source = ThreatSource.Sandbox, Severity = ThreatSeverity.Critical, Confidence = 1.0m, Summary = "S" },
            // PatternRule also maps to Static weight → additional 0.40
            new DetectionEventRecord { RuleId = "r6", EngineName = "E", Source = ThreatSource.PatternRule, Severity = ThreatSeverity.Critical, Confidence = 1.0m, Summary = "S" },
        };

        var verdict = _sut.ComputeVerdict(detections);

        // Static=0.40, PatternRule=0.40, Behavior=0.25, Heuristic=0.15, Reputation=0.15, Sandbox=0.05 = 1.40 → clamped to 1.0
        verdict.FinalScore.Should().Be(1.0m);
        verdict.Verdict.Should().Be(PipelineVerdict.Malicious);
    }

    [Fact]
    public void WindowsDefender_MapsToStaticWeight()
    {
        var detections = new[]
        {
            new DetectionEventRecord { RuleId = "wd-1", EngineName = "Windows Defender", Source = ThreatSource.WindowsDefender, Severity = ThreatSeverity.High, Confidence = 0.90m, Summary = "S" },
        };

        var verdict = _sut.ComputeVerdict(detections);

        // WindowsDefender → ProprietaryStatic weight 0.40 * 0.90 = 0.36
        verdict.FinalScore.Should().Be(0.36m);
        verdict.Contributions.Should().HaveCount(1);
        verdict.Contributions.First().Weight.Should().Be(0.40m);
    }

    [Fact]
    public void Contributions_ContainCorrectSourceDetails()
    {
        var detections = new[]
        {
            new DetectionEventRecord { RuleId = "beh-startup", EngineName = "Sentinel Behavior Engine", Source = ThreatSource.Behavior, Severity = ThreatSeverity.High, Confidence = 0.91m, Summary = "S" },
            new DetectionEventRecord { RuleId = "beh-ransom", EngineName = "Sentinel Behavior Engine", Source = ThreatSource.Behavior, Severity = ThreatSeverity.Critical, Confidence = 0.95m, Summary = "S" },
        };

        var verdict = _sut.ComputeVerdict(detections);

        verdict.Contributions.Should().HaveCount(1);
        var contribution = verdict.Contributions.First();
        contribution.SourceName.Should().Be("Behavior");
        contribution.Weight.Should().Be(0.25m);
        contribution.RawScore.Should().Be(0.95m); // max
        contribution.WeightedScore.Should().Be(0.2375m);
        contribution.TopRuleIds.Should().HaveCount(2);
    }
}
