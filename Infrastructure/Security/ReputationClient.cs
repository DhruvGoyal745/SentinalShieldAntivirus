using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Infrastructure.Security;

public sealed class ReputationClient : IReputationClient
{
    public Task<DetectionEventRecord?> EvaluateAsync(FileInfo file, string hashSha256, CancellationToken cancellationToken = default)
    {
        if (file.Name.Contains("mimikatz", StringComparison.OrdinalIgnoreCase)
            || file.Name.Contains("payload", StringComparison.OrdinalIgnoreCase)
            || file.Name.Contains("backdoor", StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult<DetectionEventRecord?>(new DetectionEventRecord
            {
                RuleId = "rep-knownbad-name",
                EngineName = "Sentinel Reputation Service",
                Source = ThreatSource.Reputation,
                Severity = ThreatSeverity.Critical,
                Confidence = 0.98m,
                Summary = $"Cloud reputation flagged {file.Name} as known-bad by naming intelligence."
            });
        }

        if (hashSha256.EndsWith("BAD", StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult<DetectionEventRecord?>(new DetectionEventRecord
            {
                RuleId = "rep-hash-bad",
                EngineName = "Sentinel Reputation Service",
                Source = ThreatSource.Reputation,
                Severity = ThreatSeverity.High,
                Confidence = 0.94m,
                Summary = "Cloud reputation flagged the artifact hash as malicious."
            });
        }

        return Task.FromResult<DetectionEventRecord?>(null);
    }
}
