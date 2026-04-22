using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
using Microsoft.Extensions.Options;

namespace Antivirus.Infrastructure.Security;

public sealed class SandboxSubmissionClient : ISandboxSubmissionClient
{
    private readonly IGovernanceRepository _governanceRepository;
    private readonly AntivirusPlatformOptions _options;

    public SandboxSubmissionClient(IGovernanceRepository governanceRepository, IOptions<AntivirusPlatformOptions> options)
    {
        _governanceRepository = governanceRepository;
        _options = options.Value;
    }

    public async Task<SandboxSubmission?> SubmitIfNeededAsync(
        int? scanJobId,
        string deviceId,
        FileInfo file,
        string hashSha256,
        PipelineVerdict verdict,
        IReadOnlyCollection<DetectionEventRecord> detections,
        CancellationToken cancellationToken = default)
    {
        if (!_options.SandboxEnabled || verdict == PipelineVerdict.Clean)
        {
            return null;
        }

        var requiresSandbox = verdict == PipelineVerdict.Suspicious
            || detections.Any(detection => detection.Confidence < 0.95m);

        if (!requiresSandbox)
        {
            return null;
        }

        var submission = new SandboxSubmission
        {
            ScanJobId = scanJobId,
            DeviceId = deviceId,
            ArtifactHash = hashSha256,
            FileName = file.Name,
            Status = SandboxSubmissionStatus.Submitted,
            CorrelationId = Guid.NewGuid().ToString("N"),
            Verdict = verdict == PipelineVerdict.Malicious ? SandboxVerdict.Suspicious : SandboxVerdict.Unknown,
            BehaviorSummary = "Vendor detonation requested from enterprise sandbox integration.",
            IndicatorsJson = "[]",
            FamilyName = string.Empty,
            TagsJson = "[]",
            CreatedAt = DateTimeOffset.UtcNow
        };

        return await _governanceRepository.CreateSandboxSubmissionAsync(submission, cancellationToken);
    }
}
