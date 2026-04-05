using Antivirus.Application.Contracts;
using Antivirus.Domain;
using Microsoft.AspNetCore.Mvc;

namespace Antivirus.Controllers;

[ApiController]
[Route("api/governance")]
public sealed class GovernanceController : ControllerBase
{
    private readonly IControlPlaneRepository _controlPlaneRepository;

    public GovernanceController(IControlPlaneRepository controlPlaneRepository)
    {
        _controlPlaneRepository = controlPlaneRepository;
    }

    [HttpGet("parity")]
    public async Task<ActionResult<IReadOnlyCollection<LegacyParitySnapshot>>> GetParity(CancellationToken cancellationToken)
    {
        return Ok(await _controlPlaneRepository.GetLegacyParitySnapshotsAsync(cancellationToken));
    }

    [HttpGet("sandbox")]
    public async Task<ActionResult<IReadOnlyCollection<SandboxSubmission>>> GetSandbox(CancellationToken cancellationToken)
    {
        return Ok(await _controlPlaneRepository.GetSandboxSubmissionsAsync(cancellationToken));
    }

    [HttpGet("reviews")]
    public async Task<ActionResult<IReadOnlyCollection<FalsePositiveReview>>> GetReviews(CancellationToken cancellationToken)
    {
        return Ok(await _controlPlaneRepository.GetFalsePositiveReviewsAsync(cancellationToken));
    }

    [HttpPost("reviews")]
    public async Task<ActionResult<FalsePositiveReview>> SubmitReview([FromBody] FalsePositiveReview review, CancellationToken cancellationToken)
    {
        var request = new FalsePositiveReview
        {
            ThreatDetectionId = review.ThreatDetectionId,
            ArtifactHash = review.ArtifactHash,
            RuleId = review.RuleId,
            Scope = review.Scope,
            Status = FalsePositiveReviewStatus.Submitted,
            Analyst = string.IsNullOrWhiteSpace(review.Analyst) ? "analyst-console" : review.Analyst,
            Notes = review.Notes,
            SubmittedAt = DateTimeOffset.UtcNow
        };

        return Ok(await _controlPlaneRepository.CreateFalsePositiveReviewAsync(request, cancellationToken));
    }
}
