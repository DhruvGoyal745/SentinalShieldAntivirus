using Antivirus.Application.Contracts;
using Antivirus.Domain;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Antivirus.Controllers;

[ApiController]
[Route("api/governance")]
[Authorize]
public sealed class GovernanceController : ControllerBase
{
    private readonly IGovernanceRepository _governanceRepository;

    public GovernanceController(IGovernanceRepository governanceRepository)
    {
        _governanceRepository = governanceRepository;
    }

    [HttpGet("sandbox")]
    public async Task<ActionResult<IReadOnlyCollection<SandboxSubmission>>> GetSandbox(CancellationToken cancellationToken)
    {
        return Ok(await _governanceRepository.GetSandboxSubmissionsAsync(cancellationToken));
    }

    [HttpGet("reviews")]
    public async Task<ActionResult<IReadOnlyCollection<FalsePositiveReview>>> GetReviews(CancellationToken cancellationToken)
    {
        return Ok(await _governanceRepository.GetFalsePositiveReviewsAsync(cancellationToken));
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

        return Ok(await _governanceRepository.CreateFalsePositiveReviewAsync(request, cancellationToken));
    }

    [HttpPost("reviews/{id:int}/decision")]
    public async Task<ActionResult<FalsePositiveReview>> DecideReview(int id, [FromBody] ReviewDecisionRequest request, CancellationToken cancellationToken)
    {
        if (request.Status is not FalsePositiveReviewStatus.Approved and not FalsePositiveReviewStatus.Rejected)
        {
            return BadRequest(new ValidationProblemDetails(new Dictionary<string, string[]>
            {
                ["status"] = ["Only Approved or Rejected decisions are supported."]
            }));
        }

        var review = await _governanceRepository.DecideFalsePositiveReviewAsync(
            id,
            request.Status,
            string.IsNullOrWhiteSpace(request.Analyst) ? "analyst-console" : request.Analyst,
            request.Notes,
            cancellationToken);

        return review is null ? NotFound() : Ok(review);
    }
}

public sealed class ReviewDecisionRequest
{
    public FalsePositiveReviewStatus Status { get; init; }

    public string Analyst { get; init; } = string.Empty;

    public string? Notes { get; init; }
}
