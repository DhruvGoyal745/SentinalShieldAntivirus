using Antivirus.Application.Contracts;
using Antivirus.Domain;
using Microsoft.AspNetCore.Mvc;

namespace Antivirus.Controllers;

[ApiController]
[Route("api/agent")]
public sealed class AgentsController : ControllerBase
{
    private readonly IAgentControlPlaneService _agentControlPlaneService;
    private readonly IControlPlaneRepository _controlPlaneRepository;

    public AgentsController(IAgentControlPlaneService agentControlPlaneService, IControlPlaneRepository controlPlaneRepository)
    {
        _agentControlPlaneService = agentControlPlaneService;
        _controlPlaneRepository = controlPlaneRepository;
    }

    [HttpPost("register")]
    public async Task<ActionResult<AgentRegistrationResponse>> Register([FromBody] AgentRegistrationRequest request, CancellationToken cancellationToken)
    {
        return Ok(await _agentControlPlaneService.RegisterAsync(request, cancellationToken));
    }

    [HttpPost("heartbeat")]
    public async Task<ActionResult<AgentHeartbeatResponse>> Heartbeat([FromBody] AgentHeartbeatRequest request, CancellationToken cancellationToken)
    {
        return Ok(await _agentControlPlaneService.HeartbeatAsync(request, cancellationToken));
    }

    [HttpGet("policy")]
    public async Task<ActionResult<DevicePolicyBundle>> GetPolicy(CancellationToken cancellationToken)
    {
        return Ok(await _controlPlaneRepository.GetActivePolicyAsync(cancellationToken));
    }

    [HttpGet("pack")]
    public async Task<ActionResult<SignaturePackManifest>> GetPack(CancellationToken cancellationToken)
    {
        return Ok(await _controlPlaneRepository.GetCurrentSignaturePackAsync(cancellationToken));
    }
}
