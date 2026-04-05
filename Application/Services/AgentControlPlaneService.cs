using Antivirus.Application.Contracts;
using Antivirus.Domain;

namespace Antivirus.Application.Services;

public sealed class AgentControlPlaneService : IAgentControlPlaneService
{
    private readonly ITenantRegistry _tenantRegistry;
    private readonly IControlPlaneRepository _controlPlaneRepository;

    public AgentControlPlaneService(ITenantRegistry tenantRegistry, IControlPlaneRepository controlPlaneRepository)
    {
        _tenantRegistry = tenantRegistry;
        _controlPlaneRepository = controlPlaneRepository;
    }

    public async Task<AgentRegistrationResponse> RegisterAsync(AgentRegistrationRequest request, CancellationToken cancellationToken = default)
    {
        var tenant = await _tenantRegistry.GetCurrentTenantAsync(cancellationToken);
        var device = await _controlPlaneRepository.UpsertDeviceAsync(request, cancellationToken);
        var policy = await _controlPlaneRepository.GetActivePolicyAsync(cancellationToken);
        var pack = await _controlPlaneRepository.GetCurrentSignaturePackAsync(cancellationToken);

        return new AgentRegistrationResponse
        {
            TenantKey = tenant.TenantKey,
            Device = device,
            Policy = policy,
            SignaturePack = pack
        };
    }

    public async Task<AgentHeartbeatResponse> HeartbeatAsync(AgentHeartbeatRequest request, CancellationToken cancellationToken = default)
    {
        await _controlPlaneRepository.SaveHeartbeatAsync(request, cancellationToken);
        var policy = await _controlPlaneRepository.GetActivePolicyAsync(cancellationToken);
        var pack = await _controlPlaneRepository.GetCurrentSignaturePackAsync(cancellationToken);

        return new AgentHeartbeatResponse
        {
            Policy = policy,
            SignaturePack = pack,
            PolicyChanged = !string.Equals(policy.Version, request.PolicyVersion, StringComparison.OrdinalIgnoreCase),
            PackChanged = !string.Equals(pack.Version, request.SignaturePackVersion, StringComparison.OrdinalIgnoreCase)
        };
    }
}
