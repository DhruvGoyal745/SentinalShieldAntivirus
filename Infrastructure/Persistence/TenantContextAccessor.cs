using System.Threading;
using Antivirus.Application.Contracts;

namespace Antivirus.Infrastructure.Persistence;

public sealed class TenantContextAccessor : ITenantContextAccessor
{
    private static readonly AsyncLocal<string?> CurrentTenant = new();

    public string? CurrentTenantKey
    {
        get => CurrentTenant.Value;
        set => CurrentTenant.Value = value;
    }
}
