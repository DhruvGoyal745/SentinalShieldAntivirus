using Antivirus.Application.Contracts;

namespace Antivirus.Middleware;

public sealed class TenantResolutionMiddleware
{
    private readonly RequestDelegate _next;

    public TenantResolutionMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, ITenantContextAccessor tenantContextAccessor)
    {
        var tenantKey = context.Request.Headers["X-Tenant-Key"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(tenantKey))
        {
            tenantKey = context.Request.Query["tenant"].FirstOrDefault();
        }

        tenantContextAccessor.CurrentTenantKey = tenantKey;

        try
        {
            await _next(context);
        }
        finally
        {
            tenantContextAccessor.CurrentTenantKey = null;
        }
    }
}
