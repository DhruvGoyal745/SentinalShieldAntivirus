using Antivirus.Infrastructure.Platform;

namespace Antivirus.Middleware;

/// <summary>
/// Validates the X-Local-Token header on sensitive service-control endpoints.
/// Only the Tray and Desktop apps (which received the token at startup) can call
/// pause/resume/scan endpoints. Public read-only endpoints (dashboard, health) are exempt.
/// </summary>
public sealed class LocalTrustMiddleware
{
    private readonly RequestDelegate _next;

    private static readonly HashSet<string> ProtectedPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "/api/service/",
    };

    /// <summary>
    /// Read-only endpoints under a protected prefix that do NOT require a local trust token.
    /// These must be safe to call without authentication (health probes, status checks).
    /// </summary>
    private static readonly HashSet<string> ExemptPaths = new(StringComparer.OrdinalIgnoreCase)
    {
        "/api/service/status",
        "/api/service/local-token",
    };

    public LocalTrustMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, ILocalTrustBoundary trustBoundary)
    {
        var path = context.Request.Path.Value ?? string.Empty;
        var isProtected = false;
        foreach (var prefix in ProtectedPrefixes)
        {
            if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                isProtected = true;
                break;
            }
        }

        if (isProtected)
        {
            // Allow read-only health/status endpoints without a trust token
            if (ExemptPaths.Contains(path))
            {
                await _next(context);
                return;
            }

            var token = context.Request.Headers["X-Local-Token"].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(token) || !trustBoundary.ValidateLocalToken(token))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsJsonAsync(new
                {
                    error = "Access denied.",
                    detail = "Service control endpoints require a valid local trust token."
                });
                return;
            }
        }

        await _next(context);
    }
}
