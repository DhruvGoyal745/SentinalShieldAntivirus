namespace Antivirus.Domain;

public enum UserRole
{
    Viewer,
    Admin
}

public sealed class AppUser
{
    public int Id { get; init; }

    public string Username { get; init; } = string.Empty;

    public string PasswordHash { get; init; } = string.Empty;

    public UserRole Role { get; init; }

    public bool IsActive { get; init; } = true;

    public DateTimeOffset CreatedAt { get; init; }

    public DateTimeOffset? LastLoginAt { get; init; }
}

public sealed class LoginRequest
{
    public string Username { get; init; } = string.Empty;

    public string Password { get; init; } = string.Empty;
}

public sealed class LoginResponse
{
    public string Token { get; init; } = string.Empty;

    public string Username { get; init; } = string.Empty;

    public string Role { get; init; } = string.Empty;

    public DateTimeOffset ExpiresAt { get; init; }
}

public sealed class RefreshResponse
{
    public string Token { get; init; } = string.Empty;

    public DateTimeOffset ExpiresAt { get; init; }
}
