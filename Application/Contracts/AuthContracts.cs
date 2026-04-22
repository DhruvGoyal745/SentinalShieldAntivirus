using Antivirus.Domain;

namespace Antivirus.Application.Contracts;

public interface IAuthService
{
    Task<LoginResponse?> AuthenticateAsync(LoginRequest request, CancellationToken cancellationToken = default);

    Task<RefreshResponse?> RefreshTokenAsync(string currentToken, CancellationToken cancellationToken = default);

    Task<AppUser?> GetUserAsync(string username, CancellationToken cancellationToken = default);

    Task EnsureDefaultAdminAsync(CancellationToken cancellationToken = default);
}

public interface IUserRepository
{
    Task<AppUser?> GetByUsernameAsync(string username, CancellationToken cancellationToken = default);

    Task<AppUser> CreateUserAsync(string username, string passwordHash, UserRole role, CancellationToken cancellationToken = default);

    Task UpdateLastLoginAsync(string username, CancellationToken cancellationToken = default);

    Task<bool> AnyUsersExistAsync(CancellationToken cancellationToken = default);
}
