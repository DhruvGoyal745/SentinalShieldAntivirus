using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Antivirus.Application.Contracts;
using Antivirus.Configuration;
using Antivirus.Domain;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Antivirus.Application.Services;

public sealed class AuthService : IAuthService
{
    private readonly IUserRepository _userRepository;
    private readonly AntivirusPlatformOptions _options;
    private readonly ILogger<AuthService> _logger;

    public AuthService(
        IUserRepository userRepository,
        IOptions<AntivirusPlatformOptions> options,
        ILogger<AuthService> logger)
    {
        _userRepository = userRepository;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<LoginResponse?> AuthenticateAsync(LoginRequest request, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
        {
            return null;
        }

        var user = await _userRepository.GetByUsernameAsync(request.Username, cancellationToken);
        if (user is null || !user.IsActive)
        {
            return null;
        }

        if (!VerifyPassword(request.Password, user.PasswordHash))
        {
            return null;
        }

        await _userRepository.UpdateLastLoginAsync(user.Username, cancellationToken);

        var expiresAt = DateTimeOffset.UtcNow.AddHours(8);
        var token = GenerateJwtToken(user, expiresAt);

        return new LoginResponse
        {
            Token = token,
            Username = user.Username,
            Role = user.Role.ToString(),
            ExpiresAt = expiresAt
        };
    }

    public async Task<RefreshResponse?> RefreshTokenAsync(string currentToken, CancellationToken cancellationToken = default)
    {
        var principal = ValidateToken(currentToken);
        if (principal is null)
        {
            return null;
        }

        var username = principal.FindFirstValue(ClaimTypes.Name);
        if (string.IsNullOrWhiteSpace(username))
        {
            return null;
        }

        var user = await _userRepository.GetByUsernameAsync(username, cancellationToken);
        if (user is null || !user.IsActive)
        {
            return null;
        }

        var expiresAt = DateTimeOffset.UtcNow.AddHours(8);
        var token = GenerateJwtToken(user, expiresAt);

        return new RefreshResponse
        {
            Token = token,
            ExpiresAt = expiresAt
        };
    }

    public Task<AppUser?> GetUserAsync(string username, CancellationToken cancellationToken = default)
    {
        return _userRepository.GetByUsernameAsync(username, cancellationToken);
    }

    public async Task EnsureDefaultAdminAsync(CancellationToken cancellationToken = default)
    {
        if (await _userRepository.AnyUsersExistAsync(cancellationToken))
        {
            return;
        }

        var defaultPassword = _options.DefaultAdminPassword ?? "SentinelAdmin!2026";
        var hash = HashPassword(defaultPassword);
        await _userRepository.CreateUserAsync("admin", hash, UserRole.Admin, cancellationToken);
        _logger.LogWarning("Default admin account created. Change the password immediately.");
    }

    private string GenerateJwtToken(AppUser user, DateTimeOffset expiresAt)
    {
        var key = GetSigningKey();
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, user.Role.ToString()),
            new Claim("sub", user.Id.ToString()),
        };

        var token = new JwtSecurityToken(
            issuer: "SentinelShield",
            audience: "SentinelShield",
            claims: claims,
            expires: expiresAt.UtcDateTime,
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private ClaimsPrincipal? ValidateToken(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        try
        {
            return handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = "SentinelShield",
                ValidateAudience = true,
                ValidAudience = "SentinelShield",
                ValidateLifetime = false, // Allow refresh of expired tokens within reason
                IssuerSigningKey = GetSigningKey(),
                ClockSkew = TimeSpan.FromMinutes(5)
            }, out _);
        }
        catch
        {
            return null;
        }
    }

    private SymmetricSecurityKey GetSigningKey()
    {
        var secret = _options.JwtSigningKey ?? GenerateAndLogDefaultKey();
        return new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
    }

    private string GenerateAndLogDefaultKey()
    {
        // In production, this should be configured. For local dev, generate a stable key.
        var key = "SentinelShield-Dev-JWT-Key-2026-CHANGE-IN-PRODUCTION!";
        _logger.LogWarning("Using default JWT signing key. Configure 'AntivirusPlatform:JwtSigningKey' for production.");
        return key;
    }

    internal static string HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations: 100_000,
            HashAlgorithmName.SHA256,
            outputLength: 32);

        return $"{Convert.ToBase64String(salt)}:{Convert.ToBase64String(hash)}";
    }

    private static bool VerifyPassword(string password, string storedHash)
    {
        var parts = storedHash.Split(':');
        if (parts.Length != 2)
        {
            return false;
        }

        var salt = Convert.FromBase64String(parts[0]);
        var expectedHash = Convert.FromBase64String(parts[1]);

        var actualHash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations: 100_000,
            HashAlgorithmName.SHA256,
            outputLength: 32);

        return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
    }
}
