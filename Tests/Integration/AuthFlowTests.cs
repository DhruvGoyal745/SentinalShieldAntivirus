using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Antivirus.Application.Contracts;
using Antivirus.Application.Services;
using Antivirus.Configuration;
using Antivirus.Domain;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;

namespace Antivirus.Tests.Integration;

/// <summary>
/// End-to-end auth flow tests using real AuthService + mocked repository.
/// Validates the full login → token → refresh → /me pipeline.
/// </summary>
public sealed class AuthFlowTests
{
    private const string JwtKey = "TestSigningKey-Minimum-32-Characters-Long-For-HMAC!!";
    private const string DefaultPassword = "Admin!2026";

    private readonly Mock<IUserRepository> _userRepo = new();
    private readonly AuthService _authService;

    public AuthFlowTests()
    {
        var options = Options.Create(new AntivirusPlatformOptions
        {
            JwtSigningKey = JwtKey,
            DefaultAdminPassword = DefaultPassword
        });
        _authService = new AuthService(_userRepo.Object, options, Mock.Of<ILogger<AuthService>>());
    }

    // ── Full Login → Refresh Flow ───────────────────────────────────────

    [Fact]
    public async Task FullFlow_Login_ThenRefresh_ThenGetMe()
    {
        var hash = AuthService.HashPassword(DefaultPassword);
        var adminUser = new AppUser
        {
            Id = 1,
            Username = "admin",
            PasswordHash = hash,
            Role = UserRole.Admin,
            IsActive = true,
            CreatedAt = DateTimeOffset.UtcNow.AddDays(-1)
        };
        _userRepo.Setup(r => r.GetByUsernameAsync("admin", It.IsAny<CancellationToken>()))
            .ReturnsAsync(adminUser);

        // Step 1: Login
        var loginResult = await _authService.AuthenticateAsync(
            new LoginRequest { Username = "admin", Password = DefaultPassword });

        loginResult.Should().NotBeNull();
        loginResult!.Token.Should().NotBeNullOrWhiteSpace();
        loginResult.Role.Should().Be("Admin");

        // Validate the JWT structure
        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(loginResult.Token);
        jwt.Issuer.Should().Be("SentinelShield");
        jwt.Claims.Should().Contain(c => c.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role" && c.Value == "Admin");

        // Step 2: Refresh
        var refreshResult = await _authService.RefreshTokenAsync(loginResult.Token);

        refreshResult.Should().NotBeNull();
        refreshResult!.Token.Should().NotBeNullOrWhiteSpace();
        refreshResult.ExpiresAt.Should().BeOnOrAfter(loginResult.ExpiresAt);

        // Step 3: GetUser (/me)
        var user = await _authService.GetUserAsync("admin");
        user.Should().NotBeNull();
        user!.Username.Should().Be("admin");
        user.Role.Should().Be(UserRole.Admin);
    }

    // ── Tampered Token ──────────────────────────────────────────────────

    [Fact]
    public async Task Token_WithWrongSigningKey_FailsRefresh()
    {
        var hash = AuthService.HashPassword(DefaultPassword);
        var user = new AppUser
        {
            Id = 1, Username = "admin", PasswordHash = hash,
            Role = UserRole.Admin, IsActive = true, CreatedAt = DateTimeOffset.UtcNow
        };
        _userRepo.Setup(r => r.GetByUsernameAsync("admin", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var wrongKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("WRONG-KEY-DOES-NOT-MATCH-ANYTHING-HERE!!!!"));
        var creds = new SigningCredentials(wrongKey, SecurityAlgorithms.HmacSha256);
        var tamperedToken = new JwtSecurityToken(
            issuer: "SentinelShield",
            audience: "SentinelShield",
            claims: new[] { new Claim(ClaimTypes.Name, "admin") },
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: creds);
        var tokenString = new JwtSecurityTokenHandler().WriteToken(tamperedToken);

        var result = await _authService.RefreshTokenAsync(tokenString);

        result.Should().BeNull("token was signed with wrong key");
    }

    // ── Role Claim Validation ───────────────────────────────────────────

    [Theory]
    [InlineData(UserRole.Admin, "Admin")]
    [InlineData(UserRole.Viewer, "Viewer")]
    public async Task Token_ContainsCorrectRole(UserRole role, string expectedRoleClaim)
    {
        var hash = AuthService.HashPassword("pass");
        var user = new AppUser
        {
            Id = 1, Username = "testuser", PasswordHash = hash,
            Role = role, IsActive = true, CreatedAt = DateTimeOffset.UtcNow
        };
        _userRepo.Setup(r => r.GetByUsernameAsync("testuser", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _authService.AuthenticateAsync(
            new LoginRequest { Username = "testuser", Password = "pass" });

        result.Should().NotBeNull();

        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(result!.Token);
        jwt.Claims.Should().Contain(c =>
            c.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
            && c.Value == expectedRoleClaim);
    }

    // ── Default Admin Seed → Login ──────────────────────────────────────

    [Fact]
    public async Task SeedAndLogin_DefaultAdmin()
    {
        _userRepo.Setup(r => r.AnyUsersExistAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        string? capturedHash = null;
        _userRepo.Setup(r => r.CreateUserAsync("admin", It.IsAny<string>(), UserRole.Admin, It.IsAny<CancellationToken>()))
            .Callback<string, string, UserRole, CancellationToken>((_, hash, _, _) => capturedHash = hash)
            .ReturnsAsync(new AppUser
            {
                Id = 1, Username = "admin", PasswordHash = "placeholder",
                Role = UserRole.Admin, IsActive = true, CreatedAt = DateTimeOffset.UtcNow
            });

        await _authService.EnsureDefaultAdminAsync();

        capturedHash.Should().NotBeNull("admin should have been created");

        // Now login with the seeded hash
        var seededUser = new AppUser
        {
            Id = 1, Username = "admin", PasswordHash = capturedHash!,
            Role = UserRole.Admin, IsActive = true, CreatedAt = DateTimeOffset.UtcNow
        };
        _userRepo.Setup(r => r.GetByUsernameAsync("admin", It.IsAny<CancellationToken>()))
            .ReturnsAsync(seededUser);

        var result = await _authService.AuthenticateAsync(
            new LoginRequest { Username = "admin", Password = DefaultPassword });

        result.Should().NotBeNull("should be able to log in with default admin password");
        result!.Role.Should().Be("Admin");
    }
}
