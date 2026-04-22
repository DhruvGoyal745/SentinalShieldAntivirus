using Antivirus.Application.Contracts;
using Antivirus.Application.Services;
using Antivirus.Configuration;
using Antivirus.Domain;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;

namespace Antivirus.Tests.Unit;

public sealed class AuthServiceTests
{
    private const string TestJwtKey = "TestSigningKey-Minimum-32-Characters-Long!!";
    private const string TestPassword = "Str0ng!Pass#2026";

    private readonly Mock<IUserRepository> _userRepo = new();
    private readonly Mock<ILogger<AuthService>> _logger = new();
    private readonly AuthService _sut;

    public AuthServiceTests()
    {
        var options = Options.Create(new AntivirusPlatformOptions
        {
            JwtSigningKey = TestJwtKey,
            DefaultAdminPassword = "DefaultAdmin!2026"
        });
        _sut = new AuthService(_userRepo.Object, options, _logger.Object);
    }

    // ── Password Hashing ────────────────────────────────────────────────

    [Fact]
    public void HashPassword_ProducesSaltAndHash()
    {
        var hash = AuthService.HashPassword(TestPassword);

        hash.Should().Contain(":");
        var parts = hash.Split(':');
        parts.Should().HaveCount(2);
        Convert.FromBase64String(parts[0]).Should().HaveCount(16, "salt should be 16 bytes");
        Convert.FromBase64String(parts[1]).Should().HaveCount(32, "hash should be 32 bytes");
    }

    [Fact]
    public void HashPassword_DifferentCallsProduceDifferentSalts()
    {
        var hash1 = AuthService.HashPassword(TestPassword);
        var hash2 = AuthService.HashPassword(TestPassword);

        hash1.Should().NotBe(hash2, "each hash uses a unique random salt");
    }

    // ── Authenticate ────────────────────────────────────────────────────

    [Fact]
    public async Task Authenticate_ValidCredentials_ReturnsToken()
    {
        var passwordHash = AuthService.HashPassword(TestPassword);
        var user = MakeUser("admin", UserRole.Admin, passwordHash);
        _userRepo.Setup(r => r.GetByUsernameAsync("admin", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _sut.AuthenticateAsync(new LoginRequest { Username = "admin", Password = TestPassword });

        result.Should().NotBeNull();
        result!.Token.Should().NotBeNullOrWhiteSpace();
        result.Username.Should().Be("admin");
        result.Role.Should().Be("Admin");
        result.ExpiresAt.Should().BeAfter(DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task Authenticate_WrongPassword_ReturnsNull()
    {
        var passwordHash = AuthService.HashPassword(TestPassword);
        var user = MakeUser("admin", UserRole.Admin, passwordHash);
        _userRepo.Setup(r => r.GetByUsernameAsync("admin", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _sut.AuthenticateAsync(new LoginRequest { Username = "admin", Password = "wrong" });

        result.Should().BeNull();
    }

    [Fact]
    public async Task Authenticate_InactiveUser_ReturnsNull()
    {
        var passwordHash = AuthService.HashPassword(TestPassword);
        var user = MakeUser("admin", UserRole.Admin, passwordHash, isActive: false);
        _userRepo.Setup(r => r.GetByUsernameAsync("admin", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _sut.AuthenticateAsync(new LoginRequest { Username = "admin", Password = TestPassword });

        result.Should().BeNull();
    }

    [Fact]
    public async Task Authenticate_NonexistentUser_ReturnsNull()
    {
        _userRepo.Setup(r => r.GetByUsernameAsync("ghost", It.IsAny<CancellationToken>()))
            .ReturnsAsync((AppUser?)null);

        var result = await _sut.AuthenticateAsync(new LoginRequest { Username = "ghost", Password = "any" });

        result.Should().BeNull();
    }

    [Theory]
    [InlineData(null, "password")]
    [InlineData("", "password")]
    [InlineData("  ", "password")]
    [InlineData("admin", null)]
    [InlineData("admin", "")]
    [InlineData("admin", "  ")]
    public async Task Authenticate_EmptyOrWhitespaceCredentials_ReturnsNull(string? username, string? password)
    {
        var result = await _sut.AuthenticateAsync(new LoginRequest
        {
            Username = username ?? string.Empty,
            Password = password ?? string.Empty
        });

        result.Should().BeNull();
        _userRepo.Verify(r => r.GetByUsernameAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Authenticate_UpdatesLastLogin_OnSuccess()
    {
        var passwordHash = AuthService.HashPassword(TestPassword);
        var user = MakeUser("admin", UserRole.Admin, passwordHash);
        _userRepo.Setup(r => r.GetByUsernameAsync("admin", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        await _sut.AuthenticateAsync(new LoginRequest { Username = "admin", Password = TestPassword });

        _userRepo.Verify(r => r.UpdateLastLoginAsync("admin", It.IsAny<CancellationToken>()), Times.Once);
    }

    // ── Token Refresh ───────────────────────────────────────────────────

    [Fact]
    public async Task Refresh_ValidToken_ReturnsNewToken()
    {
        var passwordHash = AuthService.HashPassword(TestPassword);
        var user = MakeUser("admin", UserRole.Admin, passwordHash);
        _userRepo.Setup(r => r.GetByUsernameAsync("admin", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var login = await _sut.AuthenticateAsync(new LoginRequest { Username = "admin", Password = TestPassword });
        var refresh = await _sut.RefreshTokenAsync(login!.Token);

        refresh.Should().NotBeNull();
        refresh!.Token.Should().NotBeNullOrWhiteSpace();
        refresh.ExpiresAt.Should().BeOnOrAfter(DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task Refresh_GarbageToken_ReturnsNull()
    {
        var result = await _sut.RefreshTokenAsync("not.a.valid.jwt.token");

        result.Should().BeNull();
    }

    // ── Default Admin Seeding ───────────────────────────────────────────

    [Fact]
    public async Task EnsureDefaultAdmin_NoUsers_CreatesAdmin()
    {
        _userRepo.Setup(r => r.AnyUsersExistAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        await _sut.EnsureDefaultAdminAsync();

        _userRepo.Verify(r => r.CreateUserAsync("admin", It.IsAny<string>(), UserRole.Admin, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task EnsureDefaultAdmin_UsersExist_DoesNothing()
    {
        _userRepo.Setup(r => r.AnyUsersExistAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        await _sut.EnsureDefaultAdminAsync();

        _userRepo.Verify(r => r.CreateUserAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<UserRole>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    // ── JWT Token Structure ─────────────────────────────────────────────

    [Fact]
    public async Task Token_ContainsExpectedClaims()
    {
        var passwordHash = AuthService.HashPassword(TestPassword);
        var user = MakeUser("testuser", UserRole.Viewer, passwordHash);
        _userRepo.Setup(r => r.GetByUsernameAsync("testuser", It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _sut.AuthenticateAsync(new LoginRequest { Username = "testuser", Password = TestPassword });

        result.Should().NotBeNull();
        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(result!.Token);

        jwt.Issuer.Should().Be("SentinelShield");
        jwt.Audiences.Should().Contain("SentinelShield");
        jwt.Claims.Should().Contain(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name" && c.Value == "testuser");
        jwt.Claims.Should().Contain(c => c.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role" && c.Value == "Viewer");
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private static AppUser MakeUser(string username, UserRole role, string passwordHash, bool isActive = true)
        => new()
        {
            Id = 1,
            Username = username,
            PasswordHash = passwordHash,
            Role = role,
            IsActive = isActive,
            CreatedAt = DateTimeOffset.UtcNow.AddDays(-1)
        };
}
