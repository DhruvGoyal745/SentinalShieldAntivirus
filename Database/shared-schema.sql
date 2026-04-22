IF OBJECT_ID('dbo.Tenants', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.Tenants
    (
        Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        TenantKey NVARCHAR(128) NOT NULL,
        DisplayName NVARCHAR(200) NOT NULL,
        DatabaseName NVARCHAR(200) NOT NULL,
        IsActive BIT NOT NULL CONSTRAINT DF_Tenants_IsActive DEFAULT 1,
        CreatedAt DATETIMEOFFSET NOT NULL CONSTRAINT DF_Tenants_CreatedAt DEFAULT SYSUTCDATETIME()
    );
END;

IF OBJECT_ID('dbo.GlobalSignaturePackManifests', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.GlobalSignaturePackManifests
    (
        Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        Version NVARCHAR(64) NOT NULL,
        RolloutRing NVARCHAR(32) NOT NULL,
        Channel NVARCHAR(32) NOT NULL,
        IsDelta BIT NOT NULL CONSTRAINT DF_GlobalSignaturePackManifests_IsDelta DEFAULT 0,
        Sha256 NVARCHAR(128) NOT NULL,
        DownloadUrl NVARCHAR(1024) NOT NULL,
        SignatureCount INT NOT NULL CONSTRAINT DF_GlobalSignaturePackManifests_SignatureCount DEFAULT 0,
        MinAgentVersion NVARCHAR(64) NOT NULL,
        Status NVARCHAR(32) NOT NULL,
        CreatedAt DATETIMEOFFSET NOT NULL CONSTRAINT DF_GlobalSignaturePackManifests_CreatedAt DEFAULT SYSUTCDATETIME(),
        ReleasedAt DATETIMEOFFSET NULL,
        Notes NVARCHAR(MAX) NULL
    );
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Tenants_TenantKey' AND object_id = OBJECT_ID('dbo.Tenants'))
BEGIN
    CREATE UNIQUE INDEX IX_Tenants_TenantKey ON dbo.Tenants(TenantKey);
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Tenants_DatabaseName' AND object_id = OBJECT_ID('dbo.Tenants'))
BEGIN
    CREATE UNIQUE INDEX IX_Tenants_DatabaseName ON dbo.Tenants(DatabaseName);
END;

IF OBJECT_ID('dbo.Users', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.Users
    (
        Id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        Username NVARCHAR(128) NOT NULL,
        PasswordHash NVARCHAR(512) NOT NULL,
        Role NVARCHAR(32) NOT NULL CONSTRAINT DF_Users_Role DEFAULT N'Viewer',
        IsActive BIT NOT NULL CONSTRAINT DF_Users_IsActive DEFAULT 1,
        CreatedAt DATETIMEOFFSET NOT NULL CONSTRAINT DF_Users_CreatedAt DEFAULT SYSUTCDATETIME(),
        LastLoginAt DATETIMEOFFSET NULL
    );
END;

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Users_Username' AND object_id = OBJECT_ID('dbo.Users'))
BEGIN
    CREATE UNIQUE INDEX IX_Users_Username ON dbo.Users(Username);
END;
