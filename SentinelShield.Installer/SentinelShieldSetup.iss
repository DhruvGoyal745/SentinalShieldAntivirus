; Sentinel Shield Antivirus — Inno Setup Installer Script
; Compile with: iscc.exe SentinelShieldSetup.iss

#define AppName "Sentinel Shield Antivirus"
#define AppVersion "1.0.0"
#define AppPublisher "Sentinel Shield"
#define AppExeName "SentinelShieldAntivirus.exe"
#define DesktopExeName "SentinelShieldDesktop.exe"
#define TrayExeName "SentinelShieldTray.exe"
#define ServiceName "SentinelShieldService"
#define AppUrl "http://127.0.0.1:5100"

[Setup]
AppId={{E4A7B3C1-9F2D-4E8A-B5C6-D7E8F9A0B1C2}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\SentinelShield
DefaultGroupName={#AppName}
AllowNoIcons=yes
OutputDir=..\..\artifacts\installer
OutputBaseFilename=SentinelShieldSetup
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
UninstallDisplayIcon={app}\{#DesktopExeName}
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "contextmenu"; Description: "Add 'Scan with Sentinel Shield' to right-click menu"; GroupDescription: "System integration:"

[Files]
; Service files (published output — single-file exe + supporting files)
Source: "..\..\artifacts\publish\service\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\..\artifacts\publish\desktop\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; Tray app (single-file exe)
Source: "..\..\artifacts\publish\tray\SentinelShieldTray.exe"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{commonappdata}\SentinelShield\Quarantine"
Name: "{commonappdata}\SentinelShield\Logs"
Name: "{commonappdata}\SentinelShield\SignaturePacks"

[Icons]
Name: "{group}\Sentinel Shield Antivirus"; Filename: "{app}\{#DesktopExeName}"
Name: "{group}\Uninstall Sentinel Shield"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Sentinel Shield Antivirus"; Filename: "{app}\{#DesktopExeName}"; Tasks: desktopicon

[Registry]
; Tray auto-start on user login
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "SentinelShieldTray"; ValueData: """{app}\{#TrayExeName}"""; Flags: uninsdeletevalue

; Explorer context menu — files
Root: HKLM; Subkey: "SOFTWARE\Classes\*\shell\SentinelShieldScan"; ValueType: string; ValueData: "Scan with Sentinel Shield"; Tasks: contextmenu; Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Classes\*\shell\SentinelShieldScan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\{#DesktopExeName}"",0"; Tasks: contextmenu
Root: HKLM; Subkey: "SOFTWARE\Classes\*\shell\SentinelShieldScan\command"; ValueType: string; ValueData: """{app}\{#DesktopExeName}"" --scan-target ""%1"""; Tasks: contextmenu

; Explorer context menu — folders
Root: HKLM; Subkey: "SOFTWARE\Classes\Directory\shell\SentinelShieldScan"; ValueType: string; ValueData: "Scan with Sentinel Shield"; Tasks: contextmenu; Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Classes\Directory\shell\SentinelShieldScan"; ValueType: string; ValueName: "Icon"; ValueData: """{app}\{#DesktopExeName}"",0"; Tasks: contextmenu
Root: HKLM; Subkey: "SOFTWARE\Classes\Directory\shell\SentinelShieldScan\command"; ValueType: string; ValueData: """{app}\{#DesktopExeName}"" --scan-target ""%1"""; Tasks: contextmenu

[Run]
; Grant SQL Server access to the SYSTEM account (required for Windows service)
; Uses full path to sqlcmd if available via SQL Express or SQL Server
Filename: "cmd.exe"; Parameters: "/C sqlcmd -S .\SQLEXPRESS -E -Q ""IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'NT AUTHORITY\SYSTEM') CREATE LOGIN [NT AUTHORITY\SYSTEM] FROM WINDOWS; ALTER SERVER ROLE sysadmin ADD MEMBER [NT AUTHORITY\SYSTEM];"" 2>nul || sqlcmd -S (localdb)\MSSQLLocalDB -E -Q ""IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'NT AUTHORITY\SYSTEM') CREATE LOGIN [NT AUTHORITY\SYSTEM] FROM WINDOWS;"" 2>nul || echo No SQL Server found — the service will auto-detect on first run."; Flags: runhidden waituntilterminated

; Install and start the Windows service
Filename: "sc.exe"; Parameters: "create {#ServiceName} binPath= ""{app}\{#AppExeName}"" DisplayName= ""{#AppName} Protection Service"" start= delayed-auto"; Flags: runhidden waituntilterminated
Filename: "sc.exe"; Parameters: "description {#ServiceName} ""Provides real-time antivirus protection, file scanning, and threat remediation."""; Flags: runhidden waituntilterminated
Filename: "sc.exe"; Parameters: "failure {#ServiceName} reset= 86400 actions= restart/5000/restart/5000/restart/5000"; Flags: runhidden waituntilterminated
Filename: "sc.exe"; Parameters: "start {#ServiceName}"; Flags: runhidden waituntilterminated

; Add localhost firewall rule
Filename: "netsh.exe"; Parameters: "advfirewall firewall add rule name=""Sentinel Shield Antivirus"" dir=in action=allow protocol=tcp localport=5100 localip=127.0.0.1"; Flags: runhidden waituntilterminated

; Launch tray app after install
Filename: "{app}\{#TrayExeName}"; Description: "Launch Sentinel Shield"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Stop and remove the service
Filename: "sc.exe"; Parameters: "stop {#ServiceName}"; Flags: runhidden waituntilterminated
Filename: "sc.exe"; Parameters: "delete {#ServiceName}"; Flags: runhidden waituntilterminated

; Kill the tray app
Filename: "taskkill.exe"; Parameters: "/F /IM {#TrayExeName}"; Flags: runhidden
Filename: "taskkill.exe"; Parameters: "/F /IM {#DesktopExeName}"; Flags: runhidden

; Remove firewall rule
Filename: "netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Sentinel Shield Antivirus"""; Flags: runhidden waituntilterminated

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\SentinelShield\Logs"
Type: filesandordirs; Name: "{commonappdata}\SentinelShield\SignaturePacks"
; Quarantine is intentionally NOT deleted — user data preservation

[Messages]
WelcomeLabel2=This will install {#AppName} on your computer.%n%nThe installer will:%n- Install the antivirus protection service%n- Add a native desktop dashboard%n- Add a system tray application%n- Configure real-time file monitoring%n- Add right-click scan integration%n%nPrerequisites (auto-detected on first run):%n- SQL Server Express, LocalDB, or any SQL Server instance%n- Microsoft Edge WebView2 Runtime

[Code]
var
  ResultCode: Integer;

function IsWebView2Installed(): Boolean;
var
  VersionValue: String;
begin
  Result :=
    RegQueryStringValue(HKLM32, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', VersionValue) and
    (VersionValue <> '');
end;

function IsSqlServerAvailable(): Boolean;
var
  ExitCode: Integer;
begin
  Result := Exec('cmd.exe', '/C sqlcmd -S .\SQLEXPRESS -E -Q "SELECT 1" >nul 2>nul', '', SW_HIDE, ewWaitUntilTerminated, ExitCode) and (ExitCode = 0);
  if not Result then
    Result := Exec('cmd.exe', '/C sqlcmd -S (localdb)\MSSQLLocalDB -E -Q "SELECT 1" >nul 2>nul', '', SW_HIDE, ewWaitUntilTerminated, ExitCode) and (ExitCode = 0);
  if not Result then
    Result := Exec('cmd.exe', '/C sqlcmd -S . -E -Q "SELECT 1" >nul 2>nul', '', SW_HIDE, ewWaitUntilTerminated, ExitCode) and (ExitCode = 0);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Exec('sc.exe', 'stop {#ServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('sc.exe', 'delete {#ServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('taskkill.exe', '/F /IM {#TrayExeName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('taskkill.exe', '/F /IM {#DesktopExeName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(2000);

  if not IsWebView2Installed() then
  begin
    Result :=
      'Microsoft Edge WebView2 Runtime is required for the Sentinel Shield desktop dashboard.' + #13#10 + #13#10 +
      'Install the runtime, then run this installer again.' + #13#10 +
      'Download: https://go.microsoft.com/fwlink/p/?LinkId=2124703';
    exit;
  end;

  if not IsSqlServerAvailable() then
  begin
    if MsgBox(
      'No SQL Server instance was detected on this machine.' + #13#10 + #13#10 +
      'Sentinel Shield requires SQL Server Express (free) or SQL Server LocalDB.' + #13#10 + #13#10 +
      'You can install SQL Server Express from:' + #13#10 +
      'https://go.microsoft.com/fwlink/?linkid=866658' + #13#10 + #13#10 +
      'Do you want to continue the installation anyway?' + #13#10 +
      '(The service will fail to start until SQL Server is available.)',
      mbConfirmation, MB_YESNO) = IDNO then
    begin
      Result := 'Installation cancelled. Please install SQL Server Express first.';
      exit;
    end;
  end;

  Result := '';
end;
