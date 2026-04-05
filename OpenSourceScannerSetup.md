# Open-Source Scanner Setup

The realtime watcher pipeline is implemented in the application, but the external scanner binaries are not bundled with this repository.

## Default paths

The app looks for these files by default:

- `Tools\Yara\yara64.exe`
- `Rules\Yara\starter-rules.yar`
- `Tools\ClamAV\clamscan.exe`
- `Tools\ClamAV\clamdscan.exe`

These paths can be changed in `appsettings.json` under `AntivirusPlatform`.

## YARA

1. Install YARA for Windows.
2. Place the executable at `Tools\Yara\yara64.exe`, or update `YaraExecutablePath`.
3. Replace or extend `Rules\Yara\starter-rules.yar` with your own rules.
4. If you use compiled rules, set `YaraRulesCompiled` to `true`.

## ClamAV

1. Install ClamAV for Windows.
2. Place `clamscan.exe` at `Tools\ClamAV\clamscan.exe`, or update `ClamAvExecutablePath`.
3. If you want daemon-style scanning, place `clamdscan.exe` at `Tools\ClamAV\clamdscan.exe`.
4. Set `PreferClamAvDaemon` to `true` to use `clamdscan` first.

## Watcher roots

The watcher monitors these locations by default:

- `%USERPROFILE%\Downloads`
- `%USERPROFILE%\Desktop`
- `%USERPROFILE%\Documents`
- `%TEMP%`
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`

You can change them with the `WatchRoots` setting.

## Current behavior without the tools installed

If YARA or ClamAV are not installed yet:

- file events are still captured
- events are stored in SQL
- the dashboard still shows them
- engine results are marked as unavailable instead of breaking the app
