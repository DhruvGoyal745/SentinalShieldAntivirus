# Sentinel Native Engine Scaffold

This folder is the clean-room native engine scaffold for the antivirus runtime.

Current status:
- The production application currently runs through the managed daemon fallback in the ASP.NET host.
- This native tree establishes the long-term boundaries described in the clean-room plan.
- No ClamAV code, signatures, or protocol compatibility are used here.

Subdirectories:
- `engine-core`: native scanning primitives, rule evaluation, and verdicting contracts.
- `engine-daemon`: local service and IPC host for scans and realtime submissions.
- `signature-tooling`: offline compiler and pack signing pipeline.

Guiding rules:
- Clean-room implementation only.
- No GPL code import, linking, or structural cloning.
- Keep scan logic separate from pack compilation and transport.
