# ADR-0004: Packaging and deliverable executables

- Status: Accepted (2026-09-26)

## Decision

- Every component is published as a **self-contained, single-file `win-x64` `.exe`**, so target PCs do not
  need .NET installed:
  - `OfficeSecurity.Server.exe`
  - `OfficeSecurity.Agent.exe`
  - `OfficeSecurity.AdminDashboard.exe`
  - `OfficeSecurity.StaffApp.exe`
- **GitHub Actions (windows-latest)** builds and tests the code on every push. It uploads the `.exe` files
  as downloadable build artifacts.
- In Phase 7 the executables are wrapped in **MSI installers (WiX Toolset v5)**, together with a setup
  bundle `.exe`. The installers handle:
  - Windows Service registration
  - service recovery actions
  - firewall port rules
  - upgrade and uninstall
- Until then, the `.exe` files are development/pilot builds and must be run on **test computers only**.
- Code signing is a CI step activated once a certificate is purchased (ADR-0001 #10).
