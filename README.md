# Office Computer Security System

Centralized Windows computer management, file safety and security enforcement for an office LAN.
There is no screen monitoring, screen recording, screenshots, keystroke logging, webcam or microphone capture.

> **Status: Phase 5 part 3 (approved USB drives, Wi-Fi restriction, Bluetooth, BitLocker recovery keys, self-check) complete — development build only.**
> Enforced now: USB drives, memory cards, phones and CD/DVD; staff software installation (partly); websites and
> private browsing in Edge/Chrome/Firefox; programs blocked from the network; agent self-protection; temporary
> per-computer exceptions; Application Control (audit/enforce); Windows sign-in records; file access records and
> ransomware protection for company folders; BitLocker check with recovery keys kept on the server; approved USB
> drives by hardware ID; allowed Wi-Fi networks; Bluetooth off or file transfer blocked. Each is reported only
> after Windows confirms it. USB, Wi-Fi and Bluetooth effects still need checking on a real office PC
> (`OfficeSecurity.Agent.exe check`).
> **Not yet available** (reported as `NotImplemented`, no effect): folder permissions, switching BitLocker on,
> backup, Windows sign-in restriction.

## Getting the `.exe` files

Every push is built on a Windows machine by GitHub Actions:

1. Open the repository's **Actions** tab.
2. Open the latest **"Build, test and package"** run.
3. Download the **`OfficeSecurity-win-x64`** artifact (a zip file).
4. Unzip it and follow `READ-ME-FIRST.txt` inside.

| Program | Purpose |
|---|---|
| `Server\OfficeSecurity.Server.exe` | Central server (one always-on office PC). Can run as a Windows Service. |
| `Agent\OfficeSecurity.Agent.exe` | Security agent for every office PC (`install` command registers the Windows Service). |
| `AdminDashboard\OfficeSecurity.AdminDashboard.exe` | Administrator dashboard. |
| `StaffApp\OfficeSecurity.StaffApp.exe` | Staff application. |

## Roadmap

| Phase | Content | Status |
|---|---|---|
| 1 | Architecture, decisions (ADRs), threat model, solution skeleton, signed policy format, CI | **Done** |
| 2 | Database, admin sign-in with two-step verification, staff accounts, roles, tamper-evident audit log, pinned HTTPS | **Done** |
| 3 | Computer enrollment and approval, agent Windows Service, mutual TLS, signed policy distribution, offline queue, device inventory, staff restricted to computers | **Done** |
| 4 | Software inventory, installation requests and approvals, approved deployment with hash and signature checks | **Done** |
| 5 | **Part 1 done:** USB/phone/CD-DVD blocking, staff install restriction, website & private browsing, program network blocking, agent self-protection, temporary exceptions. **Part 2 done:** Application Control, Windows sign-in records, file access records, ransomware protection, BitLocker check. **Part 3 done:** approved USB drives, Wi-Fi restriction, Bluetooth, BitLocker recovery key escrow, `check` command. **Later:** folder permissions, switching BitLocker on, Windows sign-in restriction | In progress |
| 6 | Security events, alerts, audit log, reports (CSV/PDF) | Planned |
| 7 | MSI installers, full testing, pilot deployment | Planned |

## Documentation

- [Architecture & implementation plan](docs/00-ARCHITECTURE-AND-PLAN.md)
- [Decisions (ADRs)](docs/adr/): default assumptions, database, identity & trust, packaging, authentication, agent enrollment, software management, security enforcement
- [Threat model](docs/security/threat-model.md)
- [API reference](docs/api/README.md) · [Database schema](docs/database/schema.md)
- [Phase 2 test report](docs/testing/phase-2-test-report.md) · [Phase 3 test report](docs/testing/phase-3-test-report.md) · [Phase 4 test report](docs/testing/phase-4-test-report.md) · [Phase 5 part 1 test report](docs/testing/phase-5-part-1-test-report.md) · [Phase 5 part 2 test report](docs/testing/phase-5-part-2-test-report.md) · [Phase 5 part 3 test report](docs/testing/phase-5-part-3-test-report.md)

## For developers

```
dotnet build OfficeSecurity.slnx
dotnet test  OfficeSecurity.slnx
```

Requires the .NET 10 SDK. WPF and Windows-service projects compile on any OS (`EnableWindowsTargeting`),
but they run only on Windows.

```
src/Shared/   Contracts (API DTOs, enums) · Policy (policy model, ECDSA signing & verification)
src/Server/   Domain (entities) · Application (auth, accounts, audit) · Infrastructure (EF Core/SQLite, CA) · Api (endpoints, Windows Service host)
src/Agent/    Agent (Windows Service, install commands, WMI) · Agent.Core (runtime, mTLS client, policy cache, event queue, pipe) · Agent.Enforcement
src/Clients/  Client.Core (API client, pinned TLS, pairing, shared view models) · Client.Wpf (theme, shared views) · AdminDashboard · StaffApp
tests/        Policy, Agent, Client.Core, Server unit tests · Server integration tests (in-memory and real HTTPS)
```

Both desktop apps support `--smoke-test <log file>`, which builds every screen off-screen; CI runs it on Windows.
