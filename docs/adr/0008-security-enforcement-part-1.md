# ADR-0008: Security enforcement, part 1 (Phase 5)

- Status: Accepted (2026-09-28).
- Scope: Phase 5 is delivered in parts. This record covers part 1. The controls not listed here stay
  reported as **Not available yet** (`NotImplemented`) and have no effect.

## General rules

1. **Only documented Windows mechanisms.** Every control uses one of these, and nothing undocumented:
   - a documented Group Policy setting (the machine policy keys under `HKLM\SOFTWARE\Policies`, the same
     values Group Policy writes)
   - the Windows Firewall API
   - the Service Control Manager

   A Windows-only test checks every policy value the agent writes against the policy definitions (ADMX) that
   ship with Windows.
2. **Verified, never assumed.** A control reports *On (verified)* (`Enforced`) only after reading every setting
   back. A setting that does not stick makes the control *FAILED*, with the setting named.
3. **Checked every minute, restored if changed.** The agent re-applies its policy every 60 seconds. Anything
   it had set and someone else changed or deleted is put back, and a **Critical `PolicyTamperAttempt`** event is
   sent. An existing value from another source (e.g. a domain Group Policy) is overwritten once and
   reported as a Warning.
4. **Only its own settings are removed.** The agent records every value and firewall rule it creates, in its
   protected data folder. When a control is switched off, an exception starts or the agent is uninstalled, it
   removes exactly those, and only while they still have the value it wrote.
5. **Nothing is weakened.** The agent never switches off Windows Defender, the firewall or any other protection.
   If Windows Firewall is off, program blocking reports *Partly on* and says why.
6. **Audit before enforce.** USB and phone blocking have an *Audit* mode. Nothing is blocked; each connection
   is recorded as "would be blocked".

## Controls in part 1

| Control | Mechanism | Reported state |
|---|---|---|
| USB drives, memory cards, CD/DVD (C1) | "Removable Storage Access" policies: *Removable Disks*: deny read, write, execute. *CD and DVD*, *Floppy*, *Tape*: deny read, write. | On (verified) / Audit only / Off |
| Phones and cameras, MTP/PTP (C4) | "Removable Storage Access": *WPD Devices*, deny read and write (both WPD interface classes) | On (verified) / Audit only / Off |
| Software installation by staff (C7) | "Prohibit User Installs" (`DisableUserInstalls = 2`); "Prevent non-admin users from installing packaged Windows apps" (`BlockNonAdminUserInstall = 1`) | **Partly on**: portable programs and per-user EXE installers need Application Control (a later part) |
| Website restrictions (C10) | Edge and Chrome: `URLBlocklist`, `URLAllowlist`, InPrivate / Incognito disabled. Firefox: `WebsiteFilter`, `DisablePrivateBrowsing`. | On (verified); other browsers are not covered |
| Programs blocked from the network (C9, part) | Windows Defender Firewall outbound block rule per program path, in group "Office Security System" | On (verified) / Partly on (firewall off on a profile) |
| Agent self-protection (C16) | Checks automatic start, restart on failure, and that only SYSTEM and Administrators may stop or change the service. Restores the settings if changed. | On (verified) |

When a policy asks for Wi-Fi restriction, Bluetooth, Application Control or file protection, the settings are
saved and delivered but have no effect yet. The dashboard marks them "not available yet".

## Temporary exceptions

An administrator (Admin or SuperAdmin) can lift **one** control on **one** approved computer for 5 minutes to
30 days, with a reason.
- **Controls that can be lifted:** USB drives, phones, software installation, program blocking and website
  restrictions.
- **Signed policy:** the exception is part of the computer's signed policy, so staff cannot create one.
- **Duration:** the agent lifts the control only while the exception is active. It switches the control back on
  by itself within a minute of the end time, or when an administrator ends the exception early.
- **Records:** creating and ending an exception is written to the audit log. The agent reports the start and
  end as events.

This replaces per-device USB approval for now. Approving specific devices by hardware ID (C2) needs the
Device Installation Restrictions policy and testing with real USB hardware. It is planned for a later part.

## Uninstalling

`OfficeSecurity.Agent.exe uninstall` removes every policy value and firewall rule the agent created. The
computer returns to normal Windows behaviour.

## Limitations (to be accepted)

- **Removable Storage Access settings apply when a device is connected.** A drive that was already connected
  when blocking starts must be unplugged and reconnected. These settings apply to all users, including
  administrators.
- **External USB hard disks** that Windows reports as fixed disks may not be covered by the *Removable Disks*
  class. This must be checked with real hardware.
- **The real blocking effect of USB, phone and installation settings was not tested** on the build machine: it
  has no USB devices and no standard user session. The settings themselves are verified against Windows' own
  policy definitions. The website and firewall effects *are* tested (see the Phase 5 test report).
- **Website blocking covers Edge, Chrome and Firefox.** Browsers read policies at start-up and refresh them
  every few minutes. Other browsers (Opera, Brave, portable browsers) are not restricted until Application
  Control can block them.
- **Program blocking is by path.** A copy of the program in another folder is not blocked, and Windows Firewall
  cannot block by website name.
- **Local administrators can undo anything.** The agent detects and reverses changes within a minute and
  reports them, but a local administrator can also stop the agent. Staff must use standard Windows accounts.
