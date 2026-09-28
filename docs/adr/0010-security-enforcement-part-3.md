# ADR-0010: Security enforcement, part 3 (Phase 5)

- Status: Accepted (2026-09-28). Builds on ADR-0008 and ADR-0009; their rules apply:
  - documented Windows mechanisms only
  - verified, never assumed
  - checked every minute and restored if changed
  - the agent only ever removes its own settings

## Approved USB drives (C2)

**Problem.** The Removable Storage Access policies (part 1) block all USB drives. They cannot make an
exception for one drive.

**Mechanism.** When a policy blocks USB drives (Enforce) and lists approved drives, the agent switches to
Windows' **Device Installation Restrictions** (DeviceInstallation.admx), with "layered order of evaluation":
- `AllowDenyLayered` = 1: the more specific rule wins (a device instance ID beats a compatible ID).
- "Prevent installation of devices that match any of these device IDs": `USB\Class_08`, the compatible ID of
  every USB mass-storage device.
- "Allow installation of devices that match any of these device instance IDs": the approved drive's disk ID and
  the ID of the USB device it belongs to.
- USB storage devices Windows had already installed and that are not approved are **uninstalled** (SetupAPI
  `DiUninstallDevice`), so they cannot be used again. Unplugged ones are removed too, so they cannot come back.
- The Removable Storage Access "Deny execute" setting stays on: **programs cannot be run from any USB drive**,
  approved or not. The "Deny read/write" settings are removed while approved drives exist, because they would
  also block the approved ones.

**Approving.** An administrator plugs the drive into a managed computer. The agent reports it with its parent
USB device ID. The administrator selects it on the computer's page and clicks "Approve this USB drive"
(description and optional end date). The approval is saved in that computer's **policy**, so it applies on every
computer using it. Approvals are listed and removed in the policy editor. An expired approval stops working at
the next check.

**Verification.** The control is *On (verified)* when every value reads back as written, and no unapproved USB
storage device is still installed. Connections of approved drives are reported as events.

## Wi-Fi restriction (C8)

**Mechanism.** Windows' WLAN filters (`netsh wlan add filter permission=allow ssid=… networktype=infrastructure`
and `permission=denyall networktype=infrastructure/adhoc`). Networks that are not listed disappear from the
Wi-Fi list, including phone hotspots. The filters are read back with the Windows WLAN API
(`WlanGetFilterList`), and the agent removes only the filters it added.

**Safety rule.** If the computer is connected to a Wi-Fi network that is not on the list, the agent does **not**
apply the filters, because that would disconnect the computer from the server. It reports the reason
("connected to 'X', which is not on the list") until the network is added or the computer moves to an allowed one.

**Reporting.** Wi-Fi is reported together with program network blocking under "Network restrictions". A
computer without Wi-Fi reports that there is nothing to restrict.

## Bluetooth (C7)

- **DisableRadio**: Bluetooth adapters are disabled through Plug and Play (`pnputil /disable-device`). Adapters
  that are switched back on, or added later, are switched off again within a minute (Critical tamper event). This
  also stops Bluetooth keyboards, mice and headsets. Switching the setting off re-enables only the adapters the
  agent disabled.
- **BlockFileTransfer**: Windows' Bluetooth file transfer program (`%SYSTEM32%\fsquirt.exe`) gets a **deny rule in
  the Application Control policy** (part 2). Keyboards, mice and headsets keep working. This needs Application
  Control on *Enforce*; in *Audit* it is only recorded, and with Application Control off the control is FAILED,
  explaining why. It is reported as *Partly on*, because other Bluetooth file programs would need to be kept out
  by Application Control too.

## BitLocker recovery keys (C14)

- When a policy requires BitLocker, the agent reads each encrypted drive's **recovery password** protectors
  (`Win32_EncryptableVolume.GetKeyProtectors` type 3 and `GetKeyProtectorNumericalPassword`). It sends them only
  when they changed since the last successful send, over the mutually authenticated connection.
- The server checks the format, **encrypts** the password with its data-protection key (DPAPI, as for the TOTP
  secrets), and keeps old keys. A drive that was re-encrypted can still be recovered from an older backup.
- The dashboard lists keys (drive, key ID, dates) for administrators and auditors. **Only super administrators**
  can show a key. Each reveal is audited (`bitlocker.recovery-key.reveal`, key ID, never the key).
- The system still does **not switch BitLocker on**; that is left for later. With escrow in place, it is now a
  safe next step.

## Self-check command

`OfficeSecurity.Agent.exe check` (administrator) checks on the computer itself, read-only, whether the policy's
device protections work as intended. For each part it prints ✓ (working as the policy says) or ✗ (problem):
- tries to read each connected removable drive and reports whether it is approved
- phones: whether portable devices are blocked
- Wi-Fi: filters and the current network
- Bluetooth: adapters and their state
- Application Control: whether CiTool lists the policy
- BitLocker: drive protection and whether a recovery password exists

It is for the pilot at the office, where real USB drives, phones, Wi-Fi and Bluetooth exist; the build machine has
none of them.

## Uninstalling

`uninstall` also removes the device installation restriction values, the Wi-Fi filters the agent added, and
re-enables the Bluetooth adapters it disabled.

## Still not available

- **Company folder permissions (C11).** Needs a decision on groups or domain.
- **Switching BitLocker on.**
- **Windows sign-in restriction to assigned computers (C17).**
- **Backup.**
