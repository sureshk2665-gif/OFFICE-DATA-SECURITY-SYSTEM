# ADR-0009: Security enforcement, part 2 (Phase 5)

- Status: Accepted (2026-09-28). Builds on ADR-0008; its general rules apply:
  - documented mechanisms only
  - verified, never assumed
  - checked every minute and restored if changed
  - the agent only ever removes its own settings

## Application Control (C6)

**Mechanism.** Windows App Control for Business (WDAC), with Microsoft's documented tools:
1. Start from Microsoft's **"Allow Microsoft" example policy**, which ships with Windows
   (`%windir%\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml`). It allows Windows and everything
   signed by Microsoft (Office, Teams, OneDrive, .NET…).
2. Add **file path rules** for `%OSDRIVE%\Program Files\*` and `%OSDRIVE%\Program Files (x86)\*`, plus any
   folders the administrator adds. Windows only honours a path rule for a folder that standard users cannot
   write to ("runtime FilePath rule protection" stays on).
3. Set these rule options: 0 (user-mode code integrity), 6 (unsigned policy), 11 (**scripts not restricted**),
   16 (update without restart), plus 3 in Audit mode.
4. Build the policy with the ConfigCI cmdlets (`Merge-CIPolicy`, `Set-RuleOption`, `ConvertFrom-CIPolicy`).
5. Activate, list and remove it with **`CiTool.exe`**, without a restart.

**Verification.** The policy has a fixed ID per computer and a version that increases with every change. The
control is *On (verified)* only when `CiTool --list-policies` reports that ID, active, with the expected version.
If the policy disappears, it is redeployed and a Critical `PolicyTamperAttempt` event is sent.

**What staff see.**
- **Allowed:** Windows, Microsoft programs, and programs an administrator installed in Program Files.
- **Blocked** (Enforce) or **reported only** (Audit): programs started from Downloads, the Desktop, AppData,
  a USB drive or any other user folder.
- **Reporting:** Windows logs each case (Code Integrity events 3076 and 3077). The agent reports those for its
  own policy only as "would be blocked" or "blocked", once per program per hour.

**Requirements and cautions.**
- **Windows versions:** Windows 11 22H2 or later / Windows Server 2025 (for CiTool). Older versions report
  "Not supported".
- **Audit first:** always use Audit mode for several days, check the reported programs, and install needed ones
  properly in Program Files before switching to Enforce.
- **Per-user programs:** Chrome, Zoom and similar programs installed only for the current user (AppData) are
  blocked in Enforce. Install the per-machine versions instead.
- **Scripts:** PowerShell and other scripts are not restricted (option 11), so administrators' scripts keep
  working.
- **Office apps:** the staff app and dashboard must be placed in Program Files on computers that enforce
  Application Control.
- **The agent's own files:** the agent service unpacks its native libraries into its protected install folder,
  so it keeps working under the policy. The Windows test proves this by restarting the service while Enforce
  is on.

## Windows sign-in records (C18)

- The agent switches on the audit subcategories **Logon** and **Logoff** (success and failure) with
  `auditpol.exe`, and reads them back with the Windows audit API. The previous setting is remembered and put
  back when the feature is switched off.
- **What is reported** from the Security log:
  - sign-ins (4624: at the computer, unlock, remote desktop, cached credentials)
  - failed sign-ins (4625, with the reason: wrong password, unknown user, locked out…)
  - sign-outs (4647)
- **Only real people** are reported: local and domain accounts, not Windows services or computer accounts.

## Company folder protection

- **File access records (C12).**
  - The agent switches on the **File System** audit subcategory.
  - It adds an audit entry to each protected folder: Everyone; successful read, write, append and delete;
    inherited by files and subfolders.
  - Windows event 4663 for those folders is reported as "*user* opened / changed / deleted *file*
    (program: …)", once per user, file and action every 10 minutes.
  - This records *that* a file was used, not where its content went afterwards.
- **Ransomware protection (C13).**
  - The Microsoft Defender "Controlled Folder Access" policy is set (WindowsDefender.admx; mode 1 = block),
    and the company folders are added to its protected folders.
  - The control is *On (verified)* only when Defender itself reports the mode as active.
  - If Defender is not the active antivirus, it reports "Not supported" and changes nothing.
  - Defender's block events (1123, and 1124 in audit) are reported.

## Disk encryption (C14): check only

When a policy requires BitLocker, the agent reports each fixed drive's protection state (`Win32_EncryptableVolume`).
An unprotected drive shows the control as **FAILED**, naming the drive.

The system does **not** switch BitLocker on. Doing that safely needs recovery-key escrow to the server, which is
planned for a later part. Encrypting disks without a recovery-key process risks losing data.

## Uninstalling

`uninstall` also:
- removes the Application Control policy
- puts back the audit settings it changed
- removes the folder audit entries it added
- removes the Defender policy values

## Still not available

- **Approved USB devices by hardware ID, Bluetooth, and Wi-Fi restriction.** These need testing with real
  hardware and Wi-Fi.
- **Company folder permissions (C11).** Needs a decision on groups or domain.
- **Switching BitLocker on (with recovery keys).**
- **Windows sign-in restriction to assigned computers (C17).**
