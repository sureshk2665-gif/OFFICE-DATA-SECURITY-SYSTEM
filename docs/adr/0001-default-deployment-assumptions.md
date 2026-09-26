# ADR-0001: Default deployment assumptions

- Status: Accepted (2026-09-26)
- Context: The project owner is not a developer and could not answer every open decision in
  `docs/00-ARCHITECTURE-AND-PLAN.md` §12. The owner asked for an installable Windows `.exe` application.
  The defaults below let development continue. Each one can be changed later, and the app will detect
  what it can (Windows edition, domain membership) instead of relying only on these assumptions.

## Decisions

| # | Open question | Default chosen | Why | How the app copes if the default is wrong |
|---|---|---|---|---|
| 1 | Number of PCs / Active Directory | **Small office, up to ~100 PCs, workgroup (no Active Directory)** | Most small offices have no domain controller. | The agent detects domain membership; AD-specific features are optional additions. |
| 2 | Windows editions | **Windows 10/11 Pro** minimum | Required for device-control and app-control policies. | The agent reports every control it cannot apply as "Not supported on this edition"; Home PCs are flagged in the dashboard. |
| 3 | Staff admin rights | **Staff will be standard users** | Mandatory, as stated in the plan. | The agent detects staff members of the local Administrators group and raises an alert. |
| 4 | Server machine | **One always-on office Windows PC** runs the central server; the admin dashboard may run on the same PC | No dedicated server hardware assumed. | Windows Server is also supported. |
| 5 | Sanctioned email/cloud | **Nothing is pre-approved**; the administrator maintains the allow-list in the dashboard | Owner must decide what is business use. | Configurable at runtime. |
| 6 | Microsoft 365 / Defender / Intune licences | **None assumed** | Cost. | Features needing them stay listed as "requires additional software". |
| 7 | Router / web filtering | **Not assumed** | Unknown hardware. | Website blocking uses browser policies; category filtering remains an optional infrastructure upgrade. |
| 8 | Staff login model | **Separate app account per staff member**, optionally linked to their Windows account | Works without AD; the admin controls it centrally. | Windows sign-in restrictions on non-assigned PCs are applied by the agent (local account provisioning) in Phase 5. |
| 9 | App usage / active-idle statistics | **Not built by default**; may be added later as an opt-in, aggregate-only feature | Privacy; closest to "monitoring". | — |
| 10 | Paid items | **Pilot builds are unsigned.** Buying a code-signing certificate is recommended before rollout. QuestPDF community licence and WiX v5 (no maintenance-fee requirement) are used. | Zero-cost start. | Signing is a CI step that can be switched on later. |
| 11 | Employee notice | The staff app shows a **security & privacy notice** that staff acknowledge. The owner should also inform staff in writing. | Transparency; the system is not hidden. | — |
