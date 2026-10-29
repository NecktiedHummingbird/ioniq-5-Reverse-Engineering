# Community chat leads — supplied summary, not independent validation

Recorded after the 2026-10-27 VM checkpoint. Source: the owner's message summarizing
`#general-g5w-linux` and `#userful-resources-linux`. No message links, message IDs,
raw exports, repository commit IDs or artifact hashes accompanied the summary.
The channels were **not accessed by this assistant**, repositories were not newly
inspected, and no hardware method was validated during this integration.

## What the source reports and how it changes the project

| Supplied lead | Evidence classification / applicability | Action for this project |
|---|---|---|
| Older Engineering Mode offers Update AppNavi from USB; June–October 2026 participants say newer firmware removes/patches it | Participant reports consistent with existing family-level research; exact IONIQ `260128` applicability unverified | Retain as a hardware-entry limitation, not a blocker for the already-recovered VM userspace |
| `navi_extended` temporarily replaces AppNavi to run programs | Previously analyzed tool behavior; installation gate remains separate | Reuse existing binary-analysis notes; do not re-analyze the tool as a new exploit |
| `CV_E.EUR.S5W_L.001.001.220721` might still support replacement, nickles1252 on 26 October, qualified “Iirc” | Unverified recollection; **CV_E is not our NE_E target identifier** | Comparison lead only; not a last-supported-version claim, downgrade recommendation or cross-model install candidate |
| Downgrade discussions and an assembled older firmware directory, but no demonstrated downgrade in inspected messages | Bounded negative finding about the owner's inspected messages, not all community knowledge | Keep rollback acceptance unproven; obtaining old bytes is not evidence the unit accepts them |
| 25–26 October proposed updater execution vulnerability met signature checks and reboot | Unvalidated attempt; no successful execution or bypass established | Add provenance to update-trust candidate tracking only; request traces/artifact identity before drawing a finding |
| Proposed approach reportedly does not work on IONIQ 6/INSTER/new updater; legacy fallback speculative | Platform/update-generation boundary unknown without actual artifacts | Do not transfer old-format assumptions to these vehicles or infer applicability from model year alone |
| `hkmcavn-tools` / `xcrypt`, July 2025 MY24 decryption report; MY25 problems | External compatibility reports without exact files/versions | Useful for format/version comparisons, but current project already has validated native TE2/xcrypt recovery; do not restart solved decryption work |
| `update_decryptor` Docker requires supplied files | Consistent with prior tool survey | Do not confuse wrapper availability with possession of decryptor/key or signing capability |
| `update-patcher` preserves persistence through updates | Post-entry modification, not first execution | Retain modification-created trust and USB-autorun hazards separately from stock vendor defects |
| `nudl` as replacement for reportedly broken `update_fetcher` | Acquisition lead; availability depends on region/model/token | Try only if a specific missing comparison artifact justifies it; avoid repeating historical global-API-down conclusions |
| EU INSTER numbered download paths versus revoked US EV6 historical tokens | Divergent participant reports, not contradictory universal facts | Historical availability remains model/region/endpoint/time specific; do not promise old firmware or brute-force download paths |
| October 2025 Wi-Fi config/SSH proposal | Proposal only; no successful implementation reported | No new network entry or SSH capability established; no VM networking expansion justified |
| NEMESIS incompatible with S5W_L Linux | Consistent with existing Linux/Android applicability boundary | Keep Android/Telechips techniques out of Linux/x86-64 findings |
| Dealer-mode USB log export; e-Niro Intel Atom A3930, Linux 4.1.27-abl, head unit 96560-q4340, build 250226, no AppNavi USB option | One reported different-model observation; not owner's hardware identity | Potential passive platform-identification evidence if supplied later; not proof of IONIQ driver/board identity or menu state |

## Prioritization for the VM goal

1. **Stay on the current integration task.** Authentic userspace has already been
   recovered and booted. AppNavi entry on a physical head unit, downgrade and
   signing bypass are not prerequisites for debugging this isolated VM.
2. **Best technical reuse:** exact xcrypt/updater-format differences, service/IPC
   observations, display/audio/MCU interface descriptions, and driver/kernel source
   or headers matching this recovered build. Prefer precise artifacts over names.
3. **Downloader reuse is conditional:** acquire an older comparison build only
   for a named code/contract question, preserving model/region/build/digest. No
   flashing or cross-region/cross-model installation follows from acquisition.
4. **Do not promote attempts into vulnerabilities.** Signature rejection and
   reboot do not prove updater execution. Decryption/re-encryption does not imply
   authenticated update acceptance, rollback acceptance or bootloader trust bypass.

## Reconciliation with older notes

Read `HANDOVER.md`, `evidence/corrections-log.md` and
`evidence/navigation-launch-status-contract.md` for the current VM state.
Older `gen5w-public-exploit-ecosystem.md`, `eu-root-sideload-applicability.md` and
`community-field-evidence.md` retain historical assertions that userspace is
unrecoverable without hardware or that particular APIs being down rules out all
historical downloads. Those statements are superseded or bounded by later
recovery and model-specific evidence; they must not be reintroduced as blockers.

The supplied chat summary neither establishes nor refutes a stock-to-root or
rollback method for the owner's unknown installed build. The project still has
no physical/network access to the detached head unit and has performed no new
hardware or update-installation action from these leads.

## Useful follow-up evidence (if readily available)

- Permalinks/message IDs and surrounding context for the updater attempt and
  explicit success/failure statements; redact personal/device identifiers.
- Exact repository URLs and commits for xcrypt/new-format discussion; no keys or
  credentials are needed in chat.
- Model, region, full firmware ID and file digests behind each compatibility claim.
- Logs showing which authenticated check rejected an update, not merely a reboot.
- Any existing display/MCU/service reconstruction material directly relevant to
  the VM contracts, rather than another first-entry chain.

No external fetch, tool install, firmware download, VM run, thread creation,
security discovery or hardware validation occurred while recording this source.
