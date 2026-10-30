# Corrections log

Every claim this programme got wrong, what replaced it, and why. The changelog is
chronological; this is claim-oriented, so a reader landing on an older evidence
document knows whether to trust it.

Read this before quoting any evidence document.

**2026-10-21 scope warning:** C1–C11 preserve earlier correction entries, some
of which still overstate what their evidence establishes. In particular, C3/C4
are family/field-report claims, not installed-unit validation; C6/C10 do not
prove encryption boundaries; C11 does not prove all offline analysis impossible.
Use the current VM/recovery notes and C12–C14 below for those boundaries.

---

## C1 — Kernel symbol table was mispaired by 204 entries

- **Was:** 64,923 symbols recovered and applied to Ghidra; 48 security functions
  decompiled and named.
- **Now:** the address array start was taken at the first *kernel-range* pointer,
  so leading absolute (`A`) symbols were skipped and **every** symbol was paired
  with an address 204 entries away. Prologues still looked plausible, so the
  error was invisible.
- **Why:** cross-check against `__ksymtab` showed a constant −204 shift on 4,347
  of 4,375 exports. Fixed in `tools/uk_fw/kallsyms_structural.py`; the corrected
  table matches 4,369/4,375 exports exactly with zero mismatches.
- **Affected documents:** `eu-kernel-decompilation.md`,
  `eu-kernel-symbol-recovery-and-trust-chain.md` (the latter is correct).
  Any function-level claim resting on the original naming should be re-derived.

## C2 — Boot container field `0x18` is not a checksum

- **Was:** treated as a possible CRC covering some region; zlib and
  CRC-32/MPEG-2 hypotheses were tested and failed.
- **Now:** it is a **constant format/build id** (`0x42f08d94`), identical across
  all six `iasImage*_sub` variants whose command lines differ. It cannot be
  content-derived.
- **Why:** comparing the six variants directly.

## C3 — `mmcblk0p3` / `mmcblk0p5` are A/B system partitions, not display variants

- **Was:** interpreted as two root selections tied to 1280 vs 1920 display models.
- **Now:** they are the **A/B system partition pair** of one device family. The
  update writes to the inactive partition and rewrites `/etc/fstab`.
- **Why:** the public `wideopen` wiki's update-process description plus the
  patcher's A/B handling.

## C4 — Downgrade is not blocked

- **Was:** the `>=` version check blocks downgrade on the Linux path.
- **Now:** the version gate is a single userland comparison, and the public
  `navi_extended` FAQ documents substitution — older official payloads paired
  with the **latest** `.lge.upgrade.xml` for the same vehicle, so a genuine signed
  newer manifest satisfies the check. The Android sibling differs: its signed
  `update_info` binds the package, which is why the EV6 report failed.
- **Why:** child note 10 plus the tracker evidence.
- **Caveat:** three non-cryptographic obstacles remain (feed, target build,
  unconfirmed on 2026 packages).

## C5 — The `.ver` CRC hypothesis is weaker than first stated

- **Was:** if the upgrader relied on the `.ver` CRC, a CRC-repaired payload would
  pass and custom firmware would need no key.
- **Now:** the arithmetic stands — CRC-32 is forgeable and `crc32_forge.py`
  demonstrates it. The *exploitable* reading is weakened: a public report
  describes repairing CRC **and** size and being rejected, so at least one further
  check exists. Also, `.ver` values cover **ciphertext**, so modification still
  requires the key.
- **Why:** community field evidence (child note 10 / `community-field-evidence.md`).

## C6 — Header entropy was misread

- **Was:** the 3,385-byte boot-image header looked "structured" at entropy ~5.7.
- **Now:** 6.0 is the maximum for a 64-byte block, so ~5.7 means **random**. The
  header is encrypted, not plaintext metadata.
- **Why:** recomputing entropy correctly. The region contains no little-endian
  copy of 6,210,308 / 3,385 / 13,035 / 52 / 953 / `0x42f08d94`.

## C7 — The `DecryptToPIPE` invocation was guessed, and guessed wrong

- **Was:** `gen5w_decrypt.py` defaulted to `DecryptToPipe {input} {output}` and
  assumed the package footer had to be stripped first.
- **Now:** the documented invocation is
  `DecryptToPIPE -d <keyfile> <input> 0 > <output>`. Output is on stdout, and the
  whole file — footer included — is handed over; nothing is stripped.
- **Why:** the public `update_decryptor` Dockerfile and `entrypoint.sh`.

## C8 — An attempted vulnerability was rejected

- **Was (hypothesis):** `KEYSTORE_IOC_TEST_VERIFY_ECC_SIGNATURE` (0x412037c9)
  left its tail fields uninitialised because the ioctl declared only 32 bytes.
- **Now:** rejected. Decoded size is `0x120` (288), which covers the offsets the
  handler reads. **Not a bug.**
- **Why:** decoding `_IOC` correctly instead of by eye. Recorded so it is not
  re-raised.

## C9 — A second attempted vulnerability was rejected

- **Was (hypothesis):** `keystore_get_ksm_key` zeroed one buffer then copied from
  another, suggesting an uninitialised-stack disclosure.
- **Now:** rejected at instruction level. The buffer is
  `[68-byte private][136-byte public]`; the code zeroes the private half and
  returns the public half. **Not a bug.** The earlier reading was a decompiler
  artefact.
- **Why:** disassembling the function rather than trusting Ghidra's variable
  sizing.

## C10 — The `iasImage` decomposition replaced an earlier, vaguer note

- **Was:** "16,420 bytes larger than `_sub`, five of six share a 13,035-byte
  trailer."
- **Now:** exact — `3,385 header + 6,210,308 payload + 13,035 trailer =
  6,226,728`, where the payload length equals the plaintext `_sub` size.
- **Why:** arithmetic closes exactly.

## C11 — A "kernel IAS driver" does not exist

- **Was (hope):** the `ipk.`/`iasImage` format might be handled by Linux and
  therefore analysable.
- **Now:** the kernel contains no IAS symbol, string or config option. The format
  is a **boot loader** concern; it cannot be analysed without an SPI dump.
- **Why:** symbol, string and config searches.

---

## C12 — VM impossibility, PCI enumeration and panic attribution

- **Was:** no usable block device or display path; a nearby keystore warning
  established an anti-tamper panic; successful synthetic inputs bypassed it.
- **Now:** the panic trace is a root-mount failure. QEMU SDHCI `1b36:0007`
  binds after an exact-build guest-RAM PCI-table adaptation, and a compatible
  ext4 root executes BusyBox. A userspace PCI-mapped VGA diagnostic displays
  verified pixels and accepts virtual keyboard events. Missing framebuffer
  support did not make all graphics impossible.
- **Boundary:** this is a VM-adapted vendor kernel and our research userland,
  not a recovered HMI or a boot-trust bypass. Synthetic initialization is not
  possession of device keys. Sparse logs did not prove failed PCI enumeration.
- **Evidence:** `vendor-kernel-vm.md`, `vendor-kernel-graphics.md` and fresh
  regressions in `local-ui-recovery.md`.

## C13 — Entropy, arithmetic and suffix equality do not decode an envelope

- **Was:** the 3,385/payload/13,035 split was an exact decoded layout; shared
  high-entropy suffixes were definitely encrypted descriptors; a decryptor
  must strip those suffixes; the unique prefix length was a plaintext length.
- **Now:** those interpretations exceed the measurements. Arithmetic and
  shared bytes do not establish fields, keys, signature coverage or acceptance.
  Finite-sample entropy does not distinguish encrypted data from other
  high-entropy content. The documented vendor CLI takes the **whole input**,
  as already noted in C7. `eu-ota-container-structure.md` now says so directly.
- **Boundary:** no current payload format or authentic decryption is recovered.

## C14 — Local recovery negatives must retain their search bounds

- **Was:** broad claims that no package key material or offline avenue exists.
- **Now:** the new public-RSA probe finds no type-1 block under the boot key
  in the recorded edges of 38 files. Two statically reconstructed Mac updater
  AES pairs yield no validated plaintext in the tested CBC hypotheses. Two
  gzip-marker matches fail reserved-flag/zlib checks. Positive controls pass.
- **Boundary:** other keys, encodings, locations and derivations are untested.
  The Mac updater's text/API crypto is not established firmware crypto. REA
  Mach-O inspection succeeded; its deep Ghidra function analysis timed out,
  so function claims here use explicitly identified LLVM disassembly instead.
- **Evidence:** `local-ui-recovery.md`, retained reports and 13 new RSA-probe
  unit tests. No new Fable/Council acceptance is claimed.

---

## C15 — D-Bus transition result `255` is not sufficient to call the request rejected

- **Was:** the immediate `/transition` out value `255` was treated as a
  rejection/non-success result, even after the standby state changed.
- **Now:** it is not a completion verdict in isolation. In the corroborated
  post-agreement run, the same immediate value is followed by
  `is_standby_agree_pressed ... result[1]`, exception-filter results zero,
  current AppID Home `11`, authentic Home response `ret[1]`, drawing AppID
  `11`, IVI foreground of surface `1001`, and visibly composed Home pixels.
- **Why:** the full downstream asynchronous manager/application/IVI chain is
  stronger evidence than the method's immediate integer.
- **Boundary:** this does not assign an exact enum name to `255` and does not
  prove Home↔Navigation operation. Classify each request from downstream state
  and response evidence.
- **Evidence:** `HANDOVER.md`, `Ioniq5-CHANGELOG.md` 0.44.0, and archive SHA-256
  `87d81b278f8b1bb20236faedd17dda0493b49b6cfc1e0fd2f1acfe8b8d2c6f5e`.

---

## C16 — V-006's unquoted root shell sink is not descriptor-based command injection

- **Was:** static review stopped at `util_replace_whitespace()` and concluded that
  USB serial punctuation, `${IFS}`, separators and redirects reached
  `/app/bin/usb-automount` unchanged. V-006 was therefore labelled a confirmed
  CWE-78 USB-to-root path and a physical payload sequence was documented.
- **Now:** `builtin_usb_id` next calls `util_replace_chars(..., NULL)`. Its default
  allowlist is alphanumerics plus `#+-.:=@_`; other tested printable characters
  become `_`. QEMU `usb-mtp` exercised the authentic udev → root automounter →
  `system()` chain. The old payload was sanitized and no command executed.
- **Why:** the call at `0x1c33e` was misidentified as trimming rather than the
  security-relevant character filter. Static sink analysis omitted an upstream
  transformation at the trust boundary.
- **Boundary:** the shell construction is still unsafe and a leading `#` can
  disrupt it. Other firmware/udev builds and untested property paths require
  separate validation. Physical-head-unit parity is unverified.
- **Evidence:** `v006-exploit-host.log` SHA-256
  `568f3197ff178cbf8356674c74a149b66ec1bfd96eedd5f2098a830c84adb27a`;
  sanitizer matrix SHA-256
  `de0757442ca4a74d3a3f87db79e8c3eb2b16b101dc47131d266af71ac734b0a1`;
  `Ioniq5-VULNERABILITIES.md` V-006.

---

## C17 — Missing `MS_NODEV` does not mean every USB image can carry a live device node

- **Was:** the confirmed absence of `MS_NODEV` was immediately described as a
  first-ranked path where “any normal image containing `mknod` nodes” exposes raw
  internal block devices.
- **Now:** the automounter constructs vendor filesystem names `tntfs`/`texfat`;
  other types become literal `mtp`. FAT/exFAT do not natively encode POSIX device
  inodes. Whether a special-file encoding produced on NTFS is materialized as a
  device by this exact Tuxera module is untested. Even if it is, a local process
  must still open and use the node; the node does not execute from USB.
- **Why:** mount flags establish policy, not on-disk filesystem semantics or an
  execution trigger. Those are separate reachability steps.
- **Boundary at correction time:** omitting `MS_NODEV` remained a real hardening
  error and V-011 became a post-execution/DAC-bypass candidate, not a
  stock-to-root claim. The harmless dynamic test has since been completed; see
  C21.

---

## C18 — The `4.1.27-abl` banner does not make Dirty COW present

- **Was:** CVE-2016-5195 was ranked as the leading post-execution local-root
  candidate because upstream Linux 4.1 did not receive the fix until 4.1.35.
- **Now:** the recovered vendor binary contains the fix's paired invariants:
  `follow_page_mask` requires `FOLL_FORCE | FOLL_COW` and a dirty PTE before
  following a forced write PTE, while `__get_user_pages` sets `FOLL_COW` after
  the COW fault. The vulnerable `FOLL_WRITE`-clearing sequence is not used.
- **Why:** the original ranking was version-gap triage and explicitly did not
  confirm vendor cherry-picks. Exact binary inspection now supplies that check.
- **Boundary:** this rejects Dirty COW only for recovered EU `260128`; it does
  not validate other kernel CVEs or the owner's unknown installed build.
- **Evidence:** `evidence/vendor-kernel-dirty-cow-backport.md`.

---

## C19 — Both ranked AF_PACKET races are backported in the shipped module

- **Was:** the TPACKET_V3 version-change and `PACKET_RESERVE` races remained
  ranked as AF_PACKET local-root hypotheses based on upstream fix dates.
- **Now:** shipped `af_packet.ko` acquires the socket lock at the start of
  `packet_set_ring`, locks the `PACKET_VERSION` branch around ring checks and
  `tp_version`, and separately locks the `PACKET_RESERVE` branch around ring
  checks and `tp_reserve`. These are the changes from upstream commits
  `84ac7260236a` and `c27927e372f0`.
- **Why:** as with Dirty COW, a base version identifies candidates but cannot
  establish that an OEM kernel omitted a backport.
- **Boundary:** this rejects CVE-2016-8655 and CVE-2017-1000111 only; other
  AF_PACKET bugs and actual
  `CAP_NET_RAW` assignments need separate checks.
- **Evidence:** `evidence/vendor-kernel-af-packet-backport.md`.

---

## C20 — The larger Stack Clash guard gap is present despite the old banner

- **Was:** CVE-2017-1000364 remained the leading version-derived local-root
  hypothesis after Dirty COW and the AF_PACKET races were rejected.
- **Now:** the vendor binary contains `vm_start_gap`, `stack_guard_gap`, its boot
  parameter parser, and an initialized 1 MiB gap. Those are the central changes
  from upstream commit `1be7107fbe18`.
- **Why:** ranking by the upstream stable version again missed an OEM backport.
- **Boundary:** the larger gap is mitigation rather than a proof against every
  stack-growth technique, but the generic missing-fix premise is false here.
- **Evidence:** `evidence/vendor-kernel-stack-guard-backport.md`.

---

## C21 — Exact Tuxera NTFS does preserve usable special-node semantics

- **Was:** after C17, Tuxera NTFS special-file materialization and the practical
  effect of `nodev` remained unverified.
- **Now:** exact `tntfs` `3016.7.1.2.3` retained an inert character node (`1:3`)
  across unmount/remount. Without `nodev`, numeric uid/gid 65534 under SMACK `_`
  opened it read-only; with `nodev`, the same open failed with `EACCES`.
- **Why:** filesystem semantics must be measured separately from mount-flag
  recovery. The test used only QEMU `/dev/null` and a disposable NTFS image.
- **Boundary:** this confirms a device-policy bypass primitive, not USB-to-root.
  A production local opener, useful major/minor, access mode and SMACK/path
  permission are still required.
- **Evidence:** `evidence/usb-root-test-plan.md` and the hashes recorded there.

---

## C22 — Enabled keyrings do not make CVE-2016-0728 present

- **Was:** CVE-2016-0728 remained a local-root candidate because
  `CONFIG_KEYS=y`, the vulnerable-era API exists, and the base version predates
  its upstream stable fix.
- **Now:** exact `join_session_keyring` disassembly releases the lookup reference
  when the located keyring equals the new credentials' current session keyring.
  This is the complete operation added by upstream commit `23567fd052a9`.
- **Why:** subsystem enablement and version range establish reachability for
  triage, not the absence of a vendor backport.
- **Boundary:** this rejects CVE-2016-0728 only. It does not validate unrelated
  keyring lifetime or permission paths.
- **Evidence:** `evidence/vendor-kernel-keyring-backport.md`.

---

## C23 — Read-only ALSA sequencer ioctl access does not expose every sequencer race

- **Was:** once V-013 proved uid/gid-65534 create/delete ioctl reachability on
  `/dev/snd/seq`, nearby sequencer CVEs could appear equally reachable.
- **Now:** exact `snd-seq.ko` lacks CVE-2018-1000004's official Linux 4.1 ioctl
  serialization, but its published pool sequence requires `write()` while
  recovered intended node policy is `root:root 0644`. The VM confirmed V-013
  ioctls through an `O_RDONLY` descriptor under that manually modeled mode, but
  an ordinary uid cannot obtain the write-capable descriptor needed by the
  sibling sequence.
- **Why:** device-node reachability is operation-specific; a readable ioctl
  surface does not confer file write access.
- **Boundary:** altered DAC, a passed write-capable fd, a privileged service, or
  different installed firmware could restore the precondition. The code should
  still be patched.
- **Evidence:** `evidence/vendor-kernel-alsa-follow-up-cves.md`.

---

## Standing practice that produced these corrections

1. Cross-check a symbol table against an independent table before trusting names.
2. Disassemble a function before calling a decompiler artefact a vulnerability.
3. Compute an entropy maximum before calling entropy "low".
4. Treat a field report as evidence against a hypothesis, not just for it.
5. Record rejected hypotheses, not only accepted findings.

Items C8 and C9 were never vulnerabilities; they are kept here because a reader
who finds the earlier reasoning in a draft should know it was tested and failed.
