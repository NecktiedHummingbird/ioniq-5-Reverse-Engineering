# Community chat transcript — 2026-10-29 (Discord)

Source: eight screenshots supplied by the project owner on 2026-10-29, captured from a
public Discord server discussing IONIQ 5 / EV6 / Gen5W head units. Transcribed here so
the content can be searched, diffed and cited like the rest of the evidence tree.

**Status: unverified participant reports.** This is a faithful transcription of what
appeared in the screenshots. Nothing below is a project finding. Participants are
unknown third parties; their claims are not endorsed, and several are contradicted by
our own measurements (see §6). Do not cite this file as evidence that a method works.

Transcription notes:

- The screenshots are overlapping scrolls of one channel, not eight conversations.
  They have been merged and de-duplicated; where two images show the same message it
  appears once.
- Timestamps are reproduced as displayed. The channel mixes absolute clock times
  (`8:51 AM`), relative labels (`Yesterday at 9:00 PM`) and a date divider
  (`October 29, 2026`). Relative labels are left as written rather than converted.
- Messages shown with a "replying to" quote are marked `[re: …]`.
- Images embedded in the chat are described in square brackets. Their content is not
  reproduced pixel-for-pixel.
- `(edited)` is preserved where the client displayed it.
- No message content has been added, reworded for accuracy, or attributed to anyone
  who did not send it. Participant names are as displayed.

---

## 1. Warranty and dealer-visible history

**Nexus** `8:20 AM` — `[re: DB — "but in Europe we have 7 years warranty, so, don't know
if nemesis probably would void that"]`
> In the dealer menu, it absolutely lists all software versions you have previously
> installed, and when. So... I'd be VERY careful just straight up installing a
> "patched" version of the head unit. You "can" delete the history of all installed
> upgrades, but that will come across as VERY suspicious, if you have a MY2022/2023
> and ONLY have the latest release on there when you go for a service.

**Rise** `8:23 AM` — `[re: DB]`
> if I'm not mistaken, 4 years warranty for electronics only
> so we're approaching that if your car is a 2023
> anyway I've been having Claude whack at it and we're at this point now
> `[image: terminal window, "STR_CAMERA_ALERT2----"]`

**nicklest252** `Yesterday at 8:06 PM`
> I'm not up to speed on whether the EU (or member states) have anything like
> Magnuson-Moss
> (Hacking your head unit might void the warranty on the head unit, but they can't deny
> legit claims on unrelated parts of the car)

**DB** `8:03 AM`
> don't have the knowledge
> but in Europe we have 7 years warranty, so, don't know if nemesis probably would void
> that

## 2. Engineerering mode entry (Gen5W)

**robiebabb** `8:49 AM`
> i'm looking at the engineeringmode
> to see what the new way is of entering

**Nexus** `8:50 AM`
> Is there an engineering mode? The only mode I can get into my HU is "dealer mode". All
> other random screen tap "howto's" don't work.

**robiebabb** `8:50 AM` — "i know / thats why im looking"

**Nexus** `8:50 AM`
> I know historically on the Linux version, there was an engineering mode, but I can't
> get into it anymore

**robiebabb** `8:51 AM`
> there is a file for it in the linuxrootfs

**Nexus** `8:51 AM`
> Yeah, my model looked and saw that too, but seemed to be hitting a random wall

**robiebabb** `8:54 AM`
> just delete it and ask a question for more information and then you give more info how
> to decompile it and then you say ohh you forgot to give me more information about

**Nexus** `8:57 AM`
> I tried all the youtube recommendations of tapping around the software info screen,
> nothing works
> Probably a "me" issue 😄

**robiebabb** `8:58 AM` — "yea me 2"

**Nexus** `8:59 AM`
> The most common one being the "G", 3, 1, 7, 9, 6, 5 (or 4); if you pictured a virtual
> number pad on the screen while you did it

**robiebabb** `10:29 AM` — `[image: photograph of the head unit showing ENGINEERING MODE]`
> **Engineering mode on latest Ioniq 5 firmware**
>
> Screen: **Settings → General settings → System info → Manual**. Tap the left side (QR
> code and text), not the image on the right.
> The sequence is **3 2 8 9 6 5**:
> `[image: the Manual screen, numbered 1–9, with callouts on keys 3, 2, 8, 9, 6, 5]`
>
> **PIN after that**
> - **Engineering mode (8 digits): 19480717**

The engineering-mode screen shown lists these tiles: *Software, Hardware, Dynamics,
SW Update, Diagnostic* on the top row and *System Config, Log System, Android* on the
second.

**Nexus** `11:10 AM`
> I will try that, thank you, I think I was offset a bit

**Helioyunho** `11:12 AM` — "interesting"

## 3. USB input handling / HID

**Nexus** `Yesterday at 9:20 PM`
> I asked myself a dumb question, what if we plug a keyboard or mouse into the head
> unit? So, keyboard seems to be ignored, but an interesting artefact, the mouse pointer
> shows up when you plug it in. (But doesn't move)
> `[image: photo of the head unit with a mouse pointer visible above the EV / Climate / Valet tiles]`
> So there is some form of HID detection, but it either ignores it, or the driver
> doesn't work properly

**Leo** `Yesterday at 9:33 PM`
> funnily enough, a few of my VM runs only show the cursor in that position

**Nexus** `Yesterday at 9:40 PM` — `[image: console output, kernel/USB enumeration]`
> So, that explains why the cursor pops up, because Yocto detects it, but the GUI itself
> doesn't get keyboards or mice passed through to it, explicitly only the touchscreen

**Nexus** `Yesterday at 9:50 PM`
> So, any USB input would go to the Linux OS itself, and not the GUI

**ShadowLabs** `Yesterday at 11:06 PM`
> Maybe a silly question, but couldn't you just ctrl+shift+f3 to switch from a graphic
> shell to a commandline?

**Nexus** `Yesterday at 11:10 PM`
> No, seems a no-go.
> Caps lock light doesn't even switch from off/on once the GUI is on, so it's entirely
> ignored (it seems)

**The Doctor** `1:08 AM` — `[re: Nexus, the HID question]`
> Wait WHAT? It detects a mouse? Lmao
> I tried mice, keyboard, and usb Ethernet adapters with CCNC all were a no go

**Nexus** `1:16 AM`
> Yeah, keyboard is complete no-go, but when you plug a mouse in, the pointer shows (but
> you can't do anything), remove the mouse, pointer disappears
> I did also keep keyboard in and reset the head unit, but nothing really happened. see
> the capslock light come on, then off, and then nothing.

**dij38943** `5:22 AM` — (no context) "Yes" / "LG produces ccIC(27) and Gen5W or S5W_L
Head Units" — appears as a reply to the "any USB input would go to the Linux OS itself,
and not the GUI" message.

## 4. Update package structure, signing and keys

**robiebabb** `8:13 AM`
> AppUpgrade
> lge.upgrade.xml
> whatsnew.tar.gz
>
> would be enough to make a basic upgrade package
> only thing is that it needs to be signed

**dij38943** `8:14 AM` — "4"

**robiebabb** `8:16 AM`
> mango-rootfs.tar.gz looks like a hole linux file

**dij38943** `8:16 AM`
> That is the rootfs

**Kotentopf** `8:17 AM`
> That explains the "rootfs" in the filename 😄

**robiebabb** `5:22 AM` — "Cool / I will look at it"

**dij38943** `5:30 AM`
> IONIQ 6 uses the new update logic so it cant be decrypted

**robiebabb** `5:31 AM` — "I have a Ioniq5"

**robiebabb** `5:28 AM` — `[image: file listing, "AppUpgrade 350 KB"]`
> as far as I can see it starts with AppUpgrade
> it could be that this is already enough, I will check the other files that are in
> appupgrade

**robiebabb** `5:58 AM`
> do we have the files:
> /tool/velix_aes.key
> /tool/public.crt
>
> if possible give all the files from /tool/
> nevermind found it

**robiebabb** `12:58 AM`
> Mabey there is some information about the signing and calculation; if we have that
> information, then we can create our own update

**dij38943** `1:00 AM` — `[re: robiebabb]`
> You really want to get the RSA private key from Hyundai to sign these updates?
> And what calculation, the IV? That is derived from the SHA256 of the encrypted file
> name and size...

**nicklest252** `Yesterday at 8:34 PM`
> That VM harness (even if it's only partly working) is probably going to be useful for
> testing exploit payloads
> My decompilation should be finished in the next few hours. It's mostly bogged down by
> AppNavi

**nicklest252** `5:09 AM`
> Well if there really is an exploit involving USB identifiers, we could potentially
> overwrite the pubkey list & start signing our own firmware

**robiebabb** `5:19 AM`
> If someone decrypted the firmware then the keys should be there

**dij38943** `5:19 AM`
> We already have the keys
> `60a9d7f073302a63a5ed0d0a38bac22` *(as displayed; length suggests truncation)*

**robiebabb** `5:21 AM`
> From there we need to establish how a update looks like, what pointers does it need to
> see it is an update, i think we can look at the update files and start from the boot
> files

### 4.1 Firmware file inventory posted to the channel

**dij38943** `5:22 AM`
> it has these tar.gz files

`[image: file listing, timestamps 27.10.2026]`

```
usbimage            27.10.2026 11:35   File                6,061 KB
usbimage_1200       27.10.2026 11:30   File                6,061 KB
usbimage_1200_sub   27.10.2026 11:30   File                6,065 KB
usbimage_1900_12    27.10.2026 11:30   File                6,061 KB
usbimage_1900_12_sub 27.10.2026 11:35  File                6,065 KB
usbimage_p5         27.10.2026 11:30   File                6,061 KB
usbimage_p5_1200    27.10.2026 11:35   File                6,061 KB
usbimage_p5_1200_sub 27.10.2026 11:35  File                6,065 KB
usbimage_p5_1900_12 27.10.2026 11:30   File                6,061 KB
usbimage_p5_1900_12_sub 27.10.2026 11:35 File              6,065 KB
usbimage_sub        27.10.2026 11:30   File                6,065 KB
mango-rootfs.tar.gz 27.10.2026 11:36   Compressed Archive  858,522 KB
mango-rootfs.tar.gz.out 27.10.2026 11:36 Wireshark capture   858,506 KB
mango-rwdata.tar.gz 27.10.2026 11:30   Compressed Archive  16,346 KB
multiovfcopy        27.10.2026 11:35   File                0 KB
new_gui.tar.gz      27.10.2026 11:36   Compressed Archive  2,042,813 KB
new_gui.tar.gz.out  27.10.2026 11:45   Wireshark capture   2,042,897 KB

[ HU — File folder ]
lge.upgrade.xml       27.10.2026 11:30  Microsoft Edge HTML   18 KB
lge.upgrade.xml.out   27.10.2026 11:39  Wireshark capture      2 KB
adbautotest.tar.gz    27.10.2026 11:30  Compressed Archive   277 KB
AppUpgrade            27.10.2026 11:30  File                 10,551 KB
AppUpgrade.out        27.10.2026 12:03  Wireshark capture    10,335 KB
IONIQ3_EU.ver         27.10.2026 11:30  VER File                3 KB
xcrypt.py             27.10.2026 11:39  Python Script          10 KB
```

(The `.out` entries listed as "Wireshark capture" are the tool's mis-detection of
decrypted output files, not packet captures.)

**robiebabb** `5:24 AM`
> That xml looks interesting
> I think it needs some text information to show

**dij38943** `5:24 AM`
> That XML tells the Head Unit where the rootfs is located and so
> But it is encrypted

**robiebabb** `5:24 AM` — "Exactly"

**dij38943** `5:24 AM` — `[image: terminal showing part of the decrypted XML]`

**robiebabb** `5:26 AM`
> That xml is the index of the update aa far as I can see this tells what is included,
> what version and where it can find it
> Can I download this decompiled firmware?
> Then I can also look further

**dij38943** `5:27 AM`
> Yeah sure
> It's very big lol
> You can also download the firmware and then use xcrypt to decrypt it

## 5. Tooling and shared links

**Hurtigfyr** `7:39 AM` — `[re: dij38943]`
> I have been in an absolute rabbit hole for the last few days trying to find this. Thank
> you
> Is there like a wiki for all the things that are already solved?

**nobody** `7:52 AM` — "Nope"

**robiebabb** `7:55 AM`
> https://github.com/JaredReabow/ioniq-5-Reverse-Engineering/blob/main/tools/uk_fw/gen5w_decrypt.py
> if you use this, you can unzip a lot
> fw_explorer.py also

**dij38943** `7:56 AM`
> https://github.com/galaxy4public/hkmcavn-tools/tree/main/xcrypt

**Kotentopf** `8:00 AM`
> In case here are people reading this, which are new to the whole topic: You can also
> use the ioniq-5-Reverse-Engineering repo for the EV6 251204.
>
> Cause of nemesis there are a lot more people interested in the whole topic. *(edited)*
>
> Oh and in case you want to try to boot the VM, the sha256 is:
> `adb0bed211e88f234b30f5156e15a1d7cdca17aca9a3edbeeeb0124bf42ab214`

## 6. Exploit claims and attribution caution

**nicklest252** `Yesterday at 9:00 PM`
> The decompilation is turning up some interesting vectors to look at
> - USB serial descriptors seem to be passed unauthenticated into a mount script, so a Pi
>   Zero or other similar device with shellcode in its ID might be executable. Might
>   struggle with length limits. The agent thinks that something like
>   `;cp /bin/sh /tmp/.x;chmod 4755 /tmp/.x;#` might fit.
> - Media file parsing runs as the root user (!). Shellcode execution path is unclear,
>   but if we have to go with memory corruption as a vector, that appears possible.
> - There's a serial console (with a hashed password) somewhere on the board that'll run
>   as root

**The Doctor** `Yesterday at 10:16 PM`
> Remember, Mobis is in here. I wouldn't talk about your exploits publicly.
> Does app armor exist on these units?
> it's being a real pain in the ass on CCNC
> Need a keystop/keystopt

**nicklest252** `Yesterday at 10:28 PM` — "Mobius?"

**alamo** `Yesterday at 10:44 PM` — "Hyundai Mobis"

**dij38943** `Yesterday at 10:44 PM` — "Mobis vs Mobius"

**alamo** `Yesterday at 10:45 PM`
> Mobius
> Mobis makes most of the car parts and also the infotainment system

> **Project note.** These three bullets are the claims recorded in
> `Ioniq5-VULNERABILITIES.md` as V-006, V-007 and V-008 and since tested offline. Our
> results differ materially from the claims: V-006 is a real command injection but not
> through a mount script; V-007 is configuration only, not a vulnerability; V-008 is
> normal password-gated configuration. See §7.

## 7. Claims in this transcript against our own measurements

| Claim in chat | Our status | Where |
| --- | --- | --- |
| USB descriptor reaches a shell | **Confirmed**, different mechanism: `system()` in `/app/bin/usb-automount` on the PTP/vendor-specific branch, not a mount script. The literal payload shown here would fail (spaces become `_`). | V-006 |
| Media parsing runs as root | **Confirmed as configuration** (uid 0, no seccomp/caps, zero setuid binaries), not a demonstrated vulnerability | V-007 |
| Serial console with hashed password runs as root | **Confirmed as shipped config**: `agetty` on `ttyS2 115200`, autologin commented out, `$6$` SHA-512 verifier. Not a bypass. | V-008 |
| Mouse pointer appears, keyboard ignored | **Consistent with our VM observations**: the cursor is visible in several captured frames | `HANDOVER.md`, screenshot set |
| IV derived from SHA-256 of encrypted file name and size | **Untested here** — check against `tools/uk_fw/gen5w_decrypt.py` | lead |
| "We already have the keys" + `60a9d7f073302a63a5ed0d0a38bac22` | **Untested** — compare against recovered key material | lead |
| VM image sha256 `adb0bed2…42ab214` | **Untested** — compare against our base rootfs `4953a005…6d036f`; different value is expected if it is a different build | lead |
| `/tool/velix_aes.key`, `/tool/public.crt` | **Untested** — check the extracted rootfs for `/tool/` | lead |
| Engineering mode: Settings → General settings → System info → Manual, tap left side, `3 2 8 9 6 5`, PIN `19480717` | **Untested** — `AppEngineerMode` exists in the recovered rootfs and can be checked statically | lead |
| IONIQ 6 uses newer update logic, cannot be decrypted | Consistent with our scope notes; not verified here | — |
| EV6 `251204` works with the same repo | Not verified here | — |

## 8. Preliminary checks performed on these leads (2026-10-29)

Cheap offline checks run immediately after transcribing, against the recovered
`260128` rootfs. None is conclusive; they narrow where to look next.

| Lead | Result |
| --- | --- |
| `/tool/velix_aes.key`, `/tool/public.crt` | **No `/tool/` directory exists in the rootfs.** These paths are inside the update payload (`AppUpgrade`), not the shipped rootfs, so they must be looked for in the decrypted AppUpgrade tree instead. |
| `AppEngineerMode` binary | **Present**: `/app/bin/AppEngineerMode`, 11,551,112 bytes. QML at `/app/share/AppEngineerMode/qml/main.qml`; startup string `AppEngineerMode Execute !! : main -> 230125`. SMACK labels are assigned in `etc/smack_setup.sh` and `etc/smack-relabel-ro.sh`. |
| Engineering PIN `19480717` | **Not present as a literal string** in `AppEngineerMode` or in any QML/JS/conf under `app/` or `usr/share/`. Either it is computed, split, or lives in the Settings application that accepts the tap sequence rather than in the engineering app itself. |
| Tap sequence `3 2 8 9 6 5` | **Not found as text** in the same search. Same conclusion: the entry handler is elsewhere, most plausibly the Settings app behind *System info → Manual*. |
| VM image digest `adb0bed2…42ab214` | Not compared. Our base rootfs is `4953a005…6d036f`; a different value would be expected for a different build and proves nothing on its own. |
| IV derived from SHA-256 of encrypted name+size | Not yet checked against `tools/uk_fw/gen5w_decrypt.py`. This is a concrete, testable claim and the most useful item in the transcript. |
| "We already have the keys" `60a9d7f0…` | Not matched. The displayed string is short enough to be truncated. |

Follow-up worth doing: locate the *System info → Manual* handler (likely
`AppSettings`) and search it for the six-key sequence and an 8-digit comparison,
rather than searching `AppEngineerMode`.

## 9. Publication caution

This transcript contains an engineering-mode entry sequence and PIN, a claimed VM image
digest, and a partial key-like hex string, all posted by third parties in a public
channel. It is stored here because it is directly relevant to the research, but:

- None of it is verified.
- The engineering-mode PIN and any key material should not be mirrored to the public
  repository without review; the project's `PUBLIC-RELEASE.md` boundary applies.
- The three exploit bullets in §6 describe unpatched behaviour in a shipping vehicle
  unit. Their disposition is tracked in `Ioniq5-VULNERABILITIES.md` and is a pending
  owner decision.
