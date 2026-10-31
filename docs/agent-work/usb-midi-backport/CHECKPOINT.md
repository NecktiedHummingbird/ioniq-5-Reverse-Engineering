# CVE-2016-2384 exact-module backport checkpoint

Status: complete — candidate rejected for recovered `260128` module.

## Result

- `snd-usbmidi-lib.ko` SHA-256:
  `ad2180bab3d7433287288c9b8255c8f70cefb6d4ee3c6b7d95ea4826d4b434be`.
- `CONFIG_SND_USB_AUDIO=m`; generic USB-audio/MIDI modules are shipped.
- Successful raw-MIDI creation installs exact private-free callback `0x1b34`.
- Every reviewed endpoint failure after ownership transfer returns through
  `0x2833` or `0x2880` without a second direct object free.
- CVE-2016-2384's double-free premise is absent in this module identity.

## Deliverables

- `evidence/vendor-kernel-usb-midi-backport.md`
- `evidence/artifacts/kernel-candidates/snd-usbmidi-cve-2016-2384.asm`
- `evidence/artifacts/kernel-candidates/cve-2016-2384-fix.patch`

## Boundary

This does not assess unrelated USB-audio/MIDI defects or owner-device runtime
state. No descriptor, peripheral, module, target path, or corruption attempt was
created or executed.
