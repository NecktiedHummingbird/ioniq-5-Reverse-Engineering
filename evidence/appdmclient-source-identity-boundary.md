# AppDMClient pathname verification does not bind the later consumed object

## Result

The exact recovered EU `260128` `AppDMClient` contains a static source-identity
boundary in both its AppUpgrade staging path and its USB XML reader. It verifies
a pathname and retains only an integer result. Later code consumes a pathname
again through a separate process or `QFile::open`; no open file description,
inode/device identity, or verified digest is carried from the reviewed verifier
call to that later consumer.

Classification: **exact static pathname-reopen / conditional TOCTOU candidate;
runtime source substitution and update acceptance unproved**.

This is stronger than the previous observation that the file is opened more than
once: exact caller data flow establishes that the verifier result and pathname,
not an authenticated object handle, cross the boundary. It is still not an
authentication bypass finding. Runtime mutability during the interval, a changed
object, successful staging, the launch request, child creation, inner FUMO
checks, partition writes, slot selection, boot acceptance, root, and persistence
remain separate gates.

## Identity and retained evidence

- recovered binary:
  `work/decrypted-eu-260128/extracted-safe/mango-rootfs/app/bin/AppDMClient`
- SHA-256:
  `9a1fb796d7ac24fcce71c16e3dbee9306c888f43e705ee081f41b7d473978bd0`
- Build ID: `b2dbcc5231f444d8f1dd68eb7a2376323ce805df`
- verifier-wrapper FDE: `[0x34870,0x34d43)`
- FUMO staging FDE: `[0x7ff60,0x830e4)`
- USB XML-reader FDE: `[0xe1e90,0xe3166)`
- exact retained assembly:
  `evidence/artifacts/update-candidates/appdmclient-source-identity-boundary.asm`
- assembly SHA-256:
  `26d75896207d811e67628ba9843e2fe4b43bbb3f4c27be25780263309b8468a8`

Addresses are ELF link-time virtual addresses for the PIE with image base zero.
The FDE ranges come from the recovered `.eh_frame`. Instruction claims were
confirmed with `/opt/homebrew/opt/llvm/bin/llvm-objdump`; decompiler output was
used only to assist local-variable and QString data-flow naming.

## Exact verifier-wrapper contract

Wrapper `0x34870` constructs and opens the fixed public-key file, reads it, and
closes that `QFile` at `0x34a09`. It converts the supplied target `QString` to a
local byte array at `0x34a3a..0x34a4a`, passes the resulting target pathname and
key bytes to linked verifier `0x121040` at `0x34a81`, stores the integer return
in `%ebp`, destroys its local `QFile` at `0x34ba6`, and returns the integer in
`%eax` at `0x34bd2`.

The caller receives no `QFile`, descriptor, authenticated byte buffer, inode
identity, or digest token. This does not assert that the linked verifier never
opens internal files; it establishes the narrower and decisive caller contract:
only status survives, and the later consumer is not passed an object opened by
the verifier.

## AppUpgrade staging boundary

The staging function constructs source names using the recovered format strings
at VAs `0x17ffff` and `0x17531e`. It calls verifier wrapper `0x34870` for the two
source names at:

- `0x802db`, storing the first integer at stack offset `+0x10`;
- `0x80320`, storing the second integer at stack offset `+0x18`.

Those retained integers later drive the already documented route-specific
contracts. They are not object handles.

On the reviewed later copy path, exact instructions at `0x82913` load the
`cp -f %1 %2` format string, substitute two independently retained QString
values at `0x82922..0x82961`, and call `QProcess::execute` at `0x8296b`. The
consumer process therefore resolves and opens its source by pathname after the
verifier calls have returned. No descriptor from `0x34870` is an input to that
call.

Complete-FDE review found no intervening inode/device comparison, descriptor
handoff, or digest equality check that binds the object consumed by this copy to
the object examined by the earlier verifier. The later executable-format,
permission, destination-existence, and launch checks are distinct and do not
supply that missing source identity binding.

## XML-reader boundary

The XML reader independently demonstrates the same architecture:

1. `0xe1ff7` calls verifier wrapper `0x34870` with the XML source pathname.
2. A nonzero verifier result reaches a later `QFile::open` at `0xe22d5`; the
   resulting device is parsed by `QDomDocument::setContent` at `0xe23fd`.
3. A zero result selects the separate decryption-command route. That route calls
   `system` at `0xe27c3`, then opens a generated temporary pathname with
   `QFile::open` at `0xe281f` and parses the resulting byte array at `0xe287f`.

Thus neither parser branch consumes an authenticated open description returned
by the earlier verifier. The encrypted branch additionally changes the object
namespace from source pathname to generated temporary pathname, but this report
does not infer decryption success, source control, command injection, or a
parser/authentication bypass from that fact.

## Public classification boundary

MITRE CWE-367 describes the general error as checking a resource and later
using it after state may have changed. Its filename-based example makes the
object-identity distinction explicit: two operations on a filename provide no
guarantee that the name still refers to the same object. Qt's public QProcess
documentation separately confirms that `execute` starts a new process and waits
for it. Those sources support terminology only; the recovered machine code is
the authority for this binary, and neither public source establishes runtime
mutability or exploitability here.

Public pages were retained read-only under ignored
`work/online-update-source-identity-20261103/` with SHA-256 values recorded in
the local research log. No target-specific information was submitted to either
source.

## Security classification

The exact static condition can be stated as:

```text
verify(path) -> integer status
...
later consumer resolves path (or a generated path) again
```

with no reviewed identity token connecting the objects. This is a necessary
structure for pathname substitution, but it is not sufficient for exploitation.
At least these independent facts remain unknown:

- whether the effective source filesystem and directory permit a relevant actor
  to change the named object during the interval;
- whether source-directory ownership, mount policy, SMACK, uid, or update-state
  serialization closes that interval;
- whether the object examined by the verifier and object consumed later ever
  differ in a real run;
- whether copy/decryption and the asynchronous launch request succeed;
- whether the launched outer/inner updater performs later authentication or
  payload-binding checks that reject changed content;
- whether any accepted content reaches an inactive partition, slot selection,
  boot trust, health, or mark-good;
- whether the owner's installed binary matches this recovered artifact.

Consequently the strongest supported result is a **conditional source-object
substitution candidate**, not arbitrary code execution, root, signature bypass,
modified-update acceptance, flashing, or persistence.

## Bounded model

`tools/uk_fw/update_source_identity_model.py` consumes eleven Boolean facts and
keeps name-to-object mutability, same-object content mutability, object-identity
binding, and later authentication separate:

1. whether complete static pathname-reopen facts are supplied without a retained
   open description or identity revalidation;
2. whether runtime name-to-object mapping mutability is established;
3. whether same-object content mutability or source immutability is established;
4. whether a later launch attempt is structurally reachable without an
   established authenticated-content binding for the exact staged object in the
   reviewed caller.

For the pre-recorded exact-binary state, the model reports the static boundary
and conditional launch structure as true, while runtime substitution and
unverified launch feasibility remain `null` because neither source mutability
nor immutability was established. Contradictory mutable/immutable input fails
closed.

Deterministic schema-v2 report SHA-256:
`6cbfb25c4b2eaa23da5499f20660ca5208e247be6651ccbc6e68d927155fc23b`.
Focused validation passed `9 tests, 2056 subtests`; the full suite passed
`543 tests, 140279 subtests`; the public harness passed, and independent
corrected package review returned **ACCEPT**. The model emits no firmware,
update, archive, command, target pathname, payload, launch message, or race
schedule.

## Safe future validation

The existing passive bench bundle already records `/proc/mounts`, updater
process metadata, update marker state, and metadata/hashes for staged
`/update/usb/bin` files. On a disconnected owner bench it should be run before
any active update experiment. Useful observations are installed binary identity,
effective uid/SMACK labels, source mount ownership/options, staged-file metadata,
and whether a later inner verifier is visible. No pathname replacement, race,
modified package, launch request, partition write, slot operation, or flash test
is required for that first pass.

## Safety record

No updater, verifier, helper, source pathname, recovered executable, launch
request, update package, or target syscall was exercised. No file-replacement
race, archive, malformed input, command, partition write, slot change, root
action, or persistence mechanism was created. Host-side disassembly, Boolean
classification, and Python tests used ordinary host operations outside those
target claims.
