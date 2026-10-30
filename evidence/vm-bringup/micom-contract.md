# The `com.lge.car.micom` contract — EU 260128 (5W.XXX.S5W_L.001.001.260128)

**Method: static only.** No VM was booted for this document and the image was not touched. Every
runtime statement is quoted from a log that already existed in the workspace. Every structural
statement is a `objdump`/`strings` read of a file in the rootfs tree, with the address given.

**Citation convention.** Paths are relative to `work/decrypted-eu-260128/extracted-safe/mango-rootfs`
(`mango-rootfs`) unless they start with `work/`, `tools/` or `evidence/`. "daemon 0xNNNN" is an
address inside `app/bin/micommanager_userspace`. That file is a PIE whose first load segment maps
file offset == virtual address, so `strings -t x` offsets and `objdump` target comments agree
(verified: the `/dev/ttyS1` literal at file offset `0x4f005` is the target of the `leaq` at
`0x7e07`, which objdump annotates `# 0x4f005`; the same identity holds for
`com.lge.car.micom` at file `0x4f02a` and `leaq` at `0x81a9`).

**Confidence tags.** **(V)** verified — read out of a file or quoted from an existing log.
**(I)** inferred — reasoning over verified facts, stated as such. **(U)** not established by static
evidence; §6 says what measurement settles it.

---

## 0. Summary, and one correction to the problem statement

1. The bus name is `com.lge.car.micom`, the object path for the boot information is **`/Ihu`**
   (not `/com/lge/car/micom/Ihu`), the interface is `com.lge.car.micom.ihu` and the method is
   **`AskSysBootinfo` with no input arguments and a single `out ay`** **(V)**.
2. **`AskSysBootinfo` is not a 35-byte request.** The D-Bus *request* is empty; on the wire it is a
   **5-byte** frame `AA hi lo 00 CS`. The **35 bytes are the reply payload** — `AskSysBootinfo`
   returns `ay` of length 35, and the daemon passes the MICOM's payload through verbatim **(V)**
   (§2.5, §3).
3. The daemon is a **transparent transport**. It does not parse the boot information; it converts
   D-Bus arguments to bytes, adds framing, writes to `/dev/ttyS1`, and converts the matching reply
   payload back into `ay` **(V)**. Everything semantic about the 35 bytes is therefore decided by
   the *firmware* on one side and the *consumer* (AppLauncher) on the other. The consumer side is
   fully recoverable statically and is reproduced in §3.
4. The previously recorded probe failure `No such object path '/com/lge/car/micom/Ihu'`
   (`work/vm/vendor-userspace-260128/micom-contract/micommanager-serial-ask-host.log`, the
   `dbus-send` line and the error two lines below it) is a **probe artefact**: the daemon registers
   `/Ihu` at the root **(V)**. The only object at `/com/lge/car/micom` is the *audio* interface
   **(V)**. Nothing in that log is evidence that the object tree appears only after MICOM traffic —
   the earlier "appears late" inference should be dropped.
5. This contract alone does **not** open the compositor. esinit's `SPI NOK` branch
   (`lib/systemd/esinit:150-155`) is driven by `micom.spi_validation`, which is a *kernel* module
   parameter, not a D-Bus property (§5.3).

---

## 1. The D-Bus side

### 1.1 Identity of the service **(V)**

| Item | Value | Proof |
|---|---|---|
| systemd unit | `dbus-com.lge.car.micom.service`, `Type=dbus`, `BusName=com.lge.car.micom`, `ExecStart=/app/bin/micommanager_userspace`, `Requires=dbus.service dlt.service` | `lib/systemd/system/dbus-com.lge.car.micom.service:3-9`; enabled via `lib/systemd/system/multi-user.target.wants/dbus-com.lge.car.micom.service` |
| D-Bus activation file | `Name=com.lge.car.micom`, `User=root`, `Exec=/app/bin/micommanager_userspace` | `usr/share/dbus-1/system-services/com.lge.car.micom.service` |
| policy | root may own and send to `com.lge.car.micom` | `etc/dbus-1/system.d/com.lge.car.micom.conf` |
| Smack label | `App::micommanager` → `System::micominterface` `rwx---` | `etc/smack/accesses.d/micommanager` (line 3) |
| the daemon | `app/bin/micommanager_userspace`, 542 856 B, ELF x86-64 stripped, release string `micommanager_userspace release data : 2015.10.19` | `file`; daemon 0x4f278 |
| transport | `/dev/ttyS1` | daemon 0x4f005 |

`main()` registers the name on the **system bus** and then registers every object
unconditionally, before any MICOM traffic:

```
81a9  leaq 0x4f02a -> rsi        ; "com.lge.car.micom"
81be  call QDBusConnection::registerService
8299..8346  construct 8 adaptor objects
8372  registerObject("/com/lge/car/micom")   ; 0x4f057, object #1
84cf  registerObject("/Radio")               ; 0x4f06a, object #2
862b  registerObject("/Tmu")                 ; 0x4f071, object #3
8788  registerObject("/Ihu")                 ; 0x4f094, object #4
88e5  registerObject("/Hdr")                 ; 0x4f0b7, object #5
8a42  registerObject("/Tmc")                 ; 0x4f0da, object #6
8b9f  registerObject("/Can")                 ; 0x4f0fd, object #7
8cfa  registerObject("/Eng")                 ; 0x4f120, object #8
```

Failure of any registration is reported through the adjacent `<Cannot register … object : >`
literals (daemon 0x4f099, 0x4f0bc, …). **(V)**

### 1.2 Interfaces and method signatures **(V)**

The introspection XML is compiled into the daemon as string blobs; the counts below are
`grep -c '<method name='` inside each block:

| Path | Interface | Methods | Ask\* methods | XML blob at |
|---|---|---|---|---|
| `/com/lge/car/micom` | `com.lge.car.micom.audio` | 16 | 6 | daemon 0x528fb |
| `/Radio` | `com.lge.car.micom.radio` | 16 | 5 | 0x5447b |
| `/Tmu` | `com.lge.car.micom.tmu` | 21 | 8 | 0x5654f |
| **`/Ihu`** | **`com.lge.car.micom.ihu`** | **106** | **45** (34 signals) | 0x5a58f |
| `/Hdr` | `com.lge.car.micom.hdr` | 8 | 3 | 0x6208f |
| `/Tmc` | `com.lge.car.micom.tmc` | 11 | 1 | 0x637c7 |
| `/Can` | `com.lge.car.micom.can` | 47 | 9 (16 signals) | 0x65a57 |
| `/Eng` | `com.lge.car.micom.eng` | 26 | 2 | 0x69927 |

The four signatures that matter at launch, verbatim from the `/Ihu` blob:

```xml
<method name="AskSysVersion">   <arg direction="out" type="ay"/></method>
<method name="AskSysBootinfo">  <arg direction="out" type="ay"/></method>
<method name="AskNaviOutermostRegion"><arg direction="out" type="ay"/></method>
<method name="AskSettingInfoValue">   <arg direction="out" type="ay"/></method>
<method name="AskCustomSetting">
  <arg direction="in" type="ay"/><arg direction="out" type="ay"/>
</method>
```

```xml
<signal name="NotifyETCCarIFStatusEvent"> <arg direction="out" type="ay"/></signal>
<signal name="NotifyETCPowerKeyEvent">   <arg direction="out" type="ay"/></signal>
<signal name="NotifyETCDayNightStatusEvent"><arg direction="out" type="ay"/></signal>
<signal name="NotifySpeedValueEvent">   <arg direction="out" type="ay"/></signal>
<!-- /Can -->
<signal name="NotifyKeyFrontPannelEvent"> <arg direction="out" type="ay"/></signal>
<signal name="NotifyMCANEachMsg">        <arg direction="out" type="ay"/></signal>
```

These are the vehicle-state channels (IGN/ACC/illumination/speed/keys). A simulator that only
answers the `Ask*` calls never emits any of them, so no vehicle-state transition can reach the HMI
through this path — consistent with the earlier observation that the UI draws but does not advance
state.

### 1.3 Where the caller is, exactly **(V)**

`app/bin/AppLauncher`, `MicomInterface::askSysBootinfo()`:

```
2d518  leaq 0x49441 -> rdi        ; "AskSysBootinfo"      (15 chars)
2d531  leaq 0x491cb -> rdi        ; "com.lge.car.micom.ihu" (21 chars, len reg = 0x15)
2d54a  leaq 0x491e1 -> rdi        ; "/Ihu"                 (len reg = 0x4)
2d563  leaq 0x491e6 -> rdi        ; "com.lge.car.micom"    (len reg = 0x11)
2d5b4  call QDBusMessage::createMethodCall
2d638  call QDBusConnection::systemBus.call(msg, Block, timeout=0xbb8)   ; 3000 ms
```

Then `QVariant` type check against `0xc` (`QMetaType::QByteArray`, `2d668`) and, on success, a
**fixed-length 35-byte copy** of that array:

```
2da17  movl $0x23, %ecx          ; 35
2da0c  rdx = reply bytes, rdi = destination
2da1e  call 0x26df0              ; copy 35 bytes into the MICOM message holder
2da26  call 0x2b7f0              ; parse()
```

and the reply is logged with its actual length as `[%1 Reply size = %2]` (format string at
`app/bin/AppLauncher` 0x492a7). The same 35 is used when the launcher builds the two shared-memory
objects keyed `MICOM_STATUS_MESSAGE` (0x4924b, size 0x23 at `28b0a`) and `BOOT_INFO_STATUS`
(0x49260, size 0x73 at `28b60`, constructor 0x27420). **(V)**

The launcher retries: format `[Retry count] %1` (0x49296), `movl $0x1,%ecx` = `Block` call mode,
and `cmp $0x2` on the retry counter at `2da54`. A never-answered `AskSysBootinfo` therefore costs
~3 s per attempt; this is the origin of the historical "8 second boot-info timeout".

### 1.4 Who blocks on it, and in what order **(V)**

The dependency is expressed twice — once in systemd, once in the daemon's delayed-reply design.

systemd graph (all lines verified in `lib/systemd/system/`):

| Unit | Relationship to `dbus-com.lge.car.micom.service` |
|---|---|
| `ApplicationLauncher.service` | `After=Dbuslaunch.service dbus-com.lge.car.micom.service pas-daemon.service` (`:4`), `Requires = dbus-com.lge.car.micom.service` (`:5`) — **hard gate** |
| `AudioManager.service` | `Requires=…` (`:6`), `After=…` (`:7`) — **hard gate** |
| `mof.service` | `Requires=dbus-com.lge.car.micom.service Dbuslaunch.service` (`:3`) |
| `remote.service` | `Requires=…` (`:3`), `After=… ofono Dbuslaunch dlt CryptoService` (`:4`) |
| `carplay_iAP2.service` | `Requires=…` (`:3`) |
| `carplay_mdnsd.service` | `Requires=…` (`:3`) |
| `usb-automount.service` | `Requires=…` (`:10`), `After=…` (`:11`) |
| `spi-validation.service`, `mpauto.service`, `pstore-reboot.service` | `After=…` only |
| `Dbuslaunch.service` | `After=micom.service` (`:4`) — **a unit that does not exist**, so this ordering is inert |
| `watchdogd.service` | only commented out (`:5-6`) |

Runtime order of the *data-bearing* asks, as actually observed at launch
(`work/vm/vendor-userspace-260128/micom-contract/full-chain-…-deadline-piefix-1536-evidence/launcher-chain/micom-sim.log`,
first 20 `MICOM_DBUS_SIM_CALL` lines, abbreviated):

```
:1.1 /Ihu com.lge.car.micom.ihu.AskNaviOutermostRegion()
:1.1 /Ihu com.lge.car.micom.ihu.AskSysBootinfo()
:1.1 /Ihu com.lge.car.micom.ihu.AskCustomSetting(ay 1B = 00)  ×3
:1.1 /Ihu com.lge.car.micom.ihu.AskSettingInfoValue()         ×3
     /com/lge/car/micom com.lge.car.micom.audio.AskAMPSupportInfo()
:1.5 /Can com.lge.car.micom.can.AskCANMMCANMicomReq(ay 11B = 018a0800…)
:1.2 /Ihu com.lge.car.micom.ihu.SetControlKeyLock(ay 8B = 00×8)
:1.2 /com/lge/car/micom com.lge.car.micom.audio.AskSoundSetupInfo()
:1.2 /Can com.lge.car.micom.can.SetCANMicomRecv(ay 11B = 0122080af3ff…)
```

`AskSysBootinfo` is the **second** ask the launcher makes, immediately after
`AskNaviOutermostRegion`, and `AppLauncher` is the process that logs
`[askSysBootinfo Reply size = 35]` — the DLT lines in the same evidence directories are owned by
`MANG AppL AppL` (`grep -rh 'Reply size =' work/vm/vendor-userspace-260128/micom-contract` returns
the launcher's own 35-byte confirmation for every run) **(V)**.

### 1.5 Delayed-reply semantics (the part that decides whether you block) **(V)**

Every request-style handler does:

```
12fc2  call QDBusContext::setDelayedReply(true)
12fca  call QDBusMessage()                    ; empty reply object
12ff0  call 0xb1e0(mgr, incomingMsg, &reply)  ; sender/PID bookkeeping
13074  call QDBusMessage::createReply(emptyList)
1309c  call 0xf400(mgr, <16-bit message id>, connection, replyMsg, incomingMsg)
```

`0xf400` → `0xefc0`, which logs `[writeToMicom] Ask CMD: 0x%1` (format 0x4fb33, literal 0x4fb3e)
and then:

```
f191  orw  $0x8000, %ax           ; reply-key = request id | 0x8000
f1da  movw %ax, 0x18(%rbx)        ; store key in the pending-reply queue entry
f1ec  call 0x11530                ; push entry onto m_replyQueue
f1fd  call 0xde00                 ; build frame, write to /dev/ttyS1
```

On the receive side `0xf4e0` walks `m_replyQueue` and matches
`incoming_frame_id == entry->key` (`f974: cmpw 0x18(%rbp), %bx`). **So the daemon only completes a
D-Bus ask when a MICOM frame arrives whose 16-bit id equals `request_id | 0x8000`.** There is no
timeout inside the daemon: an unanswered ask stays queued forever (the caller's 3 s timeout is all
AppLauncher's). **(V)**

---

## 2. The serial side

### 2.1 Port and line discipline **(V)**

- `/dev/ttyS1` (daemon 0x4f005), opened by a `QThread` created in `main()` at `0x7fd4`
  (ctor `0xd1a0`, started `QThread::start(priority 7)`), whose signal
  `2dataArrived(const QByteArray &)` is connected to `1parseIncomingSpiData(const QByteArray &)`
  (`0x8002`/`0x800f`; the two signature strings are at daemon 0x4f220 and 0x4f250). The
  "Spi" in that slot name is historical: the same slot handles the UART stream.
- Measured termios, from the only existing trace of the authentic daemon attached to the tty
  (`work/vm/vendor-userspace-260128/micom-contract/micommanager-serial-strace-host.log`, the three
  `TTY` lines after `ASK_RC=143`):

```
ioctl(8, TCGETS, {B9600 opost isig icanon echo ...}) = 0
ioctl(8, TCFLSH, TCIFLUSH) = 0
ioctl(8, SNDCTL_TMR_START or TCSETS, {B115200 -opost -isig -icanon -echo ...}) = 0
```

  → **115200 baud, raw (no output post-processing, no signal chars, non-canonical, no echo)**.
  Data bits/parity/flow control are **(I)**: the trace line prints only the `c_lflag`/`c_oflag`
  parts of the struct, so "8N1" is the default that follows from the untouched `c_cflag`, not a
  read value.
- Reader loop: `poll(pollfds, 3, -1)` at `0xdc13`; on `revents & POLLIN` (`0xdc26 testb $0x1,0x6`)
  it calls `readN(fd, buf, …)` = `0xd8f0`, which `read()`s up to 0x400 bytes (`0xd92c`), appends to
  a buffer, and drains complete frames. Three descriptors are polled **(V)**; *which* three is
  **(U)** — only one device path string (`/dev/ttyS1`) exists in the binary, so the other two are
  most likely a wakeup pipe and a second fd for the same device **(I)**.

### 2.2 Frame format — verified on both directions **(V)**

**Build** (`writeToMicom`, daemon `0xde00`):

```
de3e  r15 = variantList.end - variantList.begin        ; argument count
de76  append(0xAA)
de83  append((id >> 8) & 0xff)                         ; id_hi
de8d  append(id & 0xff)                                ; id_lo
dea7  append((char)argument_count)                     ; L
ded0  for each QVariant arg: append((char)arg.toInt()) ; payload, one byte per argument
df20  xor-accumulate the whole buffer, append(xor)     ; checksum
e19e  serial->write(packet)   (via 0xb130 -> 0xb050)
```

**Validate** (`checkValidCheckSum`, daemon `0xd310`):

```
d33e  data[0] == 0xAA            else reject
d373  size > 4                   else reject
d37b  L = data[3] ; need size >= L + 5   else "checkValidCheckSum :: Need to read more data."
d3e0  xor over data[0 .. L+4]    must be 0   else "checkValidCheckSum :: Non zero checksum ."
```

**Split** (buffered assembler, daemon `0xd4c0`; after the checksum passes at `0xd830`):

```
d830  append(frame_data, L + 4)        ; header + payload, checksum DROPPED
d84e  emit dataArrived(QByteArray)     ; 0x3b080 = QMetaObject::activate, signal index 0
```

**Deliver** (`parseIncomingSpiData`, daemon `0x11060`):

```
1108b  size <= 3 -> "SPI data size is too short(%d)" (0x4fee8)
110a3  id = (data[1] << 8) | data[2]            (helper 0x9a30, no bit masking)
110bf  copy frame, 110ce remove(0, 4)           ; strip AA/id_hi/id_lo/L  -> payload exactly
110d7  log "MICOM to MW" with the raw frame
1110a  writeToDBus(id, payload)                 ; 0xf4e0 -> reply queue
```

So the wire grammar is:

```
AA  id_hi  id_lo  L  p0 … p(L-1)  CS        total = L + 5
CS = p0 ^ … ^ p(L-1) ^ 0xAA ^ id_hi ^ id_lo ^ L      (i.e. XOR of the frame is 0)
```

**Both directions use the same layout** **(V)**: the builder and the validator are shared, and the
id that the receiver matches is the plain `(hi<<8)|lo`.

### 2.3 Id conventions

- Requests carry the method's 16-bit command id in `id_hi/id_lo` exactly as loaded by the handler
  (`movl $0xNNN,%esi` immediately before `call 0xf400`) **(V)**. Observed id pool for the
  IHU/HDR/audio family: `0x101…0x2b5`; for the CAN family: `0x601…0x676`; one outlier constant
  `0x9999` at `0x2681f` **(V)**.
- Replies must carry `request_id | 0x8000` (§1.5) **(V)**.
- The reader has one hard-coded diagnostic: if the first three bytes of a read are `AA 83 BB`
  (`0xd940 cmpb $-0x56` / `0xdb10 cmpb $-0x7d` / `0xdb1e cmpb $-0x45`) it logs the literal
  `read 83bb` (0x4faa8); the writer has a symmetric special case for id `0x1BB`
  (`0xe06a cmp QString::number(id,16) == "1bb"` → log `WRITE Data 01bb`, 0x4faca). These are
  **logging special cases only** — neither alters framing **(V)**.
- The **boot-info command id is (U)**. There is no id table in the binary: all 106 request handlers
  hard-code their id as an immediate, and the alphabetical/`Notify…Set…` name pools
  (daemon 0x5dc8a, 139 names; 0x60ea3, 140 names) carry names but no ids, and no
  `uint16[]` mapping array exists anywhere in the file. **The simulator does not need it** (§4.1).

### 2.4 What the daemon does *not* do

- It does not interpret any payload: no `QDBusArgument` and no `QVariant::toByteArray` import
  exists in the dynamic symbol set of `micommanager_userspace`; the only payload primitive used on
  the write path is `QVariant::toInt()` (daemon 0xdeda) **(V)**.
- It does not validate the id space, the command length, or the payload length of replies **(V)**.
- It does not time out pending requests **(V)**.

### 2.5 Consequence: the D-Bus `ay` is the firmware payload, byte for byte **(V)**

`L+4` bytes (no checksum) are emitted by the assembler, 4 are removed as header, and the reply
builder copies **all** remaining bytes into the `ay` argument
(`0xfc10…0xfc33`: loop over `0 … size-1`, `QByteArray::append`), then wraps it with
`QVariant(QByteArray)` and sends it. Hence

```
length(ay) = L = the MICOM frame length byte
```

which is confirmed externally: AppLauncher expects **35** and the observed reply size is **35**
(§1.3). The wire frame is therefore 40 bytes total.

### 2.6 Open: does the daemon ever speak first? **(U)**

In the only run in which the *authentic* daemon owned the name and was asked on the correct path
(`micommanager-serial-strace-host.log`), the harness recorded `"micom_serial_bytes": 0`
(`tools/uk_fw/vm_boot.py:413,468` counts bytes drained from the `-chardev socket` attached as
`isa-serial,chardev=micom,index=1`, `vm_boot.py:351-352`), while `AskSysBootinfo` timed out
(`ASK_RC=143`). Two readings survive the evidence:

- the daemon withholds writes until it has received at least one MICOM frame (a firmware-driven
  init/handshake), or
- the request was written but never reached the chardev (wrong fd / different device node).

The retained trace excerpt cannot separate them: the probe's `grep` filter was hard-coded to fd 8,
so a `write()` on any other descriptor is invisible in the text that was kept. **This is the
weakest link in the whole analysis**; §5.1 is the measurement that closes it. A simulator should
therefore **speak first** — it costs nothing and covers both readings.

---

## 3. The 35 bytes

### 3.1 What is verified

- Exactly **35** bytes are copied out of the reply on the launcher side (`2da17 movl $0x23,%ecx`),
  and 35 is the size of the `MICOM_STATUS_MESSAGE` object built in the launcher's constructor
  (`2b0a`), with a sibling `BOOT_INFO_STATUS` object of 115 bytes (`2b60`) **(V)**.
- The launcher's decoder (`0x2b7f0`) is a straight field extraction from the 35-byte buffer: it
  reads bytes 0…34 with the widths and bit groups listed below and writes ~135 semantic fields into
  the same object at offsets `0x3b…0x99` **(V)**.
- The 35-byte payload used in the existing simulator runs
  `00000826050000051302000003c8140000000000000000000000020001000000000000`
  decodes, in the launcher's own DLT output, to the field values in the table below
  (`…deadline-piefix-1536-evidence/launcher-chain/*.log`, the 20 `[BIS] …` lines plus the
  `[askSysBootinfo Reply size = 35]` line) **(V)**.
- `AskSysBootinfo` returns the payload unmodified, so **the 35 bytes are the MICOM firmware's
  boot-info structure, not a userspace invention** (§2.5) **(V)**.

### 3.2 Byte-level layout as far as it can be established

Read map from `app/bin/AppLauncher` `0x2b7f0` (source = byte index in the 35-byte payload,
destination = decoded field offset). Width matters: a `movl` group means the 2/4/8 bytes are one
little-endian word whose bits are then split into flags.

| Byte(s) | Width | Read at | Decoded into | Semantics (as printed by the launcher) | Confidence |
|---|---|---|---|---|---|
| 0 | 1 | `2b8b0` | 0x3b | Booting Type — `0x0 = Normal (Acc Off -> On)` | **(V)** value observed |
| 1 | 1 | `2b8a4` | 0x3c | unknown flag byte, `0x00` in the working profile | **(V)** read, **(U)** meaning |
| 2 | 1 | `2b8b7` | 0x3d = `b & 0x7`; 0xc0 = `b & 0x78`; 0xc1 = `b & 0xc0` | Buyer — `0x0 = HMC`; top bits are energy-source flags | **(V)** |
| 3 | 1 | `2b8d2` | 0x3e | Car Type — `38` (0x26) printed as `Unknown value!!` by the launcher's own table, but 0x26 selects the NE-family option row downstream | **(V)** value, **(I)** meaning |
| 4 | 1 | `2b8e5` | 0x3f | Country — `0x5 = Europe` | **(V)** |
| 5–8 | 4 (LE) | `2b8df` | 0x40…0x53 | System flags, in launcher print order: Navigation, Modem, MostAmp, RearMonitor, RadioRegion, RHD, ISRCountry (bits 0-7 of byte 8), then Limousine, Amplifier, ParkingAssist, Cluster, HUD, RearUSB (byte 7), then RRC, CDC, RearMic, DVDDeck, Clock, WIFI, ECall (byte 6) | **(V)** read map + observed log |
| 9 | 1 | `2b9f3` | 0x5d | DVD Region — `0x2 = General / M.E / Europe` | **(V)** |
| 10–11 | 2 (BE, `rolw 8` at `2b9fe`) | `2b9fa` | 0x5e | DVD Menu Language — `0` | **(V)** read, **(I)** endianness intent |
| 12 | 1 | `2ba06` | 0x60 | LCD Type — `0x3 = Type C (12.3")` | **(V)** |
| 13 | 1 | `2ba0d` | 0x61…0x6a | CarIF1 flags: AutoLight, AUX, CAMPower, Parking, ILL, ALT, IGN, ACC (bit *n* = field *n*; `0xc8` → Parking/IGN/ACC) | **(V)** |
| 14 | 1 | `2ba57` | 0x6b… | CarIF2 flags: AutoLightConnect, IGN3, DoorOpen, ParkingBrake, LowFuel, PPosition, RearGear, AutoHold (`0x14` → ParkingBrake + PPosition); **bit order not established** | **(V)** read, **(I)** bit order |
| 15, 16 | 1+1 | `2baaa`/`2baba` | 0x71, 0x72 | one of these is `Last Memory` (`0` in the working profile) | **(I)** |
| 17–24 | 8 | `2bac1` | 0x73 | ProductNo (`0`) — printed as a number | **(V)** read, **(I)** meaning |
| 25 | 1 | `2bac9` | 0x7b | ECall State (`0x0 = No ECALL` by value match) | **(I)** |
| 26 | 1 | `2bad0` | 0x7c | Language — `0x2 = English(US)` | **(V)** |
| 27 | 1 | `2bada` | 0x7d | unknown, `0` | **(U)** |
| 28 | 1 | `2bae1` | 0x7e | LastGUIMode — `1` | **(V)** |
| 29 | 1 | `2bae8` | 0x7f | TimeFormat — `0` | **(V)** value, **(I)** mapping |
| 30–33 | 4 (LE) | `2bad4` | 0x80…0x95 | Option flags: SoundMoodRamp, AMP, OutClock, HighPerformanceCar, UserProfile, USM, SEATROW, EMMC, AUX, DAB, CAN, ECall, Keyboard, RDS, RearCareMode, ClimateType, FrontClimateLCD, RearClimateLCD, Body (all 0 in the working profile) | **(V)** read, **(I)** bit order |
| 34 | 1 | `2bc15` | 0x99 | unknown last field, `0` | **(U)** |

**Explicitly not established:** the *authoritative* meaning of bytes 1, 15/16, 17-24, 27, 34, the
packing order of the multi-byte flag words, and any value that is not exercised by the working
profile. Those bytes are read but no behaviour tied to them has been observed. The launcher's
decode is the only static source for this layout; **the firmware-side definition is not in any
artifact in this workspace** (no vendor micom driver source: `work/kbuild` contains only
`linux-4.1.27.tar.xz` and the stripped `vmlinux-vendor`, and the built-in `kernel/drivers/lge/micom/micom.ko`
is listed in `lib/modules/4.1.27-abl/modules.builtin` but no `.c` exists under `work/`).

---

## 4. Minimum viable simulator

### 4.1 Two shapes, and the one to use

**(a) D-Bus-facing shim** — `tools/uk_fw/guest/micom_dbus_sim.c`, already built and proven
(`work/vm/vendor-userspace-260128/micom-contract/BOOTINFO-AND-SIM-V2.md`). Owns
`com.lge.car.micom`, answers `AskSysBootinfo` with the 35 bytes, ACKs the rest, fails closed on
unknown methods. Its one hard rule: **do not also register `dbus-com.lge.car.micom.service` in the
same boot**, or the authentic daemon will fight for the name.

**(b) Serial-facing simulator** — the same 35 bytes expressed as MICOM frames on the chardev, with
the authentic daemon left in place. This is the only variant that exercises the real transport and
therefore the only one that can be validated against the firmware. **Recommended next step.**
Algorithm, complete:

```
1. open the chardev (QEMU: -chardev socket,…,path=micom.sock  <->  -device isa-serial,chardev=micom,index=1)
2. speak first, unconditionally (see §2.6): emit one 5-byte frame, e.g. AA 82 10 00 B8
   (id 0x0210 | 0x8000, zero payload) — or simply wait for the guest's first frame and
   answer it; both are safe because the daemon only matches ids, never sequence numbers.
3. for every frame the guest sends (they are all requests, bit 0x8000 clear):
   check data[0]==0xAA and XOR(all L+5 bytes)==0;
   rid = (data[1]<<8)|data[2];  L = data[3];  payload = data[4 .. 4+L-1]
4. answer it with  id = rid|0x8000, same L and payload from your table, then the recomputed XOR
   (frames sent *to* the guest always carry bit 0x8000; frames received from the guest never do,
   because the guest is the one asking)
5. keep a per-id payload table, not a sequence: the daemon matches only the id, so an answer is
   valid at any time and may be repeated for every retry.
6. never stop answering: the daemon never times out a pending ask, so a single
   missed reply leaves that caller blocked for its own 3 s x N retries.
```

Ready-made bytes for the one payload that is known to work (request id shown only as a
placeholder; use the id the guest actually sends):

```
MW -> MICOM  AskSysBootinfo          AA xx xx 00 CS          (5 bytes, CS = AA^xx^xx^00)
MICOM -> MW                          AA (xx|0x80) xx 23 <35 bytes> CS     (40 bytes)

worked example with request id 0x0210 and the verified 35-byte profile:
  request   aa021000b8
  reply     aa821023 00000826050000051302000003c8140000000000000000000000020001000000000000 f8
            ^^^^^^ ^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ ^^
            hdr    L=35                        payload                           XOR=0xF8
```

### 4.2 The response set, in dependency order

Minimum that lets `ApplicationLauncher` proceed (order taken from §1.4's observed sequence):

| # | id | Method | Needed reply | Why it is needed |
|---|---|---|---|---|
| 1 | ? | `AskNaviOutermostRegion` | any `ay` ≥ 1 byte, e.g. `00` | asked *before* boot info; blocking it costs 3 s × retries with the authentic daemon |
| 2 | ? | **`AskSysBootinfo`** | **`ay` of exactly 35 bytes** | the launcher's field decoder reads bytes 0…34; 35 is a hard constant |
| 3 | ? | `AskCustomSetting(ay)` | `ay` ≥ len of the working answer, e.g. `00` | asked 3× at launch |
| 4 | ? | `AskSettingInfoValue` | any `ay`, e.g. `00` | asked 3× at launch |
| 5 | ? | `AskAMPSupportInfo` (audio iface) | any `ay`, e.g. `00` | asked by the audio client at launch |

`AudioManager` needs no further method of its own to *start*: `AudioManager.service:6-7` only
requires/orders on the micom unit, i.e. it needs the name to exist and to answer, not a specific
method. Its launch-blocking asks are `AskAMPSupportInfo` and `AskSoundSetupInfo` (§1.4) **(V)**
ordering, **(I)** classification as blocking vs. best-effort.

`/Can` asks (`AskCANMMCANMicomReq` with an 11-byte `CAN-ID + DLC + data` record) are **not** part of
the launch gate: navigation reaches engine success with `can0` absent
(`work/vm/vendor-userspace-260128/hmi-gap-analysis.md` §3.2) **(V)**.

**What the launch set does not cover.** Answers alone get the processes *started*; they never move
vehicle state, because every state change arrives as a MICOM→MW `Notify*` frame that the daemon
re-emits as a D-Bus signal (§1.2). For a simulator to drive IGN/ACC, day-night, gear, speed or key
events it must also inject the corresponding `Notify*` **requests on the wire** — the daemon turns an
inbound frame into a signal, not into a D-Bus method call. The exact wire id and payload of each
`Notify*` is **(U)** (§6 row 2/4); the D-Bus side of each is `out ay` and needs no discovery.

### 4.3 Provably matter vs. probably ignored

- **Provably matter** (a wrong value changes launcher behaviour, all **(V)** by read map + observed
  decode): byte 0 (boot type), byte 2 low 3 bits (buyer — this is what selects HMC vs KMC option
  tables), byte 3 (car type / `-pvv`), byte 4 (country), byte 5-8 flag word (navigation / modem /
  RHD / radio region — navigation and RHD both visibly changed downstream behaviour in the earlier
  option-row work), byte 9 (DVD region), byte 12 (LCD type; must be `3` for 1920×720), byte 13-14
  (IGN/ACC/parking: consumed by the readiness state machine), byte 26 (language), byte 28 (last GUI
  mode), byte 30-33 (option bits; the working profile leaves them 0 and the run is documented as
  producing contradictory fallbacks).
- **Probably ignored by the launch path** (read into fields that nothing in the launch decision
  consults, or that are only logged): byte 1, bytes 10-11, bytes 15-16, bytes 17-24 (ProductNo),
  byte 25, byte 27, byte 34. **This is (I)**, not (V): the launcher's `[BIS]` logs prove they are
  *copied*, not that they are *used*. Bytes 34 is at least read, so it must be present in the
  array; its value can be `00`.
- **Nothing may be omitted from the array**: the launcher copies a fixed 35 and the parser reads up
  to index 34, so a 34-byte reply would be a short read, not a graceful degradation **(V)**.

### 4.4 Failure behaviour to expect if a response is missing

With the authentic daemon: the ask is queued forever and the caller's 3 s × N retries expire
(`ASK_RC=143` pattern, `micommanager-serial-ask-host.log`) **(V)**. With the shim: the caller
proceeds with an empty `ay` and logs `[Reply null]`/`%1 Error Reply = %2` (literals at
`AppLauncher` 0x49xxx region, `[BIS] … Unknown value!!` for unset fields) **(V)**.

---

## 5. What would falsify this reading — cheapest first

### 5.1 The single observation that would most likely show the contract is different

**Capture the first bytes the authentic daemon writes to the chardev.** One run, no code change:
`tools/uk_fw/vm_boot.py --micom-serial` already writes everything the guest transmits into
`runs/<id>/micom-serial.bin`. If that file is non-empty, §2.2's framing is confirmed byte-for-byte
and the boot-info command id appears directly in `micom-serial.bin` (making §2.3's open id moot).
If it is **empty even though the D-Bus call was answered with `setDelayedReply`**, then the daemon
genuinely needs a MICOM-init frame before it will transmit — a contract term that is currently
**absent** from this document — or the tty is not the chardev (then the trace must be re-run with
the fd filter removed).

A 30-byte falsification test: `xxd -l 64 runs/<id>/micom-serial.bin`. Expected: `aa ?? ?? 00 ??`
then nothing else, or a stream of `aa …` frames. Anything whose byte 0 is not `0xAA`, or where
`XOR(all)` ≠ 0, kills §2.2.

### 5.2 Second-cheapest: a 40-byte reply the daemon accepts

Feed the daemon a single frame `aa 82 10 23 <35 bytes> f8` and then call
`dbus-send --system --print-reply --dest=com.lge.car.micom /Ihu com.lge.car.micom.ihu.AskSysBootinfo`.
If it returns 35 bytes, §1.5's `|0x8000` rule and §2.5's pass-through are both confirmed in one
step. If it returns 36 bytes (payload + checksum) then §2.5 is wrong and the `0x23` copy in the
launcher is silently discarding the last payload byte — that would invalidate §3.2 entirely.

### 5.3 Third: the compositor gate is *not* this contract

`lib/systemd/esinit:25-45` polls `/sys/module/micom/parameters/spi_validation` and, on failure,
takes the `SPI NOK` branch at `esinit:150-155`, so **weston never starts even with a perfect
`com.lge.car.micom`**. The kernel emits `lge_lcd_driver … Micom didn't sent SPI data`
(vmlinux `10967876`) because no front-display adapter registered. A userspace `echo` into that
sysfs parameter is **(I)** plausible (esinit itself writes the sibling
`/sys/module/micom/parameters/optUNECE` at `esinit:542`) but has never been tried. Any claim that
"MICOM is solved → HMI launches" must be tested against this separate gate first.

---

## 6. Open questions, ranked by what they cost the simulator

| # | Question | Status | Settles it |
|---|---|---|---|
| 1 | Does the daemon transmit before it receives? | **(U)** | §5.1 |
| 2 | The IHU command id of `AskSysBootinfo` (and of every other ask) | **(U)** — no id table exists in the binary | §5.1 (`micom-serial.bin`), or the daemon's own DLT `[writeToMicom] Ask CMD: 0x…` line |
| 3 | How an `ay` D-Bus argument is flattened onto the wire | **(U)** — the builder does `QVariant::toInt()` per argument and the binary imports no `QDBusArgument`/`toByteArray`; whether the generated handler pre-expands the array is not visible in the 106 handler bodies | one captured `SetControlKeyLock(ay 8B)` frame |
| 4 | Bytes 1, 15/16, 17-24, 25, 27, 34 semantics; bit order of bytes 14 and 30-33 | **(U)** | firmware disassembly, or a device boot-info dump |
| 5 | Meaning of the third polled descriptor | **(U)** | `strace -e trace=open,openat,poll` on the daemon |
| 6 | `0x83BB` / `0x1BB` special cases | **(V)** they are log-only; **(U)** why those ids are interesting | — (does not affect the contract) |

None of 1-6 blocks a working simulator: (1) is covered by speaking first, (2) by echoing the
received id, (3) and (4) only affect `Set*`/CAN traffic which the launch path does not gate on.

---

## 7. Reproduction of the load-bearing claims

```
R=work/decrypted-eu-260128/extracted-safe/mango-rootfs
objdump -d --start-address=0xde00 --stop-address=0xdf40 $R/app/bin/micommanager_userspace   # frame builder
objdump -d --start-address=0xd310 --stop-address=0xd4c0 $R/app/bin/micommanager_userspace   # validator
objdump -d --start-address=0xd4c0 --stop-address=0xd8f0 $R/app/bin/micommanager_userspace   # assembler
objdump -d --start-address=0x11060 --stop-address=0x111c2 $R/app/bin/micommanager_userspace # id + remove(0,4)
objdump -d --start-address=0xefc0 --stop-address=0xf210 $R/app/bin/micommanager_userspace   # |0x8000 + queue
objdump -d --start-address=0x81a1 --stop-address=0x8d00 $R/app/bin/micommanager_userspace   # registration order
objdump -d --start-address=0x2d518 --stop-address=0x2d640 $R/app/bin/AppLauncher            # the call site
objdump -d --start-address=0x2b7f0 --stop-address=0x2bc30 $R/app/bin/AppLauncher            # field decoder
objdump -d --start-address=0x2da00 --stop-address=0x2da30 $R/app/bin/AppLauncher            # 0x23 copy
strings -a -t x $R/app/bin/micommanager_userspace | awk '$1>="4f000" && $1<="4fc00"'       # literals
```

Existing workspace evidence used: `hmi-gap-analysis.md` §1-3; `micom-contract/BOOTINFO-AND-SIM-V2.md`
(simulator v2 profile and observed DLT decode); `micom-contract/PLAN.md` (the "AppLauncher-first
startup creates the 35-byte segment" result); `micom-contract/micommanager-serial-*.log`;
`micom-contract/full-chain-*-evidence/launcher-chain/micom-sim.log`;
`evidence/child-notes/04-micomd-cve-2020-8539.md` (only for the observation that the MICOM is the
CAN/head-unit-local bridge; that note describes an *Android* `/dev/socket/micomd`, a **different**
interface from this D-Bus one, and must not be cited as evidence for this contract).


## Resolution of §5.1 — the daemon transcribes first (measured 2026-10-29)

Run `work/vm/esinit-fs/runs/1793345055493857000` with `--micom-serial` on the authentic multi-user
boot captured **1056 bytes / 103 frames** on `/dev/ttyS1`, where earlier attempts recorded
`micom_serial_bytes: 0`. Both open questions in this contract are now closed by measurement:

1. **The daemon transmits before it receives.** It does not wait for a MICOM-init frame, so a passive
   peer is sufficient to reach the ask stage. The earlier zero-byte result was an artefact of the
   transcript filter, not a protocol precondition.
2. **The framing is confirmed on real traffic, not just in the validator.** All 103 frames parse as
   `AA id_hi id_lo L payload CS` with the whole-frame XOR equal to zero. Zero malformed frames.

**Empirical command-id table** (the mapping that no static table in the binary encodes):

| id | count | note |
|---|---|---|
| `0x0400` | 32 | most frequent; periodic poll candidate |
| `0x01a4` | 20 | |
| `0x029d` | 13 | |
| `0x0266` | 10 | |
| `0x0210` | 10 | |
| `0x0212` | 5 | startup burst, first three frames of the run |
| `0x0201` | 4 | |
| `0x02a3` | 3 | |
| `0x0289` | 2 | |
| `0x01aa` | 1 | carries payload `01`; boot/probe candidate |
| `0x02c3` | 1 | |
| `0x0217` | 1 | |
| `0x0110` | 1 | |

Opening order: `0x0212` ×3, `0x01aa(01)`, `0x0212` ×2, `0x02c3`, `0x0266`, `0x0201`, then a repeating
`0x0266`/`0x0201` group mixed with the high-count ids above.

**Still unestablished:** which id corresponds to `AskSysBootinfo`, and therefore which frame must carry
the 35-byte `ay` reply. The static work places `AskSysBootinfo` as the second call in the launcher's
sequence, so the pair `0x01aa (payload 01)` then the first `0x02c3` are the leading candidates. A
simulator that answers every id with a valid frame and a plausible 35-byte payload for the candidate
ids would settle this in one run by observing which `ay` the launcher's field decoder consumes.
