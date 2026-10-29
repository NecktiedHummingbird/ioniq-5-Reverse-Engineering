# AppNavi startup analysis — why a direct launch stays alive and renders nothing

Target: `/navi/Bin/AppNavi`
Rootfs: `work/decrypted-eu-260128/extracted-safe/mango-rootfs`
Build: `NE_E.EUR.S5W_L.001.001.260128`, kernel `4.1.27-abl`, x86-64
Mode: **static, read-only. No VM was booted for this analysis.** Everything below is
either read out of the shipped bytes (ELF / rootfs) or out of run logs that already
exist in the workspace.

Binary facts used throughout:

```
file: ELF 64-bit LSB shared object, x86-64, interpreter /lib/ld-linux-x86-64.so.2
BuildID[sha1]=1e0ebcdac58cb902be82f90e4df8213c3f74bafc, not stripped
sections: .text 0x4915b32 @0x144eee0, .rodata 0x92fa4f @0x5d64a40,
          .bss 0xac63b8 @0x76e8f80
symtab: 260158 defined symbols (full C++ names)
code model: file offset == vaddr for the whole AppNavi file (so VMA == file offset)
```

---

## 0. Executive answer (short form)

`AppNavi` never decides on its own "I am visible, so paint". Two pieces of state come
from **outside** the process:

1. **The ivi surface id**, which `libivi-platform-interface.so.1` takes from an
   environment variable — `QT_WAYLAND_SET_SURFACE_ID` (or `_FORCED`, or USE_PID).
   On the vehicle this is injected by **`/app/bin/AppLauncher`** before `exec()`
   (see `excerpts/23-real-vehicle-cmdline-environ.txt`). A direct launch does not have it, and
   on the VM logs the ivi surface is created under id `30000` only when it is set.
   When it is not set, the client creates a `wl_surface` and then **emits no
   `ivi_application.surface_create` at all and goes silent**
   (`excerpts/20-run-env-unset-client-protocol.log`).

2. **Compositor-driven visibility.** `IviShellSurfacePrivate::ivi_surface_visibility()`
   is the *only* thing that calls `QWindow::setVisible()` on the app window
   (`excerpts/05-libivi-ivi_surface_visibility.asm`). It fires on the
   `ivi_surface.visibility` protocol event, which the weston ivi window manager only
   sends when something issues `ivi_window_manager.set_surface_visible` /
   `set_visible_for_qtwayland` for the app's surface id. On the vehicle that something
   is ApplicationManager/launcher; in the VM the project fakes it with `/ivi-fg-navi`
   (`excerpts/22-run-env-set-no-appmgr-timeline.log`). A direct launch has neither.

Corollary that matters for the project's A/B: **ApplicationManager itself is not
required** — the existing no-AppManager probe still created an ivi surface and
attached/committed a 1920x720 buffer
(`excerpts/22-run-env-set-no-appmgr-timeline.log`). The env var and the visibility
command are the deltas that matter.

Also proven (negative results, so they can be dropped from the search):

* No command-line argument is required or gating. A launch with **no arguments at all**
  (`/navi/Bin/AppNavi`, `excerpts/20-...`) still runs the full init path
  (`NimoExSLMainLinux` → setters → `ExSLMain`); the only hard requirement is that
  `argv[0]` contains the literal `"/Bin/AppNavi"`, otherwise `NimoExSLMainLinux`
  returns 0 immediately (`excerpts/07-appnavi-NimoExSLMainLinux.asm`, `0x1ba7103`).
* `AppNavi`'s own code reads exactly **one** environment variable: `MD_CONA40_ON`
  (a map-engine debug override). There is no `APPID`, no `LAUNCHER`, no `SURFACE`
  string anywhere in the 17 MB executable.
* The 16 flags the binary understands are pure *identity/configuration*
  (`-l: -dt: -sv: -ck: -cv: -et: -sc: -dn: -vv: -gui: -nm: -by: -un: -ke: -mp: -isrcv:`).
  `-pp: -usm: -pt: -pi: -pf: -cbp: -asvr: -vc: -kt: -p2s2: -pvv: -os: -osr: -er: -is: -isa: -pitch: -cnt:`
  from the vehicle cmdline are **not parsed by AppNavi at all**.

---

## 1. Command-line parsing

### 1.1 Entry chain (proven from bytes)

`main` (0x14608f0) is a 3-instruction tail-call to `NimoExSLMainLinux(int,char**)`
(0x1ba7000). `NimoExSLMainLinux` (`excerpts/07-appnavi-NimoExSLMainLinux.asm`):

| addr | action |
|---|---|
| 0x1ba7035 | `dlt_check_library_version` |
| 0x1ba7048 | `dlt_register_app("ExSL", gen6 navi engine)` |
| 0x1ba7062 | `dlt_register_context(&mLogContext, "ExSL", "ccIC Navigation HMI Context for DLT")` |
| 0x1ba70e5 | `if (argc <= 0) return -1;` |
| 0x1ba7103 | `strstr(argv[0], "/Bin/AppNavi")` → **if NULL: return 0 immediately**, no init at all |
| 0x1ba712d | `__strncpy_chk(stack, argv[0], strlen(argv[0]) - strlen("/Bin/AppNavi"))` then `argv[0] = stack` — i.e. `argv[0]` is **rewritten to the install prefix** (`/navi`, `/navi2`) |
| 0x1ba7160 | `setPlatformInfo(std::string("LSTD5W"))` (literal built in registers: `0x4454534c`="LSTD", `0x5735`="5W") |
| 0x1ba717c..0x1ba71d1 | `setRegion`, `setECOType`, `setVendor`, `setUNECESupport`, `setIsRearMonitorExist`, `setVehicleCode`, `setDisplayType`, `setBootMicomStatus`, `setOuterMostRegion`, `createCANReceiver` — each called as `f(argc, argv)` |
| 0x1ba71db | `ExSLMain(argc, argv)` |

Strings at those call sites: `0x5dcf94c` = `"/Bin/AppNavi"`, `0x5dcf960` =
`"../../../src/NaviControlNimo/Framework/Linux/NimoExSLMainLinux.cpp"`,
`0x5dcfb18` = `"[E2E_NAVIBOOT_Perf][Start]: Linux Navi Boot"`.

`ExSLMain` (0x280cbd0, 0x60 bytes, `excerpts/11-appnavi-ExSLMain.asm`):

```
ExSLInitialize(argc, argv)              -> r
if (r > 1) { ExSLRunEventLoop(); ExSLFinalize(); }
else       { ExSLBootFailLog::SaveBootFailLogFile(); }   // and return 0
```

So a *failed* init produces a boot-fail log file and the process exits. Our process
stays alive → `ExSLInitialize` returned > 1 → init succeeded. This rules out
"initialisation refused to start" as the explanation.

### 1.2 The 16 recognised flags (proven from bytes)

All flag literals live in one contiguous blob `0x5fbddd3 .. 0x5fbde25` and are turned
into `static QString` globals by `_GLOBAL__sub_I_AppManagerComm.cpp` (0x15273c0,
`excerpts/08-appnavi-flag-qstring-init.asm`):

| literal | addr | global | symbol | consumed by |
|---|---|---|---|---|
| `-l:`  | 0x5fbddd3 | 0x7e71898 | `qsKLanguageId` | `CAppManagerComm::getLanguageId` |
| `-dt:` | 0x5fbddd7 | 0x7e71890 | `qsDisplayTypeId` | `CAppManagerComm::getDisplayType` |
| `-sv:` | 0x5fbdddc | 0x7e71888 | `qsSystemVariable` | `getSystemVariable`/`getRearLcdExist` |
| `-ck:` | 0x5fbdde1 | 0x7e71880 | `qsCustomKey` | `getCustomKey` |
| `-cv:` | 0x5fbdde6 | 0x7e71878 | `qsCountryVariant` | `getCountryVariant` |
| `-et:` | 0x5fbddeb | 0x7e71870 | `qsEcoType` | `getEcoType` |
| `-sc:` | 0x5fbddf0 | 0x7e71868 | `qsSwrcCustomKey` | `getSwrcCustomKey` |
| `-dn:` | 0x5fbddf5 | 0x7e71860 | `qsDayNightType` | `getDayNightType` |
| `-vv:` | 0x5fbddfa | 0x7e71858 | `qsVehicleVariant` | `getVehicleVariant` |
| `-gui:`| 0x5fbddff | 0x7e71850 | `qsGUIType` | `getGUIType` |
| `-nm:` | 0x5fbde05 | 0x7e71848 | `qsNModeType` | `getNModeType` |
| `-by:` | 0x5fbde0a | 0x7e71840 | `qsSTD5WVendorType` | `getVendorTypeStd5W` |
| `-un:` | 0x5fbde0f | 0x7e71838 | `qsUNECESupportType` | `getUNECESupport` |
| `-ke:` | 0x5fbde14 | 0x7e71830 | `qsEmblemType` | `getEmblemType` |
| `-mp:` | 0x5fbde19 | 0x7e71828 | `qsBuildType` | `getBuildType` |
| `-isrcv:`| 0x5fbde1e| 0x7e71820 | `qsisIslael` | `getIsIslael` |

Parser shape (`excerpts/09-appnavi-getGUIType-parser.asm`, `CAppManagerComm::getGUIType`
0x2bebaf0, identical in every sibling):

```
for (i = 0 .. argc-1) {
    QByteArray f = qsGUIType.toUtf8();            // "-gui:"
    if (strstr(argv[i], f.constData()))           // 0x144d0a0
        return strtol(argv[i] + f.size(), NULL, 10);   // 0x144b4c0
}
return <compiled-in default>;
```

Two practical consequences:

* Matching is `strstr` (substring), but the value is parsed from `argv[i] + strlen(flag)`,
  so the flag must be at offset 0 of the argument — which is how the vehicle invokes it.
* Every flag is **optional**; absence gives a compiled-in default. `-dt:` is even
  clamped: `if (v-1 > 2) v = 3;` (0x2beb133) — that is why `-dt:0` (project) and
  `-dt:4` (vehicle) behave identically.

### 1.3 What the project passes vs. what the vehicle passes

Project: `-cv:0 -vv:0 -sv:0 -dt:0 -l:0 -ck:0` (6 of 16, all zero).
Vehicle (`excerpts/23-real-vehicle-cmdline-environ.txt`):

```
/navi2/Bin/AppNavi -cv:5 -vv:38 -sv:4211 -dt:4 -l:3 -ck:0 -pp:3 -usm:1 -et:8
 -pt:128 -by:0 -pi:20 -pf:0 -cbp:1 -asvr:0 -gui:3 -sc:1 -vc:65 -kt:0 -dn:0 -nm:0
 -p2s2:1 -ke:na -pvv:0x26 -os:1 -osr:1 -un:0 -er:0 -is:0 -isa:0 -isrcv:0
 -pitch:0.1521x0.1521 -mp:1 -cnt:1
```

Flags AppNavi parses but the project omits: `-gui: -sc: -dn: -nm: -by: -un: -ke: -mp: -isrcv:`
(i.e. GUIType, SwrcCustomKey, DayNightType, NModeType, STD5WVendorType, UNECESupport,
EmblemType, BuildType, isIsrael).

**Verdict for item 1:** no flag is a render gate, and no absent flag can explain
"alive but idle". But `-gui:` (GUIType, default 0 vs vehicle 3) is the one worth
normalising, because GUIType selects HMI layout/variant resources. It is not a
startup precondition.

---

## 2. Environment variables

### 2.1 What AppNavi itself reads — exactly one variable

`nm -u` on the 143 MB executable shows only `getenv@@GLIBC_2.2.5` and
`secure_getenv@@GLIBC_2.17`, and `secure_getenv` has **zero** references. Resolving the
PLT stub for `getenv` (`0x144c330`, GOT slot `0x76a9fc8`) and scanning `.text` for
`E8 rel32` call sites gives **11** callers, and every one of them is attributable:

| caller | owner | env name |
|---|---|---|
| 0x3901a47 | `_hb_shapers_get()` | HarfBuzz internal |
| 0x3fd20f0 | `_hb_options_init()` | HarfBuzz debug flag |
| 0x40d3da3, 0x40d3db6 | `sqlite3_os_init` | SQLite internal |
| **0x44737bb, 0x447394a, 0x447395f** | **`Navi::MD::CService::InitializeMap(...)`** | **`MD_CONA40_ON`** |
| 0x4d2a954 | `curl_getenv` | curl |
| 0x5483497/0x548350f/0x5483525 | `ntlm_wb_init` | curl NTLM |

`MD_CONA40_ON` sits at `.rodata` 0x6332e47 (`excerpts/10-appnavi-getenv-MDCONA40.asm`):

```
4473944  lea  0x1ebf4fc(%rip),%rdi   # 0x6332e47  "MD_CONA40_ON"
447394b  call getenv@plt
4473950  test %rax,%rax
4473953  je   0x44739fc               ; unset -> default CONA mode
4473959  lea  0x6332e47,%rdi ; call getenv ; strtol(rax,NULL,10)
```

There is **no** `APPID`, `APP_ID`, `LAUNCHER`, `SURFACE`, `QT_WAYLAND_SET_SURFACE_ID`,
`WAYLAND_DISPLAY` or `XDG_RUNTIME_DIR` literal in AppNavi. All of those are consumed by
libraries, which is what makes a direct launch subtly different from a launcher launch.

### 2.2 What the linked libraries read (this is where the answer is)

`AppNavi` `DT_NEEDED` (28 entries) includes **`libivi-platform-interface.so.1`** and
`libivi-window-manager-api.so.1`. `usr/lib/libivi-platform-interface.so.1.0.0`
(145 KB, stripped, `.gnu_debuglink` present but no debug file shipped) is the LGE
Qt-Wayland **ivi shell integration**; `usr/lib/qt5/plugins/wayland-shell-integration/libivi.so`
is the 10 KB `QWaylandShellIntegrationPlugin` that instantiates it and links against it.

`.rodata` of `libivi-platform-interface` (0x1b060..) contains:

```
0x1b060 ivi_application
0x1b070 ivi_hmi_requester
0x1b082 QTAPP
0x1b088 surfaceId
0x1b0d8 QT_WAYLAND_SET_SURFACE_ID_FORCED
0x1b100 QT_WAYLAND_USE_PID_FOR_SURFACE_ID
0x1b122 QT_WAYLAND_SET_SURFACE_ID
0x1b158 LGE_QT_WAYLAND_VISIBILITY_CALLBACK_FILTER
0x1b1c3 appId
```

Complete inventory across the reachable ELFs: `excerpts/30-envvar-inventory.txt`.

### 2.3 Exact behaviour when each variable is unset (proven, `excerpts/01`, `02`, `05`, `06`)

`IviShellPrivate::getSurfaceIdFromEnvValue(bool& flag)` — 0x13a50:

```
flag = false;
if (qEnvironmentVariableIsSet("QT_WAYLAND_SET_SURFACE_ID_FORCED"))
        return qgetenv(...).toInt();                     // flag stays false
if (qEnvironmentVariableIsSet("QT_WAYLAND_USE_PID_FOR_SURFACE_ID")) {
        flag = true;  return QCoreApplication::applicationPid() + <base>; }
if (qEnvironmentVariableIsSet("QT_WAYLAND_SET_SURFACE_ID")) {
        flag = true;  return qgetenv(...).toInt() + <base>; }   // <base> = dword at .bss 0x2231c0
return 0;                                                // flag false
```

`isNeedToGetSurfaceIdFromEnvValue(unsigned& out)` — 0x13bb0: `return id != 0`, with
`out = id`.

`IviShellIntegration::createShellSurface(QWaylandWindow*, QString appId)` — 0x133a0:

```
if (!isNeedToGetSurfaceIdFromEnvValue(&id)) {                 // env NOT set
    if (m_requester /*0x18*/) {                               // ivi_hmi_requester bound
        r = m_requester->requestId(window, QString("QTAPP")); // ivi_hmi_requester.request_id
        id = waitForGetSurfaceId(r);                          // <-- BLOCKING
    } else {
        id = 0;  r = 0;
    }
} else {                                                      // env set
    if (m_requester) {
        r = m_requester->reserveId(window, 1, id);             // ivi_hmi_requester.reserve_id
        id = waitForGetSurfaceId(r);                          // <-- BLOCKING
    }
}
return IviShellPrivate::createShellSurface(window, id);
```

`IviShellIntegration::waitForGetSurfaceId(HmiReceiver* r)` — 0x13340
(`excerpts/03`):

```
display->flushRequests();
if (!r) return 0;
while (r->id /*offset 0x20*/ == 0)
        display->blockingReadEvents();        // QWaylandDisplay::blockingReadEvents()
return r->id;
```

and `HmiReceiver::ivi_hmi_receiver_receive_id(unsigned id)` is the only writer of that
field: `movl %esi, 0x20(%rdi)` (0x157fb). So the loop exits only on an
`ivi_hmi_receiver.receive_id` event.

**Consequence chain when `QT_WAYLAND_SET_SURFACE_ID*` are unset:**

* `m_requester` is NULL unless the client bound the `ivi_hmi_requester` global.
  In the recorded env-unset run the client **did not bind it** (registry announced
  global 14 `ivi_hmi_requester` at t=13376.198 and the client bound only 12
  `ivi_application` and 17 `ivi_controller`), so the code takes `id = 0`,
  no blocking, and calls `IviShellPrivate::createShellSurface(window, 0)`.
* If `m_requester` *is* bound, the client sends `ivi_hmi_requester.request_id("QTAPP")`
  and then parks in `blockingReadEvents()` until the compositor answers with
  `receive_id`. A compositor/module that does not implement `request_id` produces an
  indefinite, silent block — alive, no surface, no log.
* The observed VM run is the first case: it created a `wl_surface` at t=13425.514 and
  then emitted **nothing further for the remaining 120 s** — no
  `ivi_application.surface_create`, i.e. no ivi surface at all, and therefore nothing
  for the ivi shell to map, configure or make visible
  (`excerpts/20-run-env-unset-client-protocol.log`).

When the variable **is** set to `3000`, the same code path produces
`ivi_application.surface_create(30000, wl_surface, ivi_surface)` and then
`attach` + `damage(0,0,1920,720)` + `commit` (`excerpts/22-...`).

### 2.4 Variables whose absence has a *different* symptom (so they are not our bug)

* `XDG_RUNTIME_DIR` unset → `libwayland-client` prints
  `error: XDG_RUNTIME_DIR not set in the environment.` and `wl_display_connect()`
  returns NULL → Qt cannot init the `wayland` platform plugin → the app aborts.
  Our app stays alive, so this was set.
* `WAYLAND_DISPLAY` unset → socket `wayland-0` default inside `$XDG_RUNTIME_DIR`;
  wrong value → same abort path.
* `QT_QPA_PLATFORM` unset → Qt defaults to `xcb` → no libqxcb in this rootfs
  (`usr/lib/qt5/plugins/platforms/` has only `eglfs/minimal/minimalegl/offscreen/qwayland-*`)
  → abort.
* `QT_WAYLAND_SHELL_INTEGRATION` unset → no `libivi.so` shell-integration plugin is
  loaded, so `libivi-platform-interface` is never instantiated and the window falls
  back to whatever default shell the Qt Wayland client provides. Against a
  `shell=ivi-shell.so` compositor that has no xdg-shell this cannot produce a mapped
  surface. **Note:** in every recorded working run this was set to `ivi`, so this is a
  candidate but not a proven difference.
* `APPID` — **not read by AppNavi, not read by libivi-platform-interface**. It is set
  *by* `app/bin/AppLauncher`, which also sets `QT_WAYLAND_SET_SURFACE_ID` and logs
  `"AppID : %1, Set to QT_WAYLAND_SET_SURFACE_ID=%2"`. The real vehicle therefore
  carries `APPID=30` *and* `QT_WAYLAND_SET_SURFACE_ID=3000` because the launcher put
  them there; a direct launch has neither. `APPID` itself is not a requirement.
* `LGE_QT_WAYLAND_VISIBILITY_CALLBACK_FILTER` — read inside
  `IviShellSurfacePrivate::ivi_surface_visibility` (0x140b6); it only selects whether
  repeated `setVisible()` calls are latched (flag at `this+0x29`). Both branches still
  call `QWindow::setVisible()`; it is not a gate.
* `MD_CONA40_ON` — unset takes the default branch at 0x44739fc; no behavioural risk.

---

## 3. Startup preconditions (files, sockets, shared memory, DBus)

Read-only scan of the executable's `.rodata` for absolute paths under `/tmp`, `/run`,
`/var/run`, `/dev/shm` (`strings -a -n 3`):

```
/tmp/volumeInfo          /tmp/GUI_THEME_DAY        /tmp/GUI_THEME_NIGHT
/tmp/navi_encryptionfile.txt  /tmp/navi_decryptionfile.txt
/tmp/libtse/libtse.so    /tmp/UserRouteVocRequest.bin   /tmp/TITAgent.bin
/tmp/requestCenterRoute.bin /tmp/requestCenterRouteNI.bin
/tmp/reqls2gisdata.json  /tmp/RequestMCSA..D.json
/etc/version.txt
```

Nothing under `/dev/shm`, nothing under `/run`, and **no `/tmp/front_lcd.png`** string
in AppNavi (that symlink is created by the probe scripts and belongs to
ApplicationManager/HomeScreen, not AppNavi). None of these are opened before the
window: they are route/encryption/theme artefacts touched after the UI exists.

DBus service/method names present in AppNavi's `.rodata` (selected):

```
com.lge.avn.applauncher            com.lge.avn.applauncher.inform   /Inform   "launched"
com.lge.hyundai.avn.appmanager     com.lge.avn.appmanager.appbase  com.lge.avn.appmanager.info
com.lge.hkmc.avn.appnavi           /com/lge/hkmc/avn/appnavi       com.lge.hkmc.avn.appnavi.naviboot
com.lge.hkmc.avn.appnavi.loadingstate       com.lge.hkmc.avn.appnavi.thumbnail
com.lge.avn.appmanager.screentransition     com.lge.car.micom*
```

Because the environment host is a session bus that is started by the probe before the
app, DBus *connection* is not the issue; the only blocking DBus calls in the whole
binary are two registration calls (see §4), and the no-AppManager run shows they are
survivable.

Shared memory / device preconditions are ordinary EGL/Wayland: `/dev/dri/card0`,
`/dev/shm` buffers, `wl_shm` — the vehicle `/proc/<pid>/maps` shows
`/drm mm object`, `/dev/dri/card0`, `SYSV0000112c (deleted)` and the two fonts
`/app/share/fonts/New_HD2.1_{Medium,Regular}.ttf`.

---

## 4. Blocking waits

Three distinct wait primitives exist; only the first two are on the startup path.

**(a) The ivi surface-id handshake — `QWaylandDisplay::blockingReadEvents()`**

`excerpts/03-libivi-waitForGetSurfaceId.asm`:

```
13360  call QWaylandDisplay::flushRequests()
13365  test %rbx,%rbx ; je return 0          ; no receiver -> returns immediately
13379  mov 0x20(%rbx),%eax ; test %eax,%eax
1337e  je  0x13370  -> call QWaylandDisplay::blockingReadEvents()   ; uncapped loop
```

This is an uncapped `poll()` loop inside Qt's Wayland display. It ends only when
`ivi_hmi_receiver.receive_id(id)` arrives. This is the single place where AppNavi can
become permanently, silently idle *before* creating its ivi surface.

**(b) ApplicationManager registration — synchronous DBus**

`QDBusPendingCallWatcher::waitForFinished` (PLT 0x144be20) has exactly two callers:

```
0x2bf5419  CAppManagerComm::SendToAppManagerRegistrationMapFront()
0x2bf6289  CAppManagerComm::SendToAppManagerRegistrationMenuFront()
```

and `QDBusPendingCall::waitForFinished` (PLT 0x144b360) one caller,
`QDBusReply<int>::QDBusReply<int>(...)` at 0x2c2a42c.
These are *bounded*: with no ApplicationManager the bus returns
`org.freedesktop.DBus.Error.ServiceUnknown` immediately, and with a live
ApplicationManager the call returns normally — the no-AppManager run completed them and
still rendered. Also there is no "wait for the launcher to say `launched`" gate:
AppNavi *sends* `launched` to `com.lge.avn.applauncher /Inform`.

**(c) `nanosleep` / `poll` / `select` / `QWaitCondition`**

`nanosleep@GLIBC`, `poll@GLIBC`, `select@GLIBC`, `QWaitCondition::wait(QMutex*,unsigned long)`
are all imported, but they are used by worker threads (CAN receiver, map engine,
audio) and by Qt, not as a pre-render gate. No `QEventLoop::exec` appears in a
startup-critical path.

**(d) The visibility callback is *not* a wait, it is the missing trigger**

`IviShellSurfacePrivate::ivi_surface_visibility(int visible)` (0x140b0,
`excerpts/05`):

```
if (this->state /*0x28*/ == visible) return;
filter = qgetenv("LGE_QT_WAYLAND_VISIBILITY_CALLBACK_FILTER").toInt();
if (filter != 0 && this->applied /*0x29*/) return;      // latch
this->state = (visible != 0);
QWindow::setVisible( QPlatformWindow::window(this), visible );   // 0x144c10
IviShellSurface::visibility_changed(visible);
this->applied = 1;
```

`QWindow::setVisible` is the *only* way the app's QQuickWindow ever becomes visible,
and it is reached only from the `ivi_surface.visibility` protocol event. So the app
paints only after the compositor's window manager is told
`set_surface_visible(surface_id, 1)` / `set_visible_for_qtwayland(surface_id, 1)`.
`usr/share/ivi-window-manager/ivi-window-manager.xml` documents exactly these requests
(`set_surface_visible`, `set_surface_layout`, `set_visible_for_qtwayland` —
"Set visible from qtwayland. Do not use on App side", `request_fg`).

**No DBus interface/method is awaited before painting.** The thing that is awaited is a
*Wayland* reply: interface `ivi_hmi_requester`, requests `request_id`/`reserve_id`,
event `ivi_hmi_receiver.receive_id` (for the id), and later
`ivi_surface.visibility` (for visibility). Both are generated by the compositor's
`ivi-window-manager.so`, which in turn is driven by ApplicationManager via the
`ivi_window_manager` protocol.

---

## 5. Working launch vs. direct launch

`diff -u appnavi-wayland-probe.sh appnavi-render-probe.sh` (both already in
`work/vm/vendor-userspace-260128/`) isolates the deltas. The failing side launched
`/navi/Bin/AppNavi` **with no arguments** from cwd `/navi/Bin`; the working side:

| delta | working value | failing value |
|---|---|---|
| `QT_WAYLAND_SET_SURFACE_ID` | `3000` (exported just before launch) | **unset** |
| `QT_WAYLAND_SHELL_INTEGRATION` | `ivi` | `ivi` (same) |
| cwd | `/navi/navi/Bin` | `/navi/Bin` |
| `/navi/navi` | `ln -s . /navi/navi` created first | not created |
| ApplicationManager | started (and explicitly `env -u QT_WAYLAND_SET_SURFACE_ID`) | not started |
| foreground/visibility driver | `/ivi-fg-navi` every 10 s | absent |
| args | `-cv:0 -vv:0 -sv:0 -dt:0 -l:0 -ck:0` | none |
| `WAYLAND_DEBUG` | `1` | `1` |

Outcome, from the existing logs:

* env set, no ApplicationManager (`excerpts/22-...`):
  ```
  ivi_application surface_create(30000, wl_surface@3, ivi_surface@7)
  wl_surface@3.attach(wl_buffer@9, 0, 0)
  wl_surface@3.damage(0, 0, 1920, 720)
  wl_surface@3.commit()
  [00:00:08.083] Surface id(30000), Weston surface W(1920), H(720)
  ivi_controller@13.surface(30000)
  ivi_window_manager@3.set_surface_layout(3000, 0, 0, 1920, 720)
  ivi_window_manager@3.set_surface_visible(3000, 1)
  ivi_window_manager@3.set_visible_for_qtwayland(3000, 1)
  ivi_window_manager@3.request_fg(1, 3000)
  ```
  → ApplicationManager is **not** required for surface creation or for the first
  commit. This is a proven negative result and eliminates candidate "waits for
  ApplicationManager".

* env unset (`excerpts/20-...`): `wl_compositor.create_surface(wl_surface@15)` at
  t=13425.514, then 120 s of complete silence: no `ivi_application.surface_create`,
  no `attach`, no `commit`. The process was alive in `ps`. This is precisely the
  reported symptom.

### 5.1 One open number (flagged, not proven)

The working logs show the ivi surface created with id **30000**, while the visibility
helper `/ivi-fg-navi` (repo-authored, `ivi-fg-navi-build/ivi_fg_navi.S`) programmes
**3000**:

```
/* ivi_window_manager.set_surface_layout(3000, 0, 0, 1920, 720) */
/* set_surface_visible(3000, true) */
/* set_visible_for_qtwayland(3000, true) */
/* request_fg(display_plane=1, surface_id=3000) */
```

The code adds a base word kept at `.bss 0x2231c0` (in `libivi-platform-interface`) to
the environment value, and increments it by 1 per additional surface
(`excerpts/04`, 0x13c36). That word is `.bss` (NOBITS, so 0 at load) and a full
rip-relative scan finds only two references to it — the read and the increment — so the
origin of the `30000`-instead-of-`3000` offset is **not** established statically.
Consequence: the visibility commands may be addressing an id the surface does not have,
which would explain the project's byte-identical A/B screenshot **even in the
"working" configuration**. Treat as hypothesis H3 below.

---

## 6. Ordered candidate causes

Legend: **[P]** proven from shipped bytes (with address/string), **[R]** proven from a
recorded run log, **[I]** inferred.

| # | cause | evidence | confidence |
|---|---|---|---|
| **C1** | `QT_WAYLAND_SET_SURFACE_ID` (+`_FORCED`, `QT_WAYLAND_USE_PID_FOR_SURFACE_ID`) not set → no ivi surface id at startup; the client either creates the ivi surface with id 0 or blocks in `waitForGetSurfaceId` waiting for `ivi_hmi_receiver.receive_id`, and in the recorded case emits **no** `ivi_application.surface_create` at all, then goes idle. The vehicle gets this variable from `AppLauncher`. | **[P]** `libivi-platform-interface` 0x13a50 / 0x13bb0 / 0x133a0 / 0x13340 / 0x157fb; strings at 0x1b0d8/0x1b100/0x1b122. **[R]** `excerpts/20` vs `excerpts/22`. **[P]** AppLauncher string `"AppID : %1, Set to QT_WAYLAND_SET_SURFACE_ID=%2"`. **[P]** AppNavi/libivi/Qt contain no such env string. | very high |
| **C2** | Nothing drives compositor-side visibility. `QWindow::setVisible(true)` is reachable only from `IviShellSurfacePrivate::ivi_surface_visibility()`, i.e. only on `ivi_surface.visibility` events, which the ivi window manager emits only after `ivi_window_manager.set_surface_visible` / `set_visible_for_qtwayland` for that surface id. A direct launch has no ApplicationManager/launcher to issue them. | **[P]** 0x140b0 (`excerpts/05`); `usr/share/ivi-window-manager/ivi-window-manager.xml`; **[R]** the `/ivi-fg-navi` calls in `excerpts/22`. | high (mechanism), medium (that it blocks the *first* frame — the no-appmgr run did commit one frame) |
| **C3** | Surface-id space mismatch: the app's ivi surface is 30000 while everything the window manager is told about uses 3000 → even when AppNavi commits a full-screen buffer, the surface is never laid out/visible → the compositor framebuffer is unchanged (explains the byte-identical A/B). | **[R]** `surface_create(30000)` and `ivi_controller@13.surface(30000)` vs `set_surface_layout(3000)`/`set_surface_visible(3000)`/`request_fg(1,3000)`; **[P]** `/ivi-fg-navi` hard-codes 3000; base word origin unresolved (§5.1). | medium |
| **C4** | `QT_WAYLAND_SHELL_INTEGRATION=ivi` missing → `usr/lib/qt5/plugins/wayland-shell-integration/libivi.so` never loaded → no ivi_surface against an ivi-shell-only compositor. | **[P]** `libivi.so` NEEDED `libivi-platform-interface.so.1`, plugin class `IviShellIntegrationPlugin`; **[P]** rootfs has only wayland platform plugins. | medium — not observed as the difference in any recorded run |
| **C5** | Launch context: cwd `/navi/Bin` instead of `/navi/navi/Bin`, and `/navi/navi` symlink absent; `LD_LIBRARY_PATH` missing `/navi/Lib`. | **[P]** probes create `ln -s . /navi/navi`; vehicle cmdline `/navi2/Bin/AppNavi` with `LD_LIBRARY_PATH=...:/navi/navi/Lib`; `NimoExSLMainLinux` rewrites `argv[0]` to the install prefix. | low — would cause load/asset failures, not a silent idle |
| **C6** | Missing/zero CLI flags (`-gui: -dt: -sc: -dn: -nm: -by: -un: -ke: -mp:`) produce a different HMI variant than the vehicle (`-gui:3`). | **[P]** §1.2/§1.3. | low — identity/variant only, cannot stop surface creation |
| **C7** | ApplicationManager absent (blocking DBus registration). | **[R]** disproved: the no-AppManager run committed a full-screen buffer; blocking calls are bounded. | ruled out |
| **C8** | No argument / argc==1. | **[P]** `NimoExSLMainLinux` only rejects `argc<=0`; the failing evidence run used zero arguments and still initialised. | ruled out |
| **C9** | `argv[0]` not containing `"/Bin/AppNavi"` → immediate `return 0`. Note this yields *exit*, not idle. | **[P]** 0x1ba7103/0x1ba7208. | ruled out for this symptom |

---

## 7. Recommended cheapest test (single command)

Distinguish **C1/C3 (id supply)** from **C2 (visibility)** in one boot of the
already-built headless VM, with no code change:

```sh
# same weston/weston.ini as appnavi-render-no-appmgr-probe.sh, no ApplicationManager,
# no /ivi-fg-navi, WAYLAND_DEBUG=1 on both sides
cd /navi/navi/Bin
QT_WAYLAND_SET_SURFACE_ID=3000 /navi/Bin/AppNavi \
        -cv:5 -vv:38 -sv:4211 -dt:4 -l:3 -ck:0 -gui:3 -sc:1 2>/tmp/A.log &
sleep 20
grep -E 'surface_create|attach|commit|ivi_surface@' /tmp/A.log   # client side
grep -E 'surface_create|Surface id|set_surface' /tmp/weston.log  # compositor side
```

* If `ivi_application.surface_create(<N>, wl_surface@X, ivi_surface@Y)` appears and
  `N` is **30000** while the helper/fg path uses `3000` → **C3 confirmed**; the fix is
  to drive visibility with the id the surface actually got (or set
  `QT_WAYLAND_USE_PID_FOR_SURFACE_ID`/`_FORCED` to a value whose base is 0). Re-run
  `/ivi-fg-navi` with `30000` substituted and take a screenshot: if pixels appear, C3
  is proven and C2 is confirmed as the remaining gate.
* If no `surface_create` appears at all and the client log stops right after
  `wl_compositor.create_surface` → **C1 confirmed** (the id handshake is where it
  parks); the fix is to always export `QT_WAYLAND_SET_SURFACE_ID` before launching,
  exactly as `AppLauncher` does.
* If `surface_create` appears with the *same* id the helper uses and pixels still do
  not appear, the remaining suspect is C2 (visibility) and the test becomes: issue
  `ivi_window_manager.set_surface_visible(<id>,1)` +
  `set_visible_for_qtwayland(<id>,1)` + `request_fg(1,<id>)` and watch for a second
  `attach/commit` in the client log.

A cheaper zero-boot variant, if the goal is only to confirm C1 as *the* missing
launch-time input: `/app/bin/AppLauncher` is the component that sets both `APPID` and
`QT_WAYLAND_SET_SURFACE_ID` (`"AppID : %1, Set to QT_WAYLAND_SET_SURFACE_ID=%2"`), so
launching AppNavi through AppLauncher (or via its cgroup
`/system.slice/ApplicationLauncher.service`, as on the vehicle) restores C1 by
construction.

---

## 8. Proven vs inferred — one-line summary

* **Proven from bytes:** the argv contract (`"/Bin/AppNavi"` substring, `argc>0`); the
  16 flags and their globals and their `strstr`+`strtol` parser; `getenv` call sites
  and the single app-level variable `MD_CONA40_ON`; the whole
  `libivi-platform-interface` surface-id and visibility logic including the exact
  blocking loop and the exact field polled; the absence of `APPID`/`QT_WAYLAND_SET_SURFACE_ID`
  from AppNavi itself.
* **Proven from existing run logs:** with the variable set, an ivi surface is created
  and a full-screen buffer committed *without* ApplicationManager; with it unset, the
  client creates a bare `wl_surface` and then emits nothing for 120 s while staying
  alive.
* **Inferred / open:** whether the unset case blocks in
  `QWaylandDisplay::blockingReadEvents()` or simply produces id 0 (depends on whether
  `ivi_hmi_requester` was bound — it was not bound in the recorded run); the origin of
  the `27000`-style base added to the env value that turns `3000` into `30000`, and
  therefore whether C3 (id-space mismatch) is the reason the project's A/B screenshot
  is byte-identical even in its "working" configuration.

No VM was executed and no rootfs file was modified for this analysis.

---

## 9. Artifacts in this directory

```
report.md                                    this file
excerpts/01-libivi-getSurfaceIdFromEnvValue.asm       0x13a50  env -> surface id
excerpts/02-libivi-IviShellIntegration-createShellSurface.asm  0x133a0  the fork + wait
excerpts/03-libivi-waitForGetSurfaceId.asm            0x13340  blockingReadEvents loop
excerpts/04-libivi-IviShellPrivate-createShellSurface.asm      0x13c00  wl_proxy_marshal_constructor(surface_create)
excerpts/05-libivi-ivi_surface_visibility.asm         0x140b0  QWindow::setVisible from ivi event
excerpts/06-libivi-initialize-registry_global.asm     0x13170  binds ivi_application / ivi_hmi_requester
excerpts/07-appnavi-NimoExSLMainLinux.asm             0x1ba7000  argv[0] gate + init order
excerpts/08-appnavi-flag-qstring-init.asm             0x15273c0  16 flag literals -> QString globals
excerpts/09-appnavi-getGUIType-parser.asm             0x2bebaf0  strstr + strtol parser shape
excerpts/10-appnavi-getenv-MDCONA40.asm               0x4473944  the only app-level getenv
excerpts/11-appnavi-ExSLMain.asm                      0x280cbd0  init -> event loop or boot-fail
excerpts/20-run-env-unset-client-protocol.log         client WAYLAND_DEBUG, QT_WAYLAND_SET_SURFACE_ID unset
excerpts/21-run-env-unset-weston.log                  compositor side, same run
excerpts/22-run-env-set-no-appmgr-timeline.log        working run without ApplicationManager
excerpts/23-real-vehicle-cmdline-environ.txt          real vehicle /proc/<pid>/cmdline + environ
excerpts/30-envvar-inventory.txt                      which ELF contains which env-var name
tools/vma.py           VMA-aware string/byte reader (no external deps)
tools/xref.py          rip-relative disp32 scanner (numpy) for "who references this address"
tools/importxref.py    PLT/GOT resolver for "who calls this imported function"
tools/whichfn.py       address -> enclosing symbol
tools/make-symbols.sh  regenerates the 28 MB nm dump used by whichfn.py (not checked in)
```

All tools are read-only and take the binary path from `$APPNAVI` (default: the
recovered rootfs copy).
