#!/usr/bin/env python3
"""Emit and parse a read-only disconnected-bench state probe.

The emitted POSIX-shell program prints evidence to stdout only.  It does not
mount filesystems, start services, change radio state, write target files, or
send network traffic.  Capture stdout through an existing console and parse it
on the analyst host::

    python3 tools/uk_fw/bench_state_bundle.py emit -o work/bench/state-probe.sh
    # Review state-probe.sh, then run it on the isolated owner-controlled bench.
    python3 tools/uk_fw/bench_state_bundle.py parse work/bench/state.log \
        --json work/bench/state.json

The parser never executes capture contents.  Missing files and commands are
expected on old embedded images and are retained as evidence records.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable, Optional

SCHEMA = "ioniq-bench-state/v1"
MARKER = "@@IONIQ_BENCH_STATE_V1"
SAFE_ENVIRON_READ_LINE = r'''P_ENV_TEXT=$(tr '\000' '\n' < "$P_DIR/environ" 2>/dev/null); P_ENV_STATUS=$?; P_PATH=$(printf '%s\n' "$P_ENV_TEXT" | awk -F= '$1 == "PATH" { sub(/^PATH=/, ""); print; exit }' 2>/dev/null); P_PATH_STATUS=$?'''
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_SECTION_BYTES = 8 * 1024 * 1024
EXPECTED_SECTIONS = (
    "meta",
    "identity",
    "processes",
    "smack",
    "units",
    "interfaces",
    "cellular",
    "bluetooth",
    "dropbear",
    "storage",
    "hashes",
    "complete",
)
SERIAL_PREFIX_RE = re.compile(r"^\[[0-9:.]+\]\s?")
ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
BEGIN_RE = re.compile(r"^@@IONIQ_BENCH_STATE_V1\|BEGIN\|([a-z0-9_-]+)@@$")
END_RE = re.compile(r"^@@IONIQ_BENCH_STATE_V1\|END\|([a-z0-9_-]+)\|([0-9]+)@@$")
RECORD_PREFIX = "@@R|"

# The audit is deliberately stricter than shell syntax.  Every emitted probe is
# checked before it is printed or written on the host.
FORBIDDEN_LINE_PATTERNS = (
    re.compile(r"(?:^|[\s;&|()])(?:mount|umount|mountpoint)\b"),
    re.compile(r"\bsystemctl\s+(?:start|stop|restart|reload|enable|disable|mask|unmask)\b"),
    re.compile(r"(?:^|[\s;&|()])(?:service|kill|pkill|killall|reboot|poweroff|halt)\b"),
    re.compile(r"(?:^|[\s;&|()])(?:rm|mv|cp|install|touch|mkdir|mktemp|truncate|dd|tee)\b"),
    re.compile(r"(?:^|[\s;&|()])(?:curl|wget|nc|ncat|socat|ssh|scp|ftp|tftp)\b"),
    re.compile(r"(?:^|[\s;&|()])(?:apt|apt-get|dnf|yum|rpm|opkg|apk|pip|pip3)\b"),
    re.compile(r"\bwpa_cli\b"),
    re.compile(r"\biw\s+.*\b(?:scan|connect|disconnect|set)\b"),
    re.compile(r"\bbluetoothctl\b"),
    re.compile(r"\b(?:qmicli|mbimcli|mmcli)\b"),
)

PROBE_SCRIPT = r'''#!/bin/sh

COLLECT_FAILURE=0

has_command() {
    command -v "$1" >/dev/null 2>&1
}

begin_section() {
    printf '@@IONIQ_BENCH_STATE_V1|BEGIN|%s@@\n' "$1"
}

end_section() {
    printf '@@IONIQ_BENCH_STATE_V1|END|%s|%s@@\n' "$1" "$2"
}

record() {
    R_KEY=$1
    shift
    R_OD_VALUE=$(printf '%s' "$*" | od -A n -t x1 -v 2>/dev/null)
    R_OD_STATUS=$?
    R_VALUE=$(printf '%s' "$R_OD_VALUE" | tr -d ' \011\015\012' 2>/dev/null)
    R_TR_STATUS=$?
    if [ "$R_OD_STATUS" -ne 0 ] || [ "$R_TR_STATUS" -ne 0 ]; then
        COLLECT_FAILURE=1
        printf '@@R|fatal|7265636f72642d656e636f64652d6572726f72\n'
        return
    fi
    printf '@@R|%s|%s\n' "$R_KEY" "$R_VALUE"
}

read_scalar() {
    RS_LABEL=$1
    RS_PATH=$2
    RS_VALUE=
    RS_STATE=absent
    if [ ! -e "$RS_PATH" ] && [ ! -L "$RS_PATH" ]; then
        record missing-file "$RS_PATH"
        return
    fi
    if [ ! -r "$RS_PATH" ]; then
        record unreadable-file "$RS_LABEL|$RS_PATH"
        COLLECT_FAILURE=1
        RS_STATE=error
        return
    fi
    RS_VALUE=$(cat "$RS_PATH" 2>/dev/null)
    RS_STATUS=$?
    if [ "$RS_STATUS" -ne 0 ]; then
        record file-read-error "$RS_LABEL|$RS_PATH|$RS_STATUS"
        COLLECT_FAILURE=1
        RS_VALUE=
        RS_STATE=error
        return
    fi
    RS_STATE=present
}

read_link_value() {
    RL_LABEL=$1
    RL_PATH=$2
    RL_VALUE=
    RL_STATE=absent
    if [ ! -L "$RL_PATH" ]; then
        return
    fi
    if ! has_command readlink; then
        record file-link-unavailable "$RL_LABEL|$RL_PATH"
        RL_STATE=unavailable
        return
    fi
    RL_VALUE=$(readlink "$RL_PATH" 2>/dev/null)
    RL_STATUS=$?
    if [ "$RL_STATUS" -ne 0 ]; then
        record file-link-error "$RL_LABEL|$RL_PATH|$RL_STATUS"
        COLLECT_FAILURE=1
        RL_VALUE=
        RL_STATE=error
        return
    fi
    RL_STATE=present
}

capture_file() {
    CF_LABEL=$1
    CF_PATH=$2
    if [ ! -e "$CF_PATH" ] && [ ! -L "$CF_PATH" ]; then
        record missing-file "$CF_PATH"
        return
    fi
    if [ ! -r "$CF_PATH" ]; then
        record unreadable-file "$CF_PATH"
        COLLECT_FAILURE=1
        return
    fi
    if has_command awk; then
        CF_VALUE=$(awk '{ gsub(/[\t\r]/, " "); print }' "$CF_PATH" 2>/dev/null)
    else
        CF_VALUE=$(cat "$CF_PATH" 2>/dev/null)
    fi
    CF_STATUS=$?
    if [ "$CF_STATUS" -ne 0 ]; then
        record file-read-error "$CF_PATH|$CF_STATUS"
        COLLECT_FAILURE=1
        return
    fi
    if [ -n "$CF_VALUE" ]; then
        while IFS= read -r CF_LINE
        do
            record "$CF_LABEL" "$CF_LINE"
        done <<IONIQ_CAPTURE_FILE_LINES
$CF_VALUE
IONIQ_CAPTURE_FILE_LINES
    else
        record "$CF_LABEL" ""
    fi
}

file_meta() {
    FM_PATH=$1
    if [ -e "$FM_PATH" ] || [ -L "$FM_PATH" ]; then
        FM_META=unavailable
        FM_STATUS=0
        if has_command stat; then
            FM_META=$(stat -c '%a|%u|%g|%s|%F' "$FM_PATH" 2>/dev/null)
            FM_STATUS=$?
        elif has_command ls; then
            FM_META=$(ls -ldn "$FM_PATH" 2>/dev/null)
            FM_STATUS=$?
        else
            record file-meta-unavailable "$FM_PATH"
        fi
        if [ "$FM_STATUS" -ne 0 ] || [ -z "$FM_META" ]; then
            record file-meta-error "$FM_PATH|$FM_STATUS"
            COLLECT_FAILURE=1
            return
        fi
        FM_LINK=
        if [ -L "$FM_PATH" ]; then
            if ! has_command readlink; then
                FM_LINK=unavailable
                record file-link-unavailable "$FM_PATH"
            else
                FM_LINK=$(readlink "$FM_PATH" 2>/dev/null)
                FM_STATUS=$?
                if [ "$FM_STATUS" -ne 0 ]; then
                    record file-link-error "$FM_PATH|$FM_STATUS"
                    COLLECT_FAILURE=1
                    return
                fi
            fi
        fi
        record file "$FM_PATH|present|$FM_META|$FM_LINK"
    else
        record file "$FM_PATH|absent"
    fi
}

hash_file() {
    H_PATH=$1
    if [ ! -e "$H_PATH" ] && [ ! -L "$H_PATH" ]; then
        record hash "$H_PATH|absent"
        return
    fi
    if [ ! -f "$H_PATH" ]; then
        record hash-error "$H_PATH|not-regular"
        COLLECT_FAILURE=1
        return
    fi
    if [ ! -r "$H_PATH" ]; then
        record hash-error "$H_PATH|unreadable"
        COLLECT_FAILURE=1
        return
    fi
    H_PROVIDER=
    if has_command sha256sum; then
        H_PROVIDER=sha256sum
        H_VALUE=$(sha256sum "$H_PATH" 2>/dev/null)
        H_STATUS=$?
        H_DIGEST=${H_VALUE%% *}
    elif has_command openssl; then
        H_PROVIDER=openssl
        H_VALUE=$(openssl dgst -sha256 "$H_PATH" 2>/dev/null)
        H_STATUS=$?
        H_DIGEST=${H_VALUE##* }
    else
        record hash "$H_PATH|unavailable"
        return
    fi
    H_NONHEX=$(printf '%s' "$H_DIGEST" | tr -d '0123456789abcdefABCDEF' 2>/dev/null)
    H_VALIDATE_STATUS=$?
    H_FORMAT_OK=0
    case "$H_PROVIDER" in
        sha256sum)
            if [ "$H_VALUE" = "$H_DIGEST  $H_PATH" ] || [ "$H_VALUE" = "$H_DIGEST *$H_PATH" ]; then H_FORMAT_OK=1; fi
            ;;
        openssl)
            if [ "$H_VALUE" = "SHA256($H_PATH)= $H_DIGEST" ] || [ "$H_VALUE" = "SHA2-256($H_PATH)= $H_DIGEST" ]; then H_FORMAT_OK=1; fi
            ;;
    esac
    if [ "$H_STATUS" -ne 0 ] || [ "$H_VALIDATE_STATUS" -ne 0 ] || [ "${#H_DIGEST}" -ne 64 ] || [ -n "$H_NONHEX" ] || [ "$H_FORMAT_OK" -ne 1 ]; then
        record hash-error "$H_PATH|provider=$H_PROVIDER|status=$H_STATUS|validation=$H_VALIDATE_STATUS|digest=$H_DIGEST"
        COLLECT_FAILURE=1
        return
    fi
    record hash "$H_PATH|$H_DIGEST"
}

capture_command() {
    CC_LABEL=$1
    shift
    CC_CMD=$1
    if ! has_command "$CC_CMD"; then
        record missing-command "$CC_CMD"
        return
    fi
    CC_VALUE=$("$@" 2>/dev/null)
    CC_STATUS=$?
    if [ "$CC_STATUS" -ne 0 ]; then
        record command-error "$CC_CMD|$CC_STATUS"
        COLLECT_FAILURE=1
        return
    fi
    if [ -n "$CC_VALUE" ]; then
        while IFS= read -r CC_LINE
        do
            record "$CC_LABEL" "$CC_LINE"
        done <<IONIQ_CAPTURE_COMMAND_LINES
$CC_VALUE
IONIQ_CAPTURE_COMMAND_LINES
    else
        record "$CC_LABEL" ""
    fi
}

capture_process_path() {
    P_PID=$1
    P_DIR=$2
    P_ENV_TEXT=$(tr '\000' '\n' < "$P_DIR/environ" 2>/dev/null); P_ENV_STATUS=$?; P_PATH=$(printf '%s\n' "$P_ENV_TEXT" | awk -F= '$1 == "PATH" { sub(/^PATH=/, ""); print; exit }' 2>/dev/null); P_PATH_STATUS=$?
    if [ "$P_ENV_STATUS" -ne 0 ] || [ "$P_PATH_STATUS" -ne 0 ] || [ -z "$P_PATH" ]; then
        P_PATH_EMPTY=0
        [ -n "$P_PATH" ] || P_PATH_EMPTY=1
        record process-read-error "$P_PID|env-path|producer=$P_ENV_STATUS|parser=$P_PATH_STATUS|empty=$P_PATH_EMPTY"
        COLLECT_FAILURE=1
    fi
    record process-path "$P_PID|$P_PATH"
}

capture_unit() {
    U_NAME=$1
    if has_command systemctl; then
        U_RAW=$(systemctl show "$U_NAME" -p LoadState -p ActiveState -p SubState -p UnitFileState 2>/dev/null)
        U_STATUS=$?
        if [ "$U_STATUS" -ne 0 ]; then
            record unit-error "$U_NAME|systemctl-status=$U_STATUS"
            COLLECT_FAILURE=1
            return
        fi
        U_STATE=$(printf '%s\n' "$U_RAW" | tr '\012' ';' 2>/dev/null)
        U_TR_STATUS=$?
        if [ "$U_TR_STATUS" -ne 0 ]; then
            record unit-error "$U_NAME|tr-status=$U_TR_STATUS"
            COLLECT_FAILURE=1
            return
        fi
        record unit "$U_NAME|$U_STATE"
    else
        record unit "$U_NAME|systemctl-unavailable"
    fi
}

capture_interface() {
    N_DIR=$1
    N_NAME=${N_DIR#/sys/class/net/}
    read_scalar interface-operstate "$N_DIR/operstate"; N_OPER=$RS_VALUE; N_OPER_STATE=$RS_STATE
    read_scalar interface-carrier "$N_DIR/carrier"; N_CARRIER=$RS_VALUE; N_CARRIER_STATE=$RS_STATE
    read_scalar interface-type "$N_DIR/type"; N_TYPE=$RS_VALUE; N_TYPE_STATE=$RS_STATE
    read_scalar interface-ifindex "$N_DIR/ifindex"; N_IFINDEX=$RS_VALUE; N_IFINDEX_STATE=$RS_STATE
    read_scalar interface-iflink "$N_DIR/iflink"; N_IFLINK=$RS_VALUE; N_IFLINK_STATE=$RS_STATE
    read_link_value interface-driver "$N_DIR/device/driver"; N_DRIVER=$RL_VALUE
    if [ "$N_OPER_STATE" != present ] || [ "$N_TYPE_STATE" != present ] || [ "$N_IFINDEX_STATE" != present ] || [ "$N_IFLINK_STATE" != present ]; then
        record interface-read-error "$N_NAME|required-scalar-missing"
        COLLECT_FAILURE=1
    fi
    if [ "$N_CARRIER_STATE" = error ] || [ "$RL_STATE" = error ]; then
        record interface-read-error "$N_NAME|optional-query-error"
        COLLECT_FAILURE=1
    fi
    record interface "$N_NAME|$N_OPER|$N_CARRIER|$N_TYPE|$N_IFINDEX|$N_IFLINK|$N_DRIVER"
}

if ! has_command od || ! has_command tr; then
    begin_section meta
    printf '@@R|fatal|6f642d6f722d74722d756e617661696c61626c65\n'
    end_section meta 127
    exit 127
fi

begin_section meta
record schema ioniq-bench-state/v1
if has_command date; then
    M_UTC=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)
    M_STATUS=$?
    if [ "$M_STATUS" -eq 0 ] && [ -n "$M_UTC" ]; then
        record utc "$M_UTC"
    else
        record command-error "date|$M_STATUS"
        COLLECT_FAILURE=1
    fi
else
    record missing-command date
fi
read_scalar self-label /proc/self/attr/current
record self-label "$RS_VALUE"
end_section meta "$COLLECT_FAILURE"

begin_section identity
capture_command uname uname -a
capture_file os-release /etc/os-release
read_scalar kernel-cmdline /proc/cmdline
if [ "$RS_STATE" = present ]; then
    I_CMDLINE=$RS_VALUE
    for I_ARG in $I_CMDLINE
    do
        case "$I_ARG" in
            root=*|rootfstype=*|rootflags=*|rootwait|ro|rw|init=*|console=*|earlycon=*|oemkm=*|security=*|smack*)
                record cmdline-allowlisted "$I_ARG"
                ;;
        esac
    done
    I_DIGEST=
    I_STATUS=127
    I_PROVIDER=
    if has_command sha256sum; then
        I_PROVIDER=sha256sum
        I_VALUE=$(printf '%s' "$I_CMDLINE" | sha256sum 2>/dev/null)
        I_STATUS=$?
        I_DIGEST=${I_VALUE%% *}
    elif has_command openssl; then
        I_PROVIDER=openssl
        I_VALUE=$(printf '%s' "$I_CMDLINE" | openssl dgst -sha256 2>/dev/null)
        I_STATUS=$?
        I_DIGEST=${I_VALUE##* }
    fi
    if [ -z "$I_PROVIDER" ]; then
        record cmdline-sha256 unavailable
    else
        I_NONHEX=$(printf '%s' "$I_DIGEST" | tr -d '0123456789abcdefABCDEF' 2>/dev/null)
        I_VALIDATE_STATUS=$?
        I_FORMAT_OK=0
        case "$I_PROVIDER" in
            sha256sum) [ "$I_VALUE" = "$I_DIGEST  -" ] && I_FORMAT_OK=1 ;;
            openssl)
                if [ "$I_VALUE" = "SHA256(stdin)= $I_DIGEST" ] || [ "$I_VALUE" = "SHA2-256(stdin)= $I_DIGEST" ] || [ "$I_VALUE" = "SHA256((stdin))= $I_DIGEST" ] || [ "$I_VALUE" = "SHA2-256((stdin))= $I_DIGEST" ]; then I_FORMAT_OK=1; fi
                ;;
        esac
        if [ "$I_STATUS" -ne 0 ] || [ "$I_VALIDATE_STATUS" -ne 0 ] || [ "${#I_DIGEST}" -ne 64 ] || [ -n "$I_NONHEX" ] || [ "$I_FORMAT_OK" -ne 1 ]; then
            record cmdline-sha256-error "provider=$I_PROVIDER|status=$I_STATUS|validation=$I_VALIDATE_STATUS|digest=$I_DIGEST"
            COLLECT_FAILURE=1
        else
            record cmdline-sha256 "$I_DIGEST"
        fi
    fi
fi
capture_file kernel-version /proc/version
for I_PATH in /etc/version /etc/issue /app/etc/version /app/share/version /update/updateVersionInfo
do
    capture_file identity-file "$I_PATH"
done
end_section identity 0

begin_section processes
BT_DAEMON_RUNNING=0
for P_DIR in /proc/[0-9]*
do
    [ -d "$P_DIR" ] || continue
    P_PID=${P_DIR#/proc/}
    if [ ! -r "$P_DIR/status" ]; then
        record process-read-error "$P_PID|status-unreadable"
        COLLECT_FAILURE=1
        continue
    fi
    P_UID=$(awk '$1 == "Uid:" { print $2; exit }' "$P_DIR/status" 2>/dev/null)
    P_STATUS=$?
    P_GID=$(awk '$1 == "Gid:" { print $2; exit }' "$P_DIR/status" 2>/dev/null)
    P_GID_STATUS=$?
    if [ "$P_STATUS" -ne 0 ] || [ "$P_GID_STATUS" -ne 0 ] || [ -z "$P_UID" ] || [ -z "$P_GID" ]; then
        record process-read-error "$P_PID|status-parse|uid=$P_STATUS|gid=$P_GID_STATUS"
        COLLECT_FAILURE=1
        continue
    fi
    read_scalar process-comm "$P_DIR/comm"
    P_COMM=$RS_VALUE
    if [ "$RS_STATE" != present ]; then
        record process-read-error "$P_PID|comm-$RS_STATE"
        COLLECT_FAILURE=1
        continue
    fi
    read_link_value process-exe "$P_DIR/exe"
    P_EXE=$RL_VALUE
    if [ "$RL_STATE" = error ]; then
        record process-read-error "$P_PID|exe-error"
    fi
    read_scalar process-label "$P_DIR/attr/current"
    P_LABEL=$RS_VALUE
    if [ "$RS_STATE" = error ]; then
        record process-read-error "$P_PID|label-error"
    fi
    P_CMD=
    P_PATH=
    case "$P_COMM" in
        connmand|ofonod|wpa_supplicant|supplicantmanager|vbtd|bluetoothd|dropbear|dropbearmulti|AppLauncher|AppDMClient|AppScomoDM|AppUpgrade)
            if [ ! -r "$P_DIR/cmdline" ]; then
                record process-read-error "$P_PID|cmdline-unreadable"
                COLLECT_FAILURE=1
            else
                P_CMD=$(tr '\000' ' ' < "$P_DIR/cmdline" 2>/dev/null)
                P_CMD_STATUS=$?
                if [ "$P_CMD_STATUS" -ne 0 ]; then
                    record process-read-error "$P_PID|cmdline-$P_CMD_STATUS"
                    COLLECT_FAILURE=1
                fi
            fi
            capture_process_path "$P_PID" "$P_DIR"
            ;;
    esac
    case "$P_COMM" in vbtd|bluetoothd) BT_DAEMON_RUNNING=1 ;; esac
    record process "$P_PID|$P_UID|$P_GID|$P_LABEL|$P_EXE|$P_COMM|$P_CMD"
done
end_section processes 0

begin_section smack
capture_file smack-mounts /proc/mounts
capture_file smack-rule /sys/fs/smackfs/load2
capture_file smack-onlycap /sys/fs/smackfs/onlycap
capture_file smack-ambient /sys/fs/smackfs/ambient
end_section smack 0

begin_section units
for U_NAME in connman.service ofono.service ofono.path supplicantmanager.service supplicantmanager.path vbtd.service dropbear.socket dropbear@.service dropbearkey.service ApplicationLauncher.service MediaBrowser.service dbus.service
 do
    capture_unit "$U_NAME"
 done
file_meta /tmp/no_unece
file_meta /tmp/no_isa
file_meta /tmp/telematics_code_TELEMATICS
file_meta /tmp/session_appmgr.env
file_meta /tmp/secure_console_disable
end_section units 0

begin_section interfaces
for N_DIR in /sys/class/net/*
do
    [ -d "$N_DIR" ] || continue
    capture_interface "$N_DIR"
done
capture_command ip-link ip -o link show
capture_command ip-address ip -o address show
capture_command ip-route ip route show table all
capture_file proc-wireless /proc/net/wireless
capture_command iw-dev iw dev
if has_command ss; then
    capture_command listener ss -lntup
elif has_command netstat; then
    capture_command listener netstat -lntup
else
    record missing-command ss-or-netstat
fi
end_section interfaces 0

begin_section cellular
for C_PATH in /dev/cdc-wdm0 /dev/cdc-wdm1 /dev/ttyUSB0 /dev/ttyUSB1 /dev/ttyUSB2 /dev/ttyUSB3 /sys/class/net/wwan0
 do
    file_meta "$C_PATH"
 done
file_meta /usr/sbin/ofonod
file_meta /lib/systemd/system/ofono.service
file_meta /lib/systemd/system/ofono.path
end_section cellular 0

begin_section bluetooth
if [ "$BT_DAEMON_RUNNING" = 1 ]; then
    capture_command local-sdp sdptool browse local
else
    record local-sdp-status daemon-not-observed
fi
for B_PROFILE in /app/share/BluetoothHMI/qml/EngMode/profile.conf /app/share/BluetoothHMI/qml/EngMode/profile-63.conf
 do
    if [ ! -e "$B_PROFILE" ] && [ ! -L "$B_PROFILE" ]; then
        record missing-file "$B_PROFILE"
    elif [ ! -r "$B_PROFILE" ]; then
        record unreadable-file "$B_PROFILE"
        COLLECT_FAILURE=1
    else
        capture_command bluetooth-profile grep -E '^[[:space:]]*(PAN|A2DP|AVRCP|HFP|HSP|PBAP|MAP|SPP)[[:space:]]*:' "$B_PROFILE"
    fi
 done
file_meta /app/bin/vbtd
file_meta /tmp/vbtd
file_meta /tmp/bt_patchram.hcd
end_section bluetooth 0

begin_section dropbear
for D_PATH in /usr/sbin/dropbear /usr/sbin/dropbearmulti /lib/systemd/system/dropbear.socket /lib/systemd/system/dropbear@.service /lib/systemd/system/dropbearkey.service /var/dropbear/dropbear_rsa_host_key /home/root/.ssh/authorized_keys /etc/dropbear/authorized_keys
 do
    file_meta "$D_PATH"
 done
end_section dropbear 0

begin_section storage
capture_file fstab /etc/fstab
capture_file partitions /proc/partitions
capture_file mounts /proc/mounts
for S_FLAG in activeNaviPath activeResourcePath updateVersionInfo fota_status showEncryptionMenu disableEncryptionUpdate force_launch system_update_complete system_update_completed firmware_update_complete scheduled_update_complete scheduled_update_complete_for_DM updateCompleteTime
 do
    capture_file update-flag "/update/$S_FLAG"
 done
for S_DIR in /update/sysroot /update/usb/upgrade /update/usb/bin
 do
    file_meta "$S_DIR"
 done
end_section storage 0

begin_section hashes
for H_META in /bin/busybox /usr/bin/unzip /usr/bin/unzip64 /app/bin/AppLauncher /app/bin/AppDMClient /app/bin/AppScomoDM /app/bin/AppUpgrade /app/bin/CarOption.csv /app/share/AppUpgrade/DecryptToPIPE /app/share/AppUpgrade/teruten5_pub.key /update/usb/bin/AppUpgrade /update/usb/bin/.lge.upgrade.xml /tmp/AppUpgrade
 do
    file_meta "$H_META"
 done
for H_TARGET in /usr/sbin/connmand /usr/sbin/ofonod /usr/sbin/wpa_supplicant /app/bin/supplicantmanager /app/bin/vbtd /tmp/vbtd /lib/systemd/system/vbtd.service /etc/setup_bt_patchram.sh /usr/sbin/dropbear /usr/sbin/dropbearmulti /bin/busybox /usr/bin/unzip /usr/bin/unzip64 /app/bin/AppLauncher /app/bin/AppDMClient /app/bin/AppScomoDM /app/bin/AppUpgrade /app/bin/CarOption.csv /app/share/AppUpgrade/AppUpgrade /app/share/AppUpgrade/DecryptToPIPE /app/share/AppUpgrade/teruten5_pub.key /update/usb/bin/AppUpgrade /update/usb/bin/.lge.upgrade.xml /tmp/AppUpgrade /lib/modules/4.1.27-abl/kernel/sound/core/seq/snd-seq.ko
 do
    hash_file "$H_TARGET"
 done
end_section hashes 0

begin_section complete
if [ "$COLLECT_FAILURE" -eq 0 ]; then
    record result complete
    end_section complete 0
else
    record result collection-error
    end_section complete 1
fi
'''


def audit_script(script: str) -> list[str]:
    """Return human-readable safety violations in an emitted probe."""

    violations: list[str] = []
    for lineno, raw in enumerate(script.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Stderr suppression to /dev/null is non-persistent and is the only
        # output redirection allowed. Reading allowlisted cmdline/PATH fields
        # and the two fixed in-memory line-loop here-documents are the only
        # input redirections allowed.
        redirection_check = (
            line.replace("2>/dev/null", "")
            .replace(">/dev/null", "")
            .replace("2>&1", "")
        )
        if ">" in redirection_check:
            violations.append(f"line {lineno}: output redirection is forbidden")
        if "environ" in line and line != SAFE_ENVIRON_READ_LINE:
            violations.append(f"line {lineno}: non-allowlisted environment read")
        if (
            "<" in redirection_check
            and '< "$P_DIR/cmdline"' not in redirection_check
            and '< "$P_DIR/environ"' not in redirection_check
            and redirection_check
            not in (
                "done <<IONIQ_CAPTURE_FILE_LINES",
                "done <<IONIQ_CAPTURE_COMMAND_LINES",
            )
        ):
            violations.append(f"line {lineno}: unexpected input redirection")
        for pattern in FORBIDDEN_LINE_PATTERNS:
            if pattern.search(f" {line} "):
                violations.append(f"line {lineno}: forbidden command pattern: {line}")
                break
    return violations


def shell_syntax_check(script: str) -> tuple[bool, str]:
    """Run the host's POSIX shell parser without executing the probe."""

    try:
        proc = subprocess.run(
            ["/bin/sh", "-n"],
            input=script,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"shell syntax check unavailable: {exc}"
    return proc.returncode == 0, proc.stderr.strip()


def _normalise_capture_line(line: str) -> str:
    line = ANSI_RE.sub("", line.rstrip("\r\n"))
    return SERIAL_PREFIX_RE.sub("", line)


def _split_fields(value: str, count: int) -> list[str]:
    parts = value.split("|", count - 1)
    parts.extend([""] * (count - len(parts)))
    return parts


def _derive_facts(sections: Iterable[dict[str, Any]]) -> dict[str, Any]:
    facts: dict[str, Any] = {
        "hashes": {},
        "units": {},
        "processes": [],
        "process_paths": {},
        "interfaces": [],
        "files": {},
        "update_flags": [],
        "listeners": [],
        "local_sdp": [],
    }
    for section in sections:
        for record in section["records"]:
            key = record["key"]
            value = record["value"]
            if key == "hash":
                path, digest = _split_fields(value, 2)
                facts["hashes"][path] = digest
            elif key == "unit":
                name, state = _split_fields(value, 2)
                facts["units"][name] = state
            elif key == "process":
                pid, uid, gid, label, exe, comm, cmdline = _split_fields(value, 7)
                facts["processes"].append(
                    {
                        "pid": int(pid) if pid.isdigit() else pid,
                        "uid": int(uid) if uid.isdigit() else uid,
                        "gid": int(gid) if gid.isdigit() else gid,
                        "smack_label": label,
                        "exe": exe,
                        "comm": comm,
                        "cmdline": cmdline,
                    }
                )
            elif key == "process-path":
                pid, path = _split_fields(value, 2)
                facts["process_paths"][pid] = path
            elif key == "interface":
                name, operstate, carrier, kind, ifindex, iflink, driver = _split_fields(value, 7)
                facts["interfaces"].append(
                    {
                        "name": name,
                        "operstate": operstate,
                        "carrier": carrier,
                        "type": kind,
                        "ifindex": int(ifindex) if ifindex.isdigit() else ifindex,
                        "iflink": int(iflink) if iflink.isdigit() else iflink,
                        "driver": driver,
                    }
                )
            elif key == "file":
                path, state = _split_fields(value, 2)
                facts["files"][path] = state
            elif key == "update-flag":
                facts["update_flags"].append(value)
            elif key == "listener":
                facts["listeners"].append(value)
            elif key == "local-sdp":
                facts["local_sdp"].append(value)
    facts["processes"].sort(key=lambda item: (str(item["pid"])))
    facts["interfaces"].sort(key=lambda item: item["name"])
    return facts


def _finalize_section(section: dict[str, Any]) -> dict[str, Any]:
    section["captured_bytes"] = section.pop("_encoded_bytes", 0)
    canonical = json.dumps(
        section, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    section["sha256"] = hashlib.sha256(canonical).hexdigest()
    return section


def _iter_bounded_lines(data: bytes) -> Iterable[tuple[int, bytes]]:
    source = io.BytesIO(data)
    line_number = 0
    while True:
        line = source.readline(MAX_SECTION_BYTES + 1)
        if not line:
            return
        line_number += 1
        if len(line) > MAX_SECTION_BYTES:
            raise ValueError(f"capture line {line_number} exceeds {MAX_SECTION_BYTES} byte limit")
        yield line_number, line


def parse_capture(data: bytes) -> dict[str, Any]:
    """Parse a probe transcript without executing or interpreting its content."""

    if len(data) > MAX_CAPTURE_BYTES:
        raise ValueError(f"capture exceeds {MAX_CAPTURE_BYTES} byte limit")
    sections: list[dict[str, Any]] = []
    current: Optional[dict[str, Any]] = None
    warnings: list[str] = []
    seen_names: set[str] = set()

    for line_number, original_bytes in _iter_bounded_lines(data):
        original = original_bytes.decode("utf-8", "replace")
        line = _normalise_capture_line(original)
        begin = BEGIN_RE.match(line)
        if begin:
            if current is not None:
                current["complete"] = False
                current["end_status"] = None
                sections.append(_finalize_section(current))
                warnings.append(
                    f"line {line_number}: section {current['name']} was not closed before {begin.group(1)}"
                )
            name = begin.group(1)
            if name in seen_names:
                warnings.append(f"line {line_number}: duplicate section {name}")
            seen_names.add(name)
            current = {
                "name": name,
                "complete": False,
                "end_status": None,
                "records": [],
                "raw": [],
                "_encoded_bytes": 0,
            }
            continue

        end = END_RE.match(line)
        if end:
            name, status_text = end.groups()
            if current is None:
                warnings.append(f"line {line_number}: unmatched end marker for {name}")
                continue
            if current["name"] != name:
                warnings.append(
                    f"line {line_number}: end marker {name} does not match {current['name']}"
                )
                current["raw"].append(line)
                continue
            current["complete"] = True
            current["end_status"] = int(status_text)
            sections.append(_finalize_section(current))
            current = None
            continue

        if current is not None:
            current["_encoded_bytes"] += len(original_bytes)
            if current["_encoded_bytes"] > MAX_SECTION_BYTES:
                raise ValueError(
                    f"section {current['name']} exceeds {MAX_SECTION_BYTES} byte limit"
                )
            if line.startswith(RECORD_PREFIX):
                pieces = line.split("|", 2)
                if len(pieces) == 3 and pieces[1]:
                    try:
                        decoded = bytes.fromhex(pieces[2]).decode("utf-8", "replace")
                    except ValueError:
                        current["raw"].append(line)
                        warnings.append(f"line {line_number}: malformed hex record")
                    else:
                        current["records"].append({"key": pieces[1], "value": decoded})
                else:
                    current["raw"].append(line)
                    warnings.append(f"line {line_number}: malformed record")
            else:
                current["raw"].append(line)
                warnings.append(
                    f"line {line_number}: unframed content in section {current['name']}"
                )

    if current is not None:
        sections.append(_finalize_section(current))
        warnings.append(f"end of capture: section {current['name']} is incomplete")

    section_order = [section["name"] for section in sections]
    expected_order = list(EXPECTED_SECTIONS)
    if not sections:
        warnings.append("no bench-state markers found")
    elif section_order != expected_order:
        warnings.append(
            "section sequence mismatch: expected "
            + ",".join(expected_order)
            + " observed "
            + ",".join(section_order)
        )

    all_closed = bool(sections) and all(section["complete"] for section in sections)
    zero_status = all(section["end_status"] == 0 for section in sections if section["complete"])
    if not zero_status:
        warnings.append("one or more section end statuses are nonzero")

    fatal_values = [
        record["value"]
        for section in sections
        for record in section["records"]
        if record["key"] == "fatal"
    ]
    if fatal_values:
        warnings.append("probe reported fatal collection error")

    meta_schema = False
    complete_section = False
    for section in sections:
        if section["name"] == "meta":
            schema_values = [
                record["value"]
                for record in section["records"]
                if record["key"] == "schema"
            ]
            meta_schema = schema_values == [SCHEMA]
        elif section["name"] == "complete":
            complete_section = section["records"] == [
                {"key": "result", "value": "complete"}
            ]
    if not meta_schema:
        warnings.append("meta schema record missing or invalid")
    if not complete_section:
        warnings.append("terminal complete record missing or invalid")

    valid_sequence = section_order == expected_order
    is_complete = bool(
        valid_sequence
        and all_closed
        and zero_status
        and meta_schema
        and complete_section
        and not warnings
    )
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "capture_sha256": hashlib.sha256(data).hexdigest(),
        "capture_bytes": len(data),
        "complete": is_complete,
        "section_order": section_order,
        "sections": sections,
        "facts": _derive_facts(sections),
        "warnings": warnings,
    }
    canonical = json.dumps(
        report, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    report["canonical_sha256"] = hashlib.sha256(canonical).hexdigest()
    return report


def _read_capture_bounded(path: Path) -> bytes:
    with open(path, "rb") as source:
        data = source.read(MAX_CAPTURE_BYTES + 1)
    if len(data) > MAX_CAPTURE_BYTES:
        raise ValueError(f"capture exceeds {MAX_CAPTURE_BYTES} byte limit")
    return data


def _write_json(path: Optional[Path], report: dict[str, Any]) -> None:
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if path is None:
        sys.stdout.write(payload)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    emit = sub.add_parser("emit", help="emit the read-only target probe")
    emit.add_argument("-o", "--output", type=Path, help="host path for the generated shell script")

    audit = sub.add_parser("audit", help="audit an emitted probe without running it")
    audit.add_argument("script", type=Path)

    parse = sub.add_parser("parse", help="parse a captured probe transcript")
    parse.add_argument("capture", type=Path)
    parse.add_argument("--json", type=Path, help="write JSON here instead of stdout")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "emit":
        violations = audit_script(PROBE_SCRIPT)
        syntax_ok, syntax_error = shell_syntax_check(PROBE_SCRIPT)
        if violations or not syntax_ok:
            for violation in violations:
                print(violation, file=sys.stderr)
            if not syntax_ok:
                print(syntax_error, file=sys.stderr)
            return 2
        if args.output is None:
            sys.stdout.write(PROBE_SCRIPT)
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(PROBE_SCRIPT, encoding="utf-8")
            args.output.chmod(0o700)
            print(f"wrote host-side probe: {args.output}")
        return 0

    if args.command == "audit":
        script = args.script.read_text(encoding="utf-8")
        violations = audit_script(script)
        syntax_ok, syntax_error = shell_syntax_check(script)
        result = {
            "path": str(args.script),
            "sha256": hashlib.sha256(script.encode()).hexdigest(),
            "safe": not violations and syntax_ok,
            "syntax_ok": syntax_ok,
            "syntax_error": syntax_error,
            "violations": violations,
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["safe"] else 2

    if args.command == "parse":
        try:
            report = parse_capture(_read_capture_bounded(args.capture))
        except ValueError as exc:
            print(f"parse failed: {exc}", file=sys.stderr)
            return 2
        _write_json(args.json, report)
        return 0

    raise AssertionError(f"unhandled command {shlex.quote(args.command)}")


if __name__ == "__main__":
    raise SystemExit(main())
