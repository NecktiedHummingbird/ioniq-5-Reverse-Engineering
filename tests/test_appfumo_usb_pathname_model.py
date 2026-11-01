from __future__ import annotations

import hashlib
import importlib.util
import itertools
import json
import os
import re
import struct
import subprocess
import sys
import tarfile
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "tools/uk_fw/appfumo_usb_pathname_model.py"
ARTIFACT_PATH = (
    ROOT
    / "evidence/artifacts/update-candidates/"
    / "appfumo-usb-pathname-provenance-exact-static.asm"
)
MOUNT_ARTIFACT_PATH = (
    ROOT
    / "evidence/artifacts/update-candidates/"
    / "appfumo-iso9660-mount-prerequisite-exact-static.txt"
)
EVIDENCE_PATH = ROOT / "evidence/appfumo-usb-pathname-provenance.md"
MOUNT_EVIDENCE_PATH = ROOT / "evidence/appfumo-iso9660-mount-prerequisite.md"
KERNEL_CONFIG = ROOT / "work/eu-260128/kernel.config"
PERSISTENT_STORAGE_RULES = (
    ROOT
    / "work/decrypted-eu-260128/extracted-safe/mango-rootfs/"
    / "lib/udev/rules.d/60-persistent-storage.rules"
)
EXACT_USB_AUTOMOUNT = (
    ROOT
    / "work/decrypted-eu-260128/extracted-safe/mango-rootfs/app/bin/usb-automount"
)
EXACT_LIBBLKID = (
    ROOT
    / "work/decrypted-eu-260128/extracted-safe/mango-rootfs/lib/libblkid.so.1.1.0"
)
CANONICAL_ARCHIVE = ROOT / "work/decrypted-eu-260128/HU/images/mango-rootfs.tar.gz"
ISO9660_SOURCE = (
    ROOT
    / "work/appfumo-usb-pathname-provenance/util-linux-2.27.1/"
    / "libblkid/src/superblocks/iso9660.c"
)
LIBBLKID_MEMBER = "./lib/libblkid.so.1.1.0"
KERNEL_MEMBER = "./boot/bzImage-4.1.27-abl"
RULES_MEMBER = "./lib/udev/rules.d/60-persistent-storage.rules"
MODULE_ROOT = "./lib/modules/4.1.27-abl/"
EXPECTED_VMLINUX_SHA256 = (
    "f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b"
)
EXPECTED_VMLINUX_BUILD_ID = "273378887b4cf563c10862fdf18b2292765df781"
LEGACY_LZ4_MAGIC = b"\x02\x21\x4c\x18"
IKCONFIG_START = b"IKCFG_ST"
IKCONFIG_END = b"IKCFG_ED"
MAX_BZIMAGE_SIZE = 16 * 1024 * 1024
MAX_COMPRESSED_PAYLOAD_SIZE = 16 * 1024 * 1024
MAX_VMLINUX_SIZE = 32 * 1024 * 1024
MAX_LZ4_BLOCK_SIZE = 8 * 1024 * 1024
MAX_IKCONFIG_COMPRESSED_SIZE = 1024 * 1024
MAX_IKCONFIG_SIZE = 1024 * 1024
MAX_OVERLAP_COPY_CHUNK = 64 * 1024
EXPECTED_REPORT_SHA256 = (
    "56b7a941a4180472292af59e60b5b1bdf5b3e369205b75519a3d3c4f073f1804"
)

LIBBLKID_ISO9660_ROWS = {
    0x1C4C0: "41 57",
    0x1C4D3: "44 0f b6 06",
    0x1C4E7: "0f b6 46 02",
    0x1C4EB: "44 0f b6 4e 01",
    0x1C500: "0f b6 46 03",
    0x1C511: "0f b6 46 04",
    0x1C51D: "0f b6 46 05",
    0x1C529: "0f b6 46 06",
    0x1C535: "0f b6 46 07",
    0x1C541: "0f b6 46 08",
    0x1C54D: "0f b6 46 09",
    0x1C551: "0f b6 5e 0a",
    0x1C555: "0f b6 6e 0b",
    0x1C559: "44 0f b6 66 0c",
    0x1C55E: "44 0f b6 6e 0d",
    0x1C567: "44 0f b6 76 0e",
    0x1C570: "44 0f b6 7e 0f",
    0x1C5A8: "0f b6 08",
    0x1C5AF: "80 f9 30",
    0x1C5BF: "83 fa 10",
    0x1C5C2: "74 7c",
    0x1C5C6: "48 8d 0d 9b 8d 01 00",
    0x1C5CD: "ba 10 00 00 00",
    0x1C60C: "e8 6f 36 00 00",
    0x1C7EB: "48 8d b3 3e 03 00 00",
    0x1C7F5: "e8 c6 fc ff ff",
    0x1C7FA: "85 c0",
    0x1CA10: "48 8d b3 2d 03 00 00",
    0x1CA1A: "e8 a1 fa ff ff",
}
ISO9660_UUID_FORMAT = b"%c%c%c%c-%c%c-%c%c-%c%c-%c%c-%c%c-%c%c\0"

MOUNT_PREREQUISITE_ROWS = {
    0x4C62: "e8 79 d6 ff ff",
    0x4C7A: "e8 61 d6 ff ff",
    0x4C81: "0f 85 49 03 00 00",
    0x4CD7: "b8 0b 00 ed c0",
    0x4CDC: "48 89 44 24 18",
    0x4D59: "48 8b 4c 24 18",
    0x4D69: "4c 8d 05 3f 2b 00 00",
    0x4D70: "e8 fb d6 ff ff",
    0x4D75: "85 c0",
    0x4D77: "0f 84 81 00 00 00",
    0x4DEC: "b9 0b 00 ed c0",
    0x4DF1: "e8 7a d6 ff ff",
    0x4DF6: "85 c0",
    0x4DF8: "0f 85 32 01 00 00",
    0x4DFE: "bf 64 00 00 00",
    0x4E08: "4d 85 ff",
    0x4E0B: "0f 84 57 02 00 00",
    0x4E28: "48 8d 3d 20 2a 00 00",
    0x4E34: "e8 37 fa ff ff",
    0x4F20: "b8 0a 00 ed c0",
    0x4F25: "48 89 44 24 18",
    0x4FD8: "49 89 d8",
    0x4FEF: "48 8d 0d 58 29 00 00",
    0x4FF6: "e8 d5 d0 ff ff",
}

USB_ROWS = {
    0x3A59: "4d 89 cd",
    0x3A5E: "4d 89 c4",
    0x3A88: "48 89 4c 24 08",
    0x3A8D: "4c 8b 74 24 60",
    0x3B28: "48 8b 54 24 08",
    0x3B31: "4d 89 f1",
    0x3B34: "4d 89 e8",
    0x3B37: "4c 89 e1",
    0x3B49: "e9 b2 10 00 00",
    0x3E7F: "48 89 fe",
    0x3E82: "4c 89 d7",
    0x3E85: "e8 26 e3 ff ff",
    0x3EC0: "49 89 f1",
    0x3EC3: "49 89 f8",
    0x3EC8: "48 8d 0d c6 36 00 00",
    0x3EDE: "e8 ed e1 ff ff",
    0x4435: "4c 8b 4c 24 58",
    0x443A: "4c 8b 44 24 68",
    0x4C0A: "48 89 d3",
    0x4C2A: "4c 89 4c 24 08",
    0x4C5C: "49 89 cf",
    0x4C5F: "4d 89 c5",
    0x4D16: "41 55",
    0x4D1A: "48 8d 0d 85 2b 00 00",
    0x4E15: "49 89 d9",
    0x4E18: "4c 89 f9",
    0x4E23: "4c 8b 44 24 18",
    0x4E31: "4c 89 e6",
    0x4E34: "e8 37 fa ff ff",
}

OUTPUT_KEYS = {
    "input",
    "exact_static_fact_set_complete",
    "automounter_static_fact_set_complete",
    "appdm_callback_to_staging_edge_established",
    "appupgrade_package_suffix_to_sink_edge_established",
    "per_binary_edge_fact_set_complete",
    "uuid_or_no_uuid_alternate_is_automounter_path_component",
    "label_is_automounter_path_component",
    "ordinary_filesystem_label_shell_active_mount_path_route",
    "constrained_uuid_families_shell_active_mount_path_route",
    "iso9660_static_shell_path_sensitive_uuid_byte_route",
    "userspace_iso9660_recognition_and_generic_mount_dispatch_established",
    "userspace_iso9660_read_only_retry_established",
    "mount_success_signal_requires_mount_success",
    "canonical_bzimage_to_vmlinux_identity_chain_established",
    "embedded_ikconfig_to_recovered_config_identity_chain_established",
    "recovered_kernel_named_iso9660_mount_prerequisite_absence",
    "recovered_kernel_iso9660_mount_prerequisite_absence",
    "exact_recovered_stack_named_iso9660_mount_route",
    "exact_recovered_stack_iso9660_mount_route",
    "exact_recovered_stack_named_physical_optical_sr_route",
    "exact_recovered_stack_physical_optical_sr_route",
    "no_uuid_alternate_shell_active_mount_path_effect",
    "shell_sensitive_label_dbus_bytes_preserved",
    "hardware_descriptor_control_established",
    "physical_iso9660_source_control_established",
    "materially_different_runtime_identity_established",
    "installed_iso9660_media_accepted_and_mounted",
    "physical_iso9660_mount_path_delivery_established",
    "end_to_end_package_base_delivery_established",
    "relevant_decryptionfile_invocation_established",
    "physical_iso9660_path_delivery_to_decryption_input_established",
    "overall_physical_shell_sensitive_sink_delivery_established",
    "verifier_before_shell_sink_established",
    "authentication_acceptance_established",
    "process_security_context_established",
    "command_success_observed",
    "privilege_or_domain_amplification_observed",
    "root_impact_observed",
    "persistence_observed",
    "extraction_member_names_are_qprocess_arguments",
    "enumerated_member_path_route_established",
    "signed_container_member_name_binding_established",
    "physically_supplied_authenticated_member_name_route_established",
}


def _load_model():
    spec = importlib.util.spec_from_file_location("appfumo_usb_provenance", MODEL_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _all_offsets(data: bytes, marker: bytes) -> list[int]:
    offsets: list[int] = []
    cursor = 0
    while True:
        offset = data.find(marker, cursor)
        if offset < 0:
            return offsets
        offsets.append(offset)
        cursor = offset + 1


def _u32le(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise ValueError("u32 read is out of bounds")
    return struct.unpack_from("<I", data, offset)[0]


def _decompress_lz4_block(
    block: bytes, *, max_output_size: int = MAX_LZ4_BLOCK_SIZE
) -> bytes:
    if max_output_size <= 0 or max_output_size > MAX_LZ4_BLOCK_SIZE:
        raise ValueError("LZ4 block output bound is invalid")
    output = bytearray()
    cursor = 0
    while cursor < len(block):
        token = block[cursor]
        cursor += 1
        literal_length = token >> 4
        if literal_length == 15:
            while True:
                if cursor >= len(block):
                    raise ValueError("truncated LZ4 literal length")
                extension = block[cursor]
                cursor += 1
                literal_length += extension
                if extension != 255:
                    break
        if cursor + literal_length > len(block):
            raise ValueError("LZ4 literal exceeds compressed block")
        literal_capacity = max_output_size - len(output)
        if literal_length > literal_capacity:
            raise ValueError("LZ4 literal output exceeds bound before extend")
        output.extend(block[cursor : cursor + literal_length])
        cursor += literal_length
        if cursor == len(block):
            break
        if cursor + 2 > len(block):
            raise ValueError("truncated LZ4 match offset")
        match_offset = block[cursor] | (block[cursor + 1] << 8)
        cursor += 2
        if match_offset == 0 or match_offset > len(output):
            raise ValueError("invalid LZ4 match offset")
        match_length = token & 0x0F
        if match_length == 15:
            while True:
                if cursor >= len(block):
                    raise ValueError("truncated LZ4 match length")
                extension = block[cursor]
                cursor += 1
                match_length += extension
                if extension != 255:
                    break
        match_length += 4
        match_capacity = max_output_size - len(output)
        if match_length > match_capacity:
            raise ValueError("LZ4 match output exceeds bound before copy")

        copy_start = len(output) - match_offset
        remaining_match = match_length
        while remaining_match:
            available = len(output) - copy_start
            copy_length = min(
                remaining_match,
                available,
                MAX_OVERLAP_COPY_CHUNK,
            )
            if copy_length <= 0 or copy_length > max_output_size - len(output):
                raise ValueError("LZ4 overlap copy violates output bound")
            output.extend(output[copy_start : copy_start + copy_length])
            remaining_match -= copy_length
    return bytes(output)


def _decompress_linux_legacy_lz4_payload(
    payload: bytes, *, max_output_size: int = MAX_VMLINUX_SIZE
) -> bytes:
    if max_output_size <= 0 or max_output_size > MAX_VMLINUX_SIZE:
        raise ValueError("decompressed vmlinux bound is invalid")
    if len(payload) > MAX_COMPRESSED_PAYLOAD_SIZE:
        raise ValueError("compressed kernel payload exceeds bound")
    if not payload.startswith(LEGACY_LZ4_MAGIC):
        raise ValueError("legacy LZ4 magic is missing")
    cursor = len(LEGACY_LZ4_MAGIC)
    output = bytearray()
    block_count = 0
    while len(payload) - cursor > 4:
        block_size = _u32le(payload, cursor)
        cursor += 4
        if block_size == 0 or block_size > MAX_LZ4_BLOCK_SIZE:
            raise ValueError("invalid legacy LZ4 block size")
        if cursor + block_size > len(payload) - 4:
            raise ValueError("legacy LZ4 block exceeds payload")
        block_output = _decompress_lz4_block(
            payload[cursor : cursor + block_size]
        )
        aggregate_capacity = max_output_size - len(output)
        if len(block_output) > aggregate_capacity:
            raise ValueError(
                "decompressed vmlinux aggregate exceeds bound before extend"
            )
        output.extend(block_output)
        cursor += block_size
        block_count += 1
    if block_count == 0 or len(payload) - cursor != 4:
        raise ValueError("legacy LZ4 payload footer is missing")
    expected_size = _u32le(payload, cursor)
    if expected_size != len(output):
        raise ValueError("legacy LZ4 payload size footer mismatch")
    return bytes(output)


def _extract_vmlinux_from_bzimage(bzimage: bytes) -> tuple[bytes, int, int]:
    if len(bzimage) < 0x250 or len(bzimage) > MAX_BZIMAGE_SIZE:
        raise ValueError("bzImage size is outside bounds")
    if bzimage[0x202:0x206] != b"HdrS":
        raise ValueError("bzImage setup-header magic is missing")
    protocol_version = struct.unpack_from("<H", bzimage, 0x206)[0]
    if protocol_version < 0x0208:
        raise ValueError("bzImage protocol lacks payload fields")
    setup_sects = bzimage[0x1F1] or 4
    setup_size = (setup_sects + 1) * 512
    payload_relative_offset = _u32le(bzimage, 0x248)
    payload_length = _u32le(bzimage, 0x24C)
    payload_offset = setup_size + payload_relative_offset
    if payload_length == 0 or payload_length > MAX_COMPRESSED_PAYLOAD_SIZE:
        raise ValueError("bzImage payload length is outside bounds")
    if payload_offset < setup_size or payload_offset + payload_length > len(bzimage):
        raise ValueError("bzImage payload is out of bounds")
    if bzimage[payload_offset : payload_offset + 4] != LEGACY_LZ4_MAGIC:
        raise ValueError("derived bzImage payload has unexpected compression magic")

    magic_offsets = _all_offsets(bzimage, LEGACY_LZ4_MAGIC)
    valid_offsets: list[int] = []
    selected_vmlinux: bytes | None = None
    for candidate in magic_offsets:
        if candidate + payload_length > len(bzimage):
            continue
        try:
            decompressed = _decompress_linux_legacy_lz4_payload(
                bzimage[candidate : candidate + payload_length]
            )
        except ValueError:
            continue
        if decompressed.startswith(b"\x7fELF"):
            valid_offsets.append(candidate)
            if candidate == payload_offset:
                selected_vmlinux = decompressed
    if valid_offsets != [payload_offset] or selected_vmlinux is None:
        raise ValueError("bzImage does not contain one uniquely valid kernel payload")
    return selected_vmlinux, payload_offset, payload_length


def _gnu_build_id(elf: bytes) -> str:
    if len(elf) < 64 or elf[:6] != b"\x7fELF\x02\x01":
        raise ValueError("vmlinux is not little-endian ELF64")
    program_offset = struct.unpack_from("<Q", elf, 32)[0]
    program_entry_size = struct.unpack_from("<H", elf, 54)[0]
    program_count = struct.unpack_from("<H", elf, 56)[0]
    if program_entry_size != 56 or program_count == 0:
        raise ValueError("unexpected ELF program-header table")
    if program_offset + program_entry_size * program_count > len(elf):
        raise ValueError("ELF program-header table is out of bounds")
    build_ids: list[bytes] = []
    for index in range(program_count):
        header = program_offset + index * program_entry_size
        if _u32le(elf, header) != 4:  # PT_NOTE
            continue
        note_offset = struct.unpack_from("<Q", elf, header + 8)[0]
        note_size = struct.unpack_from("<Q", elf, header + 32)[0]
        if note_offset + note_size > len(elf):
            raise ValueError("ELF note segment is out of bounds")
        cursor = note_offset
        end = note_offset + note_size
        while cursor < end:
            if cursor + 12 > end:
                raise ValueError("truncated ELF note")
            name_size, value_size, note_type = struct.unpack_from("<III", elf, cursor)
            cursor += 12
            name_end = cursor + name_size
            value_offset = (name_end + 3) & ~3
            value_end = value_offset + value_size
            next_note = (value_end + 3) & ~3
            if name_end > end or value_end > end or next_note > end:
                raise ValueError("ELF note fields are out of bounds")
            name = elf[cursor:name_end]
            value = elf[value_offset:value_end]
            if name == b"GNU\0" and note_type == 3:
                build_ids.append(value)
            cursor = next_note
    if len(build_ids) != 1 or len(build_ids[0]) != 20:
        raise ValueError("expected one SHA-1 GNU Build ID")
    return build_ids[0].hex()


def _extract_ikconfig(vmlinux: bytes) -> tuple[bytes, int, int]:
    starts = _all_offsets(vmlinux, IKCONFIG_START)
    ends = _all_offsets(vmlinux, IKCONFIG_END)
    if len(starts) != 1 or len(ends) != 1:
        raise ValueError("IKCONFIG markers are not unique")
    start, end = starts[0], ends[0]
    compressed_offset = start + len(IKCONFIG_START)
    if end <= compressed_offset or end - compressed_offset > MAX_IKCONFIG_COMPRESSED_SIZE:
        raise ValueError("IKCONFIG compressed payload is outside bounds")
    compressed = vmlinux[compressed_offset:end]
    if not compressed.startswith(b"\x1f\x8b\x08"):
        raise ValueError("IKCONFIG gzip magic is missing")
    if vmlinux.count(b"\x1f\x8b\x08") != 1:
        raise ValueError("IKCONFIG gzip stream is not unique")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    config = decoder.decompress(compressed, MAX_IKCONFIG_SIZE + 1)
    if decoder.unconsumed_tail or len(config) > MAX_IKCONFIG_SIZE:
        raise ValueError("IKCONFIG output exceeds bound")
    config += decoder.flush()
    if (
        not decoder.eof
        or decoder.unused_data
        or decoder.unconsumed_tail
        or len(config) > MAX_IKCONFIG_SIZE
    ):
        raise ValueError("IKCONFIG gzip stream is malformed or exceeds bounds")
    return config, start, end


def _tri(value: bool) -> bool | None:
    return True if value else None


def _artifact_rows(path: Path = ARTIFACT_PATH) -> dict[int, bytes]:
    rows: dict[int, bytes] = {}
    pattern = re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} ?)+)\s", re.I)
    for line in path.read_text(encoding="utf-8").splitlines():
        match = pattern.match(line)
        if match:
            rows[int(match.group(1), 16)] = bytes.fromhex(match.group(2))
    return rows


def _run_model(encoding: str) -> bytes:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = encoding
    completed = subprocess.run(
        [sys.executable, str(MODEL_PATH)],
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
    )
    assert completed.stderr == b""
    return completed.stdout


def test_retained_artifact_hash_and_all_identity_bindings() -> None:
    model = _load_model()
    assert _sha256(ARTIFACT_PATH) == model.STATIC_ARTIFACT_SHA256
    assert (
        _sha256(MOUNT_ARTIFACT_PATH)
        == model.ISO9660_MOUNT_PREREQUISITE_ARTIFACT_SHA256
    )
    text = ARTIFACT_PATH.read_text(encoding="utf-8")
    mount_text = MOUNT_ARTIFACT_PATH.read_text(encoding="utf-8")
    for identity in (
        model.ROOTFS_ARCHIVE_SHA256,
        model.USB_AUTOMOUNT_SHA256,
        model.SYSTEMD_UDEVD_SHA256,
        model.LIBBLKID_SHA256,
        model.LIBBLKID_BUILD_ID,
        model.ISO9660_SOURCE_SHA256,
        model.APPDMCLIENT_SHA256,
        model.APPUPGRADE_SHA256,
        "20748cf9928ba155ac4201a33bb1e29e64ae9139",
        "91b0e9592a52274a97e185fed528d6af3557e49d",
        "863a8730e66a1c5245a1bf458fe2554adee0351a",
    ):
        assert identity in text
    for identity in (
        model.ROOTFS_ARCHIVE_SHA256,
        model.KERNEL_CONFIG_SHA256,
        model.KERNEL_IMAGE_SHA256,
        model.VMLINUX_SHA256,
        model.VMLINUX_BUILD_ID,
        model.USB_AUTOMOUNT_SHA256,
        model.SYSTEMD_UDEVD_SHA256,
        model.LIBBLKID_SHA256,
        model.PERSISTENT_STORAGE_RULES_SHA256,
        model.KO_MEMBER_NAME_MANIFEST_SHA256,
        *model.MODULE_METADATA_SHA256.values(),
    ):
        assert identity in mount_text


def test_canonical_archive_directly_binds_libblkid_when_available() -> None:
    model = _load_model()
    if not CANONICAL_ARCHIVE.exists():
        pytest.skip("ignored canonical archive is not present")
    assert _sha256(CANONICAL_ARCHIVE) == model.ROOTFS_ARCHIVE_SHA256
    with tarfile.open(CANONICAL_ARCHIVE, "r:gz") as archive:
        member = archive.extractfile(LIBBLKID_MEMBER)
        assert member is not None
        assert hashlib.sha256(member.read()).hexdigest() == model.LIBBLKID_SHA256
    assert _sha256(EXACT_LIBBLKID) == model.LIBBLKID_SHA256
    assert bytes.fromhex(model.LIBBLKID_BUILD_ID) in EXACT_LIBBLKID.read_bytes()
    assert _sha256(ISO9660_SOURCE) == model.ISO9660_SOURCE_SHA256
    source = ISO9660_SOURCE.read_text(encoding="utf-8")
    assert "probe_iso9660_set_uuid" in source
    assert '"%c%c%c%c-%c%c-%c%c-%c%c-%c%c-%c%c-%c%c"' in source


def test_exact_kernel_config_rows_and_offsets() -> None:
    model = _load_model()
    assert _sha256(KERNEL_CONFIG) == model.KERNEL_CONFIG_SHA256
    data = KERNEL_CONFIG.read_bytes()
    expected = {
        0x861A: (1292, b"# CONFIG_BLK_DEV_SR is not set\n"),
        0x17E34: (3666, b"# CONFIG_ISO9660_FS is not set\n"),
        0x17E53: (3667, b"# CONFIG_UDF_FS is not set\n"),
    }
    for offset, (line_number, row) in expected.items():
        assert data[offset : offset + len(row)] == row
        assert data[:offset].count(b"\n") + 1 == line_number
    for positive in (
        b"CONFIG_BLOCK=y\n",
        b"CONFIG_SCSI=m\n",
        b"CONFIG_BLK_DEV_SD=m\n",
        b"CONFIG_USB_STORAGE=m\n",
    ):
        assert positive in data


def test_lz4_output_growth_is_rejected_before_copy_or_aggregate_extend() -> None:
    oversized_literal = bytes((0xF0, 0x00)) + b"A" * 15
    with pytest.raises(
        ValueError, match="literal output exceeds bound before extend"
    ):
        _decompress_lz4_block(oversized_literal, max_output_size=8)

    oversized_overlap_match = bytes((0x1F, ord("A"), 0x01, 0x00, 0x00))
    with pytest.raises(ValueError, match="match output exceeds bound before copy"):
        _decompress_lz4_block(oversized_overlap_match, max_output_size=8)

    literal_block = bytes((0x30,)) + b"abc"
    two_block_payload = (
        LEGACY_LZ4_MAGIC
        + struct.pack("<I", len(literal_block))
        + literal_block
        + struct.pack("<I", len(literal_block))
        + literal_block
        + struct.pack("<I", 6)
    )
    with pytest.raises(
        ValueError, match="aggregate exceeds bound before extend"
    ):
        _decompress_linux_legacy_lz4_payload(
            two_block_payload, max_output_size=5
        )


def test_canonical_archive_bzimage_vmlinux_embedded_ikconfig_chain() -> None:
    model = _load_model()
    if not CANONICAL_ARCHIVE.exists():
        pytest.skip("ignored canonical archive is not present")
    assert _sha256(CANONICAL_ARCHIVE) == model.ROOTFS_ARCHIVE_SHA256
    with tarfile.open(CANONICAL_ARCHIVE, "r:gz") as archive:
        members = [member for member in archive.getmembers() if member.isfile()]
        matches = [member for member in members if member.name == KERNEL_MEMBER]
        assert len(matches) == 1
        stream = archive.extractfile(matches[0])
        assert stream is not None
        bzimage = stream.read(MAX_BZIMAGE_SIZE + 1)
        assert len(bzimage) <= MAX_BZIMAGE_SIZE
        assert stream.read(1) == b""

    assert hashlib.sha256(bzimage).hexdigest() == model.KERNEL_IMAGE_SHA256
    vmlinux, payload_offset, payload_length = _extract_vmlinux_from_bzimage(bzimage)
    assert payload_offset == model.KERNEL_PAYLOAD_OFFSET == 0x406E
    assert payload_length == model.KERNEL_PAYLOAD_LENGTH == 0x50EBF7
    assert hashlib.sha256(vmlinux).hexdigest() == model.VMLINUX_SHA256
    assert model.VMLINUX_SHA256 == EXPECTED_VMLINUX_SHA256
    assert len(vmlinux) == model.VMLINUX_SIZE == 0xFA3828
    assert _gnu_build_id(vmlinux) == model.VMLINUX_BUILD_ID
    assert model.VMLINUX_BUILD_ID == EXPECTED_VMLINUX_BUILD_ID

    config, marker_start, marker_end = _extract_ikconfig(vmlinux)
    assert marker_start == model.IKCONFIG_START_OFFSET == 0x809860
    assert marker_end == model.IKCONFIG_END_OFFSET == 0x80FAB2
    assert hashlib.sha256(config).hexdigest() == model.KERNEL_CONFIG_SHA256
    assert config == KERNEL_CONFIG.read_bytes()
    for offset, line_number, row in (
        (0x861A, 1292, b"# CONFIG_BLK_DEV_SR is not set\n"),
        (0x17E34, 3666, b"# CONFIG_ISO9660_FS is not set\n"),
        (0x17E53, 3667, b"# CONFIG_UDF_FS is not set\n"),
    ):
        assert config[offset : offset + len(row)] == row
        assert config[:offset].count(b"\n") + 1 == line_number

    malformed = bytearray(bzimage)
    malformed[payload_offset] ^= 0xFF
    with pytest.raises(ValueError, match="compression magic"):
        _extract_vmlinux_from_bzimage(bytes(malformed))
    with pytest.raises(ValueError):
        _decompress_linux_legacy_lz4_payload(
            bzimage[payload_offset : payload_offset + payload_length - 1]
        )
    with pytest.raises(ValueError, match="not unique"):
        _extract_ikconfig(vmlinux + IKCONFIG_START)


def test_canonical_archive_kernel_rules_and_module_inventory() -> None:
    model = _load_model()
    if not CANONICAL_ARCHIVE.exists():
        pytest.skip("ignored canonical archive is not present")
    assert _sha256(CANONICAL_ARCHIVE) == model.ROOTFS_ARCHIVE_SHA256
    with tarfile.open(CANONICAL_ARCHIVE, "r:gz") as archive:
        members = [member for member in archive.getmembers() if member.isfile()]
        by_name = {member.name: member for member in members}

        for name, expected_hash in (
            (KERNEL_MEMBER, model.KERNEL_IMAGE_SHA256),
            (RULES_MEMBER, model.PERSISTENT_STORAGE_RULES_SHA256),
        ):
            stream = archive.extractfile(by_name[name])
            assert stream is not None
            assert hashlib.sha256(stream.read()).hexdigest() == expected_hash

        ko_names = sorted(member.name for member in members if member.name.endswith(".ko"))
        assert len(ko_names) == 163
        encoded_names = ("\n".join(ko_names) + "\n").encode("utf-8")
        assert hashlib.sha256(encoded_names).hexdigest() == (
            model.KO_MEMBER_NAME_MANIFEST_SHA256
        )
        tested_module_basenames = {
            "isofs.ko",
            "iso9660.ko",
            "udf.ko",
            "sr_mod.ko",
            "sr.ko",
        }
        assert not {Path(name).name.lower() for name in ko_names} & tested_module_basenames
        tested_module_paths = re.compile(
            rb"(?:^|/)(?:isofs|iso9660|udf|sr_mod|sr)\.ko(?:$|[:\x00\s])",
            re.IGNORECASE | re.MULTILINE,
        )
        tested_identifiers = re.compile(
            rb"(?<![A-Za-z0-9_-])(?:fs-(?:iso9660|isofs|udf)|"
            rb"isofs|iso9660|udf|sr_mod)(?![A-Za-z0-9_-])",
            re.IGNORECASE,
        )
        tested_scsi_cdrom_aliases = re.compile(
            rb"(?im)^alias\s+(?:scsi:t-0x0?5\S*|block-major-11-\S*)\s+\S+"
        )

        metadata = {
            Path(member.name).name: member
            for member in members
            if member.name.startswith(MODULE_ROOT + "modules.")
        }
        assert set(metadata) == set(model.MODULE_METADATA_SHA256)
        for basename, expected_hash in model.MODULE_METADATA_SHA256.items():
            stream = archive.extractfile(metadata[basename])
            assert stream is not None
            payload = stream.read()
            assert hashlib.sha256(payload).hexdigest() == expected_hash
            assert tested_module_paths.search(payload) is None
            assert tested_identifiers.search(payload) is None
            assert tested_scsi_cdrom_aliases.search(payload) is None

    rules = PERSISTENT_STORAGE_RULES.read_text(encoding="utf-8").splitlines()
    assert _sha256(PERSISTENT_STORAGE_RULES) == model.PERSISTENT_STORAGE_RULES_SHA256
    assert rules[8] == (
        'KERNEL!="loop*|mmcblk*[0-9]|msblk*[0-9]|mspblk*[0-9]|nvme*|sd*|sr*|vd*|xvd*|bcache*|cciss*|dasd*|ubd*", GOTO="persistent_storage_end"'
    )
    assert rules[65] == 'KERNEL!="sr*", IMPORT{builtin}="blkid"'


def test_retained_generic_mount_retry_and_success_signal_rows() -> None:
    model = _load_model()
    rows = _artifact_rows(MOUNT_ARTIFACT_PATH)
    binary = EXACT_USB_AUTOMOUNT.read_bytes()
    assert _sha256(EXACT_USB_AUTOMOUNT) == model.USB_AUTOMOUNT_SHA256
    for address, expected_hex in MOUNT_PREREQUISITE_ROWS.items():
        expected = bytes.fromhex(expected_hex)
        assert rows[address] == expected
        assert binary[address : address + len(expected)] == expected
    assert binary[0x794E:0x7951] == b"%s\0"
    assert binary[0x784F:0x7858] == b"UsbMount\0"


def test_retained_dispatcher_and_mount_rows_match_exact_binary() -> None:
    model = _load_model()
    rows = _artifact_rows()
    for address, expected_hex in USB_ROWS.items():
        assert rows[address] == bytes.fromhex(expected_hex)

    if not EXACT_USB_AUTOMOUNT.exists():
        pytest.skip("ignored exact usb-automount is not present")
    assert _sha256(EXACT_USB_AUTOMOUNT) == model.USB_AUTOMOUNT_SHA256
    binary = EXACT_USB_AUTOMOUNT.read_bytes()
    for address, expected_hex in USB_ROWS.items():
        expected = bytes.fromhex(expected_hex)
        assert binary[address : address + len(expected)] == expected
        assert rows[address] == binary[address : address + len(expected)]


def test_retained_iso9660_rows_and_format_match_exact_libblkid() -> None:
    model = _load_model()
    rows = _artifact_rows()
    binary = EXACT_LIBBLKID.read_bytes()
    assert _sha256(EXACT_LIBBLKID) == model.LIBBLKID_SHA256
    for address, expected_hex in LIBBLKID_ISO9660_ROWS.items():
        expected = bytes.fromhex(expected_hex)
        assert rows[address] == expected
        assert binary[address : address + len(expected)] == expected
        assert rows[address] == binary[address : address + len(expected)]
    assert binary[0x35368 : 0x35368 + len(ISO9660_UUID_FORMAT)] == ISO9660_UUID_FORMAT
    text = ARTIFACT_PATH.read_text(encoding="utf-8")
    assert '0x35368 is the exact NUL-terminated string' in text
    assert '"%c%c%c%c-%c%c-%c%c-%c%c-%c%c-%c%c-%c%c"' in text


def test_retained_artifact_captures_other_decisive_instructions() -> None:
    text = ARTIFACT_PATH.read_text(encoding="utf-8")
    for needle in (
        "3d4ce: e8 9d c8 fc ff",
        "cfc4: c6 44 3d 00 5f",
        "cff5: 48 8d 35 64 6c 02 00",
        "4676: e8 d5 f7 ff ff",
        "4683: 4c 8b 8c 24 88 00 00 00",
        "848e0: 48 8d b8 28 01 00 00",
        "849a7: e8 b4 b5 ff ff",
        "101563: 48 8d 35 f9 a5 10 00",
        "102dbb: 4c 8b a4 24 80 00 00 00",
        "102de9: e8 42 dd ff ff",
        "1027f5: e8 d6 06 f2 ff",
        "10281c: e8 0f e3 ff ff",
        "10337b: e8 50 fb f1 ff",
        "103398: e8 93 d7 ff ff",
        "100bb0: e8 6b 4c f4 ff",
        "101d3b: 48 8b 54 24 08",
        "101d7c: e8 7f 1b f2 ff",
    ):
        assert needle in text


def test_pre_recorded_classification_asserts_every_output() -> None:
    model = _load_model()
    result = model.build_report()["pre_recorded_target_classification"]
    assert set(result) == OUTPUT_KEYS
    expected = {
        "exact_static_fact_set_complete": True,
        "automounter_static_fact_set_complete": True,
        "appdm_callback_to_staging_edge_established": True,
        "appupgrade_package_suffix_to_sink_edge_established": True,
        "per_binary_edge_fact_set_complete": True,
        "uuid_or_no_uuid_alternate_is_automounter_path_component": True,
        "label_is_automounter_path_component": False,
        "ordinary_filesystem_label_shell_active_mount_path_route": False,
        "constrained_uuid_families_shell_active_mount_path_route": False,
        "iso9660_static_shell_path_sensitive_uuid_byte_route": True,
        "userspace_iso9660_recognition_and_generic_mount_dispatch_established": True,
        "userspace_iso9660_read_only_retry_established": True,
        "mount_success_signal_requires_mount_success": True,
        "canonical_bzimage_to_vmlinux_identity_chain_established": True,
        "embedded_ikconfig_to_recovered_config_identity_chain_established": True,
        "recovered_kernel_named_iso9660_mount_prerequisite_absence": True,
        "recovered_kernel_iso9660_mount_prerequisite_absence": None,
        "exact_recovered_stack_named_iso9660_mount_route": False,
        "exact_recovered_stack_iso9660_mount_route": None,
        "exact_recovered_stack_named_physical_optical_sr_route": False,
        "exact_recovered_stack_physical_optical_sr_route": None,
        "no_uuid_alternate_shell_active_mount_path_effect": False,
        "shell_sensitive_label_dbus_bytes_preserved": True,
        "hardware_descriptor_control_established": None,
        "physical_iso9660_source_control_established": None,
        "materially_different_runtime_identity_established": None,
        "installed_iso9660_media_accepted_and_mounted": None,
        "physical_iso9660_mount_path_delivery_established": None,
        "end_to_end_package_base_delivery_established": None,
        "relevant_decryptionfile_invocation_established": None,
        "physical_iso9660_path_delivery_to_decryption_input_established": None,
        "overall_physical_shell_sensitive_sink_delivery_established": None,
        "verifier_before_shell_sink_established": True,
        "authentication_acceptance_established": None,
        "process_security_context_established": None,
        "command_success_observed": None,
        "privilege_or_domain_amplification_observed": None,
        "root_impact_observed": None,
        "persistence_observed": None,
        "extraction_member_names_are_qprocess_arguments": False,
        "enumerated_member_path_route_established": True,
        "signed_container_member_name_binding_established": None,
        "physically_supplied_authenticated_member_name_route_established": None,
    }
    assert result["input"] == model.PRE_RECORDED_STATE
    for name, value in expected.items():
        assert result[name] is value, name


def test_model_requires_exact_keys_and_literal_booleans() -> None:
    model = _load_model()
    state = dict(model.PRE_RECORDED_STATE)

    missing = dict(state)
    missing.pop(model.FACTS[0])
    with pytest.raises(model.ModelError, match="state keys mismatch"):
        model.classify_pathname_provenance(**missing)

    extra = dict(state)
    extra["unexpected"] = False
    with pytest.raises(model.ModelError, match="state keys mismatch"):
        model.classify_pathname_provenance(**extra)

    for invalid in (1, 0, "true", None):
        non_boolean = dict(state)
        non_boolean[model.FACTS[0]] = invalid
        with pytest.raises(model.ModelError, match="must be a boolean"):
            model.classify_pathname_provenance(**non_boolean)


def test_model_rejects_static_causal_contradictions() -> None:
    model = _load_model()
    cases = (
        ("constrained_uuid_family_alphabet_bound", "constrained-family"),
        ("uuid_or_alternate_selected_as_path_component_bound", "constrained-family"),
        ("iso9660_raw_date_copy_bound", "zero-check"),
        ("iso9660_all_zero_only_validation_bound", "raw-character formatting"),
        ("iso9660_raw_char_uuid_format_bound", "safe-string preservation"),
        ("iso9660_uuid_safe_string_preservation_bound", "ISO9660 mount dispatch"),
        ("complete_dispatcher_remap_bound", "ISO9660 mount dispatch"),
        ("automounter_property_registers_bound", "ordinary USB sd/blkid route"),
        ("ordinary_usb_sd_blkid_route_bound", "generic mount dispatch"),
        ("iso9660_generic_mount_dispatch_bound", "read-only retry"),
        ("canonical_bzimage_vmlinux_identity_chain_bound", "embedded IKCONFIG"),
        ("embedded_ikconfig_recovered_config_identity_chain_bound", "prerequisite absence"),
        ("recovered_kernel_config_identity_bound", "embedded IKCONFIG"),
        ("canonical_rootfs_tested_module_identities_absence_bound", "prerequisite absence"),
        ("no_uuid_fallback_inputs_bound", "fallback inputs"),
        ("usb_serial_precheck_and_sanitizer_bound", "serial sanitization"),
        ("label_transform_bound", "label D-Bus"),
        ("label_and_model_separate_dbus_fields_bound", "label D-Bus"),
    )
    for fact, message in cases:
        state = dict(model.PRE_RECORDED_STATE)
        state[fact] = False
        with pytest.raises(model.ModelError, match=message):
            model.classify_pathname_provenance(**state)


def test_iso9660_static_route_requires_bound_binary_and_source_identity() -> None:
    model = _load_model()
    for fact in ("libblkid_member_identity_bound", "iso9660_source_identity_bound"):
        state = dict(model.PRE_RECORDED_STATE)
        state[fact] = False
        if fact == "libblkid_member_identity_bound":
            state["ordinary_usb_sd_blkid_route_bound"] = False
            state["iso9660_generic_mount_dispatch_bound"] = False
            state["iso9660_read_only_retry_bound"] = False
            state["mount_success_signal_dominance_bound"] = False
        result = model.classify_pathname_provenance(**state)
        assert result["iso9660_static_shell_path_sensitive_uuid_byte_route"] is None
        assert result["automounter_static_fact_set_complete"] is None


def test_success_requires_delivery_and_authentication() -> None:
    model = _load_model()
    for delivery, invocation, authentication in (
        (False, False, False),
        (True, False, True),
        (True, True, False),
        (False, True, True),
    ):
        state = dict(model.PRE_RECORDED_STATE)
        state["installed_cross_process_delivery_established"] = delivery
        state["relevant_decryptionfile_invocation_established"] = invocation
        state["authentication_acceptance_established"] = authentication
        state["command_success_observed"] = True
        with pytest.raises(
            model.ModelError,
            match="installed delivery, relevant decryptionFile invocation and authentication acceptance",
        ):
            model.classify_pathname_provenance(**state)


def test_pre_auth_decryption_input_delivery_is_not_shell_sink_delivery() -> None:
    model = _load_model()
    state = dict(model.PRE_RECORDED_STATE)
    state.update(
        physical_iso9660_source_control_established=True,
        materially_different_runtime_identity_established=True,
        installed_iso9660_media_accepted_and_mounted=True,
        installed_cross_process_delivery_established=True,
        relevant_decryptionfile_invocation_established=True,
        authentication_acceptance_established=False,
    )
    result = model.classify_pathname_provenance(**state)
    assert result[
        "physical_iso9660_path_delivery_to_decryption_input_established"
    ] is True
    assert result["overall_physical_shell_sensitive_sink_delivery_established"] is None
    assert result["command_success_observed"] is None

    state["command_success_observed"] = True
    with pytest.raises(
        model.ModelError,
        match="relevant decryptionFile invocation and authentication acceptance",
    ):
        model.classify_pathname_provenance(**state)


def test_persistence_remains_independent() -> None:
    model = _load_model()
    state = dict(model.PRE_RECORDED_STATE)
    state["persistence_observed"] = True
    result = model.classify_pathname_provenance(**state)
    assert result["persistence_observed"] is True
    assert result["command_success_observed"] is None
    assert result["root_impact_observed"] is None


def test_installed_mount_true_requires_materially_different_runtime_identity() -> None:
    model = _load_model()
    state = dict(model.PRE_RECORDED_STATE)
    state["installed_iso9660_media_accepted_and_mounted"] = True
    with pytest.raises(
        model.ModelError,
        match="requires a materially different runtime identity",
    ):
        model.classify_pathname_provenance(**state)

    state["materially_different_runtime_identity_established"] = True
    result = model.classify_pathname_provenance(**state)
    assert result["installed_iso9660_media_accepted_and_mounted"] is True
    assert result["exact_recovered_stack_named_iso9660_mount_route"] is False
    assert result["exact_recovered_stack_iso9660_mount_route"] is None
    assert result["physical_iso9660_mount_path_delivery_established"] is None


def test_all_established_runtime_gates_classify_without_changing_static_negatives() -> None:
    model = _load_model()
    state = {name: True for name in model.FACTS}
    result = model.classify_pathname_provenance(**state)
    assert set(result) == OUTPUT_KEYS
    assert result["hardware_descriptor_control_established"] is True
    assert result["physical_iso9660_source_control_established"] is True
    assert result["materially_different_runtime_identity_established"] is True
    assert result["installed_iso9660_media_accepted_and_mounted"] is True
    assert result["physical_iso9660_mount_path_delivery_established"] is True
    assert result["end_to_end_package_base_delivery_established"] is True
    assert result["relevant_decryptionfile_invocation_established"] is True
    assert result[
        "physical_iso9660_path_delivery_to_decryption_input_established"
    ] is True
    assert result["overall_physical_shell_sensitive_sink_delivery_established"] is True
    assert result["ordinary_filesystem_label_shell_active_mount_path_route"] is False
    assert result["constrained_uuid_families_shell_active_mount_path_route"] is False
    assert result["iso9660_static_shell_path_sensitive_uuid_byte_route"] is True
    assert result[
        "userspace_iso9660_recognition_and_generic_mount_dispatch_established"
    ] is True
    assert result["userspace_iso9660_read_only_retry_established"] is True
    assert result["mount_success_signal_requires_mount_success"] is True
    assert result["canonical_bzimage_to_vmlinux_identity_chain_established"] is True
    assert result[
        "embedded_ikconfig_to_recovered_config_identity_chain_established"
    ] is True
    assert result[
        "recovered_kernel_named_iso9660_mount_prerequisite_absence"
    ] is True
    assert result["recovered_kernel_iso9660_mount_prerequisite_absence"] is None
    assert result["exact_recovered_stack_named_iso9660_mount_route"] is False
    assert result["exact_recovered_stack_iso9660_mount_route"] is None
    assert result[
        "exact_recovered_stack_named_physical_optical_sr_route"
    ] is False
    assert result["exact_recovered_stack_physical_optical_sr_route"] is None
    assert result["no_uuid_alternate_shell_active_mount_path_effect"] is False
    assert result["command_success_observed"] is True
    assert result["root_impact_observed"] is True
    assert result["persistence_observed"] is True
    assert result["physically_supplied_authenticated_member_name_route_established"] is True


def test_exhaustive_runtime_states_assert_every_formula_and_contradiction() -> None:
    model = _load_model()
    base = dict(model.PRE_RECORDED_STATE)
    accepted = rejected = 0

    for bits in itertools.product((False, True), repeat=len(model.RUNTIME_FACTS)):
        state = dict(base)
        state.update(dict(zip(model.RUNTIME_FACTS, bits, strict=True)))
        iso_control = state["physical_iso9660_source_control_established"]
        runtime_identity = state["materially_different_runtime_identity_established"]
        iso_media = state["installed_iso9660_media_accepted_and_mounted"]
        delivery = state["installed_cross_process_delivery_established"]
        invocation = state["relevant_decryptionfile_invocation_established"]
        authentication = state["authentication_acceptance_established"]
        command = state["command_success_observed"]
        amplification = state["privilege_or_domain_amplification_observed"]
        root = state["root_impact_observed"]
        contradictory = (
            (iso_media and not runtime_identity)
            or (command and not (delivery and invocation and authentication))
            or (amplification and not command)
            or (root and not amplification)
        )

        if contradictory:
            with pytest.raises(model.ModelError, match="contradictory state"):
                model.classify_pathname_provenance(**state)
            rejected += 1
            continue

        result = model.classify_pathname_provenance(**state)
        accepted += 1
        assert set(result) == OUTPUT_KEYS
        assert all(
            value in (True, False, None)
            for key, value in result.items()
            if key != "input"
        )
        assert result["hardware_descriptor_control_established"] is _tri(
            state["hardware_descriptor_control_established"]
        )
        assert result["physical_iso9660_source_control_established"] is _tri(
            iso_control
        )
        assert result["materially_different_runtime_identity_established"] is _tri(
            runtime_identity
        )
        assert result["installed_iso9660_media_accepted_and_mounted"] is _tri(
            iso_media
        )
        iso_mount = iso_control and iso_media
        iso_input = iso_mount and delivery and invocation
        iso_sink = iso_input and authentication
        assert result["physical_iso9660_mount_path_delivery_established"] is _tri(
            iso_mount
        )
        assert result["end_to_end_package_base_delivery_established"] is _tri(delivery)
        assert result["relevant_decryptionfile_invocation_established"] is _tri(
            invocation
        )
        assert result[
            "physical_iso9660_path_delivery_to_decryption_input_established"
        ] is _tri(iso_input)
        assert result[
            "overall_physical_shell_sensitive_sink_delivery_established"
        ] is _tri(iso_sink)
        assert result["authentication_acceptance_established"] is _tri(authentication)
        assert result["process_security_context_established"] is _tri(
            state["process_security_context_established"]
        )
        assert result["command_success_observed"] is _tri(command)
        assert result["privilege_or_domain_amplification_observed"] is _tri(
            amplification
        )
        assert result["root_impact_observed"] is _tri(root)
        assert result["persistence_observed"] is _tri(state["persistence_observed"])
        assert result["signed_container_member_name_binding_established"] is _tri(
            state["signed_container_member_name_binding_established"]
        )
        member = (
            state["physical_archive_member_name_control_established"]
            and state["signed_container_member_name_binding_established"]
            and authentication
        )
        assert result[
            "physically_supplied_authenticated_member_name_route_established"
        ] is _tri(member)
        for static_negative in (
            "label_is_automounter_path_component",
            "ordinary_filesystem_label_shell_active_mount_path_route",
            "constrained_uuid_families_shell_active_mount_path_route",
            "exact_recovered_stack_named_iso9660_mount_route",
            "exact_recovered_stack_named_physical_optical_sr_route",
            "no_uuid_alternate_shell_active_mount_path_effect",
            "extraction_member_names_are_qprocess_arguments",
        ):
            assert result[static_negative] is False
        assert result["iso9660_static_shell_path_sensitive_uuid_byte_route"] is True
        assert result[
            "userspace_iso9660_recognition_and_generic_mount_dispatch_established"
        ] is True
        assert result["userspace_iso9660_read_only_retry_established"] is True
        assert result["mount_success_signal_requires_mount_success"] is True
        assert result[
            "recovered_kernel_named_iso9660_mount_prerequisite_absence"
        ] is True
        assert result["recovered_kernel_iso9660_mount_prerequisite_absence"] is None
        assert result["exact_recovered_stack_iso9660_mount_route"] is None
        assert result["exact_recovered_stack_physical_optical_sr_route"] is None

    assert accepted + rejected == 2 ** len(model.RUNTIME_FACTS)
    assert accepted > 0
    assert rejected > 0


def test_cli_report_is_frozen_and_encoding_independent() -> None:
    outputs = [_run_model(value) for value in ("ascii", "latin-1", "utf-16")]
    assert outputs[0] == outputs[1] == outputs[2]
    payload = outputs[0]
    assert hashlib.sha256(payload).hexdigest() == EXPECTED_REPORT_SHA256
    assert payload.endswith(b"\n")
    assert not payload.endswith(b"\n\n")
    assert b"\r" not in payload
    assert all(byte < 0x80 for byte in payload)
    report = json.loads(payload.decode("utf-8"))
    assert report["schema_version"] == 5
    assert report["evidence_binding"]["libblkid_sha256"] == (
        "56a6b8b7fd08dcec92a6c1ad84bc7a7cc44071f33c571339415e1cbf00d60701"
    )
    assert report["evidence_binding"]["iso9660_source_sha256"] == (
        "601d9311b1a68b5fbccf7d6af28f089b4f919494b36edb7f144786cec651477b"
    )
    assert report["evidence_binding"]["kernel_config_sha256"] == (
        "987268a1a4b333d67c219c63b690c3828811136a7a3b203eb6f20552e82dad56"
    )
    assert report["evidence_binding"]["regular_ko_member_count"] == 163
    assert report["evidence_binding"]["kernel_config_offsets"] == {
        "CONFIG_BLK_DEV_SR": "byte 0x861a, line 1292",
        "CONFIG_ISO9660_FS": "byte 0x17e34, line 3666",
        "CONFIG_UDF_FS": "byte 0x17e53, line 3667",
    }
    assert (
        "verifier dominance over command construction and popen"
        in report["claim_boundary"]["establishes"]
    )
    assert (
        "installed-unit kernel identity or extra installed modules"
        in report["claim_boundary"]["does_not_establish"]
    )
    assert report["claim_boundary"]["persistence_is_independent"] is True
    assert report["claim_boundary"][
        "exact_named_stock_negative_does_not_suppress_materially_different_runtime"
    ] is True
    assert report["claim_boundary"]["emits_no_operational_material"] is True


def test_cli_rejects_partial_and_duplicate_inputs() -> None:
    partial = subprocess.run(
        [
            sys.executable,
            str(MODEL_PATH),
            "--stock-archive-member-identity-bound",
            "true",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert partial.returncode != 0
    assert "all AppFUMO USB pathname-provenance arguments are required" in partial.stderr

    duplicate = subprocess.run(
        [
            sys.executable,
            str(MODEL_PATH),
            "--stock-archive-member-identity-bound",
            "true",
            "--stock-archive-member-identity-bound",
            "false",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert duplicate.returncode != 0
    assert "may be specified only once" in duplicate.stderr


def test_evidence_states_corrected_route_and_remaining_unknowns() -> None:
    text = EVIDENCE_PATH.read_text(encoding="utf-8")
    for needle in (
        "0x3a59",
        "0x3b49",
        "ID_FS_UUID",
        "ID_SERIAL_SHORT",
        "ID_PART_ENTRY_NUMBER",
        "label and model are separate D-Bus fields",
        "filesystem-label mount-path route: **rejected**",
        "ISO9660 raw-date UUID static byte route: **established**",
        "0x1c4c0",
        "0x1c5c6",
        "0x35368",
        "601d9311b1a68b5fbccf7d6af28f089b4f919494b36edb7f144786cec651477b",
        "combined filesystem-metadata rejection is withdrawn",
        "`#` is not a comment introducer",
        "hardware-descriptor control: **unknown**",
        "launch-argument/inner-AppUpgrade-constructor bridge",
        "0x102de9",
        "0x10281c",
        "member names as direct QProcess arguments: **false**",
        "top-level signature cryptographically binding decrypted tar member names:\n  **unknown**",
        "exact_recovered_stack_iso9660_mount_route",
        "schema-v5",
    ):
        assert needle in text

    mount_text = MOUNT_EVIDENCE_PATH.read_text(encoding="utf-8")
    for needle in (
        "# CONFIG_BLK_DEV_SR is not set",
        "# CONFIG_ISO9660_FS is not set",
        "# CONFIG_UDF_FS is not set",
        "0x4d70",
        "0x4df1",
        "0x4e34",
        "163 regular `.ko` members",
        "materially different runtime identity",
        "mixed-case/dot ISO naming extensions",
        "successful port-1 callback",
    ):
        assert needle in mount_text


def test_tracked_outputs_have_no_absolute_workstation_path() -> None:
    for path in (
        MODEL_PATH,
        ARTIFACT_PATH,
        MOUNT_ARTIFACT_PATH,
        EVIDENCE_PATH,
        MOUNT_EVIDENCE_PATH,
    ):
        text = path.read_text(encoding="utf-8")
        assert "/Users/" not in text
        assert "/opt/homebrew/" not in text
