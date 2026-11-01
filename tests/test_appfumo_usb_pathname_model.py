from __future__ import annotations

import hashlib
import importlib.util
import itertools
import json
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "tools/uk_fw/appfumo_usb_pathname_model.py"
ARTIFACT_PATH = (
    ROOT
    / "evidence/artifacts/update-candidates/"
    / "appfumo-usb-pathname-provenance-exact-static.asm"
)
EVIDENCE_PATH = ROOT / "evidence/appfumo-usb-pathname-provenance.md"
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
EXPECTED_REPORT_SHA256 = (
    "026b421772bd708c7f6ccec9200ed8fb47fee3307b1821415c3b9db516854aa3"
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
    "no_uuid_alternate_shell_active_mount_path_effect",
    "shell_sensitive_label_dbus_bytes_preserved",
    "hardware_descriptor_control_established",
    "physical_iso9660_source_control_established",
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


def _tri(value: bool) -> bool | None:
    return True if value else None


def _artifact_rows() -> dict[int, bytes]:
    rows: dict[int, bytes] = {}
    pattern = re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} ?)+)\s", re.I)
    for line in ARTIFACT_PATH.read_text(encoding="utf-8").splitlines():
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
    text = ARTIFACT_PATH.read_text(encoding="utf-8")
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
        "no_uuid_alternate_shell_active_mount_path_effect": False,
        "shell_sensitive_label_dbus_bytes_preserved": True,
        "hardware_descriptor_control_established": None,
        "physical_iso9660_source_control_established": None,
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


def test_all_established_runtime_gates_classify_without_changing_static_negatives() -> None:
    model = _load_model()
    state = {name: True for name in model.FACTS}
    result = model.classify_pathname_provenance(**state)
    assert set(result) == OUTPUT_KEYS
    assert result["hardware_descriptor_control_established"] is True
    assert result["physical_iso9660_source_control_established"] is True
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
        iso_media = state["installed_iso9660_media_accepted_and_mounted"]
        delivery = state["installed_cross_process_delivery_established"]
        invocation = state["relevant_decryptionfile_invocation_established"]
        authentication = state["authentication_acceptance_established"]
        command = state["command_success_observed"]
        amplification = state["privilege_or_domain_amplification_observed"]
        root = state["root_impact_observed"]
        contradictory = (
            (command and not (delivery and invocation and authentication))
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
            "no_uuid_alternate_shell_active_mount_path_effect",
            "extraction_member_names_are_qprocess_arguments",
        ):
            assert result[static_negative] is False
        assert result["iso9660_static_shell_path_sensitive_uuid_byte_route"] is True

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
    assert report["schema_version"] == 4
    assert report["evidence_binding"]["libblkid_sha256"] == (
        "56a6b8b7fd08dcec92a6c1ad84bc7a7cc44071f33c571339415e1cbf00d60701"
    )
    assert report["evidence_binding"]["iso9660_source_sha256"] == (
        "601d9311b1a68b5fbccf7d6af28f089b4f919494b36edb7f144786cec651477b"
    )
    assert (
        "verifier dominance over command construction and popen"
        in report["claim_boundary"]["establishes"]
    )
    assert (
        "authentication acceptance or actual physical shell-sink delivery"
        in report["claim_boundary"]["does_not_establish"]
    )
    assert report["claim_boundary"]["persistence_is_independent"] is True
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
    ):
        assert needle in text


def test_tracked_outputs_have_no_absolute_workstation_path() -> None:
    for path in (MODEL_PATH, ARTIFACT_PATH, EVIDENCE_PATH):
        text = path.read_text(encoding="utf-8")
        assert "/Users/" not in text
        assert "/opt/homebrew/" not in text
