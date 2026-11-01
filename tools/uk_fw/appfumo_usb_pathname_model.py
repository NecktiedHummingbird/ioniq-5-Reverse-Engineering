#!/usr/bin/env python3
"""Classify bounded AppFUMO USB pathname-provenance facts safely.

Inputs are literal Booleans only. False means "not established", except that
named exact-static negative facts explicitly carry a positive ``*_bound`` fact.
The model does not inspect media, archives, paths, D-Bus, mounts, commands, or
recovered binaries and emits no operational material.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 4
ROOTFS_ARCHIVE_SHA256 = (
    "423491fd8b86bd815d4e12f47054e08a589a5159f87213f08980fcc3a0e47c84"
)
USB_AUTOMOUNT_SHA256 = (
    "7db44d8e34fbece4d5b8ef4896a99239cb540a22d1d756335dde4bc219af3802"
)
SYSTEMD_UDEVD_SHA256 = (
    "f32f6296ea20d959ac046ae80724f39e317aaaf492a5c7eedd9270b5b2abab0d"
)
LIBBLKID_SHA256 = (
    "56a6b8b7fd08dcec92a6c1ad84bc7a7cc44071f33c571339415e1cbf00d60701"
)
LIBBLKID_BUILD_ID = "c6f98d98cb2cbc2ff864167f37048233d90a8fef"
ISO9660_SOURCE_SHA256 = (
    "601d9311b1a68b5fbccf7d6af28f089b4f919494b36edb7f144786cec651477b"
)
APPDMCLIENT_SHA256 = (
    "9a1fb796d7ac24fcce71c16e3dbee9306c888f43e705ee081f41b7d473978bd0"
)
APPUPGRADE_SHA256 = (
    "464a87646153213ce1f405743a10cff78eb90c203b619f983002358ca74ef0e7"
)
PUBLIC_FIELD_LOG_SHA256 = (
    "84d5bb69270dd610b132c8950c31dd98adad844c5a2c108b4df617381685de86"
)
STATIC_ARTIFACT_SHA256 = (
    "932510a860b40cce280f217670cbf2c213e31b0a90008ac5c011c933cd584e8f"
)

AUTOMOUNTER_STATIC_FACTS = (
    "stock_archive_member_identity_bound",
    "libblkid_member_identity_bound",
    "iso9660_source_identity_bound",
    "automounter_property_registers_bound",
    "complete_dispatcher_remap_bound",
    "uuid_or_alternate_selected_as_path_component_bound",
    "label_and_model_separate_dbus_fields_bound",
    "constrained_uuid_family_alphabet_bound",
    "constrained_uuid_family_shell_active_bytes_excluded_bound",
    "iso9660_raw_date_copy_bound",
    "iso9660_all_zero_only_validation_bound",
    "iso9660_raw_char_uuid_format_bound",
    "iso9660_uuid_safe_string_preservation_bound",
    "iso9660_uuid_dispatch_to_mount_component_bound",
    "no_uuid_fallback_inputs_bound",
    "usb_serial_precheck_and_sanitizer_bound",
    "prefixed_command_word_shell_effect_excluded_bound",
    "label_transform_bound",
    "shell_sensitive_label_dbus_preservation_bound",
    "automounter_dbus_mount_path_field_bound",
)
APPDM_STATIC_FACTS = ("appdm_callback_path_forwarding_bound",)
APPUPGRADE_STATIC_FACTS = (
    "appupgrade_package_suffix_bound",
    "verifier_before_shell_sink_bound",
    "unquoted_shell_sink_bound",
)
PER_BINARY_STATIC_FACTS = (
    AUTOMOUNTER_STATIC_FACTS + APPDM_STATIC_FACTS + APPUPGRADE_STATIC_FACTS
)
EXTRACTION_STATIC_FACTS = (
    "extraction_qprocess_operands_exclude_member_names_bound",
    "enumerated_member_path_reaches_decryption_bound",
    "enumerated_member_verifier_before_sink_bound",
)
STATIC_FACTS = PER_BINARY_STATIC_FACTS + EXTRACTION_STATIC_FACTS
RUNTIME_FACTS = (
    "hardware_descriptor_control_established",
    "physical_iso9660_source_control_established",
    "installed_iso9660_media_accepted_and_mounted",
    "installed_cross_process_delivery_established",
    "relevant_decryptionfile_invocation_established",
    "authentication_acceptance_established",
    "process_security_context_established",
    "command_success_observed",
    "privilege_or_domain_amplification_observed",
    "root_impact_observed",
    "persistence_observed",
    "physical_archive_member_name_control_established",
    "signed_container_member_name_binding_established",
)
FACTS = STATIC_FACTS + RUNTIME_FACTS
PRE_RECORDED_STATE = {
    **{name: True for name in STATIC_FACTS},
    **{name: False for name in RUNTIME_FACTS},
}


class ModelError(ValueError):
    """Raised when input is outside the strict Boolean evidence schema."""


def _tri(value: bool) -> bool | None:
    return True if value else None


def classify_pathname_provenance(**values: bool) -> dict[str, Any]:
    """Return bounded tri-state findings for one complete Boolean fact set."""
    expected = set(FACTS)
    supplied = set(values)
    if supplied != expected:
        raise ModelError(
            f"state keys mismatch: missing={sorted(expected - supplied)}, "
            f"extra={sorted(supplied - expected)}"
        )

    state: dict[str, bool] = {}
    for name in FACTS:
        value = values[name]
        if not isinstance(value, bool):
            raise ModelError(f"{name} must be a boolean")
        state[name] = value

    contradictions: list[str] = []
    if state["constrained_uuid_family_shell_active_bytes_excluded_bound"] and not (
        state["constrained_uuid_family_alphabet_bound"]
        and state["uuid_or_alternate_selected_as_path_component_bound"]
    ):
        contradictions.append(
            "constrained-family exclusion requires alphabet and UUID path selection"
        )
    if state["iso9660_all_zero_only_validation_bound"] and not state[
        "iso9660_raw_date_copy_bound"
    ]:
        contradictions.append("ISO9660 zero-check binding requires raw date copy")
    if state["iso9660_raw_char_uuid_format_bound"] and not (
        state["iso9660_raw_date_copy_bound"]
        and state["iso9660_all_zero_only_validation_bound"]
    ):
        contradictions.append(
            "ISO9660 raw-character formatting requires copy and validation bindings"
        )
    if state["iso9660_uuid_safe_string_preservation_bound"] and not state[
        "iso9660_raw_char_uuid_format_bound"
    ]:
        contradictions.append(
            "ISO9660 safe-string preservation requires raw-character UUID formatting"
        )
    if state["iso9660_uuid_dispatch_to_mount_component_bound"] and not (
        state["iso9660_uuid_safe_string_preservation_bound"]
        and state["uuid_or_alternate_selected_as_path_component_bound"]
        and state["complete_dispatcher_remap_bound"]
    ):
        contradictions.append(
            "ISO9660 mount dispatch requires preservation, UUID selection and dispatcher"
        )
    if state["prefixed_command_word_shell_effect_excluded_bound"] and not (
        state["no_uuid_fallback_inputs_bound"]
        and state["usb_serial_precheck_and_sanitizer_bound"]
    ):
        contradictions.append(
            "prefixed-word exclusion requires fallback inputs and serial sanitization"
        )
    if state["shell_sensitive_label_dbus_preservation_bound"] and not (
        state["label_transform_bound"]
        and state["label_and_model_separate_dbus_fields_bound"]
    ):
        contradictions.append(
            "label D-Bus preservation requires transform and separate-field bindings"
        )
    if state["installed_cross_process_delivery_established"] and not all(
        state[name] for name in PER_BINARY_STATIC_FACTS
    ):
        contradictions.append(
            "installed delivery requires all separate per-binary path edges"
        )
    if state["command_success_observed"] and not (
        state["installed_cross_process_delivery_established"]
        and state["relevant_decryptionfile_invocation_established"]
        and state["authentication_acceptance_established"]
    ):
        contradictions.append(
            "command success requires installed delivery, relevant decryptionFile invocation and authentication acceptance"
        )
    if (
        state["privilege_or_domain_amplification_observed"]
        and not state["command_success_observed"]
    ):
        contradictions.append("amplification requires command success")
    if (
        state["root_impact_observed"]
        and not state["privilege_or_domain_amplification_observed"]
    ):
        contradictions.append("root impact requires amplification")
    if (
        state["signed_container_member_name_binding_established"]
        and not state["enumerated_member_path_reaches_decryption_bound"]
    ):
        contradictions.append(
            "member-name binding requires the enumerated-member route"
        )
    if contradictions:
        raise ModelError("contradictory state: " + "; ".join(contradictions))

    automounter_static_complete = all(
        state[name] for name in AUTOMOUNTER_STATIC_FACTS
    )
    appdm_static_complete = all(state[name] for name in APPDM_STATIC_FACTS)
    appupgrade_static_complete = all(
        state[name] for name in APPUPGRADE_STATIC_FACTS
    )
    per_binary_static_complete = all(
        state[name] for name in PER_BINARY_STATIC_FACTS
    )
    extraction_static_complete = all(
        state[name] for name in EXTRACTION_STATIC_FACTS
    )
    label_path_route_rejected = (
        state["uuid_or_alternate_selected_as_path_component_bound"]
        and state["label_and_model_separate_dbus_fields_bound"]
    )
    constrained_uuid_shell_route_rejected = (
        state["uuid_or_alternate_selected_as_path_component_bound"]
        and state["constrained_uuid_family_alphabet_bound"]
        and state["constrained_uuid_family_shell_active_bytes_excluded_bound"]
    )
    iso9660_static_byte_route = all(
        state[name]
        for name in (
            "libblkid_member_identity_bound",
            "iso9660_source_identity_bound",
            "iso9660_raw_date_copy_bound",
            "iso9660_all_zero_only_validation_bound",
            "iso9660_raw_char_uuid_format_bound",
            "iso9660_uuid_safe_string_preservation_bound",
            "iso9660_uuid_dispatch_to_mount_component_bound",
        )
    )
    no_uuid_shell_route_rejected = (
        state["no_uuid_fallback_inputs_bound"]
        and state["usb_serial_precheck_and_sanitizer_bound"]
        and state["prefixed_command_word_shell_effect_excluded_bound"]
    )
    physical_iso9660_mount_delivery = (
        iso9660_static_byte_route
        and state["physical_iso9660_source_control_established"]
        and state["installed_iso9660_media_accepted_and_mounted"]
    )
    end_to_end_package_base_delivery = (
        per_binary_static_complete
        and state["installed_cross_process_delivery_established"]
    )
    physical_iso9660_decryption_input_delivery = (
        physical_iso9660_mount_delivery
        and end_to_end_package_base_delivery
        and state["relevant_decryptionfile_invocation_established"]
    )
    physical_iso9660_shell_sink_delivery = (
        physical_iso9660_decryption_input_delivery
        and state["authentication_acceptance_established"]
    )
    member_route_physically_supplied = (
        extraction_static_complete
        and state["physical_archive_member_name_control_established"]
        and state["signed_container_member_name_binding_established"]
        and state["authentication_acceptance_established"]
    )

    return {
        "input": state,
        "exact_static_fact_set_complete": all(state[name] for name in STATIC_FACTS),
        "automounter_static_fact_set_complete": _tri(automounter_static_complete),
        "appdm_callback_to_staging_edge_established": _tri(appdm_static_complete),
        "appupgrade_package_suffix_to_sink_edge_established": _tri(
            appupgrade_static_complete
        ),
        "per_binary_edge_fact_set_complete": _tri(per_binary_static_complete),
        "uuid_or_no_uuid_alternate_is_automounter_path_component": _tri(
            state["uuid_or_alternate_selected_as_path_component_bound"]
        ),
        "label_is_automounter_path_component": (
            False if label_path_route_rejected else None
        ),
        "ordinary_filesystem_label_shell_active_mount_path_route": (
            False if label_path_route_rejected else None
        ),
        "constrained_uuid_families_shell_active_mount_path_route": (
            False if constrained_uuid_shell_route_rejected else None
        ),
        "iso9660_static_shell_path_sensitive_uuid_byte_route": _tri(
            iso9660_static_byte_route
        ),
        "no_uuid_alternate_shell_active_mount_path_effect": (
            False if no_uuid_shell_route_rejected else None
        ),
        "shell_sensitive_label_dbus_bytes_preserved": _tri(
            state["shell_sensitive_label_dbus_preservation_bound"]
        ),
        "hardware_descriptor_control_established": _tri(
            state["hardware_descriptor_control_established"]
        ),
        "physical_iso9660_source_control_established": _tri(
            state["physical_iso9660_source_control_established"]
        ),
        "installed_iso9660_media_accepted_and_mounted": _tri(
            state["installed_iso9660_media_accepted_and_mounted"]
        ),
        "physical_iso9660_mount_path_delivery_established": _tri(
            physical_iso9660_mount_delivery
        ),
        "end_to_end_package_base_delivery_established": _tri(
            end_to_end_package_base_delivery
        ),
        "relevant_decryptionfile_invocation_established": _tri(
            state["relevant_decryptionfile_invocation_established"]
        ),
        "physical_iso9660_path_delivery_to_decryption_input_established": _tri(
            physical_iso9660_decryption_input_delivery
        ),
        "overall_physical_shell_sensitive_sink_delivery_established": _tri(
            physical_iso9660_shell_sink_delivery
        ),
        "verifier_before_shell_sink_established": _tri(
            state["verifier_before_shell_sink_bound"]
        ),
        "authentication_acceptance_established": _tri(
            state["authentication_acceptance_established"]
        ),
        "process_security_context_established": _tri(
            state["process_security_context_established"]
        ),
        "command_success_observed": _tri(state["command_success_observed"]),
        "privilege_or_domain_amplification_observed": _tri(
            state["privilege_or_domain_amplification_observed"]
        ),
        "root_impact_observed": _tri(state["root_impact_observed"]),
        "persistence_observed": _tri(state["persistence_observed"]),
        "extraction_member_names_are_qprocess_arguments": (
            False
            if state["extraction_qprocess_operands_exclude_member_names_bound"]
            else None
        ),
        "enumerated_member_path_route_established": _tri(
            extraction_static_complete
        ),
        "signed_container_member_name_binding_established": _tri(
            state["signed_container_member_name_binding_established"]
        ),
        "physically_supplied_authenticated_member_name_route_established": _tri(
            member_route_physically_supplied
        ),
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "appfumo-usb-pathname-provenance-exact-static",
        "evidence_binding": {
            "rootfs_archive_sha256": ROOTFS_ARCHIVE_SHA256,
            "usb_automount_sha256": USB_AUTOMOUNT_SHA256,
            "systemd_udevd_sha256": SYSTEMD_UDEVD_SHA256,
            "libblkid_sha256": LIBBLKID_SHA256,
            "libblkid_build_id": LIBBLKID_BUILD_ID,
            "iso9660_source_sha256": ISO9660_SOURCE_SHA256,
            "iso9660_source_provenance": (
                "util-linux v2.27.1 libblkid/src/superblocks/iso9660.c "
                "probe_iso9660_set_uuid lines 110-151"
            ),
            "appdmclient_sha256": APPDMCLIENT_SHA256,
            "appupgrade_sha256": APPUPGRADE_SHA256,
            "public_field_log_sha256": PUBLIC_FIELD_LOG_SHA256,
            "retained_static_artifact_sha256": STATIC_ARTIFACT_SHA256,
            "usb_automount_build_id": "20748cf9928ba155ac4201a33bb1e29e64ae9139",
            "systemd_udevd_build_id": "91b0e9592a52274a97e185fed528d6af3557e49d",
            "appupgrade_build_id": "863a8730e66a1c5245a1bf458fe2554adee0351a",
            "virtual_addresses": {
                "automounter_event_fde": "0x3ef0..0x4836",
                "mount_dispatcher": "0x3a50..0x3b53",
                "port_classifier_fde": "0x3850..0x38f3",
                "no_uuid_helper_fde": "0x3e50..0x3eea",
                "mount_fde": "0x4c00..0x508d",
                "mount_format": "0x78a6",
                "udev_builtin_blkid_fde": "0x3d210..0x3d69d",
                "blkid_safe_string_fde": "0xced0..0xd09c",
                "iso9660_uuid_producer": "0x1c4c0..0x1c654",
                "iso9660_uuid_format": "0x35368",
                "usb_id_sanitizer_fde": "0x22a00..0x22b20",
                "appdm_mounted_callback": "0x84700",
                "appupgrade_decryption_fde": "0x100b30..0x10110c",
                "copy_whats_new_fde": "0x101110..0x104c1b",
                "direct_decryption_calls": "0x10281c,0x102de9,0x103398",
            },
            "assessment": "evidence/appfumo-usb-pathname-provenance.md",
            "pre_recorded_state_source": (
                "separate exact-static review; not verified by model execution"
            ),
        },
        "claim_boundary": {
            "establishes": [
                "UUID or serial/partition alternate as the mount-path component",
                "label and model as separate D-Bus fields",
                "negative shell-active result for constrained UUID families",
                "ISO9660 raw-date UUID static shell/path-sensitive byte route",
                "negative shell-active result for the no-UUID sanitized word",
                "separate per-binary AppDMClient and AppUpgrade edges",
                "verifier dominance over command construction and popen",
                "separation of pre-auth decryption-input delivery from shell-sink delivery",
                "separation of package-base and post-extraction member-name routes",
            ],
            "does_not_establish": [
                "physical ISO9660 source control, media acceptance or mount success",
                "hardware-descriptor control for an applicable no-UUID route",
                "AppDMClient launch-argument to inner AppUpgrade package-base bridge",
                "installed-device identity or observed cross-process delivery",
                "relevant decryptionFile invocation with the delivered path",
                "authentication acceptance or actual physical shell-sink delivery",
                "member-name signature binding",
                "process security context or command success",
                "privilege/domain amplification, root impact, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "causally_contradictory_inputs_are_rejected": True,
            "persistence_is_independent": True,
            "false_input_means_not_established_not_disproved": True,
            "emits_no_operational_material": True,
        },
        "pre_recorded_target_classification": classify_pathname_provenance(
            **PRE_RECORDED_STATE
        ),
    }
    if state is not None:
        report["classification"] = classify_pathname_provenance(**state)
    return report


def _boolean(value: str) -> bool:
    normalized = value.lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


class _Once(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest) is not None:
            parser.error(f"{option_string} may be specified only once")
        setattr(namespace, self.dest, values)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in FACTS:
        parser.add_argument(
            f"--{name.replace('_', '-')}",
            dest=name,
            type=_boolean,
            action=_Once,
        )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    state = {name: getattr(args, name) for name in FACTS}
    supplied = [value is not None for value in state.values()]
    if any(supplied) and not all(supplied):
        raise SystemExit("all AppFUMO USB pathname-provenance arguments are required")
    report = build_report(state if all(supplied) else None)
    payload = json.dumps(report, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    sys.stdout.buffer.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
