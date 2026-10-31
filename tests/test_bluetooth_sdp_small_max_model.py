from __future__ import annotations

import hashlib
import importlib.util
import itertools
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/uk_fw/bluetooth_sdp_small_max_model.py"
SPEC = importlib.util.spec_from_file_location("bluetooth_sdp_small_max_model", TOOL)
assert SPEC and SPEC.loader
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)

UNKNOWN_FIELDS = {
    "path_prerequisites_observed_by_model",
    "peer_requested_max_list_len",
    "ordinary_protocol_valid_remote_mtu_observed",
    "corrupted_or_impossible_internal_attr_offset_safety_established",
    "partial_attribute_helper_general_memory_safety_established",
    "other_sdp_handler_safety_established",
    "negotiated_mtu_edge_case_safety_established",
    "allocator_corruption_absence_established",
    "vendor_equivalent_unnamed_path_absence_established",
    "runtime_handler_reachability_observed",
    "runtime_adapter_policy_observed",
    "runtime_channel_security_observed",
    "owner_device_applicability_established",
    "memory_corruption_observed",
    "code_execution_observed",
    "unrestricted_root_observed",
    "persistence_observed",
}
EXPECTED_FIELDS = {
    "input",
    "classification_path",
    "classification_is_conditional_on_path_prerequisites",
    "syntactically_valid_handler_input_required",
    "ordinary_response_list_construction_reached_required",
    "scratch_allocation_or_reuse_success_required",
    "valid_internal_continuation_state_required",
    "early_error_exits_classified_by_write_matrix",
    "matrix_quantity_is_effective_internal_maximum_after_cap",
    "ordinary_protocol_valid_remote_mtu_required_for_peer_equivalence",
    "small_peer_maximum_maps_to_effective_maximum_under_precondition",
    "low_or_invalid_remote_mtu_cap_behavior_classified",
    "source_like_less_than_four_guard_present",
    "scratch_allocation_operand",
    "scratch_allocation_uses_effective_internal_maximum",
    "scratch_allocation_failure_allows_scratch_writes",
    "minimum_successful_gki_user_capacity_bytes",
    "partial_attribute_helper_complete_ranges_bound",
    "partial_attribute_helper_valid_state_copy_length_clamped_to_remaining",
    "partial_attribute_helper_valid_state_destination_advance_clamped_to_remaining",
    "valid_internal_attr_offset_required_for_partial_helper_bound",
    "initial_header_maximum_written_offset_on_feasible_path",
    "initial_header_write_extent_on_feasible_path_bytes",
    "continuation_write_extent_upper_bound_on_feasible_path_bytes",
    "scratch_write_extent_upper_bound_on_feasible_path_bytes",
    "highest_scratch_offset_upper_bound_on_feasible_path",
    "response_copy_length_upper_bound_on_feasible_path_bytes",
    "logical_effective_limit_exceedance_on_feasible_path",
    "successful_gki_scratch_capacity_exceeded_on_feasible_path",
    "public_small_maximum_physical_oob_write_mechanism_rejected_on_stated_preconditions",
    "general_sdp_memory_safety_established",
    *UNKNOWN_FIELDS,
}
DEFAULT_REPORT_SHA256 = (
    "7d471272700166a4ea26ece68fc4ffdcdeec47d38ec799a379a66523c4258590"
)


def expected_classification(
    handler: str, request_state: str, effective_max_list_len: int
) -> dict[str, object]:
    initial = request_state == "initial"
    extent = 3 if initial else effective_max_list_len
    highest = 2 if initial else (
        effective_max_list_len - 1 if effective_max_list_len else None
    )
    result: dict[str, object] = {
        "input": {
            "handler": handler,
            "request_state": request_state,
            "effective_internal_max_list_len": effective_max_list_len,
        },
        "classification_path": "feasible_ordinary_response_list_construction",
        "classification_is_conditional_on_path_prerequisites": True,
        "syntactically_valid_handler_input_required": True,
        "ordinary_response_list_construction_reached_required": True,
        "scratch_allocation_or_reuse_success_required": True,
        "valid_internal_continuation_state_required": not initial,
        "early_error_exits_classified_by_write_matrix": False,
        "matrix_quantity_is_effective_internal_maximum_after_cap": True,
        "ordinary_protocol_valid_remote_mtu_required_for_peer_equivalence": True,
        "small_peer_maximum_maps_to_effective_maximum_under_precondition": True,
        "low_or_invalid_remote_mtu_cap_behavior_classified": False,
        "source_like_less_than_four_guard_present": False,
        "scratch_allocation_operand": "remote_mtu",
        "scratch_allocation_uses_effective_internal_maximum": False,
        "scratch_allocation_failure_allows_scratch_writes": False,
        "minimum_successful_gki_user_capacity_bytes": 64,
        "partial_attribute_helper_complete_ranges_bound": True,
        "partial_attribute_helper_valid_state_copy_length_clamped_to_remaining": True,
        "partial_attribute_helper_valid_state_destination_advance_clamped_to_remaining": True,
        "valid_internal_attr_offset_required_for_partial_helper_bound": not initial,
        "initial_header_maximum_written_offset_on_feasible_path": (
            2 if initial else None
        ),
        "initial_header_write_extent_on_feasible_path_bytes": (
            3 if initial else 0
        ),
        "continuation_write_extent_upper_bound_on_feasible_path_bytes": (
            0 if initial else effective_max_list_len
        ),
        "scratch_write_extent_upper_bound_on_feasible_path_bytes": extent,
        "highest_scratch_offset_upper_bound_on_feasible_path": highest,
        "response_copy_length_upper_bound_on_feasible_path_bytes": extent,
        "logical_effective_limit_exceedance_on_feasible_path": (
            initial and effective_max_list_len < 3
        ),
        "successful_gki_scratch_capacity_exceeded_on_feasible_path": False,
        "public_small_maximum_physical_oob_write_mechanism_rejected_on_stated_preconditions": True,
        "general_sdp_memory_safety_established": False,
    }
    result.update({name: None for name in UNKNOWN_FIELDS})
    return result


class BluetoothSdpSmallMaxModelTests(unittest.TestCase):
    def test_exhaustive_handlers_states_maxima_and_every_field(self) -> None:
        seen: set[tuple[str, str, int]] = set()
        for handler, state, maximum in itertools.product(
            M.HANDLERS, M.REQUEST_STATES, M.EFFECTIVE_SMALL_MAXIMA
        ):
            with self.subTest(handler=handler, state=state, maximum=maximum):
                result = M.classify_small_maximum(handler, state, maximum)
                self.assertEqual(set(result), EXPECTED_FIELDS)
                self.assertEqual(
                    result, expected_classification(handler, state, maximum)
                )
                seen.add((handler, state, maximum))
        self.assertEqual(len(seen), 16)

    def test_logical_exceedance_is_separate_from_physical_capacity(self) -> None:
        for handler in M.HANDLERS:
            for maximum in M.EFFECTIVE_SMALL_MAXIMA:
                initial = M.classify_small_maximum(handler, "initial", maximum)
                continuation = M.classify_small_maximum(
                    handler, "continuation", maximum
                )
                with self.subTest(handler=handler, maximum=maximum):
                    self.assertEqual(
                        initial[
                            "logical_effective_limit_exceedance_on_feasible_path"
                        ],
                        maximum < 3,
                    )
                    self.assertFalse(
                        initial[
                            "successful_gki_scratch_capacity_exceeded_on_feasible_path"
                        ]
                    )
                    self.assertTrue(
                        initial[
                            "public_small_maximum_physical_oob_write_mechanism_rejected_on_stated_preconditions"
                        ]
                    )
                    self.assertFalse(
                        continuation[
                            "logical_effective_limit_exceedance_on_feasible_path"
                        ]
                    )
                    self.assertFalse(
                        continuation[
                            "successful_gki_scratch_capacity_exceeded_on_feasible_path"
                        ]
                    )
                    self.assertTrue(
                        continuation["valid_internal_continuation_state_required"]
                    )
                    self.assertIsNone(
                        continuation[
                            "corrupted_or_impossible_internal_attr_offset_safety_established"
                        ]
                    )

    def test_matrix_is_conditional_and_uses_effective_internal_maximum(self) -> None:
        for state in M.REQUEST_STATES:
            result = M.classify_small_maximum("service-attr", state, 2)
            with self.subTest(state=state):
                self.assertTrue(
                    result["classification_is_conditional_on_path_prerequisites"]
                )
                self.assertTrue(result["syntactically_valid_handler_input_required"])
                self.assertTrue(
                    result["ordinary_response_list_construction_reached_required"]
                )
                self.assertTrue(
                    result["scratch_allocation_or_reuse_success_required"]
                )
                self.assertEqual(
                    result["valid_internal_continuation_state_required"],
                    state == "continuation",
                )
                self.assertFalse(
                    result["early_error_exits_classified_by_write_matrix"]
                )
                self.assertTrue(
                    result["matrix_quantity_is_effective_internal_maximum_after_cap"]
                )
                self.assertIsNone(result["peer_requested_max_list_len"])
                self.assertTrue(
                    result[
                        "ordinary_protocol_valid_remote_mtu_required_for_peer_equivalence"
                    ]
                )
                self.assertIsNone(
                    result["ordinary_protocol_valid_remote_mtu_observed"]
                )
                self.assertFalse(
                    result["low_or_invalid_remote_mtu_cap_behavior_classified"]
                )
                self.assertTrue(
                    result[
                        "partial_attribute_helper_valid_state_copy_length_clamped_to_remaining"
                    ]
                )
                self.assertIsNone(
                    result[
                        "corrupted_or_impossible_internal_attr_offset_safety_established"
                    ]
                )

    def test_rejects_bool_as_int_and_all_out_of_domain_inputs(self) -> None:
        invalid = (
            (True, "initial", 0, "handler must be a string"),
            ("service-attr", False, 0, "request_state must be a string"),
            (
                "service-attr",
                "initial",
                True,
                "integer, not a boolean",
            ),
            ("other", "initial", 0, "handler must be one of"),
            ("service-attr", "later", 0, "request_state must be one of"),
            (
                "service-attr",
                "initial",
                -1,
                "effective_max_list_len must be one of",
            ),
            (
                "service-attr",
                "initial",
                4,
                "effective_max_list_len must be one of",
            ),
            ("service-attr", "initial", 1.0, "must be an integer"),
            ("service-attr", "initial", "1", "must be an integer"),
        )
        for handler, state, maximum, message in invalid:
            with self.subTest(
                handler=handler, state=state, maximum=maximum
            ):
                with self.assertRaisesRegex(M.ModelError, message):
                    M.classify_small_maximum(handler, state, maximum)

    def test_report_binds_exact_binaries_ranges_fix_and_pool_capacity(self) -> None:
        report = M.build_report()
        binding = report["evidence_binding"]
        binaries = binding["binaries"]
        self.assertEqual(set(binaries), {"vbtd-51", "vbtd-63"})
        self.assertEqual(
            binaries["vbtd-51"]["sha256"],
            "55e21d077082e97f56fb113a1d3b216c0f2e63aa02fc4cd754a6593bc6cec9e0",
        )
        self.assertEqual(
            binaries["vbtd-51"]["build_id"],
            "12175aa88ccff70cc56498e0208c9a51aac0c9e9",
        )
        self.assertEqual(
            binaries["vbtd-63"]["sha256"],
            "c56b68fdd35b16b95688ab54a48ffb9f18034d925c057e86f8b9fe304f8b26b9",
        )
        self.assertEqual(
            binaries["vbtd-63"]["build_id"],
            "04141ed222ee8f150c0eb0e46fdb73624d168920",
        )
        self.assertEqual(
            binaries["vbtd-51"][
                "partial_attribute_helper_disassembly_sha256"
            ],
            "a6299c8bf1761a5f4f706a635b292e4410356ebb295cd51b7c8a882efc84f235",
        )
        self.assertEqual(
            binaries["vbtd-63"][
                "partial_attribute_helper_disassembly_sha256"
            ],
            "206c2f60f1bd6c96642dda82eeca69a19ccb0a698adc806418fddb0ad533ce96",
        )
        self.assertEqual(
            binaries["vbtd-51"]["fde_ranges"],
            {
                "service_search_attribute": "[0x841dc0,0x842628)",
                "service_attribute_dispatcher": "[0x842630,0x842e0b)",
                "gki_getbuf_r": "[0x7ad2e0,0x7ad690)",
                "gki_buffer_init": "[0x7ac590,0x7ad284)",
                "sdpu_build_partial_attrib_entry": "[0x8445f0,0x8448bf)",
            },
        )
        self.assertEqual(
            binaries["vbtd-63"]["fde_ranges"],
            {
                "service_search_attribute": "[0x8425b0,0x842e00)",
                "service_attribute_dispatcher": "[0x842e00,0x8435c3)",
                "gki_getbuf": "[0x7af2f0,0x7af633)",
                "gki_buffer_init": "[0x7ae5a0,0x7af294)",
                "sdpu_build_partial_attrib_entry": "[0x844d90,0x84504f)",
            },
        )
        self.assertEqual(
            binaries["vbtd-51"]["addresses"]["pool_0_capacity_store"],
            "0x7acbc4",
        )
        self.assertEqual(
            binaries["vbtd-63"]["addresses"]["pool_0_capacity_store"],
            "0x7aebd4",
        )
        self.assertEqual(
            binaries["vbtd-51"]["addresses"][
                "partial_attribute_valid_state_clamp_copy_and_advance"
            ],
            "0x8446ec-0x84472a",
        )
        self.assertEqual(
            binaries["vbtd-63"]["addresses"][
                "partial_attribute_valid_state_clamp_copy_and_advance"
            ],
            "0x844e84-0x844eb6",
        )
        self.assertEqual(binding["gki_minimum_successful_user_capacity_bytes"], 64)
        self.assertEqual(
            binding["public_fix"],
            {
                "commit": "f0edf6571d2d58e66ee0b100ebe49c585d31489f",
                "parent": "ec16f7d8c7e359a68ffe6b76e88add2210bf2cbd",
                "patch_sha256": "a0470c20592473144f8114cf41ab4cb2479fe2c108a4aa73fa4864eabd02ca34",
                "android_bug_by_handler": {
                    "service-attr": "68776054",
                    "service-search-attr": "68817966",
                },
                "added_check": "max_list_len < 4",
            },
        )

    def test_default_matrix_is_complete_and_ordered(self) -> None:
        matrix = M.build_report()["bounded_matrix"]
        expected_inputs = [
            {
                "handler": handler,
                "request_state": state,
                "effective_internal_max_list_len": maximum,
            }
            for handler in M.HANDLERS
            for state in M.REQUEST_STATES
            for maximum in M.EFFECTIVE_SMALL_MAXIMA
        ]
        self.assertEqual([case["input"] for case in matrix], expected_inputs)
        self.assertEqual(len(matrix), 16)

    def test_cli_complete_and_fail_closed_cases(self) -> None:
        complete = [
            "--handler",
            "service-search-attr",
            "--request-state",
            "continuation",
            "--effective-max-list-len",
            "3",
        ]
        run = subprocess.run(
            [sys.executable, str(TOOL), *complete],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(
            json.loads(run.stdout)["classification"],
            expected_classification("service-search-attr", "continuation", 3),
        )

        cases = (
            (["--handler", "service-attr"], "must be supplied together"),
            (
                [
                    "--handler",
                    "service-attr",
                    "--handler",
                    "service-search-attr",
                ],
                "only once",
            ),
            (["--hand", "service-attr"], "unrecognized arguments"),
            (
                [
                    "--handler",
                    "service-attr",
                    "--request-state",
                    "initial",
                    "--effective-max-list-len",
                    "true",
                ],
                "invalid int value",
            ),
            (
                [
                    "--handler",
                    "service-attr",
                    "--request-state",
                    "initial",
                    "--effective-max-list-len",
                    "4",
                ],
                "effective_max_list_len must be one of",
            ),
        )
        for argv, message in cases:
            with self.subTest(argv=argv):
                run = subprocess.run(
                    [sys.executable, str(TOOL), *argv],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertNotEqual(run.returncode, 0)
                self.assertEqual(run.stdout, "")
                self.assertIn(message, run.stderr)

    def test_default_output_is_deterministic_explicit_utf8_lf(self) -> None:
        expected = (
            json.dumps(M.build_report(), indent=2, sort_keys=True).encode("utf-8")
            + b"\n"
        )
        outputs = []
        for encoding in ("ascii:strict", "latin-1:strict", "utf-16:strict"):
            with self.subTest(encoding=encoding):
                env = dict(os.environ, PYTHONIOENCODING=encoding)
                run = subprocess.run(
                    [sys.executable, str(TOOL)],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                )
                self.assertEqual(run.stdout, expected)
                self.assertTrue(run.stdout.endswith(b"\n"))
                self.assertNotIn(b"\r", run.stdout)
                outputs.append(run.stdout)
        self.assertEqual(len(set(outputs)), 1)
        self.assertEqual(
            hashlib.sha256(outputs[0]).hexdigest(), DEFAULT_REPORT_SHA256
        )

    def test_report_and_source_contain_no_operational_message_material(self) -> None:
        report_text = json.dumps(M.build_report(), sort_keys=True).lower()
        source_text = TOOL.read_text(encoding="utf-8").lower()
        for forbidden in (
            "malformed",
            "payload",
            "packet",
            "pdu",
            "socket",
            "radio",
            "executable",
            "endpoint",
            "target bytes",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, report_text)
                self.assertNotIn(forbidden, source_text)
        for forbidden_import in ("import socket", "import scapy", "import bluetooth"):
            self.assertNotIn(forbidden_import, source_text)
        boundary = M.build_report()["claim_boundary"]
        self.assertTrue(boundary["pure_deterministic_model"])
        self.assertTrue(
            boundary["emits_only_non_operational_classification_metadata"]
        )
        self.assertFalse(boundary["controlled_execution_performed"])


if __name__ == "__main__":
    unittest.main()
