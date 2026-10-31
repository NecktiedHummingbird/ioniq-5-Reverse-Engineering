from __future__ import annotations

import hashlib
import itertools
import json
import subprocess
import sys
import unittest
from pathlib import Path

from tools.uk_fw import af_packet_frame_geometry_model as model

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "uk_fw" / "af_packet_frame_geometry_model.py"


class GeometryTests(unittest.TestCase):
    def test_zero_wrapped_count_keeps_index_and_offset_in_range(self) -> None:
        result = model.classify_geometry(
            bit_width=4,
            frames_per_block=4,
            block_count=4,
            block_size=4,
            frame_size=1,
            frame_count=0,
        )
        self.assertTrue(result["accepted_by_wrapping_equality"])
        self.assertTrue(result["lookup_geometry_safe"])

    def test_nonzero_wrapped_count_keeps_index_and_offset_in_range(self) -> None:
        result = model.classify_geometry(
            bit_width=4,
            frames_per_block=5,
            block_count=4,
            block_size=10,
            frame_size=2,
            frame_count=4,
        )
        self.assertTrue(result["accepted_by_wrapping_equality"])
        self.assertTrue(result["block_index_in_allocated_vector"])
        self.assertTrue(result["offset_inside_allocated_block"])

    def test_wrong_frame_count_is_not_treated_as_accepted_or_safe(self) -> None:
        result = model.classify_geometry(
            bit_width=4,
            frames_per_block=3,
            block_count=2,
            block_size=7,
            frame_size=2,
            frame_count=5,
        )
        self.assertEqual(
            result,
            {
                "accepted_by_wrapping_equality": False,
                "block_index_in_allocated_vector": False,
                "offset_inside_allocated_block": False,
                "lookup_geometry_safe": False,
            },
        )

    def test_exhaustive_small_geometries(self) -> None:
        for width in range(2, 6):
            limit = 1 << width
            with self.subTest(width=width):
                for block_size, frame_size, block_count in itertools.product(
                    range(1, limit), repeat=3
                ):
                    frames_per_block = block_size // frame_size
                    if frames_per_block == 0:
                        continue
                    frame_count = (frames_per_block * block_count) & (limit - 1)
                    result = model.classify_geometry(
                        bit_width=width,
                        frames_per_block=frames_per_block,
                        block_count=block_count,
                        block_size=block_size,
                        frame_size=frame_size,
                        frame_count=frame_count,
                    )
                    self.assertTrue(result["lookup_geometry_safe"])

    def test_reduced_width_summaries_include_zero_count_and_no_violation(self) -> None:
        for width in range(2, 9):
            with self.subTest(width=width):
                summary = model.reduced_width_summary(width)
                self.assertGreater(summary["accepted_states"], 0)
                self.assertGreater(summary["zero_wrapped_count_states"], 0)
                self.assertEqual(summary["block_index_violations"], 0)
                self.assertTrue(summary["all_accepted_block_indices_safe"])

    def test_geometry_rejects_invalid_domains_and_inconsistent_division(self) -> None:
        valid = {
            "bit_width": 4,
            "frames_per_block": 2,
            "block_count": 2,
            "block_size": 4,
            "frame_size": 2,
            "frame_count": 4,
        }
        mutations = [
            {"bit_width": 1},
            {"bit_width": True},
            {"frames_per_block": 0},
            {"block_count": 16},
            {"block_size": 0},
            {"frame_size": True},
            {"frame_count": -1},
            {"frames_per_block": 3},
        ]
        for mutation in mutations:
            case = valid | mutation
            with self.subTest(mutation=mutation):
                with self.assertRaises(model.ModelError):
                    model.classify_geometry(**case)


class EvidenceAndCliTests(unittest.TestCase):
    def test_default_evidence_rejects_lookup_oob_and_out_of_vma_insert(self) -> None:
        result = model.classify_evidence(**model.EVIDENCE_FACTS)
        self.assertTrue(result["v1_v2_frame_lookup_oob_rejected_by_supplied_effects"])
        self.assertTrue(result["out_of_vma_page_insert_rejected_by_supplied_effects"])
        self.assertFalse(result["missing_guard_has_proven_memory_corruption"])
        self.assertIsNone(result["root_observed"])

    def test_all_boolean_states_fail_closed(self) -> None:
        names = list(model.EVIDENCE_FACTS)
        lookup_names = set(names) - {"mmap_insert_rejects_addresses_outside_vma"}
        for bits in itertools.product((False, True), repeat=len(names)):
            supplied = dict(zip(names, bits, strict=True))
            result = model.classify_evidence(**supplied)
            self.assertEqual(
                result["v1_v2_frame_lookup_oob_rejected_by_supplied_effects"],
                all(supplied[name] for name in lookup_names),
            )
            self.assertEqual(
                result["out_of_vma_page_insert_rejected_by_supplied_effects"],
                supplied["mmap_insert_rejects_addresses_outside_vma"],
            )
            self.assertFalse(result["missing_guard_has_proven_memory_corruption"])

    def test_evidence_rejects_key_and_type_mismatches(self) -> None:
        missing = dict(model.EVIDENCE_FACTS)
        missing.pop(next(iter(missing)))
        with self.assertRaises(model.ModelError):
            model.classify_evidence(**missing)
        bad_type = dict(model.EVIDENCE_FACTS)
        bad_type[next(iter(bad_type))] = 1  # type: ignore[assignment]
        with self.assertRaises(model.ModelError):
            model.classify_evidence(**bad_type)

    def test_cli_is_deterministic_utf8_lf_and_has_no_operational_fields(self) -> None:
        env = {"PYTHONIOENCODING": "ascii"}
        first = subprocess.run(
            [sys.executable, str(TOOL)],
            cwd=ROOT,
            env=env,
            check=True,
            capture_output=True,
        ).stdout
        second = subprocess.run(
            [sys.executable, str(TOOL)],
            cwd=ROOT,
            env={"PYTHONIOENCODING": "utf-16"},
            check=True,
            capture_output=True,
        ).stdout
        self.assertEqual(first, second)
        self.assertTrue(first.endswith(b"\n"))
        self.assertNotIn(b"setsockopt", first.lower())
        self.assertNotIn(b"tp_block_size", first.lower())
        self.assertNotIn(b"tp_frame_nr", first.lower())
        self.assertNotIn(b"target_path", first.lower())
        report = json.loads(first)
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(len(report["reduced_width_checks"]), 7)
        self.assertEqual(
            hashlib.sha256(first).hexdigest(),
            "28fd6c15d874d669882bb5f23530e042d9155f62999a778fdcc230ad43b64f05",
        )

    def test_cli_rejects_duplicates_invalid_values_and_positionals(self) -> None:
        cases = [
            [
                "--frame-product-equality-uses-wrapping-u32=1",
                "--frame-product-equality-uses-wrapping-u32=0",
            ],
            [
                "--mmap=0",
                "--mmap-insert-rejects-addresses-outside-vma=1",
            ],
            ["--allocation-uses-block-count-not-frame-count=2"],
            ["unexpected"],
        ]
        for args in cases:
            with self.subTest(args=args):
                completed = subprocess.run(
                    [sys.executable, str(TOOL), *args],
                    cwd=ROOT,
                    capture_output=True,
                )
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(completed.stdout, b"")


if __name__ == "__main__":
    unittest.main()
