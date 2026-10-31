#!/usr/bin/env python3
"""Model the recovered BusyBox CVE-2015-9261 initialized-slot boundary.

The recovered code compares a cursor into ``v[]`` with ``v + n`` even though
only an initialized prefix is populated.  The stable upstream correction
initializes every slot to ``UINT_MAX`` and treats that sentinel as invalid.  This
tool classifies supplied integer indices only.  It does not model the short-lived
and later corrected ``v_end`` implementation, parse or construct compressed data,
or execute target code.
"""
from __future__ import annotations

import argparse
import json
from typing import Any

SCHEMA_VERSION = 2
N_MAX = 288
BUSYBOX_SHA256 = "95bab633630fb158344497af52dc112e9e777458b810860068d4daa257bd9ebc"
BUSYBOX_BUILD_IDS = (
    "42e0a4c7631667cf9106ca36a4f2e7886f6f72b0",
    "dc25533aa5ad984ec9a7ed388925f24d328c1836",
)
INITIAL_FIX = "1de25a6e87e0e627aa34298105a3d17c60a1f44e"
CORRECTIVE_FOLLOWUP = "6bd3fff51aa74e2ee2d87887b12182a3b09792ef"
HUFT_BUILD_VA = 0x473F2
VULNERABLE_BOUND_VA = 0x4788A
VULNERABLE_DEREFERENCE_VA = 0x47938
EXTRA_BITS_READ_VA = 0x47970
BASE_VALUES_READ_VA = 0x47974


class ModelError(ValueError):
    """An input is outside the bounded integer model."""


def _integer(name: str, value: int, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ModelError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise ModelError(f"{name} must be in range {minimum}..{maximum}")
    return value


def classify(n: int, initialized_count: int, p_index: int, s: int) -> dict[str, Any]:
    """Classify one abstract table-build cursor state.

    Populated ``v[]`` entries form the prefix ``[0, initialized_count)``.  The
    supplied state is not claimed reachable from a DEFLATE bitstream, and the
    value of an uninitialized target slot remains indeterminate.
    """
    n = _integer("n", n, 1, N_MAX)
    initialized_count = _integer("initialized_count", initialized_count, 0, n)
    p_index = _integer("p_index", p_index, 0, n)
    s = _integer("s", s, 0, N_MAX)

    recovered_reads_slot = p_index < n
    recovered_reads_uninitialized = (
        recovered_reads_slot and p_index >= initialized_count
    )
    stable_slot_is_sentinel = p_index >= initialized_count

    if not recovered_reads_slot:
        recovered_outcome = "emit-invalid-code-without-v-read"
    elif recovered_reads_uninitialized:
        recovered_outcome = "read-uninitialized-v-entry"
    else:
        recovered_outcome = "read-initialized-v-entry"

    stable_outcome = (
        "emit-invalid-code-from-initialized-sentinel"
        if stable_slot_is_sentinel
        else "read-populated-v-entry"
    )

    return {
        "input": {
            "n": n,
            "initialized_count": initialized_count,
            "p_index": p_index,
            "s": s,
        },
        "populated_v_index_range": (
            [0, initialized_count - 1] if initialized_count else None
        ),
        "recovered_bound_index": n,
        "recovered_reads_v_slot": recovered_reads_slot,
        "recovered_reads_uninitialized_v": recovered_reads_uninitialized,
        "recovered_outcome": recovered_outcome,
        "uninitialized_window": (
            [initialized_count, n - 1] if initialized_count < n else None
        ),
        "uninitialized_window_entry_count": n - initialized_count,
        "stable_followup_initializes_all_slots": True,
        "stable_slot_is_uint_max_sentinel": stable_slot_is_sentinel,
        "stable_outcome": stable_outcome,
        "value_branch_if_uninitialized_read_occurs": {
            "value_less_than_s": "treated as an arbitrary simple symbol",
            "value_at_least_s": (
                "used to index base/extra tables; validity depends on the "
                "indeterminate value and call-specific tables"
            ),
            "indeterminate_value_is_attacker_selected": False,
        }
        if recovered_reads_uninitialized
        else None,
    }


def build_report(
    n: int | None = None,
    initialized_count: int | None = None,
    p_index: int | None = None,
    s: int | None = None,
) -> dict[str, Any]:
    supplied = (n, initialized_count, p_index, s)
    if any(value is not None for value in supplied) and not all(
        value is not None for value in supplied
    ):
        raise ModelError(
            "n, initialized_count, p_index, and s must be supplied together"
        )

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "busybox-cve-2015-9261-initialized-slot-bound",
        "evidence_binding": {
            "busybox_sha256": BUSYBOX_SHA256,
            "busybox_build_ids": list(BUSYBOX_BUILD_IDS),
            "initial_upstream_fix_commit": INITIAL_FIX,
            "corrective_followup_commit": CORRECTIVE_FOLLOWUP,
            "virtual_addresses": {
                "huft_build": f"0x{HUFT_BUILD_VA:x}",
                "recovered_v_plus_n_compare": f"0x{VULNERABLE_BOUND_VA:x}",
                "v_entry_read": f"0x{VULNERABLE_DEREFERENCE_VA:x}",
                "extra_bits_indexed_read": f"0x{EXTRA_BITS_READ_VA:x}",
                "base_values_indexed_read": f"0x{BASE_VALUES_READ_VA:x}",
            },
        },
        "call_classes": [
            {"name": "dynamic-code-length", "n": 19, "s": 19},
            {"name": "dynamic-literal-length", "n_range": [257, 286], "s": 257},
            {"name": "dynamic-distance", "n_range": [1, 30], "s": 0},
        ],
        "semantics": {
            "recovered_read_condition": "p_index < n",
            "recovered_uninitialized_condition": (
                "initialized_count <= p_index < n"
            ),
            "initial_fix_note": (
                "1de25a6e introduced a v_end bound but was corrected four days "
                "later; this model does not equate v_end with initialized_count"
            ),
            "stable_followup": (
                "6bd3fff initializes every v slot to UINT_MAX and emits an "
                "invalid code when the selected slot retains that sentinel"
            ),
        },
        "claim_boundary": {
            "establishes": (
                "Whether the recovered bound reads outside the populated v prefix "
                "for supplied integers, and the stable sentinel behavior."
            ),
            "does_not_establish": [
                "encoding or reachability of a supplied state from compressed input",
                "the exact behavior of the short-lived v_end implementation",
                "the indeterminate stack value read from an uninitialized entry",
                "a particular invalid table address or process crash",
                "controlled execution, signature bypass, root access, or persistence",
                "applicability to an owner build with a different binary identity",
            ],
        },
    }
    if all(value is not None for value in supplied):
        report["classification"] = classify(  # type: ignore[arg-type]
            n, initialized_count, p_index, s
        )
    else:
        report["summary"] = {
            "maximum_symbol_count": N_MAX,
            "affected_when": (
                "initialized_count < n and the cursor enters [initialized_count,n)"
            ),
            "stable_behavior": (
                "read an initialized UINT_MAX sentinel and emit an invalid code"
            ),
            "contains_only_numeric_invariants_and_text_metadata": True,
        }
    return report


def _cli_integer(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {value}") from exc


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=_cli_integer)
    parser.add_argument("--initialized-count", type=_cli_integer)
    parser.add_argument("--p-index", type=_cli_integer)
    parser.add_argument("--s", type=_cli_integer)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = build_report(args.n, args.initialized_count, args.p_index, args.s)
    except ModelError as exc:
        raise SystemExit(f"error: {exc}") from exc
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
