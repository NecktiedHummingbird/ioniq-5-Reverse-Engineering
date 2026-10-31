#!/usr/bin/env python3
"""Model the bounded semantic premises of CVE-2018-17182.

Inputs are booleans only. The model does not map or unmap memory, create a
thread, wrap a target counter, execute recovered code, dereference a cache,
create a race, or emit a command, trigger, payload, or firmware byte sequence.
Pre-recorded target state comes from separate instruction-level review and is
not verified by model execution.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

SCHEMA_VERSION = 1
VMLINUX_SHA256 = "f5ee9c2f97eed44f9827153c273125bf131a9ca9a96c63bb6e93cfc5af6b102b"
VMLINUX_BUILD_ID = "273378887b4cf563c10862fdf18b2292765df781"
PRE_RECORDED_TARGET_STATE = {
    "generation_increment_is_32_bit": True,
    "zero_wrap_calls_global_flush": True,
    "single_user_flush_returns_without_cache_clear": True,
    "lookup_compares_32_bit_generations": True,
}


class ModelError(ValueError):
    """Raised when supplied state is outside this bounded model."""


def _boolean(name: str, value: bool) -> bool:
    if not isinstance(value, bool):
        raise ModelError(f"{name} must be a boolean")
    return value


def classify_vmacache_wrap(
    generation_increment_is_32_bit: bool,
    zero_wrap_calls_global_flush: bool,
    single_user_flush_returns_without_cache_clear: bool,
    lookup_compares_32_bit_generations: bool,
) -> dict[str, Any]:
    """Classify the named stale-generation premise for supplied state."""

    state = {
        "generation_increment_is_32_bit": _boolean(
            "generation_increment_is_32_bit", generation_increment_is_32_bit
        ),
        "zero_wrap_calls_global_flush": _boolean(
            "zero_wrap_calls_global_flush", zero_wrap_calls_global_flush
        ),
        "single_user_flush_returns_without_cache_clear": _boolean(
            "single_user_flush_returns_without_cache_clear",
            single_user_flush_returns_without_cache_clear,
        ),
        "lookup_compares_32_bit_generations": _boolean(
            "lookup_compares_32_bit_generations",
            lookup_compares_32_bit_generations,
        ),
    }
    premise = all(state.values())
    return {
        "input": state,
        "cve_2018_17182_named_premise_present": premise,
        "generation_states_before_repeat": 1 << 32 if premise else None,
        "stale_vma_dereference_observed": None,
        "memory_corruption_observed": None,
        "privilege_escalation": None,
    }


def build_report(state: dict[str, bool] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": "vmacache-generation-wrap",
        "evidence_binding": {
            "vmlinux_sha256": VMLINUX_SHA256,
            "vmlinux_build_id": VMLINUX_BUILD_ID,
            "pre_recorded_target_state": {
                "source": (
                    "separate instruction-level review; not verified by this "
                    "model execution"
                ),
                **PRE_RECORDED_TARGET_STATE,
            },
            "virtual_addresses": {
                "vmacache_flush_all": (
                    "[0xffffffff810e96d2,0xffffffff810e9797)"
                ),
                "vmacache_update": "[0xffffffff810e9797,0xffffffff810e97c8)",
                "vmacache_find": "[0xffffffff810e97c8,0xffffffff810e9864)",
                "vma_adjust_wrap_edge": "0xffffffff810f1fdd..0xffffffff810f1feb",
                "do_munmap_wrap_edge": "0xffffffff810f2d9b..0xffffffff810f2db0",
            },
        },
        "claim_boundary": {
            "establishes": [
                "classification of the four supplied generation and flush facts",
                "the finite generation-state count when all named premises hold",
            ],
            "does_not_establish": [
                "automatic extraction or verification of target instructions",
                "ability to perform the required number of target invalidations",
                "a stale VMA pointer, dereference, controlled reuse, or corruption",
                "code execution, root access, policy escape, or persistence",
            ],
            "inputs_are_boolean_only": True,
            "emits_no_trigger_or_target_material": True,
        },
    }
    report["pre_recorded_target_classification"] = classify_vmacache_wrap(
        **PRE_RECORDED_TARGET_STATE
    )
    if state is not None:
        report["classification"] = classify_vmacache_wrap(**state)
    return report


def _cli_boolean(value: str) -> bool:
    normalized = value.lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


class _SingleBooleanAction(argparse.Action):
    """Reject duplicate state options instead of taking the final value."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: bool,
        option_string: str | None = None,
    ) -> None:
        if getattr(namespace, self.dest) is not None:
            parser.error(f"{option_string} may be specified only once")
        setattr(namespace, self.dest, values)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for option in (
        "generation-increment-is-32-bit",
        "zero-wrap-calls-global-flush",
        "single-user-flush-returns-without-cache-clear",
        "lookup-compares-32-bit-generations",
    ):
        parser.add_argument(
            f"--{option}", type=_cli_boolean, action=_SingleBooleanAction
        )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    state = {
        "generation_increment_is_32_bit": args.generation_increment_is_32_bit,
        "zero_wrap_calls_global_flush": args.zero_wrap_calls_global_flush,
        "single_user_flush_returns_without_cache_clear": (
            args.single_user_flush_returns_without_cache_clear
        ),
        "lookup_compares_32_bit_generations": (
            args.lookup_compares_32_bit_generations
        ),
    }
    supplied = [value is not None for value in state.values()]
    if any(supplied) and not all(supplied):
        raise SystemExit("error: all vmacache-state arguments must be supplied together")
    try:
        report = build_report(state if all(supplied) else None)  # type: ignore[arg-type]
    except ModelError as exc:
        raise SystemExit(f"error: {exc}") from exc
    serialized = json.dumps(report, indent=2, sort_keys=True).encode("utf-8")
    sys.stdout.buffer.write(serialized + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
