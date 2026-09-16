#!/usr/bin/env python3
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import hashlib
import json
import re
from pathlib import Path


POLICY_RESULTS = {"compatible", "policy-incompatible"}
ALL_RESULTS = POLICY_RESULTS | {"infrastructure-failure"}
SHA256_LINE = re.compile(r"^[0-9a-f]{64}\s+\*?\S.*$")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def generation_inputs(path: Path) -> dict:
    lines = [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    invalid = [line for line in lines if not SHA256_LINE.fullmatch(line)]
    if invalid:
        raise ValueError(f"{path}: invalid sha256 manifest line {invalid[0]!r}")
    return {
        "entries": len(lines),
        "path": str(path),
        "sha256": sha256(path),
    }


def normalize_expectation(value, variant: str) -> dict:
    if isinstance(value, str):
        value = {"result": value}
    if not isinstance(value, dict):
        raise ValueError(f"{variant}: expectation must be a string or object")
    unknown = set(value) - {"result", "denial_contains"}
    if unknown:
        raise ValueError(f"{variant}: unknown expectation fields: {sorted(unknown)}")
    result = value.get("result")
    if result not in POLICY_RESULTS:
        raise ValueError(f"{variant}: invalid policy expectation {result!r}")
    denial_contains = value.get("denial_contains", [])
    if isinstance(denial_contains, str):
        denial_contains = [denial_contains]
    if not isinstance(denial_contains, list) or not all(
        isinstance(item, str) and item for item in denial_contains
    ):
        raise ValueError(f"{variant}: denial_contains must contain nonempty strings")
    if result == "policy-incompatible" and not denial_contains:
        raise ValueError(
            f"{variant}: policy-incompatible probes require denial_contains attribution"
        )
    if result == "compatible" and denial_contains:
        raise ValueError(f"{variant}: compatible expectation cannot require denial text")
    return {"denial_contains": denial_contains, "result": result}


def load_expectations(path: Path | None, variants: list[str], probe: bool) -> dict:
    if path is None:
        if probe:
            raise ValueError("security probes require explicit expectations")
        return {
            variant: {"denial_contains": [], "result": "compatible"}
            for variant in variants
        }

    values = json.loads(path.read_text(encoding="utf-8"))
    unknown = set(values) - set(variants)
    missing = set(variants) - set(values)
    if unknown or missing:
        raise ValueError(
            f"{path}: expectation variants missing={sorted(missing)} "
            f"unknown={sorted(unknown)}"
        )
    return {
        variant: normalize_expectation(values[variant], variant)
        for variant in variants
    }


def load_observation(path: Path, status: int, expectation: dict) -> dict:
    report = {}
    if path.is_file():
        report = json.loads(path.read_text(encoding="utf-8"))
    result = report.get("result", "infrastructure-failure")
    if result not in ALL_RESULTS:
        raise ValueError(f"{path}: unknown compatibility result {result!r}")
    denial = report.get("denial")
    denial_text = denial.get("text", "") if isinstance(denial, dict) else ""
    attribution = expectation["denial_contains"]
    attribution_matches = {
        text: text in denial_text for text in attribution
    }
    status_consistent = (
        (result == "compatible" and status == 0)
        or (result == "policy-incompatible" and status != 0)
    )
    passed = (
        result == expectation["result"]
        and result != "infrastructure-failure"
        and status_consistent
        and all(attribution_matches.values())
    )
    return {
        "actual": result,
        "container_exit_status": status,
        "denial": denial,
        "denial_attribution": attribution_matches,
        "expected": expectation["result"],
        "passed": passed,
        "result_path": str(path),
        "status_consistent": status_consistent,
    }


def variant_report(
    policy_path: Path,
    generation_inputs_path: Path,
    control_result: Path,
    control_status: int,
    expectation: dict,
    probe_result: Path | None = None,
    probe_status: int | None = None,
    generator_path: Path | None = None,
) -> dict:
    report = {
        "control": load_observation(
            control_result,
            control_status,
            {"denial_contains": [], "result": "compatible"},
        ),
        "generation_inputs": generation_inputs(generation_inputs_path),
        "policy": {
            "path": str(policy_path),
            "sha256": sha256(policy_path),
        },
    }
    if generator_path is not None:
        report["generator"] = {
            "path": str(generator_path),
            "sha256": sha256(generator_path),
        }
    if probe_result is not None:
        report["probe"] = load_observation(
            probe_result,
            probe_status,
            expectation,
        )
    report["passed"] = report["control"]["passed"] and report.get(
        "probe", {"passed": True}
    )["passed"]
    return report


def build_case_report(args) -> dict:
    candidate = args.candidate_policy is not None
    variants = ["baseline"] + (["candidate"] if candidate else [])
    generation_hash = sha256(args.generation_workload)
    runtime_hash = sha256(args.runtime_workload)
    probe = generation_hash != runtime_hash
    expectations = load_expectations(args.expectations, variants, probe)

    reports = {
        "baseline": variant_report(
            args.baseline_policy,
            args.baseline_generation_inputs,
            args.baseline_control_result,
            args.baseline_control_status,
            expectations["baseline"],
            args.baseline_probe_result,
            args.baseline_probe_status,
        )
    }
    if candidate:
        reports["candidate"] = variant_report(
            args.candidate_policy,
            args.candidate_generation_inputs,
            args.candidate_control_result,
            args.candidate_control_status,
            expectations["candidate"],
            args.candidate_probe_result,
            args.candidate_probe_status,
            args.candidate_generator,
        )

    return {
        "case": args.name,
        "evaluation_type": "security-probe" if probe else "compatibility",
        "generation_workload": {
            "path": str(args.generation_workload),
            "sha256": generation_hash,
        },
        "passed": all(report["passed"] for report in reports.values()),
        "runtime_workload": {
            "path": str(args.runtime_workload),
            "sha256": runtime_hash,
        },
        "schema_version": 2,
        "variants": reports,
    }


def build_matrix_report(case_reports: list[Path], expected_cases: list[str]) -> dict:
    cases = [
        json.loads(path.read_text(encoding="utf-8")) for path in sorted(case_reports)
    ]
    reported = [case.get("case") for case in cases]
    missing = sorted(set(expected_cases) - set(reported))
    unexpected = sorted(set(reported) - set(expected_cases))
    duplicate = sorted(
        {name for name in reported if reported.count(name) > 1 and name is not None}
    )
    complete = (
        bool(expected_cases)
        and len(cases) == len(expected_cases)
        and not missing
        and not unexpected
        and not duplicate
    )
    inventory_failures = len(missing) + len(unexpected) + len(duplicate)
    return {
        "case_inventory": {
            "complete": complete,
            "duplicate": duplicate,
            "expected": expected_cases,
            "missing": missing,
            "unexpected": unexpected,
        },
        "cases": cases,
        "passed": complete and all(case.get("passed") is True for case in cases),
        "schema_version": 2,
        "summary": {
            "compatibility_cases": sum(
                case.get("evaluation_type") == "compatibility" for case in cases
            ),
            "failed_cases": inventory_failures
            + sum(case.get("passed") is not True for case in cases),
            "security_probe_cases": sum(
                case.get("evaluation_type") == "security-probe" for case in cases
            ),
            "total_cases": len(cases),
        },
    }


def write_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def add_variant_arguments(parser, variant: str, candidate: bool = False) -> None:
    prefix = f"--{variant}-"
    parser.add_argument(f"{prefix}policy", type=Path, required=not candidate)
    parser.add_argument(
        f"{prefix}generation-inputs", type=Path, required=not candidate
    )
    parser.add_argument(
        f"{prefix}control-result", type=Path, required=not candidate
    )
    parser.add_argument(
        f"{prefix}control-status", type=int, required=not candidate
    )
    parser.add_argument(f"{prefix}probe-result", type=Path)
    parser.add_argument(f"{prefix}probe-status", type=int)
    if candidate:
        parser.add_argument(f"{prefix}generator", type=Path)


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    case = subparsers.add_parser("case")
    case.add_argument("--name", required=True)
    case.add_argument("--generation-workload", type=Path, required=True)
    case.add_argument("--runtime-workload", type=Path, required=True)
    add_variant_arguments(case, "baseline")
    add_variant_arguments(case, "candidate", candidate=True)
    case.add_argument("--expectations", type=Path)
    case.add_argument("--output", type=Path, required=True)

    matrix = subparsers.add_parser("matrix")
    matrix.add_argument("--case-report", type=Path, action="append", default=[])
    matrix.add_argument("--expected-case", action="append", default=[])
    matrix.add_argument("--output", type=Path, required=True)

    args = parser.parse_args()
    if args.command == "case":
        candidate_args = (
            args.candidate_policy,
            args.candidate_generation_inputs,
            args.candidate_control_result,
            args.candidate_control_status,
            args.candidate_generator,
        )
        if any(value is not None for value in candidate_args) and not all(
            value is not None for value in candidate_args
        ):
            parser.error(
                "all candidate policy, generator, generation-input, control-result, "
                "and control-status arguments must be used together"
            )
        for variant in ("baseline", "candidate"):
            result = getattr(args, f"{variant}_probe_result")
            status = getattr(args, f"{variant}_probe_status")
            if (result is None) != (status is None):
                parser.error(
                    f"--{variant}-probe-result and --{variant}-probe-status "
                    "must be used together"
                )
        write_report(args.output, build_case_report(args))
    else:
        write_report(
            args.output,
            build_matrix_report(args.case_report, args.expected_case),
        )


if __name__ == "__main__":
    main()
