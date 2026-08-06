#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
appliance_dir=$(cd "${script_dir}/.." && pwd)
engine=${CONTAINER_ENGINE:?CONTAINER_ENGINE is required}
reference_image=${REFERENCE_IMAGE:?REFERENCE_IMAGE is required}
agent_ctl=${AGENT_CTL:?AGENT_CTL is required}
kata_agent=${KATA_AGENT:?KATA_AGENT is required}
configuration=${POLICY_MATRIX_CONFIGURATION:-${script_dir}/fixtures/configuration.toml}
output_root=${POLICY_MATRIX_OUTPUT:-${appliance_dir}/../../../../target/genpolicy-policy-matrix}

[[ -f "${configuration}" ]] || {
	echo "matrix configuration not found: ${configuration}" >&2
	exit 2
}

if (($# == 0)); then
	set -- \
		"${script_dir}/fixtures/pod.yaml" \
		"${script_dir}/fixtures/policy-matrix-env-pod.yaml" \
		"${script_dir}/fixtures/policy-matrix-process-pod.yaml" \
		"${script_dir}/fixtures/complex-workload.yaml" \
		"${script_dir}/fixtures/storage-classes-workload.yaml"
fi

case "${output_root}" in
/|"${HOME}")
	echo "refusing unsafe matrix output directory: ${output_root}" >&2
	exit 2
	;;
esac
rm -rf "${output_root}"
mkdir -p "${output_root}/cases"

case_metadata=()
case_names=()
for workload in "$@"; do
	[[ -f "${workload}" ]] || {
		echo "matrix workload not found: ${workload}" >&2
		exit 2
	}
	case_name=$(basename "${workload}")
	case_name=${case_name%.yaml}
	case_name=${case_name%.yml}
	case_name=$(printf '%s' "${case_name}" | tr -c 'A-Za-z0-9._-' '-')
	if [[ " ${case_names[*]} " == *" ${case_name} "* ]]; then
		echo "duplicate matrix case name: ${case_name}" >&2
		exit 2
	fi
	case_names+=("${case_name}")

	case_dir="${output_root}/cases/${case_name}"
	mkdir -p "${case_dir}/input/images" "${case_dir}/capture-output" \
		"${case_dir}/request-derived" "${case_dir}/legacy"
	cp "${workload}" "${case_dir}/input/workload.yaml"
	cp "${configuration}" "${case_dir}/input/configuration.toml"

	set +o errexit
	"${engine}" run --rm --privileged --network=none \
		-e GENPOLICY_CAPTURE_ONLY=0 \
		-e GENPOLICY_KATA_CONFIG=/input/configuration.toml \
		--cgroupns=host \
		-v "${case_dir}/input:/input:ro" \
		-v "${case_dir}/capture-output:/output" \
		"${reference_image}" \
		>"${case_dir}/generation.log" 2>&1
	generation_status=$?
	set -o errexit

	request_status=125
	legacy_status=125
	if [[ ${generation_status} -eq 0 ]]; then
		set +o errexit
		KATA_AGENT="${kata_agent}" AGENT_CTL="${agent_ctl}" \
			"${appliance_dir}/scripts/analyze_capture.sh" \
			--policy "${case_dir}/capture-output/policy.rego" \
			"${case_dir}/capture-output/capture" \
			"${case_dir}/request-derived" \
			>"${case_dir}/request-derived.log" 2>&1
		request_status=$?
		KATA_AGENT="${kata_agent}" AGENT_CTL="${agent_ctl}" \
			"${appliance_dir}/scripts/analyze_capture.sh" \
			--policy "${case_dir}/capture-output/legacy-reference-policy.rego" \
			"${case_dir}/capture-output/capture" \
			"${case_dir}/legacy" \
			>"${case_dir}/legacy.log" 2>&1
		legacy_status=$?
		set -o errexit
	fi

	metadata="${case_dir}/result.json"
	python3 - "${metadata}" "${case_name}" "${workload}" \
		"${generation_status}" "${request_status}" "${legacy_status}" \
		"${case_dir}/request-derived/policy-test-result.json" \
		"${case_dir}/legacy/policy-test-result.json" <<'PY'
import json
import sys
from pathlib import Path

(
    output,
    name,
    workload,
    generation_status,
    request_status,
    legacy_status,
    request_report,
    legacy_report,
) = sys.argv[1:]


def load_report(path: str, status: str) -> dict:
    report_path = Path(path)
    if report_path.is_file():
        return json.loads(report_path.read_text(encoding="utf-8"))
    return {
        "result": "not-run",
        "exit_code": int(status),
        "checked_requests": 0,
        "phase": "generation",
        "failed_request": None,
    }

result = {
    "name": name,
    "workload": str(Path(workload).resolve()),
    "generation": {
        "result": "pass" if int(generation_status) == 0 else "fail",
        "exit_code": int(generation_status),
    },
    "request_derived": load_report(request_report, request_status),
    "legacy": load_report(legacy_report, legacy_status),
}
result["result"] = (
    "pass"
    if result["generation"]["result"] == "pass"
    and result["request_derived"]["result"] == "pass"
    and result["legacy"]["result"] == "pass"
    else "fail"
)
Path(output).write_text(
    json.dumps(result, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
	case_metadata+=("${metadata}")
done

python3 - "${output_root}/policy-matrix-results.json" "${case_metadata[@]}" <<'PY'
import json
import sys
from pathlib import Path

output = Path(sys.argv[1])
cases = [
    json.loads(Path(path).read_text(encoding="utf-8"))
    for path in sys.argv[2:]
]
summary = {
    "schema_version": 1,
    "result": "pass" if all(case["result"] == "pass" for case in cases) else "fail",
    "case_count": len(cases),
    "passed": sum(case["result"] == "pass" for case in cases),
    "failed": sum(case["result"] != "pass" for case in cases),
    "cases": cases,
}
output.write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

print("CASE\tGENERATION\tREQUEST-DERIVED\tLEGACY\tRESULT")
for case in cases:
    print(
        f"{case['name']}\t{case['generation']['result']}\t"
        f"{case['request_derived']['result']}\t{case['legacy']['result']}\t"
        f"{case['result']}"
    )
print(f"summary: {output}")
raise SystemExit(0 if summary["result"] == "pass" else 1)
PY
