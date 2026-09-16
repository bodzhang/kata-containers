#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
engine=${CONTAINER_ENGINE:?CONTAINER_ENGINE is required}
genpolicy_bin=${GENPOLICY_BIN:?GENPOLICY_BIN is required}
erofs_utils_version=${EROFS_UTILS_VERSION:?EROFS_UTILS_VERSION is required}
profile_file=${PROFILE_FILE:?PROFILE_FILE is required}
repo_root=${REPO_ROOT:?REPO_ROOT is required}
nested_image=${NESTED_IMAGE:?NESTED_IMAGE is required}
request_capture_decoder=${REQUEST_CAPTURE_DECODER:?REQUEST_CAPTURE_DECODER is required}
kata_root=${KATA_ROOT:?KATA_ROOT is required}
kata_config=${KATA_CONFIG:?KATA_CONFIG is required}
output_root=${OUTPUT_ROOT:?OUTPUT_ROOT is required}
output_marker="${output_root}/.nested-policy-compat-output"
candidate_policy_generator=${CANDIDATE_POLICY_GENERATOR:-}
runtime_fixtures_dir=${RUNTIME_FIXTURES_DIR:-}
expectations_dir=${POLICY_EXPECTATIONS_DIR:-}
report_script="${script_dir}/../scripts/policy_evaluation_report.py"

device_args=(--device /dev/kvm --device /dev/net/tun)
if [[ -e /dev/vhost-vsock ]]; then
	device_args+=(--device /dev/vhost-vsock)
fi

if [[ -e "${output_root}" && ! -d "${output_root}" ]]; then
	echo "matrix output path is not a directory: ${output_root}" >&2
	exit 2
fi
if [[ -n "${candidate_policy_generator}" && ! -x "${candidate_policy_generator}" ]]; then
	echo "candidate policy generator is not executable: ${candidate_policy_generator}" >&2
	exit 2
fi
if [[ ! -x "${request_capture_decoder}" ]]; then
	echo "Agent request capture decoder is not executable: ${request_capture_decoder}" >&2
	exit 2
fi
if [[ -n "${runtime_fixtures_dir}" && ! -d "${runtime_fixtures_dir}" ]]; then
	echo "runtime fixtures directory not found: ${runtime_fixtures_dir}" >&2
	exit 2
fi
if [[ -n "${expectations_dir}" && ! -d "${expectations_dir}" ]]; then
	echo "policy expectations directory not found: ${expectations_dir}" >&2
	exit 2
fi
mkdir -p "${output_root}"
if [[ ! -f "${output_marker}" ]] &&
	find "${output_root}" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
	echo "refusing nonempty matrix output directory without harness marker: ${output_root}" >&2
	exit 2
fi
touch "${output_marker}"
rm -rf "${output_root}/cases"
rm -rf "${output_root}/generation-assets"
mkdir -p \
	"${output_root}/cases" \
	"${output_root}/generation-assets/images"

asset_container=$("${engine}" create "${nested_image}")
# shellcheck disable=SC2317,SC2329
cleanup_asset_container() {
	"${engine}" rm -f "${asset_container}" >/dev/null 2>&1 || true
}
trap cleanup_asset_container EXIT
"${engine}" cp \
	"${asset_container}:/opt/genpolicy/images/." \
	"${output_root}/generation-assets/images"
"${engine}" cp \
	"${asset_container}:/opt/genpolicy/registry-tls/registry.crt" \
	"${output_root}/generation-assets/registry.crt"
"${engine}" cp \
	"${asset_container}:/opt/genpolicy/erofs-runtime" \
	"${output_root}/generation-assets/erofs-runtime"
"${engine}" rm "${asset_container}" >/dev/null
asset_container=
trap - EXIT
if find "${output_root}/generation-assets/erofs-runtime" -type l -print -quit |
	grep -q .; then
	echo "EROFS runtime bundle must contain only resolved regular files" >&2
	exit 1
fi

default_fixtures=(
	pod.yaml
	policy-matrix-env-pod.yaml
	policy-matrix-process-pod.yaml
	complex-workload.yaml
	service-account-workload.yaml
	local-emptydir-workload.yaml
	storage-classes-workload.yaml
	runtime-operations-workload.yaml
)
if [[ -n "${FIXTURES:-}" ]]; then
	read -r -a fixtures <<<"${FIXTURES}"
else
	fixtures=("${default_fixtures[@]}")
fi

run_nested_variant() {
	local case_dir=$1
	local variant=$2
	local phase=$3
	local policy=$4
	local runtime_workload=$5
	local input_dir_name=nested-input
	local output_dir_name=nested-output
	local log_name=nested.log
	if [[ "${variant}" != "baseline" ]]; then
		input_dir_name="${variant}-nested-input"
		output_dir_name="${variant}-nested-output"
		log_name="${variant}-nested.log"
	fi
	if [[ "${phase}" != "control" ]]; then
		input_dir_name="${variant}-${phase}-nested-input"
		output_dir_name="${variant}-${phase}-nested-output"
		log_name="${variant}-${phase}-nested.log"
	fi

	mkdir -p \
		"${case_dir}/${input_dir_name}/images" \
		"${case_dir}/${output_dir_name}/logs"
	python3 "${script_dir}/annotate_workload.py" \
		--workload "${runtime_workload}" \
		--policy "${policy}" \
		--registry-ca "${output_root}/generation-assets/registry.crt" \
		--output "${case_dir}/${input_dir_name}/workload.yaml"
	cp "${output_root}/generation-assets/images/busybox.tar" \
		"${case_dir}/${input_dir_name}/images/busybox.tar"

	set +o errexit
	"${engine}" run --rm --privileged --cgroupns=host \
		"${device_args[@]}" \
		-e GENPOLICY_POD_READY_TIMEOUT="${POD_READY_TIMEOUT:-180s}" \
		-e NESTED_KATA_CONFIG=/nested-policy-compat/configuration.toml \
		-v "${kata_root}:/opt/kata:ro" \
		-v "${kata_config}:/nested-policy-compat/configuration.toml:ro" \
		-v "${case_dir}/${input_dir_name}:/input:ro" \
		-v "${case_dir}/${output_dir_name}:/output" \
		"${nested_image}" >"${case_dir}/${log_name}" 2>&1
	variant_status=$?
	set -o errexit

	set +o errexit
	"${request_capture_decoder}" \
		--input "${case_dir}/${output_dir_name}/agent-rpcs" \
		--output "${case_dir}/${output_dir_name}/agent-requests" \
		>"${case_dir}/${output_dir_name}/logs/request-capture-decoder.log" 2>&1
	decoder_status=$?
	set -o errexit
	if [[ "${decoder_status}" -ne 0 ]]; then
		printf '%s\t%s-%s\t%s\trequest-capture-decode-failed\n' \
			"${case_dir##*/}" "${variant}" "${phase}" "${decoder_status}"
		((failures += 1))
	fi

	set +o errexit
	variant_result=$(python3 - "${case_dir}/${output_dir_name}/compatibility.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
print(json.loads(path.read_text(encoding="utf-8"))["result"] if path.exists() else "infrastructure-failure")
PY
)
	result_status=$?
	set -o errexit
	if [[ "${result_status}" -ne 0 ]]; then
		variant_result=infrastructure-failure
		((failures += 1))
	fi
}

failures=0
case_reports=()
for fixture in "${fixtures[@]}"; do
	name=${fixture%.yaml}
	case_dir="${output_root}/cases/${name}"
	mkdir -p "${case_dir}/generation-input" "${case_dir}/generation-output"
	cp "${script_dir}/fixtures/${fixture}" \
		"${case_dir}/generation-input/workload.yaml"

	set +o errexit
	CONTAINER_ENGINE="${engine}" \
		GENPOLICY_BIN="${genpolicy_bin}" \
		GENPOLICY_EROFS_BUNDLE_DIR="${output_root}/generation-assets/erofs-runtime" \
		EROFS_UTILS_VERSION="${erofs_utils_version}" \
		PROFILE_FILE="${profile_file}" \
		REPO_ROOT="${repo_root}" \
		GENPOLICY_INPUT_DIR="${case_dir}/generation-input" \
		GENPOLICY_OUTPUT_DIR="${case_dir}/generation-output" \
		GENPOLICY_REFERENCE_IMAGES_DIR="${output_root}/generation-assets/images" \
		GENPOLICY_LAYER_CACHE="${output_root}/layers-cache.json" \
		"${repo_root}/src/tools/genpolicy/nested-policy-compat/scripts/generate_policy.sh" \
		>"${case_dir}/generation.log" 2>&1
	generation_status=$?
	set -o errexit
	if [[ "${generation_status}" -ne 0 ]]; then
		printf '%s\t%s\tgeneration-failed\n' "${name}" "${generation_status}"
		((failures += 1))
		continue
	fi
	if ! grep -Fq "reason :=" \
		"${case_dir}/generation-output/policy.rego"; then
		printf '%s\t1\treason-rules-missing\n' "${name}"
		((failures += 1))
		continue
	fi

	candidate_dir=
	if [[ -n "${candidate_policy_generator}" ]]; then
		candidate_dir="${case_dir}/candidate-generation-output"
		candidate_reference="${case_dir}/candidate-baseline-reference"
		candidate_input="${case_dir}/candidate-generation-input"
		mkdir -p "${candidate_dir}"
		cp -a "${case_dir}/generation-output" "${candidate_reference}"
		cp -a "${case_dir}/generation-input" "${candidate_input}"
		baseline_snapshot=$(
			sha256sum \
				"${case_dir}/generation-output/policy.rego" \
				"${case_dir}/generation-output/workload.yaml" \
				"${case_dir}/generation-output/generation-inputs.sha256"
		)
		set +o errexit
		env -i \
			BASELINE_GENERATION_DIR="${candidate_reference}" \
			CANDIDATE_OUTPUT_DIR="${candidate_dir}" \
			CONTAINER_ENGINE="${engine}" \
			GENERATION_INPUT_DIR="${candidate_input}" \
			HOME="${HOME:-/root}" \
			PATH="${PATH}" \
			PROFILE_FILE="${profile_file}" \
			REFERENCE_IMAGES_DIR="${output_root}/generation-assets/images" \
			REPO_ROOT="${repo_root}" \
			"${candidate_policy_generator}" \
			>"${case_dir}/candidate-generation.log" 2>&1
		candidate_generation_status=$?
		set -o errexit
		current_baseline_snapshot=$(
			sha256sum \
				"${case_dir}/generation-output/policy.rego" \
				"${case_dir}/generation-output/workload.yaml" \
				"${case_dir}/generation-output/generation-inputs.sha256"
		)
		if [[ "${baseline_snapshot}" != "${current_baseline_snapshot}" ]]; then
			printf '%s\tcandidate\t1\tbaseline-inputs-modified\n' "${name}"
			((failures += 1))
			continue
		fi
		if [[ "${candidate_generation_status}" -ne 0 ||
			! -s "${candidate_dir}/policy.rego" ||
			! -s "${candidate_dir}/generation-inputs.sha256" ]]; then
			printf '%s\tcandidate\t%s\tgeneration-failed\n' \
				"${name}" "${candidate_generation_status}"
			((failures += 1))
			continue
		fi
	fi

	runtime_workload="${case_dir}/generation-output/workload.yaml"
	if [[ -n "${runtime_fixtures_dir}" ]]; then
		runtime_source="${runtime_fixtures_dir}/${fixture}"
		if [[ ! -f "${runtime_source}" ]]; then
			printf '%s\t1\truntime-workload-missing\n' "${name}"
			((failures += 1))
			continue
		fi
		runtime_workload="${case_dir}/runtime-workload.yaml"
		cp "${runtime_source}" "${runtime_workload}"
	fi
	is_probe=0
	cmp -s "${case_dir}/generation-output/workload.yaml" "${runtime_workload}" ||
		is_probe=1

	expectations=
	if [[ -n "${expectations_dir}" ]]; then
		expectations="${expectations_dir}/${name}.json"
		if [[ ! -f "${expectations}" ]]; then
			printf '%s\t1\texpectations-missing\n' "${name}"
			((failures += 1))
			continue
		fi
	elif [[ "${is_probe}" == "1" ]]; then
		printf '%s\t1\tsecurity-probe-expectations-required\n' "${name}"
		((failures += 1))
		continue
	fi

	run_nested_variant \
		"${case_dir}" baseline control \
		"${case_dir}/generation-output/policy.rego" \
		"${case_dir}/generation-output/workload.yaml"
	baseline_control_status=${variant_status}
	baseline_control_result=${variant_result}
	if [[ -z "${candidate_policy_generator}" && "${is_probe}" == "0" ]]; then
		printf '%s\t%s\t%s\n' \
			"${name}" "${baseline_control_status}" "${baseline_control_result}"
	else
		printf '%s\tbaseline-control\t%s\t%s\n' \
			"${name}" "${baseline_control_status}" "${baseline_control_result}"
	fi

	baseline_probe_status=
	baseline_probe_result=
	if [[ "${is_probe}" == "1" ]]; then
		run_nested_variant \
			"${case_dir}" baseline probe \
			"${case_dir}/generation-output/policy.rego" "${runtime_workload}"
		baseline_probe_status=${variant_status}
		baseline_probe_result=${variant_result}
		printf '%s\tbaseline-probe\t%s\t%s\n' \
			"${name}" "${baseline_probe_status}" "${baseline_probe_result}"
	fi

	report_args=(
		case
		--name "${name}"
		--generation-workload "${case_dir}/generation-output/workload.yaml"
		--runtime-workload "${runtime_workload}"
		--baseline-policy "${case_dir}/generation-output/policy.rego"
		--baseline-generation-inputs \
		"${case_dir}/generation-output/generation-inputs.sha256"
		--baseline-control-result \
		"${case_dir}/nested-output/compatibility.json"
		--baseline-control-status "${baseline_control_status}"
		--output "${case_dir}/policy-evaluation.json"
	)
	[[ -n "${expectations}" ]] &&
		report_args+=(--expectations "${expectations}")
	if [[ -n "${baseline_probe_status}" ]]; then
		report_args+=(
			--baseline-probe-result \
			"${case_dir}/baseline-probe-nested-output/compatibility.json"
			--baseline-probe-status "${baseline_probe_status}"
		)
	fi

	if [[ -n "${candidate_policy_generator}" ]]; then
		run_nested_variant \
			"${case_dir}" candidate control \
			"${candidate_dir}/policy.rego" \
			"${case_dir}/generation-output/workload.yaml"
		candidate_control_status=${variant_status}
		candidate_control_result=${variant_result}
		printf '%s\tcandidate-control\t%s\t%s\n' \
			"${name}" "${candidate_control_status}" "${candidate_control_result}"
		report_args+=(
			--candidate-policy "${candidate_dir}/policy.rego"
			--candidate-generation-inputs \
			"${candidate_dir}/generation-inputs.sha256"
			--candidate-generator "${candidate_policy_generator}"
			--candidate-control-result \
			"${case_dir}/candidate-nested-output/compatibility.json"
			--candidate-control-status "${candidate_control_status}"
		)
		if [[ "${is_probe}" == "1" ]]; then
			run_nested_variant \
				"${case_dir}" candidate probe \
				"${candidate_dir}/policy.rego" "${runtime_workload}"
			candidate_probe_status=${variant_status}
			candidate_probe_result=${variant_result}
			printf '%s\tcandidate-probe\t%s\t%s\n' \
				"${name}" "${candidate_probe_status}" "${candidate_probe_result}"
			report_args+=(
				--candidate-probe-result \
				"${case_dir}/candidate-probe-nested-output/compatibility.json"
				--candidate-probe-status "${candidate_probe_status}"
			)
		fi
	fi

	set +o errexit
	python3 "${report_script}" "${report_args[@]}"
	report_status=$?
	set -o errexit
	if [[ "${report_status}" -ne 0 ]]; then
		printf '%s\t1\treport-failed\n' "${name}"
		((failures += 1))
		continue
	fi
	case_reports+=("${case_dir}/policy-evaluation.json")
	case_passed=$(python3 - "${case_dir}/policy-evaluation.json" <<'PY'
import json
import sys

print("yes" if json.load(open(sys.argv[1], encoding="utf-8"))["passed"] else "no")
PY
)
	if [[ "${case_passed}" != "yes" ]]; then
		((failures += 1))
	fi
done

matrix_args=(matrix --output "${output_root}/policy-evaluation.json")
for fixture in "${fixtures[@]}"; do
	matrix_args+=(--expected-case "${fixture%.yaml}")
done
for report in "${case_reports[@]}"; do
	matrix_args+=(--case-report "${report}")
done
python3 "${report_script}" "${matrix_args[@]}"
matrix_passed=$(python3 - "${output_root}/policy-evaluation.json" <<'PY'
import json
import sys

print("yes" if json.load(open(sys.argv[1], encoding="utf-8"))["passed"] else "no")
PY
)
if [[ "${matrix_passed}" != "yes" && "${failures}" == "0" ]]; then
	failures=1
fi

exit "${failures}"
