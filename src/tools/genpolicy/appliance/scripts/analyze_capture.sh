#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

readonly appliance_root="${GENPOLICY_APPLIANCE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
capture_dir=
output_dir=
agent_replay=0
baseline_dir=
policy_file=

usage() {
	echo "usage: $0 [--agent-replay | --policy POLICY_FILE] [--baseline CAPTURE_DIR] CAPTURE_DIR OUTPUT_DIR" >&2
	exit 2
}

while (($#)); do
	case "$1" in
	--agent-replay)
		agent_replay=1
		shift
		;;
	--baseline)
		(($# >= 2)) || usage
		baseline_dir=$2
		shift 2
		;;
	--policy)
		(($# >= 2)) || usage
		policy_file=$2
		shift 2
		;;
	--*) usage ;;
	*)
		if [[ -z "${capture_dir}" ]]; then
			capture_dir=$1
		elif [[ -z "${output_dir}" ]]; then
			output_dir=$1
		else
			usage
		fi
		shift
		;;
	esac
done
[[ -n "${capture_dir}" && -n "${output_dir}" ]] || usage
[[ -z "${policy_file}" || "${agent_replay}" == "0" ]] || usage

python3 "${appliance_root}/scripts/capture_bundle.py" validate \
	--bundle "${capture_dir}" \
	--require-complete

if [[ -n "${policy_file}" ]]; then
	[[ -f "${policy_file}" ]] || {
		echo "policy file not found: ${policy_file}" >&2
		exit 2
	}
	: "${KATA_AGENT:?KATA_AGENT is required with --policy}"
	: "${AGENT_CTL:?AGENT_CTL is required with --policy}"
	mkdir -p "${output_dir}"
	ln -sfn "${capture_dir}/createcontainer-requests" \
		"${output_dir}/createcontainer-requests"
	ln -sfn "${capture_dir}/execprocess-requests" \
		"${output_dir}/execprocess-requests"
	KATA_AGENT="${KATA_AGENT}" AGENT_CTL="${AGENT_CTL}" \
		"${appliance_root}/tests/policy-runtime-e2e.sh" \
		--policy "${policy_file}" "${output_dir}"
	exit
fi

mkdir -p "${output_dir}/tagged-requests"
python3 "${appliance_root}/scripts/analyze_request_provenance.py" \
	--capture "${capture_dir}" \
	--transformations "${output_dir}/request-transformations.json" \
	--provenance "${output_dir}/request-field-provenance.json"
python3 "${appliance_root}/scripts/analyze_storage_mounts.py" \
	--capture "${capture_dir}" \
	--output "${output_dir}/storage-mount-analysis.json"

if [[ -n "${baseline_dir}" ]]; then
	python3 "${appliance_root}/scripts/capture_bundle.py" validate \
		--bundle "${baseline_dir}" \
		--require-complete
	python3 "${appliance_root}/scripts/compare_profile_requests.py" \
		--baseline "${baseline_dir}" \
		--candidate "${capture_dir}" \
		--output "${output_dir}/profile-request-diff.json"
fi

python3 "${appliance_root}/scripts/tag_oci.py" \
	--raw-requests-dir "${capture_dir}/createcontainer-requests" \
	--dynamic-values "${capture_dir}/dynamic-values.json" \
	--output-dir "${output_dir}/tagged-requests" \
	--manifest "${output_dir}/dynamic-tags.json"

coverage_arg=()
[[ "${STRICT_STORAGE_COVERAGE:-0}" == "1" ]] &&
	coverage_arg=(--strict-storage-coverage true)

"${GENPOLICY_COMPILER:-genpolicy-oci-compiler}" \
	--raw-requests-dir "${capture_dir}/createcontainer-requests" \
	--tagged-requests-dir "${output_dir}/tagged-requests" \
	--tag-manifest "${output_dir}/dynamic-tags.json" \
	--rules "${GENPOLICY_RULES:-/opt/genpolicy/policy/rules.rego}" \
	--settings "${GENPOLICY_SETTINGS:-/opt/genpolicy/policy/settings}" \
	--workload "${capture_dir}/workload.yaml" \
	--output "${output_dir}/policy.rego" \
	--diff-output "${output_dir}/policy-oci-diff.json" \
	--annotation-output "${output_dir}/policy-annotation.txt" \
	--annotated-yaml-output "${output_dir}/workload-policy.yaml" \
	"${coverage_arg[@]}"

if [[ "${agent_replay}" == "1" ]]; then
	: "${KATA_AGENT:?KATA_AGENT is required with --agent-replay}"
	: "${AGENT_CTL:?AGENT_CTL is required with --agent-replay}"
	ln -sfn "${capture_dir}/createcontainer-requests" \
		"${output_dir}/createcontainer-requests"
	ln -sfn "${capture_dir}/execprocess-requests" \
		"${output_dir}/execprocess-requests"
	KATA_AGENT="${KATA_AGENT}" AGENT_CTL="${AGENT_CTL}" \
		"${appliance_root}/tests/policy-runtime-e2e.sh" "${output_dir}"
fi

echo "Analyzed capture bundle into ${output_dir}"