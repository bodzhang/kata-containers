#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

output_dir=${1:?usage: policy-runtime-e2e.sh OUTPUT_DIR}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../../.." && pwd)
agent=${KATA_AGENT:?KATA_AGENT is required}
agent_ctl=${AGENT_CTL:?AGENT_CTL is required}
socket="unix://@/tmp/genpolicy-policy-only-$$.sock"
agent_log=$(mktemp)
policy_log=/tmp/policy.jsonl
agent_pid=

cleanup() {
	if [[ -n "${agent_pid}" ]]; then
		kill "${agent_pid}" 2>/dev/null || true
		wait "${agent_pid}" 2>/dev/null || true
	fi
	if [[ -f "${policy_log}" ]]; then
		cp "${policy_log}" "${output_dir}/policy-runtime-inputs.jsonl"
		rm -f "${policy_log}"
	fi
	rm -f "${agent_log}"
}
trap cleanup EXIT

rm -f "${policy_log}"
unshare --mount --propagation private env \
	KATA_AGENT_SERVER_ADDR="${socket}" \
	KATA_AGENT_LOG_LEVEL=debug \
	KATA_AGENT_POLICY_FILE="${repo_root}/src/kata-opa/allow-all.rego" \
	KATA_AGENT_POLICY_ONLY=true \
	"${agent}" >"${agent_log}" 2>&1 &
agent_pid=$!

ready=false
for _ in {1..100}; do
	if "${agent_ctl}" connect --server-address "${socket}" -c Check >/dev/null 2>&1; then
		ready=true
		break
	fi
	if ! kill -0 "${agent_pid}" 2>/dev/null; then
		cat "${agent_log}" >&2
		exit 1
	fi
	read -r -t 0.1 _ </dev/null || true
done
if [[ "${ready}" != true ]]; then
	cat "${agent_log}" >&2
	echo "policy-only Agent did not become ready" >&2
	exit 1
fi

"${agent_ctl}" connect --server-address "${socket}" \
	-c "SetPolicy json://{\"policy_file\":\"${output_dir}/policy.rego\"}" \
	>/dev/null

for request in "${output_dir}"/createcontainer-requests/*.json; do
	echo "checking CreateContainerRequest: $(basename "${request}")"
	"${agent_ctl}" connect --no-auto-values true --server-address "${socket}" \
		-c "CreateContainerRaw file://${request}" >/dev/null
done
if [[ -d "${output_dir}/execprocess-requests" ]]; then
	for request in "${output_dir}"/execprocess-requests/*.json; do
		[[ -e "${request}" ]] || continue
		echo "checking ExecProcessRequest: $(basename "${request}")"
		"${agent_ctl}" connect --no-auto-values true --server-address "${socket}" \
			-c "ExecProcess file://${request}" >/dev/null
	done
fi

echo "generated policy authorized all captured Agent requests"