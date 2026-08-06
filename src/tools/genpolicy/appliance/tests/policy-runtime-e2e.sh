#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

usage() {
	echo "usage: policy-runtime-e2e.sh [--policy POLICY_FILE] OUTPUT_DIR" >&2
}

policy_file=
if [[ "${1:-}" == "--policy" ]]; then
	[[ $# -ge 2 ]] || { usage; exit 2; }
	policy_file=$2
	shift 2
fi
[[ $# -eq 1 ]] || { usage; exit 2; }
output_dir=$1
policy_file=${policy_file:-${output_dir}/policy.rego}
[[ -f "${policy_file}" ]] || {
	echo "policy file not found: ${policy_file}" >&2
	exit 2
}
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../../.." && pwd)
agent=${KATA_AGENT:?KATA_AGENT is required}
agent_ctl=${AGENT_CTL:?AGENT_CTL is required}
socket="unix://@/tmp/genpolicy-policy-only-$$.sock"
agent_log=$(mktemp)
policy_log=/tmp/policy.jsonl
agent_pid=
checked_requests=0
test_phase=set-policy
failed_request=

cleanup() {
	local status=$?
	if [[ -n "${agent_pid}" ]]; then
		kill "${agent_pid}" 2>/dev/null || true
		wait "${agent_pid}" 2>/dev/null || true
	fi
	if [[ -f "${policy_log}" ]]; then
		cp "${policy_log}" "${output_dir}/policy-runtime-inputs.jsonl"
		rm -f "${policy_log}"
	fi
	cp "${agent_log}" "${output_dir}/policy-agent.log"
	rm -f "${agent_log}"
	POLICY_TEST_STATUS="${status}" \
	POLICY_TEST_FILE="${policy_file}" \
	POLICY_TEST_CHECKED="${checked_requests}" \
	POLICY_TEST_PHASE="${test_phase}" \
	POLICY_TEST_FAILED_REQUEST="${failed_request}" \
		python3 - "${output_dir}/policy-test-result.json" <<'PY'
import json
import os
import sys
from pathlib import Path

status = int(os.environ["POLICY_TEST_STATUS"])
Path(sys.argv[1]).write_text(
	json.dumps(
		{
			"schema_version": 1,
			"result": "pass" if status == 0 else "fail",
			"exit_code": status,
			"policy": os.environ["POLICY_TEST_FILE"],
			"checked_requests": int(os.environ["POLICY_TEST_CHECKED"]),
			"phase": os.environ["POLICY_TEST_PHASE"],
			"failed_request": os.environ["POLICY_TEST_FAILED_REQUEST"] or None,
		},
		indent=2,
		sort_keys=True,
	)
	+ "\n",
	encoding="utf-8",
)
PY
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
	-c "SetPolicy json://{\"policy_file\":\"${policy_file}\"}" \
	>/dev/null

for request in "${output_dir}"/createcontainer-requests/*.json; do
	test_phase=create-container
	failed_request=$(basename "${request}")
	echo "checking CreateContainerRequest: $(basename "${request}")"
	"${agent_ctl}" connect --no-auto-values true --server-address "${socket}" \
		-c "CreateContainerRaw file://${request}" >/dev/null
	checked_requests=$((checked_requests + 1))
	failed_request=
done
if [[ -d "${output_dir}/execprocess-requests" ]]; then
	for request in "${output_dir}"/execprocess-requests/*.json; do
		[[ -e "${request}" ]] || continue
		test_phase=exec-process
		failed_request=$(basename "${request}")
		echo "checking ExecProcessRequest: $(basename "${request}")"
		"${agent_ctl}" connect --no-auto-values true --server-address "${socket}" \
			-c "ExecProcess file://${request}" >/dev/null
		checked_requests=$((checked_requests + 1))
		failed_request=
	done
fi

test_phase=complete
echo "policy ${policy_file} authorized all captured Agent requests"