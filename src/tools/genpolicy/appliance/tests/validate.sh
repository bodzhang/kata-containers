#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
appliance_dir=$(cd "${script_dir}/.." && pwd)
pycache_dir=$(mktemp -d)
trap 'rm -rf "${pycache_dir}"' EXIT
export PYTHONPYCACHEPREFIX="${pycache_dir}"

# shellcheck source=/dev/null
source "${appliance_dir}/profile.env"

python3 -m compileall -q "${appliance_dir}/scripts" "${appliance_dir}/tests"
python3 -m unittest discover -s "${appliance_dir}/tests" -p 'test_*.py'

for script in "${appliance_dir}"/scripts/*.sh "${appliance_dir}"/scripts/runc-capture "${appliance_dir}"/tests/*.sh; do
	bash -n "${script}"
done

grep -Fq "ARG KUBERNETES_VERSION=${KUBERNETES_VERSION}" "${appliance_dir}/Dockerfile"
grep -Fq "ARG CONTAINERD_VERSION=${CONTAINERD_VERSION}" "${appliance_dir}/Dockerfile"
grep -Fq "ARG RUNC_VERSION=${RUNC_VERSION}" "${appliance_dir}/Dockerfile"
grep -Fq "ARG ETCD_VERSION=${ETCD_VERSION}" "${appliance_dir}/Dockerfile"
grep -Fq "ARG CNI_PLUGINS_VERSION=${CNI_PLUGINS_VERSION}" "${appliance_dir}/Dockerfile"
grep -Fq "sandbox_image = \"${PAUSE_IMAGE}\"" "${appliance_dir}/config/containerd.toml"

# Rego policy-rule tests (EROFS dm-verity storage pinning). Requires `opa`.
if command -v opa >/dev/null 2>&1; then
	opa test "${appliance_dir}/../rules.rego" "${appliance_dir}/tests/erofs_dmverity_test.rego"
else
	echo "opa not found; skipping rego policy tests" >&2
fi

(
	cd "${appliance_dir}/../../../.."
	cargo test --locked --package genpolicy-oci-compiler
	cargo test --locked --package kata-storage-predictor
)

echo "appliance validation passed"
