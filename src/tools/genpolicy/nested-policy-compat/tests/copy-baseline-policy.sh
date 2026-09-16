#!/usr/bin/env bash
#
# Copyright (c) 2026 Microsoft Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

baseline_dir=${BASELINE_GENERATION_DIR:?BASELINE_GENERATION_DIR is required}
output_dir=${CANDIDATE_OUTPUT_DIR:?CANDIDATE_OUTPUT_DIR is required}

mkdir -p "${output_dir}"
cp "${baseline_dir}/policy.rego" "${output_dir}/policy.rego"
{
	sha256sum \
		"${BASH_SOURCE[0]}" \
		"${baseline_dir}/policy.rego" \
		"${baseline_dir}/workload.yaml" \
		"${baseline_dir}/generation-inputs.sha256"
} >"${output_dir}/generation-inputs.sha256"
