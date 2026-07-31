#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace

readonly appliance_root="${GENPOLICY_APPLIANCE_ROOT:-/opt/genpolicy/appliance}"
readonly input_dir="${GENPOLICY_INPUT_DIR:-/input}"
readonly output_dir="${GENPOLICY_OUTPUT_DIR:-/output}"
readonly workload="${input_dir}/workload.yaml"

# shellcheck source=/dev/null
source "${appliance_root}/profile.env"

mkdir -p "${output_dir}/raw" "${output_dir}/tagged" "${output_dir}/logs"

pids=()
cleanup() {
	local pid
	for pid in "${pids[@]}"; do
		kill "${pid}" 2>/dev/null || true
	done
}
trap cleanup EXIT

fail() {
	echo "ERROR: $*" >&2
	exit 1
}

wait_for() {
	local description=$1
	shift
	local attempt
	for attempt in $(seq 1 120); do
		if "$@" >/dev/null 2>&1; then
			return
		fi
		sleep 1
	done
	fail "timed out waiting for ${description}"
}

[[ "$(id -u)" == "0" ]] || fail "the appliance must run as root"
[[ -f "${workload}" ]] || fail "${workload} is required"
[[ "$(stat -fc %T /sys/fs/cgroup)" == "cgroup2fs" ]] ||
	fail "cgroup v2 is required"

python3 "${appliance_root}/scripts/submit_workload.py" \
	--input "${workload}" \
	--images-output "${output_dir}/requested-images.txt" \
	--validate-only

install -D -m 0644 "${appliance_root}/config/containerd.toml" /etc/containerd/config.toml
install -D -m 0644 "${appliance_root}/config/kubelet.yaml" /etc/kubernetes/kubelet.yaml
install -D -m 0644 "${appliance_root}/config/10-genpolicy.conflist" /etc/cni/net.d/10-genpolicy.conflist
install -D -m 0755 "${appliance_root}/scripts/runc-capture" /usr/local/bin/runc-capture
mkdir -p "/etc/containerd/certs.d/${LOCAL_REGISTRY}"
cat >"/etc/containerd/certs.d/${LOCAL_REGISTRY}/hosts.toml" <<EOF
server = "http://${LOCAL_REGISTRY}"

[host."http://${LOCAL_REGISTRY}"]
  capabilities = ["pull", "resolve", "push"]
EOF

mkdir -p /etc/kubernetes/pki /var/lib/etcd /var/lib/kubelet /var/lib/containerd /run/containerd
printf '127.0.0.1 genpolicy.local\n' >>/etc/hosts
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
	-subj "/CN=kube-apiserver" \
	-addext "subjectAltName=IP:127.0.0.1,DNS:kubernetes,DNS:kubernetes.default,DNS:kubernetes.default.svc" \
	-keyout /etc/kubernetes/pki/apiserver.key \
	-out /etc/kubernetes/pki/apiserver.crt \
	>"${output_dir}/logs/openssl.log" 2>&1
openssl genrsa -out /etc/kubernetes/pki/sa.key 2048 >>"${output_dir}/logs/openssl.log" 2>&1
openssl rsa -in /etc/kubernetes/pki/sa.key -pubout \
	-out /etc/kubernetes/pki/sa.pub >>"${output_dir}/logs/openssl.log" 2>&1
printf '%s\n' \
	'genpolicy-clean-room-token,genpolicy,1000,"system:masters"' \
	>/etc/kubernetes/token.csv

etcd \
	--data-dir=/var/lib/etcd \
	--listen-client-urls=http://127.0.0.1:2379 \
	--advertise-client-urls=http://127.0.0.1:2379 \
	>"${output_dir}/logs/etcd.log" 2>&1 &
pids+=("$!")
wait_for etcd etcdctl --endpoints=http://127.0.0.1:2379 endpoint health

kube-apiserver \
	--advertise-address="$(hostname -i | awk '{print $1}')" \
	--allow-privileged=true \
	--anonymous-auth=true \
	--authorization-mode=AlwaysAllow \
	--disable-admission-plugins=DefaultStorageClass,DefaultTolerationSeconds,ServiceAccount \
	--etcd-servers=http://127.0.0.1:2379 \
	--secure-port=6443 \
	--service-account-issuer=https://kubernetes.default.svc \
	--service-account-key-file=/etc/kubernetes/pki/sa.pub \
	--service-account-signing-key-file=/etc/kubernetes/pki/sa.key \
	--service-cluster-ip-range=10.96.0.0/12 \
	--tls-cert-file=/etc/kubernetes/pki/apiserver.crt \
	--tls-private-key-file=/etc/kubernetes/pki/apiserver.key \
	--token-auth-file=/etc/kubernetes/token.csv \
	>"${output_dir}/logs/kube-apiserver.log" 2>&1 &
pids+=("$!")
wait_for kube-apiserver curl -kfsS \
	-H 'Authorization: Bearer genpolicy-clean-room-token' \
	https://127.0.0.1:6443/livez

cat >/etc/kubernetes/kubeconfig <<'EOF'
apiVersion: v1
kind: Config
clusters:
- name: local
  cluster:
    server: https://127.0.0.1:6443
    insecure-skip-tls-verify: true
users:
- name: genpolicy
  user:
    token: genpolicy-clean-room-token
contexts:
- name: local
  context:
    cluster: local
    user: genpolicy
current-context: local
EOF
export KUBECONFIG=/etc/kubernetes/kubeconfig

kubectl get namespace default >/dev/null 2>&1 || kubectl create namespace default >/dev/null
kubectl get namespace kube-system >/dev/null 2>&1 || kubectl create namespace kube-system >/dev/null
cat <<'EOF' | kubectl apply -f - >/dev/null
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: kata
handler: kata
EOF

containerd --config /etc/containerd/config.toml \
	>"${output_dir}/logs/containerd.log" 2>&1 &
pids+=("$!")
wait_for containerd ctr --address /run/containerd/containerd.sock version

ctr --address /run/containerd/containerd.sock --namespace k8s.io images import \
	--digests /opt/genpolicy/images/pause.tar >/dev/null
ctr --address /run/containerd/containerd.sock --namespace k8s.io images import \
	--digests /opt/genpolicy/images/busybox.tar >/dev/null
if [[ -d "${input_dir}/images" ]]; then
	while IFS= read -r -d '' image; do
		ctr --address /run/containerd/containerd.sock --namespace k8s.io images import \
			--digests "${image}" >/dev/null
	done < <(find "${input_dir}/images" -type f -name '*.tar' -print0)
fi
while IFS= read -r image_ref; do
	digest=${image_ref##*@}
	if ctr --address /run/containerd/containerd.sock --namespace k8s.io \
		images list -q | grep -Fxq "${image_ref}"; then
		continue
	fi
	source_ref=$(
		ctr --address /run/containerd/containerd.sock --namespace k8s.io \
			images list |
			awk -v digest="${digest}" 'NR > 1 && $3 == digest { print $1; exit }'
	)
	if [[ -n "${source_ref}" ]]; then
		ctr --address /run/containerd/containerd.sock --namespace k8s.io images tag \
			"${source_ref}" "${image_ref}" >/dev/null
	else
		[[ "${image_ref}" != "${LOCAL_REGISTRY}/"* ]] ||
			fail "no imported image has requested manifest digest ${digest}"
		ctr --address /run/containerd/containerd.sock --namespace k8s.io \
			images pull --hosts-dir /etc/containerd/certs.d "${image_ref}" >/dev/null
	fi
done <"${output_dir}/requested-images.txt"

iptables --flush OUTPUT
iptables --append OUTPUT --out-interface lo --jump ACCEPT
iptables --policy OUTPUT DROP
ip6tables --flush OUTPUT
ip6tables --append OUTPUT --out-interface lo --jump ACCEPT
ip6tables --policy OUTPUT DROP
[[ "$(iptables --list-rules OUTPUT | head -n 1)" == "-P OUTPUT DROP" ]] ||
	fail "failed to seal IPv4 outbound traffic"
iptables --check OUTPUT --out-interface lo --jump ACCEPT
[[ "$(ip6tables --list-rules OUTPUT | head -n 1)" == "-P OUTPUT DROP" ]] ||
	fail "failed to seal IPv6 outbound traffic"
ip6tables --check OUTPUT --out-interface lo --jump ACCEPT

if [[ "${GENPOLICY_LEGACY_REFERENCE:-0}" == "1" ]]; then
	mkdir -p /etc/docker/registry /var/lib/registry
	cat >/etc/docker/registry/config.yml <<'EOF'
version: 0.1
storage:
  filesystem:
    rootdirectory: /var/lib/registry
http:
  addr: 127.0.0.1:5000
EOF
	registry serve /etc/docker/registry/config.yml \
		>"${output_dir}/logs/registry.log" 2>&1 &
	pids+=("$!")
	wait_for local-registry curl -fsS http://127.0.0.1:5000/v2/
	while IFS= read -r image_ref; do
		[[ "${image_ref}" == "${LOCAL_REGISTRY}/"* ]] || continue
		ctr --address /run/containerd/containerd.sock --namespace k8s.io images push \
			--plain-http "${image_ref}" >/dev/null
	done < <(ctr --address /run/containerd/containerd.sock --namespace k8s.io images list -q)
fi

kubelet \
	--config=/etc/kubernetes/kubelet.yaml \
	--hostname-override="${NODE_NAME}" \
	--kubeconfig=/etc/kubernetes/kubeconfig \
	--node-ip="$(hostname -i | awk '{print $1}')" \
	--root-dir=/var/lib/kubelet \
	>"${output_dir}/logs/kubelet.log" 2>&1 &
pids+=("$!")
wait_for kubelet-node kubectl get "node/${NODE_NAME}"

python3 "${appliance_root}/scripts/submit_workload.py" \
	--input "${workload}" \
	--node-name "${NODE_NAME}" \
	--objects-output "${output_dir}/submitted-objects.json" \
	--pods-output "${output_dir}/pods.json" \
	--dynamic-output "${output_dir}/dynamic-values.json"

while IFS=$'\t' read -r namespace pod_name; do
	kubectl wait \
		--namespace "${namespace}" \
		--for=condition=Ready \
		--timeout=180s \
		"pod/${pod_name}"
done < <(python3 - "${output_dir}/pods.json" <<'PY'
import json
import sys

for pod in json.load(open(sys.argv[1], encoding="utf-8")):
    metadata = pod["metadata"]
    print(metadata.get("namespace", "default"), metadata["name"], sep="\t")
PY
)

expected_captures=$(python3 - "${output_dir}/pods.json" <<'PY'
import json
import sys

pods = json.load(open(sys.argv[1], encoding="utf-8"))
print(sum(1 + len(pod["spec"].get("initContainers", [])) + len(pod["spec"]["containers"]) for pod in pods))
PY
)

for _ in $(seq 1 180); do
	captures=$(find "${output_dir}/raw" -type f -name '*.config.json' | wc -l)
	if [[ "${captures}" -ge "${expected_captures}" ]]; then
		break
	fi
	sleep 1
done
captures=$(find "${output_dir}/raw" -type f -name '*.config.json' | wc -l)
[[ "${captures}" -eq "${expected_captures}" ]] ||
	fail "expected ${expected_captures} OCI captures, found ${captures}"

python3 "${appliance_root}/scripts/tag_oci.py" \
	--raw-dir "${output_dir}/raw" \
	--dynamic-values "${output_dir}/dynamic-values.json" \
	--output-dir "${output_dir}/tagged" \
	--manifest "${output_dir}/dynamic-tags.json"

# Capture the Kata container rootfs_mounts (e.g. multi-layer erofs) that a
# snapshotter would hand to the Kata shim. The appliance runs runc/overlayfs, so
# the erofs mounts are prepared out-of-band on an equipped prep host and the
# per-image snapshotter mounts are provided via GENPOLICY_ROOTFS_MOUNTS_DIR.
# Best-effort; writes raw/<name>.rootfs-mounts.json consumed by the predictor.
if [[ -n "${GENPOLICY_ROOTFS_MOUNTS_DIR:-}" && -d "${GENPOLICY_ROOTFS_MOUNTS_DIR}" ]]; then
	python3 "${appliance_root}/scripts/capture_rootfs_mounts.py" \
		--raw-dir "${output_dir}/raw" \
		--mounts-dir "${GENPOLICY_ROOTFS_MOUNTS_DIR}" \
		--report "${output_dir}/rootfs-mounts-captured.json" \
		2>"${output_dir}/logs/rootfs-capture.log" ||
		echo "rootfs-mounts capture failed; see logs/rootfs-capture.log" >&2
fi

# Predict Kata agent storages/devices from the captured OCI specs using the real
# runtime-rs volume handlers driven by a dry-run hypervisor (no VM). The EROFS
# dm-verity root hashes drive policy generation below; the rest is audit-only.
# Best-effort; the mount-type rewriting inspects live host mount state, so this
# must run while the workload volumes are still mounted.
python3 "${appliance_root}/scripts/predict_storages.py" \
	--raw-dir "${output_dir}/raw" \
	--predictor /usr/local/bin/storage-predictor \
	--emptydir-mode "${GENPOLICY_EMPTYDIR_MODE:-shared-fs}" \
	--block-driver "${GENPOLICY_BLOCK_DRIVER:-virtio-blk-pci}" \
	--kata-config "${GENPOLICY_KATA_CONFIG:-}" \
	--output "${output_dir}/storages-devices-predicted.json" \
	2>"${output_dir}/logs/storage-predictor.log" ||
	echo "storage prediction failed; see logs/storage-predictor.log" >&2

# Feed the predicted EROFS dm-verity root hashes into policy generation. The
# predicted-storages file is best-effort, so pass it only when present.
predicted_arg=()
[[ -f "${output_dir}/storages-devices-predicted.json" ]] &&
	predicted_arg=(--predicted-storages "${output_dir}/storages-devices-predicted.json")

# Opt-in coverage gate: refuse to generate a policy that would fail closed on an
# unsupported volume storage class (STRICT_STORAGE_COVERAGE=1).
coverage_arg=()
[[ "${STRICT_STORAGE_COVERAGE:-0}" == "1" ]] &&
	coverage_arg=(--strict-storage-coverage true)

genpolicy-oci-compiler \
	--raw-dir "${output_dir}/raw" \
	--tagged-dir "${output_dir}/tagged" \
	--tag-manifest "${output_dir}/dynamic-tags.json" \
	--rules /opt/genpolicy/policy/rules.rego \
	--settings /opt/genpolicy/policy/settings \
	--workload "${workload}" \
	--output "${output_dir}/policy.rego" \
	--diff-output "${output_dir}/policy-oci-diff.json" \
	--annotation-output "${output_dir}/policy-annotation.txt" \
	--annotated-yaml-output "${output_dir}/workload-policy.yaml" \
	"${predicted_arg[@]}" \
	"${coverage_arg[@]}"

if [[ "${GENPOLICY_BALANCED:-0}" == "1" ]]; then
	python3 "${appliance_root}/scripts/tag_oci.py" \
		--raw-dir "${output_dir}/raw" \
		--dynamic-values "${output_dir}/dynamic-values.json" \
		--output-dir "${output_dir}/tagged-balanced" \
		--manifest "${output_dir}/dynamic-tags-balanced.json" \
		--regex-policy-mode balanced

	genpolicy-oci-compiler \
		--raw-dir "${output_dir}/raw" \
		--tagged-dir "${output_dir}/tagged-balanced" \
		--tag-manifest "${output_dir}/dynamic-tags-balanced.json" \
		--rules /opt/genpolicy/policy/rules.rego \
		--settings /opt/genpolicy/policy/settings \
		--workload "${workload}" \
		--output "${output_dir}/policy-balanced.rego" \
		--diff-output "${output_dir}/policy-oci-diff-balanced.json" \
		--annotation-output "${output_dir}/policy-annotation-balanced.txt" \
		--annotated-yaml-output "${output_dir}/workload-policy-balanced.yaml" \
		--regex-policy-mode balanced \
		"${predicted_arg[@]}" \
		"${coverage_arg[@]}"
fi

if [[ "${GENPOLICY_LEGACY_REFERENCE:-0}" == "1" ]]; then
	policy_work_dir=/var/lib/genpolicy-appliance
	mkdir -p "${policy_work_dir}"
	cp "${workload}" "${policy_work_dir}/workload.yaml"
	genpolicy \
		--yaml-file "${policy_work_dir}/workload.yaml" \
		--rego-rules-path /opt/genpolicy/policy/rules.rego \
		--json-settings-path /opt/genpolicy/policy/settings \
		--containerd-socket-path=/run/containerd/containerd.sock \
		--insecure-registry "${LOCAL_REGISTRY}" \
		--silent-unsupported-fields \
		--raw-out \
		>"${output_dir}/legacy-reference-policy.rego" \
		2>"${output_dir}/logs/genpolicy-reference.log"
fi

if [[ "${GENPOLICY_BALANCED:-0}" == "1" ]]; then
	python3 "${appliance_root}/scripts/compare_policy_modes.py" \
		--output-dir "${output_dir}" \
		--output "${output_dir}/policy-mode-report.json"
fi

provenance_artifacts=(
	--artifact "kube-apiserver=/usr/local/bin/kube-apiserver"
	--artifact "kubelet=/usr/local/bin/kubelet"
	--artifact "kubectl=/usr/local/bin/kubectl"
	--artifact "etcd=/usr/local/bin/etcd"
	--artifact "containerd=/usr/local/bin/containerd"
	--artifact "runc=/usr/local/bin/runc.real"
	--artifact "genpolicy-oci-compiler=/usr/local/bin/genpolicy-oci-compiler"
	--artifact "storage-predictor=/usr/local/bin/storage-predictor"
	--artifact "containerd-config=/etc/containerd/config.toml"
	--artifact "kubelet-config=/etc/kubernetes/kubelet.yaml"
	--artifact "cni-config=/etc/cni/net.d/10-genpolicy.conflist"
	--artifact "genpolicy-settings=/opt/genpolicy/policy/settings/genpolicy-settings.json"
	--artifact "genpolicy-appliance-settings=/opt/genpolicy/policy/settings/genpolicy-settings.d/10-appliance.json"
	--artifact "pause-image=/opt/genpolicy/images/pause.tar"
	--artifact "busybox-image=/opt/genpolicy/images/busybox.tar"
)
if [[ -d "${input_dir}/images" ]]; then
	while IFS= read -r -d '' image; do
		provenance_artifacts+=(--artifact "input-image-$(basename "${image}")=${image}")
	done < <(find "${input_dir}/images" -type f -name '*.tar' -print0)
fi

provenance_generated=(
	--generated "policy.rego=${output_dir}/policy.rego"
	--generated "requested-images.txt=${output_dir}/requested-images.txt"
	--generated "policy-oci-diff.json=${output_dir}/policy-oci-diff.json"
	--generated "policy-annotation.txt=${output_dir}/policy-annotation.txt"
	--generated "workload-policy.yaml=${output_dir}/workload-policy.yaml"
	--generated "storages-devices-predicted.json=${output_dir}/storages-devices-predicted.json"
)
if [[ -f "${output_dir}/rootfs-mounts-captured.json" ]]; then
	provenance_generated+=(
		--generated "rootfs-mounts-captured.json=${output_dir}/rootfs-mounts-captured.json"
	)
fi
if [[ "${GENPOLICY_BALANCED:-0}" == "1" ]]; then
	provenance_generated+=(
		--generated "dynamic-tags-balanced.json=${output_dir}/dynamic-tags-balanced.json"
		--generated "policy-balanced.rego=${output_dir}/policy-balanced.rego"
		--generated "policy-oci-diff-balanced.json=${output_dir}/policy-oci-diff-balanced.json"
		--generated "policy-annotation-balanced.txt=${output_dir}/policy-annotation-balanced.txt"
		--generated "workload-policy-balanced.yaml=${output_dir}/workload-policy-balanced.yaml"
		--generated "policy-mode-report.json=${output_dir}/policy-mode-report.json"
	)
fi

python3 "${appliance_root}/scripts/write_provenance.py" \
	--profile "${appliance_root}/profile.env" \
	--input "${workload}" \
	--tag-manifest "${output_dir}/dynamic-tags.json" \
	--raw-dir "${output_dir}/raw" \
	--tagged-dir "${output_dir}/tagged" \
	--output "${output_dir}/provenance.json" \
	"${provenance_generated[@]}" \
	"${provenance_artifacts[@]}"

echo "Generated ${captures} tagged OCI specifications and OCI-derived ${output_dir}/policy.rego"
