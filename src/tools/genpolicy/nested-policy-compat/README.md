# Nested policy compatibility harness

This harness tests an externally generated Kata policy against the real Agent
requests produced by a pinned Kubernetes/containerd profile. It runs an
unmodified Kata shim and policy-enabled Agent through nested virtualization.

## Host prerequisites

Run the harness on a disposable Linux x86-64 L1 VM with:

- nested virtualization enabled and `/dev/kvm` available;
- `/dev/net/tun`, plus `/dev/vhost-vsock` only when the selected VMM
  configuration uses native vhost-vsock;
- Podman or Docker, with permission to run a privileged container in the host
  cgroup namespace;
- GNU Make, Bash, Python 3, curl, `skopeo`, and a Rust/Cargo toolchain capable
  of building the repository's `x86_64-unknown-linux-musl` GenPolicy target;
- a Kata installation supplied through `KATA_ROOT` or approval to install one.

`fixture-e2e` and `ci-fixture-e2e` check these prerequisites before building or
running a fixture.
If the Kata installation is missing, it stops and prints the missing paths and
the exact opt-in command. It does not pull images or write host files without
approval. Set `APPROVE_KATA_INSTALL=yes` to authorize pulling
`quay.io/kata-containers/kata-deploy-ci:kata-containers-latest` and installing
the packaged Cloud Hypervisor, guest kernel, runtime-rs shim, confidential
image, root hash, and a dedicated compatibility configuration under
`KATA_ROOT`. Override the source with `KATA_ARTIFACT_IMAGE`.
CI always forces `APPROVE_KATA_INSTALL=no`; artifact installation must be a
separate, explicit preparation step.

CI should set `KATA_ARTIFACT_DIR` to a directory of tarballs built from the
exact pull-request merge commit instead of pulling the default image. Required
filenames are `kata-static-cloud-hypervisor.tar.zst`,
`kata-static-kernel.tar.zst`, `kata-static-shim-v2-rust.tar.zst`, and
`kata-static-rootfs-image-confidential.tar.zst`.

The default locations are:

```text
KATA_ROOT=/opt/kata
KATA_CONFIG=/opt/kata/share/defaults/kata-containers/runtime-rs/configuration-nested-policy-compat.toml
```

Writing `/opt/kata` commonly requires running the command as root. To avoid
elevation, select a writable directory and pass both `KATA_ROOT` and
`KATA_CONFIG`; the Kata paths inside the generated configuration remain
`/opt/kata` because the harness mounts the selected host directory there.

For example, after reviewing the image and destination:

```bash
make -C src/tools/genpolicy/nested-policy-compat fixture-e2e \
  PROFILE=k8s-1.36-containerd-2.3-guest-pull \
  APPROVE_KATA_INSTALL=yes \
  KATA_ROOT="$HOME/.local/lib/kata-nested-policy-compat" \
  KATA_CONFIG="$HOME/.local/lib/kata-nested-policy-compat/share/defaults/kata-containers/runtime-rs/configuration-nested-policy-compat.toml" \
  OUTPUT_ROOT="$PWD/target/nested-policy-compat-fixtures"
```

The EROFS dm-verity profiles additionally require a Cloud Hypervisor build
containing flat-VMDK support. If the packaged VMM lacks it, approved bootstrap
builds Cloud Hypervisor PR 8599 from the pinned commit
`f50661fffd0fef38ddfec88c5fafa93f9779149a` and installs the resulting binary.
Override `FLAT_VMDK_CLOUD_HYPERVISOR_REPO` and
`FLAT_VMDK_CLOUD_HYPERVISOR_COMMIT` together to select another audited source.
The build requires `build-essential`, `m4`, `bison`, `flex`, `uuid-dev`,
`qemu-utils`, `musl-tools`, `pkg-config`, `protobuf-compiler`, `jq`, `kmod`,
Git, and Rust/Cargo. EROFS policy generation also runs `mkfs.erofs` directly
on the host. Approved bootstrap installs missing `protobuf-compiler`, `jq`,
`curl` and `skopeo` packages on Ubuntu hosts. The running host kernel
must also provide EROFS filesystem and dm-verity device-mapper support;
approved bootstrap loads the `erofs` and `dm_verity` modules and fails clearly
if the kernel does not provide them. The harness copies the repository-pinned
`mkfs.erofs` binary, dynamic loader, and shared libraries from the static
execution image and uses that exact runtime bundle for host policy generation,
so its EROFS layout matches nested containerd. The complete bundle hash is part
of the GenPolicy layer-cache key.
Guest-pull profiles do not require flat-VMDK, host EROFS, or dm-verity.
The Kata build scripts also require `yq`; install the repository-pinned version
with `./ci/install_yq.sh` and add `${HOME}/go/bin` to `PATH`, or let
approved bootstrap install the pinned version under `/usr/local/bin`.
The host Rust toolchain must include the target used for GenPolicy
(`x86_64-unknown-linux-musl` by default). Approved bootstrap installs a missing
target with `rustup`; without approval, preflight reports the exact missing target.

The supplied or approved installation provides the VMM, guest kernel, and initial runtime
configuration. The harness builds GenPolicy from the checkout. Before running
fixtures, it verifies a rebuild-generated marker that binds the installed
runtime-rs shim and monolithic confidential image to the current runtime-rs and
strict-Agent build inputs, including local tracked and untracked changes. If
they differ, it reuses the repository's Kata local-build pipeline with
harness-owned exact fingerprints. Unchanged Agent, CoCo/CDH, pause, runtime-rs,
and confidential-image archives are reused. A changed embedded guest component
invalidates the confidential image and dm-verity metadata; a runtime-rs-only
change rebuilds only the shim. The resulting artifacts are installed under
`KATA_ROOT`, recorded in the source-and-artifact provenance marker, and
verified again. All compatibility profiles boot that same monolithic image so
profile comparisons do not also compare different guest environments.
`KATA_ROOT` must therefore be writable when a rebuild is needed.

These Cloud Hypervisor profiles are intentionally non-confidential development
VMs. Their rebuilt Agent enables `allow-unattested-initdata` so the host can
deliver the generated test policy through init-data without a TEE launch
measurement. The monolithic image is dm-verity protected, but accepting
unattested init-data still makes this a development-only configuration. Do not
use this appliance build mode for a confidential production guest.

The Kata installation must contain the runtime-rs
`containerd-shim-kata-v2`, the selected VMM and guest kernel, the monolithic
confidential image, and its dm-verity root hash. The runtime configuration's
image setting is replaced with that confidential image for the test. For the
retained Cloud Hypervisor profiles, the VMM must include flat-VMDK support from
[cloud-hypervisor/cloud-hypervisor#8599](https://github.com/cloud-hypervisor/cloud-hypervisor/pull/8599).
The selected runtime configuration must enable the `cc_init_data` annotation
and use `shared_fs = "none"`.

Kubernetes, containerd, etcd, runc, and CNI plugins do not need to be installed
on the host; the appliance image downloads them. The host also does not need an
existing Kubernetes cluster or containerd daemon. GenPolicy runs directly on
the host against a temporary local registry. The static image supplies the
fixture OCI archives and retains the EROFS and registry tools needed by nested
execution.

## Build

Build the selected profile directly from this branch:

```bash
make -C src/tools/genpolicy/nested-policy-compat \
  PROFILE=k8s-1.36-containerd-2.3-erofs-dmverity image
```

The image downloads the Kubernetes, containerd, etcd, runc, and CNI versions
declared by the selected profile. It is a static nested-execution image and
does not embed GenPolicy, `rules.rego`, or GenPolicy settings. Those inputs are
built or read from the checkout when each host generation phase runs. No
appliance branch or prebuilt appliance image is an input. The other Kata
components come from the separately prepared `KATA_ROOT`; they are not
compiled by this target.

All profiles use the shared `Dockerfile`; the Makefile passes the selected
profile's version pins as Docker build arguments and stores the resulting tag
in the local Podman or Docker image store. See `appliance/README.md` for the
directory layout, build flow, image tags, and storage details.

For compatibility tests, the host generation script appends
`tests/policy/create-sandbox-reasons.rego.inc` to the selected `rules.rego`.
These test-only rules add denial attribution for sandbox guest hooks, kernel
modules, PID namespace mode, and storage matching. This is a GenPolicy
rules-file input (`--rego-rules-path`/`-p`), not a settings option.

## CI/CD execution contract

The build, provenance, and test phases are separate so a Kata CI workflow can
cache or transfer artifacts without weakening the source check:

```bash
# Build and install checkout-derived shim and strict-Agent guest image.
make -C src/tools/genpolicy/nested-policy-compat prepare-kata-stack \
  KATA_ROOT=/path/to/writable/opt/kata \
  KATA_CONFIG=/path/to/configuration.toml

# A later job may verify downloaded artifacts without rebuilding them.
make -C src/tools/genpolicy/nested-policy-compat verify-kata-provenance \
  KATA_ROOT=/path/to/opt/kata \
  KATA_CONFIG=/path/to/configuration.toml

# CI uses verify-only behavior, so stale artifacts fail rather than trigger a
# hidden rebuild inside the test job.
make -C src/tools/genpolicy/nested-policy-compat ci-fixture-e2e \
  PROFILE=k8s-1.36-containerd-2.3-erofs-dmverity \
  KATA_ROOT=/path/to/opt/kata \
  KATA_CONFIG=/path/to/configuration.toml \
  OUTPUT_ROOT=/path/to/test-results
```

Run `ci-fixture-e2e` once per retained profile as a CI matrix. The job requires
an x86-64 runner with nested KVM and the same privileged-container devices
listed above. Keep `KATA_ROOT`, the appliance image store, and result output in
separate cache/artifact locations: Kata build artifacts can be reused after
`verify-kata-provenance`, while test results should always be uploaded from a
fresh output directory.

The reusable `.github/workflows/run-nested-policy-compat.yaml` implements this
producer/consumer split. It starts from the exact PR-built Cloud Hypervisor,
kernel, runtime-rs, and confidential-image tarballs. If that Cloud Hypervisor
lacks flat-VMDK support, the approved preparation step replaces it with the
pinned PR 8599 build described above. It then prepares one strict compatibility
bundle and runs all retained profiles as verify-only matrix jobs. Results are
uploaded even when a profile fails.

The workflow is available as an opt-in CI pilot through the
`nested-policy-compat` input to `.github/workflows/ci.yaml`; its default is
`false`. Enable it on a trusted ephemeral nested-KVM runner before adding its
profile jobs to `tools/testing/gatekeeper/required-tests.yaml`. Do not execute
untrusted pull-request code on a persistent privileged runner.

## Generation and inputs

Before each nested run, `fixture-matrix-e2e.sh` creates a stopped container from
the static image and copies out its fixture OCI archives and registry
certificate. It does not start the appliance for generation. The host
`generate_policy.sh` starts only a temporary Distribution registry, publishes
the exact requested manifests through Podman or Docker, and invokes the
checkout-built GenPolicy without a containerd socket. The temporary generation
registry authority is replaced with the profile's nested registry authority in
both the policy and annotated workload before execution.

GenPolicy, rules, and settings therefore do not participate in the static image
fingerprint. A GenPolicy-only change rebuilds the binary and regenerates policy
without rebuilding the Kubernetes/runtime image or Kata guest appliance.

- `/input/workload.yaml`: digest-pinned workload carrying an externally
  generated `io.katacontainers.config.hypervisor.cc_init_data` annotation.
- `/input/images/*.tar`: optional OCI image-layout archives, using the same
  format as the base appliance.
- `/opt/kata`: an unmodified Kata installation containing
  `containerd-shim-kata-v2`, the selected VMM and guest kernel, the monolithic
  confidential image and root hash, and the runtime-rs configuration.

The default Kata configuration path is:

```text
/opt/kata/share/defaults/kata-containers/runtime-rs/configuration.toml
```

The selected hypervisor configuration must include `cc_init_data` in
`enable_annotations`; otherwise the runtime drops the policy annotation and
the Agent silently uses its baked-in default policy. The harness rejects that
configuration instead of reporting a false compatibility result. Override the
configuration path with `NESTED_KATA_CONFIG`.

All profiles require `shared_fs = "none"` in the selected hypervisor
configuration. The EROFS profiles use containerd 2.x's EROFS snapshotter to create
verified block-backed root filesystems, so neither virtio-fs nor runtime-rs
`force_guest_pull` is used. The harness rejects a mismatched Kata
configuration rather than recording an unrelated sandbox-storage denial.
The snapshotter uses `default_size = "0"` so the Agent creates the writable
overlay upper under `/run`; only the read-only, dm-verity-bound image layers
cross the policy boundary as block storage.

The compatibility profiles are:

| Profile | Kubernetes | containerd | Image path |
|---|---:|---:|---|
| `k8s-1.33-containerd-2.3-erofs-dmverity` | 1.33.13 | 2.3.5 | host EROFS/dm-verity |
| `k8s-1.36-containerd-2.3-erofs-dmverity` | 1.36.3 | 2.3.5 | host EROFS/dm-verity |
| `k8s-1.33-containerd-1.7-guest-pull` | 1.33.13 | 1.7.34 | guest pull |
| `k8s-1.36-containerd-2.3-guest-pull` | 1.36.3 | 2.3.5 | guest pull |

The older guest-pull profile exercises containerd's version-2 CRI
configuration and OCI 1.1.0 requests. The current profile exercises
containerd's split CRI plugins and OCI 1.3.0 requests. Guest-pull policy
generation requires digest-qualified image references, enables
`allow_guest_pull_images`, and retains `require_pinned_image_digests`.
Runtime-rs receives `force_guest_pull` only in the derived guest-pull
configuration; the caller's configuration and runtime-rs source are unchanged.

At runtime, the appliance publishes only its deterministic fixture images on
the TLS-protected, non-overlapping CNI gateway registry at
`10.188.0.1:5000`, embeds its CA certificate in the workload's CDH init-data
configuration, and blocks forwarded traffic.
The integrity chain is:

```text
GenPolicy image annotation contains the expected manifest digest
    -> Agent policy requires the image_guest_pull source digest to match
    -> CDH/image-rs downloads the manifest
    -> rust-oci-client hashes the downloaded manifest bytes and rejects mismatch
```

This verifies manifest identity, while EROFS dm-verity verifies the host-built
read-only layer block devices. They are distinct integrity mechanisms.
The profile maps the existing disk-backed emptyDir policy template to the
runtime-rs guest-local storage request without changing GenPolicy itself.
Cloud Hypervisor must include flat VMDK support from
[cloud-hypervisor/cloud-hypervisor#8599](https://github.com/cloud-hypervisor/cloud-hypervisor/pull/8599);
the v51.1 binary pinned by this repository does not support the GPT+VMDK disk
format emitted by runtime-rs. The harness checks this capability before
starting the control plane.

## Run

Run inside a disposable L1 VM that exposes nested virtualization:

```bash
docker run --rm --privileged --cgroupns=host \
  --device /dev/kvm \
  --device /dev/net/tun \
  -e NESTED_KATA_CONFIG=/opt/kata/share/defaults/kata-containers/runtime-rs/configuration.toml \
  -v /opt/kata:/opt/kata:ro \
  -v "$PWD/input:/input:ro" \
  -v "$PWD/output:/output" \
  nested-policy-compat:k8s-1.36-containerd-2.3-erofs-dmverity
```

For a VMM using native vhost-vsock, also expose `/dev/vhost-vsock`. The first
implementation requires a hybrid-vsock configuration using `ch-vm.sock`,
`kata.hvsock`, or `vsock.sock`. The image itself is not intrinsically
privileged; the container is granted these privileges at launch because it
operates a nested Kubernetes node and manages KVM, cgroups, networking, mounts,
udev, and device-mapper state. See `DESIGN.md` for the complete
privilege rationale.

## Outputs

- `compatibility.json`: `compatible`, `policy-incompatible`, or
  `infrastructure-failure`;
- `agent-rpcs/`: byte-exact bidirectional hybrid-vsock captures;
- `agent-requests/requests.jsonl`: versioned, structured Agent request records
  derived from each `shim-to-agent.bin`;
- `agent-requests/manifest.json`: raw-stream hashes, decode coverage, and
  connection/frame/request counts;
- `submitted-objects.json`, `pods.json`, and `pod-status.json`;
- `component-versions.txt` and `kata-artifacts.sha256`;
- control-plane, shim, relay, and Agent-related logs available through
  containerd.
- `generation-inputs.sha256`: hashes of the host GenPolicy binary, composed
  rules, and effective settings used for that fixture.

The raw Agent channel intentionally retains complete test request traffic,
including the synthetic Secret and ConfigMap fixture values, for diagnostics.

## Failure diagnostics

The fixture-matrix console prints one summary line per fixture:

```text
<fixture> <container-exit-status> <result>
```

It does not print the complete Agent denial. When the Agent rejects a request,
the policy `reason` returned in the RPC status propagates into a runtime log,
normally `nested-output/logs/containerd.log`.
`compat_report.py` finds the first policy denial and records its source file and
text in:

```text
cases/<fixture>/nested-output/compatibility.json
```

For example:

```json
{
  "result": "policy-incompatible",
  "denial": {
    "file": "/output/logs/containerd.log",
    "text": "...CreateContainerRequest is blocked by policy: <reason>..."
  }
}
```

The complete logs remain under `cases/<fixture>/nested-output/logs/`. If policy
generation fails, the VM cannot start, or another infrastructure error occurs
before the request reaches Agent policy evaluation, there is no returned policy
reason and `denial` is `null`.

All Kubernetes objects, Secret values, ConfigMap values, images, and cluster
configuration used by the supplied fixtures are synthetic test data. Complete
logs, raw `agent-rpcs/` captures, and decoded `agent-requests/` records may
therefore include those values by design. The raw stream remains the
authoritative capture. Decoded request files are analysis-only output and are
never passed to baseline or candidate policy generation; unknown methods are
retained as base64 protobuf payloads and reported as incomplete typed coverage.
Known methods with unknown protobuf fields also retain their complete encoded
payload. Non-Agent hybrid-vsock ports are recorded but are not interpreted as
ttRPC.

## Policy-tightening evaluation

The harness can run two policies against the same pinned runtime inputs:

- `baseline`: the policy produced by the checkout's GenPolicy implementation;
- `candidate`: a policy produced by an external candidate generator.

Use `policy-evaluation-e2e` and provide an executable
`CANDIDATE_POLICY_GENERATOR`. The harness invokes that executable once per
fixture with these environment variables:

| Variable | Meaning |
|---|---|
| `BASELINE_GENERATION_DIR` | Private copy of the baseline `policy.rego`, normalized workload, GenPolicy log, and generation-input hashes |
| `CANDIDATE_OUTPUT_DIR` | Directory where the generator must write `policy.rego` and `generation-inputs.sha256` |
| `GENERATION_INPUT_DIR` | Private copy of the original workload used to generate the baseline policy |
| `PROFILE_FILE` | Exact Kubernetes/containerd/rootfs compatibility profile |
| `REFERENCE_IMAGES_DIR` | Fixture OCI archives copied from the pinned appliance image |
| `REPO_ROOT` | Current repository checkout |
| `CONTAINER_ENGINE` | Selected Podman or Docker executable |

The candidate generator owns the contents of
`generation-inputs.sha256`. It must hash every compiler, rule, setting,
capture, and other input needed to reproduce its policy. The harness validates
the manifest syntax, records its hash and entry count, and independently hashes
the candidate-generator executable. The manifest remains an attestation by the
candidate generator: the harness cannot discover undeclared inputs used by an
arbitrary external program.

The harness invokes the candidate generator before reading or copying the
runtime probe workload or its expectations, under a clean environment
containing only the variables listed above plus `HOME` and `PATH`. Both
policies are generated before either nested execution starts, and the harness
checks that candidate generation did not change the authoritative baseline
policy, workload, or generation-input manifest. The generator is still a
trusted test component with repository filesystem access; this isolation
prevents accidental probe coupling, not deliberate discovery by hostile code.

For a positive compatibility comparison, omit `RUNTIME_FIXTURES_DIR`; both
variants execute the same normalized workload used for baseline generation:

```bash
make -C src/tools/genpolicy/nested-policy-compat policy-evaluation-e2e \
  CANDIDATE_POLICY_GENERATOR=/path/to/generate-candidate-policy \
  PROFILE=k8s-1.36-containerd-2.3-erofs-dmverity \
  OUTPUT_ROOT="$PWD/target/nested-policy-evaluation"
```

Use `tests/copy-baseline-policy.sh` as the candidate generator to smoke-test
the two-variant orchestration before integrating another compiler. Because it
copies the baseline policy byte for byte, both variants must produce identical
verdicts. The checked-in command-mutation probe exercises both the automatic
positive controls and attributed negative runs:

```bash
make -C src/tools/genpolicy/nested-policy-compat policy-evaluation-e2e \
  FIXTURES=pod.yaml \
  CANDIDATE_POLICY_GENERATOR="$PWD/src/tools/genpolicy/nested-policy-compat/tests/copy-baseline-policy.sh" \
  RUNTIME_FIXTURES_DIR="$PWD/src/tools/genpolicy/nested-policy-compat/tests/policy-evaluation/command-mutation/runtime" \
  POLICY_EXPECTATIONS_DIR="$PWD/src/tools/genpolicy/nested-policy-compat/tests/policy-evaluation/command-mutation/expectations" \
  PROFILE=k8s-1.36-containerd-2.3-guest-pull \
  OUTPUT_ROOT="$PWD/target/nested-policy-command-mutation"
```

To evaluate a suspected authorization gap, set `RUNTIME_FIXTURES_DIR` to a
directory containing files with the same names as the selected `FIXTURES`.
Policy is generated from the repository fixture, but both variants execute the
corresponding runtime fixture. This models an untrusted host presenting a
request derived from different workload intent.

Every distinct runtime workload requires
`POLICY_EXPECTATIONS_DIR/<fixture-name>.json`. The file states the expected
Agent verdict and denial attribution for each active variant:

```json
{
  "baseline": {
    "result": "policy-incompatible",
    "denial_contains": [
      "CreateContainerRequest",
      "annotations"
    ]
  },
  "candidate": {
    "result": "policy-incompatible",
    "denial_contains": [
      "CreateContainerRequest",
      "annotations"
    ]
  }
}
```

Valid expected verdicts are `compatible` and `policy-incompatible`.
Infrastructure and policy generation failures always fail the harness and are
never accepted as expected security outcomes. Every security-probe variant
first runs an automatic positive control using the generation workload; the
probe is accepted only when that control is compatible and the probe's denial
contains every configured attribution string. An unexpected baseline
`compatible` result in a probe expected to be denied is evidence of a policy
authorization gap; a candidate-only denial on a positive fixture is a
compatibility regression, not proof of improved security.

Each case writes `policy-evaluation.json` with workload, policy, and generation
input hashes plus expected and actual verdicts. The matrix writes an aggregate
`policy-evaluation.json` under `OUTPUT_ROOT`, requires exactly one report for
every selected fixture, and fails when any observed verdict differs from its
expectation.

## Validation

```bash
make -C src/tools/genpolicy/nested-policy-compat validate
```

Run the positive GenPolicy compatibility fixture matrix with a Kata
configuration that enables `cc_init_data`:

```bash
make -C src/tools/genpolicy/nested-policy-compat fixture-e2e \
  PROFILE=k8s-1.36-containerd-2.3-erofs-dmverity \
  IMAGE=nested-policy-compat:k8s-1.36-containerd-2.3-erofs-dmverity \
  KATA_ROOT=/opt/kata \
  KATA_CONFIG=/path/to/configuration.toml \
  GENPOLICY_TARGET=x86_64-unknown-linux-musl \
  OUTPUT_ROOT="$PWD/target/nested-policy-compat-fixtures"
```

The matrix covers the basic Pod, environment mutation, process/TTY,
two-container Deployment, service-account mutation, guest-local disk-backed
emptyDir, and memory/projected-volume workloads. Every case must generate a
policy with the repository's GenPolicy implementation and reach `compatible`
in the nested guest.
The disk-backed emptyDir fixture deliberately has no Pod `fsGroup`; the
separate storage fixture retains nonzero `fsGroup` coverage for memory-backed
emptyDir without conflating it with runtime-rs's local-storage encoding.
Boundary fixtures that intentionally require unsupported hostPath
authorization are excluded. The generator embeds the repository-tip
`rules.rego` and settings, and the image contains the GenPolicy binary built
from the same source tree. This keeps policy generation pinned to the
checked-out `manifold-cc`-based branch while adding the current attributable
`reason` rules.

Set `FIXTURES` to a space-separated subset for a focused run, for example
`FIXTURES=pod.yaml`.

The positive matrix includes a runtime-operations fixture that exercises
generated names, allowed sysctls, readiness, `kubectl exec`, the configured
`SIGHUP` stop signal on containerd 2.x, containerd 1.7's default graceful-stop
path, finalizer removal, and Pod deletion. Containerd 1.7 predates CRI custom
stop-signal support, so Kubernetes cannot deliver the fixture's requested
`SIGHUP` through that runtime; the containerd 1.7 generation path removes that
unsupported field before generating and applying the workload so the policy
authorizes the runtime's default stop signal. The old runtime does not retain
the trap output after teardown, so that profile verifies the zero exit status
rather than a log marker. Guest-pull teardown can likewise remove current
containerd's log source before collection; its generated policy only authorizes
the configured `SIGHUP`, so a zero exit status still verifies graceful
delivery.

Termination-message files are covered by a separate fixture because strict
Agent builds currently reject the `GetDiagnosticData` request runtime-rs uses
to recover `/dev/termination-log` when `shared_fs = "none"`. Run that known-gap
case separately:

```bash
make -C src/tools/genpolicy/nested-policy-compat termination-log-e2e \
  PROFILE=k8s-1.36-containerd-2.3-erofs-dmverity \
  IMAGE=nested-policy-compat:k8s-1.36-containerd-2.3-erofs-dmverity \
  KATA_ROOT=/opt/kata \
  KATA_CONFIG=/path/to/configuration.toml \
  OUTPUT_ROOT="$PWD/target/nested-policy-compat-runtime-operations"
```

The focused case writes `runtime-operations.json` with `"complete": false` and
the missing init-container and signal-handler termination messages under
`gaps`, then fails to keep the known limitation visible. GenPolicy has a
`request_defaults.GetDiagnosticDataRequest` setting, but enabling it cannot
override the strict Agent build's unconditional RPC rejection.

Custom service-account field references are also a known GenPolicy gap.
GenPolicy currently resolves `fieldRef: spec.serviceAccountName` from the
container representation rather than the Pod spec, so a custom value falls
back to `default` in the generated policy. The positive
`service-account-workload.yaml` fixture uses the default service account; run
the production-style custom-name reproducer separately:

```bash
make -C src/tools/genpolicy/nested-policy-compat custom-service-account-e2e \
  PROFILE=k8s-1.36-containerd-2.3-erofs-dmverity \
  IMAGE=nested-policy-compat:k8s-1.36-containerd-2.3-erofs-dmverity \
  KATA_ROOT=/opt/kata \
  KATA_CONFIG=/path/to/configuration.toml \
  OUTPUT_ROOT="$PWD/target/nested-policy-compat-custom-service-account"
```

`fixture-e2e` automatically reuses a current local appliance image. Each image
stores a content fingerprint covering the selected profile; appliance,
harness, fixture, and test scripts; GenPolicy source and configuration;
runtime-rs shim and Agent source; the selected Kata configuration; and
installed shim or Agent binaries found under `KATA_ROOT`. The target rebuilds
the image when it is missing, unlabelled, or has a different fingerprint.
Fingerprinting checkout sources detects a potentially stale appliance, but
does not build those sources or prove that the artifacts under `KATA_ROOT`
were produced from them. The separate mandatory provenance preflight performs
that source-equivalence check for the runtime-rs shim and guest Agent.
Changing `FIXTURES` or `OUTPUT_ROOT` alone does not rebuild the image because
those values select a run rather than change image contents. Use `make image`
when an unconditional rebuild is required.
