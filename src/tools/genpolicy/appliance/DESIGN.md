# GenPolicy OCI Conversion Appliance

## Status

Initial compatibility profile:

- Kubernetes API server and kubelet: `v1.33.13`
- containerd: `v1.7.29`
- runc: `v1.2.8`
- etcd: `v3.5.21`
- CNI plugins: `v1.7.1`
- pause image: `genpolicy.local:5000/pause:3.10`, populated from the pinned
  `registry.k8s.io/pause:3.10` build input

The profile follows the Kubernetes 1.33 API line and containerd 1.7 runtime
assumptions currently present in this repository. It is intentionally immutable:
changing any component version creates a new profile and image tag.

Version pinning reproduces component behavior and defaults; it does not require
deployment hosts to install kubelet, containerd, runc, or Kata under the same
directory prefixes used inside the appliance. Host-side paths must therefore
be classified and normalized by semantic role, for example:

- kubelet pod directory;
- containerd sandbox directory;
- runc bundle directory;
- Kata shared-filesystem root;
- external volume source.

The policy may exactly match guest/container destinations and security-relevant
suffixes, types, and options. It must not exact-match an appliance-specific
host installation prefix. A role matcher must normalize the path, reject
traversal and ambiguous components, and preserve sandbox/container/volume
identity relationships.

## Goal

Generate the OCI runtime specification that a versioned kubelet and containerd
would produce from Kubernetes YAML without contacting an existing cluster.
The appliance runs as one privileged container inside a disposable Linux VM.
Referenced Kubernetes objects must be supplied locally. Workload images may be
supplied as local OCI archives or fetched by immutable manifest digest during
the preparation phase.

This appliance is a deterministic policy-generation environment, not a
general-purpose Kubernetes cluster.

The rationale is fidelity. Legacy GenPolicy predicts the environment variables,
storages, and mounts that the API server, kubelet, containerd, and Kata shim add
by encoding one point-in-time understanding of those components as hardcoded
templates, which drift as the components evolve. The appliance instead runs the
pinned real components and captures what they actually produce, so the set and
structure of injected fields need never be guessed. The values in those fields
belong to this dry-run cluster and are generalized for deployment by the policy
compiler; see [policy-compiler/DESIGN.md](policy-compiler/DESIGN.md).

## Pipeline

1. Start a private etcd and kube-apiserver.
2. Start containerd with the profile's CRI configuration.
3. Start the pinned kubelet and register one synthetic node.
4. Submit every input YAML object to the API server so normal schema decoding
   and API-server defaulting occur.
5. Convert workload controllers to bound Pods without running scheduler or
   controller-manager. The Pod template is read back from the API server after
   defaulting.
6. Let kubelet produce the real CRI sandbox and container requests.
7. Let containerd produce the OCI runtime specification.
8. Route the `kata` RuntimeClass through the appliance capture shim, which
  reuses runtime-rs task services and container/resource managers behind a
  dry-run hypervisor and recording Agent.
9. Predict the Kata Agent `storages` and `devices` the workload would produce
   by running the real `runtime-rs` shim handlers behind a no-VM dry-run
   `Hypervisor`, and emit `storages-devices-predicted.json` (see
   [Storage and device prediction](#storage-and-device-prediction)) for audit.
10. Require one final Agent `CreateContainerRequest` capture per expected
  sandbox or container. Record probe and lifecycle `ExecProcessRequest`
  calls from the same live shim service.
11. Tag deployment-variable values in each request's nested OCI and emit a
    manifest with request-rooted JSON pointers.
12. Compile policy from paired raw/tagged requests using the appliance-local
    Rust compiler described in
    [policy-compiler/DESIGN.md](policy-compiler/DESIGN.md).
13. Encode the compiled policy as initdata, annotate the input workload, and
    emit field-level provenance.

## Trust and isolation

The appliance requires `--privileged`, cgroup v2 access, mount propagation, and
network namespace operations. Run it only inside a disposable VM or equivalent
strong isolation boundary. A privileged appliance container must not run
directly on a shared workstation or CI host.

Outbound networking is available only during image preparation. The appliance
imports matching OCI archives from `/input/images` or pulls digest-qualified
repository references, then installs namespace-local firewall rules that block
non-loopback outbound traffic before starting the control plane. The outer
container may use `--network=none` only when all requested manifests are
available locally; repository-backed inputs require temporary network access
during this preparation phase.

Kubelet and containerd resolve image entrypoint, arguments, environment,
working directory, user/group, capabilities, and runtime defaults before the
OCI bundle is captured. The policy stage therefore does not pull images or run
the legacy GenPolicy executable. Workload images only need to be available to
the pinned containerd instance before kubelet creates the containers.

## Inputs

The `/input` directory contains:

- `workload.yaml`: one or more Kubernetes YAML documents.
- `images/*.tar`: optional OCI or Docker image archives imported before the
  workload is submitted.

Workload image references must end in an immutable
`@sha256:<manifest-digest>` reference. Tags without a digest, including
version-looking tags, are rejected before the clean-room services start. If an
imported archive contains the requested manifest, the appliance creates the
exact repository/digest alias locally. Otherwise it pulls that immutable
reference before outbound networking is disabled.

ConfigMaps and Secrets needed for environment resolution must be included in
`workload.yaml`. Unsupported external dependencies fail the run rather than
being silently approximated.

## Outputs

The `/output` directory contains:

- `raw/`: OCI `config.json` captures and runc invocation metadata.
- `createcontainer-requests/*.json`: exact final Agent
  `CreateContainerRequest` captures.
- `tagged-requests/*.tagged.json`: complete captured requests whose nested
  `oci` strings contain dynamic markers; request-level fields remain exact.
- `dynamic-tags.json`: marker definitions, request-rooted JSON pointers,
  original-value digests, and suggested regexes.
- `policy.rego`: policy compiled from paired raw/tagged requests and explicit
  policy normalizations.
- `policy-oci-diff.json`: field-level provenance for captured and normalized
  values.
- `policy-annotation.txt`: encoded initdata annotation value.
- `workload-policy.yaml`: workload YAML containing the generated annotation.
- `submitted-objects.json`: API-server-defaulted input objects.
- `pods.json`: synthetic bound Pods and their assigned UIDs.
- `provenance.json`: compatibility profile and input/output hashes.
- service logs for diagnostics.

## Dynamic marker format

String values use the following marker:

```text
{{GENPOLICY_DYNAMIC:<tag>}}
```

Markers can replace a full value or a substring. Examples:

```text
{{GENPOLICY_DYNAMIC:pod.uid}}
/var/log/pods/{{GENPOLICY_DYNAMIC:pod.uid}}/container/0.log
KUBERNETES_SERVICE_HOST={{GENPOLICY_DYNAMIC:service-env.KUBERNETES_SERVICE_HOST}}
```

`dynamic-tags.json` records each occurrence:

```json
{
  "tag": "pod.uid",
  "marker": "{{GENPOLICY_DYNAMIC:pod.uid}}",
  "source": "api-server",
  "suggested_regex": "[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
  "occurrences": [
    {
      "file": "tagged/0001-container.tagged.json",
      "json_pointer": "/oci/annotations/io.kubernetes.cri.sandbox-uid",
      "original_sha256": "<sha256-of-the-original-value>"
    }
  ]
}
```

The tag is semantic and stable across runs. The original dynamic value is not
included in the manifest; provenance contains only its SHA-256 digest. A policy
compiler can translate the marker to the recorded regex without learning a
deployment-specific identifier. The `file` value is the tagger's stable logical
artifact name; the appliance writes that artifact under
`/output/tagged-requests/`.

### Manifest generation

The appliance runs `tag_oci.py` only after it has captured one final
`CreateContainerRequest` for every expected sandbox and workload container. The
tagger loads the following inputs:

- `createcontainer-requests/*.json`: the authoritative requests;
- `dynamic-values.json`: values learned earlier from the clean-room Kubernetes
  run, including generated Pod names and UIDs and the synthetic node name.

For each request, the tagger requires a nested `oci` object and augments the
known dynamic values with identifiers visible at the request boundary:

- `io.kubernetes.cri.sandbox-id` becomes `sandbox.id`;
- `io.kubernetes.cri.sandbox-uid` becomes `pod.uid`;
- the request's `container_id` becomes `container.id` for finding that value
  where it occurs inside OCI.

It also recognizes context-specific OCI values: Kubernetes service environment
variables, the kubelet termination-log ID in a mount source, and the generated
CNI network-namespace path. Each recognized string or substring is replaced by
`{{GENPOLICY_DYNAMIC:<tag>}}`. Every replacement records the semantic tag,
source, suggested bounded grammar, tagged request filename, request-rooted JSON
pointer, and SHA-256 digest of the original value. Definitions and input files
are processed in sorted order, so repeated generation is deterministic.

The tagger then writes the complete request to `tagged-requests/`, replacing
only `request.oci`. It leaves `container_id`, `storages`, `devices`, request
flags, and other request-level fields unchanged. Finally, it sorts definitions
by tag and writes them as `dynamic-tags.json`; balanced mode additionally
records `"regex_policy_mode": "balanced"`.

This boundary is deliberate. The captured request decides which Agent fields
exist and remains authoritative for request-level data. Tagging only makes
approved deployment-variable OCI strings portable to another cluster. It
cannot add runtime structure, generalize a storage or device accidentally, or
change the request identity used to pair raw and tagged artifacts.

Values are tagged from authoritative sources:

- API-server generated Pod names and all assigned Pod UIDs.
- the synthetic node name.
- containerd sandbox IDs exposed in OCI annotations and the captured request's
  container ID where either value occurs in nested OCI.
- Kubernetes service environment variables.
- paths containing one of those exact values.

Unknown variable fields are left unchanged and reported by conformance
comparison. Numeric or structural dynamic fields cannot contain string markers;
future profiles must represent them only through manifest JSON pointers.

### Field-by-field regex treatment

The dynamic markers above record *where* a deployment-specific value occurs and
a suggested grammar. *How* each field is generalized — the exact/regex split,
the typed grammars, the identity correlations, and the security invariants that
keep generated regexes bounded — is the policy compiler's contract and lives in
[policy-compiler/DESIGN.md](policy-compiler/DESIGN.md).

## Controller handling

The appliance does not run controller-manager or scheduler. It creates the
original object, reads the defaulted object back, extracts its Pod template, and
creates a synthetic Pod bound to `genpolicy-node`.

Supported paths:

| Kind | Pod template |
|---|---|
| Pod | `.spec` |
| PodTemplate | `.template` |
| Deployment, DaemonSet, ReplicaSet, StatefulSet, Job | `.spec.template` |
| ReplicationController | `.spec.template` |
| CronJob | `.spec.jobTemplate.spec.template` |

Synthetic names are dynamic and tagged. This preserves container-level
defaulting and kubelet/containerd conversion while avoiding controller timing
and replica behavior.

## Fidelity boundaries

The appliance captures the exact configured profile, including API-server
defaulting, kubelet CRI generation, and containerd OCI generation. It does not
reproduce:

- cluster admission webhooks not explicitly included in the profile;
- arbitrary Services and their environment variables unless supplied;
- CSI, device-plugin, or cloud-provider behavior;
- node-specific files, devices, and runtime configuration outside the profile;
- post-generation mutation by a different runtime implementation.

These are policy inputs, not hidden defaults. A production profile must either
provide fixtures for them or retain explicit regex/allowlist policy rules.

## OCI capture

containerd 1.7 invokes `io.containerd.kata-capture.v2` for Pods selecting the
`kata` RuntimeClass. The appliance-owned shim receives containerd's final OCI
bundle and routes normal task requests through runtime-rs. Its recording Agent
writes the amended OCI from each final `CreateContainerRequest` to
`/output/raw` together with container metadata. This runtime-rs backend is the
default build and also records live `ExecProcessRequest` calls.

This captures the OCI and Agent request at the policy enforcement boundary
without patching containerd or booting a VM.

An explicit `CAPTURE_BACKEND=runc` compatibility build does not compile the
integrated shim and therefore does not depend on its runtime-rs constructor
APIs. It uses `runc-capture` to retain final OCI bundles during the Kubernetes
run, then passes those bundles through the standalone no-VM
`createreq-capture` tool. That path produces final create-request policy inputs
but cannot observe live probe or lifecycle exec requests; those commands remain
sourced from the trusted workload YAML.

## Storage and device prediction

The captured OCI `config.json` records containerd's bind/tmpfs mount view, not
the Kata Agent `storages` and `devices` the Kata shim synthesizes downstream —
and it is that downstream shape, not the OCI mounts, that the in-TEE agent
actually enforces. The same rationale as the rest of the appliance applies:
legacy GenPolicy reimplements the shim's storage synthesis from a template that
drifts (it omits hugepage, block, direct-volume, and device synthesis), so the
appliance runs the *real* code instead. It links the pinned `runtime-rs`
`resource` crate and executes the shim's own volume and rootfs handlers behind a
no-op dry-run `Hypervisor` and a stub `Agent`, producing the concrete Agent
`storages`/`devices` **without booting a VM**.

Because the storage shape depends on host-controlled Kata configuration
(`shared_fs`, block driver, `emptydir_mode`) and not only the YAML, the predictor
is fed the deployment's `configuration.toml` so its output matches the CC profile
the workload will run under. The result (`storages-devices-predicted.json`) is
retained for diagnostics and comparison. It does not drive the compiler.
Rootfs identity, volume storages, devices, and rewritten mounts come from the
captured final request.

The design rationale (which authority decides each storage, the Confidential
Containers threat model, and the no-VM prediction internals) is in
[storage-predictor/DESIGN.md](storage-predictor/DESIGN.md); usage and the
policy-generation behaviour it drives are in
[storage-predictor/README.md](storage-predictor/README.md).

## Authoritative CreateContainerRequest capture

The OCI capture and storage/device prediction are upstream inputs and diagnostic
artifacts. Neither is a compiler input. The final Agent-visible request is
captured as one artifact so OCI, storages, devices, and request flags cannot
drift across independently modeled sources.

The appliance capture shim closes that gap by handling containerd task requests
through the **real** runtime-rs service and container-create path with no VM. It
builds the pinned `ResourceManager` and public `VirtContainerManager` behind a
dry-run `Hypervisor`, injects a **recording `Agent`**, and seeds that runtime
instance into the normal `RuntimeHandlerManager` and `ServiceManager`. The
shim's own `Container::create` performs rootfs, volume, and device handling,
spec amendment, and namespace normalization before handing the assembled
`agent::CreateContainerRequest` to the recording Agent. OCI, storages, devices,
and request flags are therefore one authoritative artifact produced by real
shim code, with no compiler-side normalization template. The same Agent records
`ExecProcessRequest` calls generated by kubelet probes and lifecycle hooks.
The shim enables runtime-rs's existing `force_guest_pull` experiment so the
native snapshotter's host bind rootfs is converted by `ResourceManager` into the
same guest-pull virtual volume that the confidential deployment uses.

Three properties follow from running the real code:

- The container **rootfs** is synthesized through the shim's real rootfs
  handlers. With no snapshotter artifact it takes the guest-pull path
  (`kata_types::mount::adjust_rootfs_mounts` → the `image_guest_pull` `Storage`),
  the confidential-containers default and a pure transform needing no
  snapshotter, device, or VM. When a snapshotter-captured `rootfs-mounts`
  artifact is supplied (the same one the storage-predictor consumes), it instead
  takes the erofs multi-layer / single-layer block / **dm-verity** path, so the
  captured request carries the root-hash-pinned rootfs storages.
- The **volume** handlers perform real host filesystem operations —
  canonicalizing kubelet bind-mount sources and taking the configured
  `shared_fs` path. Those host paths (`/var/lib/kubelet/pods/<uid>/…`) and the
  shared-filesystem domain exist only *inside* the appliance at capture time, so
  this stage must run co-located with the capture, exactly as the OCI capture
  itself does; it is not a step that can be replayed against saved captures on an
  arbitrary host. In particular, with `shared_fs = "none"`, ConfigMap and Secret
  volumes take runtime-rs's copy-to-guest path: the recording Agent accepts the
  `CopyFile` calls, the final OCI bind source is rewritten to
  `<cpath>/<cid>-<16 hex>-<destination basename>`, and no Agent `Storage` is
  emitted. The compiler templates that captured mount shape and the policy
  confines `CopyFile` paths and file types. The individual copy payloads are not
  serialized into the captured `CreateContainerRequest`, and the policy does not
  attest host-supplied ConfigMap or Secret contents.
- **CSI direct volumes** can be replayed at the shim boundary. A CSI driver
  signals such a device by writing `mountInfo.json` under the Kata direct-volume
  root before container creation; the clean room has no CSI driver, so the
  operator can supply replay fixtures via `--direct-volume-mounts`. The tool
  stages them with the same `add_volume_mount_info` writer used by production
  Kata components, then the real `handle_direct_volume` path processes the
  device through the dry-run `Hypervisor` (deterministic guest address, no VM).
  This is not a CDH encryption contract: raw direct-volume handling does not add
  `encryption_key=ephemeral` to `Storage.driver_options` and does not invoke CDH.
  Direct-volume policy admission also remains fail-closed pending dedicated
  storage-to-mount correlation.

The tool is deterministic-value agnostic: like the OCI capture, its output still
carries this dry-run cluster's deployment-specific values (sandbox/container IDs,
Pod UID, service endpoints), which the tagging and compiler stages generalize as
before. It raises structural fidelity (which fields the Agent sees), not the
value-generalization contract.

Scope is the per-container `CreateContainerRequest` (including the sandbox
container of type `sandbox`). The pod-level `CreateSandboxRequest` is **not**
captured: its policy is entirely profile-driven — empty `guest_hook_path`, empty
`kernel_modules`, `sandbox_pidns == false`, and sandbox storages from the
versioned settings profile — with no workload-derived inputs, so it is authored
from settings rather than captured. Capturing the real `CreateSandboxRequest`
would also be VM-coupled (the shim sends it only after `start_vm` and
`setup_after_start_vm`), so it is deliberately out of scope for this no-VM stage.

## Deferred: production CSI direct-volume capture

This design is intentionally pinned for later implementation. The high-fidelity
path is to run the repository's real `csi-kata-directvolume` driver inside the
throwaway cluster rather than synthesize PVC resolution or `mountInfo.json` from
workload YAML.

The target flow is:

1. Start etcd, the API server, kubelet, containerd, and a narrowly configured
  `kube-controller-manager` providing DaemonSet reconciliation and persistent
  volume binding.
2. Load pinned images for `directvolplugin`, the external provisioner, node
  driver registrar, and liveness probe before outbound networking is sealed.
3. Deploy the real CSI driver and wait for `CSIDriver`, `CSINode`, provisioner,
  and node-plugin readiness.
4. Submit the input `StorageClass`, PVC, and workload YAML. The real controller
  provisions the volume and kubelet drives `NodeStageVolume` /
  `NodePublishVolume`.
5. Let the CSI node plugin create the production target-path bind mount and
  canonical `mountInfo.json`. `runc-capture` then records the unmodified OCI
  mount emitted by kubelet/containerd.
6. Run `createreq-capture` without replay fixtures. The real runtime-rs
  direct-volume handler reads the CSI-created metadata and records the final
  Agent `CreateContainerRequest`; only VM hotplug and Agent execution remain
  simulated.
7. Keep CSI metadata alive through request capture, then allow normal
  `NodeUnpublishVolume` cleanup.

Infrastructure containers must be excluded from workload captures by OCI
annotation/namespace, not by deleting early captures, because a sidecar restart
could otherwise contaminate policy inputs. The appliance must also validate the
`StorageClass -> PVC -> Pod volume -> container volumeMount` relationship and
record its correlation to the PV, CSI target path, OCI source, Agent storage,
and rewritten mount.

The existing `GENPOLICY_DIRECT_VOLUME_MOUNTS` input remains useful only as an
explicit post-CSI replay mechanism for regression tests and externally resolved
devices. It must not be presented as equivalent to YAML-to-PVC analysis.

This milestone captures production behavior through the Kata shim but does not
make host-provided storage confidential. CDH/KBS-backed persistent encryption
requires a separate runtime/Agent storage contract and corresponding policy
constraints. Direct-volume policy admission is a subsequent milestone.

## Validation

`make validate` performs:

- Python unit tests for controller normalization and dynamic tagging;
- Python bytecode compilation;
- shell syntax checks;
- profile and Dockerfile version consistency checks.

`make e2e` additionally builds and runs the privileged appliance when Docker or
Podman is available. It verifies that:

- the API server and kubelet process the sample Pod;
- at least the sandbox and workload OCI specs are captured;
- dynamic values are replaced by markers;
- provenance and tag manifests are emitted.

The end-to-end test must run inside a disposable VM.

## Policy compilation

The final stage compiles paired raw/tagged `CreateContainerRequest` captures and
`dynamic-tags.json` into
deployable Kata Agent policy. Its contract — reused GenPolicy components,
appliance-local implementation, non-OCI policy fields, the external
storage/device trust boundary, the legacy and balanced policy modes, the
regex/value-generalization design, and the compiler validation contract — is
documented in [policy-compiler/DESIGN.md](policy-compiler/DESIGN.md).

The dividing line is deliberate: this document covers how the dry-run reproduces
a real cluster's normalization at high fidelity; the compiler document covers
how deployment-specific captured values are generalized into a policy that a
different production cluster will still satisfy.
