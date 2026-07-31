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
8. Capture each final bundle `config.json` through a runc wrapper immediately
   before runc consumes it.
9. Replace known deployment- or cluster-specific values with dynamic markers
   and emit a manifest describing every replacement.
10. Compile policy directly from the tagged OCI captures using the
    appliance-local Rust compiler described in
    [Standalone policy compiler](#standalone-policy-compiler).
11. Encode the compiled policy as initdata, annotate the input workload, and
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
- `tagged/*.json`: OCI specs with dynamic markers.
- `dynamic-tags.json`: marker definitions, JSON pointers, and suggested regexes.
- `policy.rego`: policy compiled from captured OCI and explicit Kata
  normalizations.
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
      "file": "tagged/container.json",
      "json_pointer": "/annotations/io.kubernetes.cri.sandbox-uid"
    }
  ]
}
```

The tag is semantic and stable across runs. The original dynamic value is not
included in the manifest; provenance contains only its SHA-256 digest. A policy
compiler can translate the marker to the recorded regex without learning a
deployment-specific identifier.

Values are tagged from authoritative sources:

- API-server generated Pod names and all assigned Pod UIDs.
- the synthetic node name.
- containerd sandbox and container IDs exposed in OCI annotations or runc IDs.
- Kubernetes service environment variables.
- paths containing one of those exact values.

Unknown variable fields are left unchanged and reported by conformance
comparison. Numeric or structural dynamic fields cannot contain string markers;
future profiles must represent them only through manifest JSON pointers.

### Dynamic OCI field treatment

Regexes apply to complete policy field values, not to unchecked fragments. For
environment entries, the matched value is the complete `NAME=value` string and
every input entry must match an exact policy environment entry or an approved
anchored regex.

| OCI-derived value | Legacy mode | Balanced mode |
| --- | --- | --- |
| Explicit image/YAML environment values | Exact `NAME=value` | Exact `NAME=value` |
| Kubernetes service-link environment values | Omitted from exact `Env` when covered by an inherited, anchored service-variable regex; generation fails if any captured variable lacks coverage | Exact captured `NAME=value`; regeneration is required when the resolved service IP or port changes |
| Pod name, Pod UID, and node-derived environment values | Structured substitutions such as `$(sandbox-name)`, `$(pod-uid)`, and `$(node-name)` | Same structured substitutions; these are correlations to request/runtime state rather than arbitrary wildcard regexes |
| Sandbox ID and other typed generated identities | Anchored, type-bounded patterns such as 64 hexadecimal characters | Same bounded identity treatment where deployment-time generation prevents an exact value |
| Kata `nerdctl/network-namespace` | Synthesized from the sandbox OCI network namespace and matched with the bounded `/var/run/netns/cni-<UUID>` grammar | Same bounded CNI grammar; an exact captured UUID is not deployable because CNI generates a new value |
| Sandbox log directory | Namespace and sandbox name are correlated to the request; only the Pod UID component uses a typed UUID grammar | Same relational pattern |
| Termination-message request path | Legacy-compatible `^/.*$` | Exact `/dev/termination-log`, accepted only when capture proves the dedicated external kubelet bind mount |
| Guest-visible source of an externally backed mount | Trusted-profile regex anchored within the Kata shared-filesystem domain | Same trust-domain-confined regex; exact matching would not make mutable host content trustworthy |
| Process argv, working directory, UID/GID, capabilities, root read-only state, mount destinations/types/options, masked paths, and read-only paths | Exact captured values, with documented Kata normalization where required | Exact captured values, with the same documented Kata normalization |
| Unknown dynamic strings or unsupported marker contexts | Left exact or generation fails; never converted to `.*` | Left exact or generation fails; never converted to `.*` |

`dynamic-tags.json` records marker provenance and grammars. `raw/` remains the
exact OCI reference, while `policy-oci-diff.json` records whether each compiled
field came from captured OCI, trusted workload YAML, or an explicit Kata
normalization.

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

containerd 1.7 invokes `io.containerd.runc.v2`, which invokes the configured
runc binary after writing the bundle's `config.json`. The profile config sets
`BinaryName` to `runc-capture`. The wrapper copies `config.json` and invocation
metadata to `/output/raw` and then execs the real pinned runc.

This captures the specification at the last stable boundary before execution
without patching containerd.

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

## Standalone policy compiler

This section is the source of truth for implementation of the appliance's last
stage. Implementation changes must be checked against this contract.

The compiler is an appliance-local Rust binary. Its primary workload inputs are
`tagged/*.json` and `dynamic-tags.json`, produced by the preceding OCI capture
and tagging stages. Captured OCI remains authoritative for container creation.
The compiler also reads exact exec commands from workload probe and lifecycle
actions because those future Agent `ExecProcessRequest` operations are not part
of the OCI `CreateContainer` specification.

The production appliance must not build, install, or invoke the legacy
`genpolicy` binary. It must not call `AgentPolicy::from_files()`,
`get_container_policy()`, or the Pod/controller-specific YAML-to-policy
generators. A separate test-only Docker target may build and invoke the legacy
binary solely to compare outputs during validation.

### Code reused directly

The compiler should depend on the repository GenPolicy library and reuse these
public components without modifying `src/tools/genpolicy/src`:

- `settings::Settings::new()` and the existing settings/drop-in format;
- policy OCI types including `KataSpec`, `KataProcess`, `KataMount`,
  `KataLinux`, and their child types;
- `policy::get_kata_namespaces()` for guest namespace normalization;
- `yaml::{new_k8s_resource, K8sResource::get_containers}` for common Pod and
  controller traversal;
- `yaml::K8sResource::get_sandbox_name()` for controller-specific Pod-name
  patterns derived from workload metadata;
- `pod::Container::get_exec_commands()` for exact probe and lifecycle commands;
- `yaml::add_policy_annotation()` for annotation placement;
- `kata_types::initdata::{InitData, encode_initdata}` for initdata encoding;
- the existing `rules.rego`, base settings, and appliance settings drop-ins.

The compiler owns small serializable `PolicyData` and `ContainerPolicy`
wrappers because the corresponding legacy container fields are private.

### Appliance-local implementation

The compiler must implement:

- loading tagged OCI captures and matching them by CRI container type/name;
- deterministic ordering and deduplication of equivalent kubelet retries;
- conversion of captured process, user, arguments, environment, working
  directory, capabilities, no-new-privileges, root read-only state, mounts,
  masked paths, and read-only paths into the policy OCI model;
- replacement of dynamic markers with constrained environment, annotation, or
  mount regexes from `dynamic-tags.json`;
- reuse of inherited GenPolicy service-link regexes in legacy mode rather than
  generating redundant service-specific regexes from captured values;
- fail-fast validation that every captured service-link environment variable
  removed from the explicit policy environment is covered by an inherited
  legacy regex, with coverage counts recorded in `policy-oci-diff.json`;
- explicit Kata normalization for guest root paths, shared-filesystem mount
  sources, guest namespaces, bundle annotations, and container-type
  annotations;
- extraction of exact liveness, readiness, startup, post-start, and pre-stop
  exec command arrays from the trusted workload YAML;
- controller-specific sandbox-name patterns from the workload kind and
  `metadata.name` or `metadata.generateName`, rather than the synthetic Pod name
  used only to exercise the clean-room runtime;
- sandbox log-directory patterns bound to the request sandbox namespace and
  name through Rego substitutions, with only the API-assigned Pod UID admitted
  through a typed UUID regex;
- policy assembly with existing Rego rules, deterministic JSON serialization,
  initdata encoding, workload annotation, and field-level provenance.

Captured OCI is authoritative. A settings template can normalize a captured
field for the Kata guest, but it cannot introduce a workload mount or process
property that is absent from the capture.

### Non-OCI policy fields

OCI does not represent every Kata Agent request field. For the initial
compatibility profile:

- sandbox storages come from the versioned settings profile;
- workload storages and devices are empty unless a later capture stage provides
  authoritative CRI request data;
- exec command allowlists contain exact commands from workload probe and
  lifecycle actions;
- standard optional runtime annotation patterns are added locally;
- unsupported storage, device, or volume behavior fails explicitly rather than
  being reconstructed from Kubernetes YAML.

A future profile that needs volumes, CDI devices, or other non-OCI request data
must capture the kubelet/containerd CRI request and feed that artifact to the
compiler. Probe and lifecycle exec commands are the narrow exception: the
workload declaration is the authoritative source for these future operations,
and the policy admits their argument arrays exactly.

### External storage and device trust boundary

Exact string matching is not a security benefit for the guest-visible source
of host-provided storage. Code inside the Kata UVM must treat the content as
untrusted and mutable even when the source string is stable. The policy's
security obligation is instead to prove that a source classified as external
cannot be redirected to code, data, sockets, devices, or other trusted state
inside the Kata UVM.

The source trust domain is a property of the resolved backing object, not just
its path spelling. A path inside the guest may be an externally backed shared
filesystem mount, while a syntactically similar path may resolve to UVM-local
state through a symlink, bind mount, mount-namespace alias, `..` traversal, or
runtime reconfiguration. A future authoritative CRI/runtime capture for
storages and devices must therefore include enough information to classify and
validate the resolved source.

Storage and device policy generation must follow these rules:

- treat source, mount point, driver, filesystem type, options, device type,
  device ID, and container-visible destination as security-sensitive fields;
- accept external sources only from explicitly allowlisted runtime-managed
  roots or identifiers whose backing object is proven to originate outside the
  UVM;
- canonicalize and resolve the source in the relevant mount namespace before
  classification; reject `..`, symlink escapes, bind aliases, and ambiguous or
  nonexistent sources;
- permit a compiler-generated guest-source regex when it is anchored wholly
  inside an allowlisted runtime-managed external domain, such as Kata's shared
  filesystem root; exact matching within that domain does not protect against
  mutable untrusted content;
- reject any source that resolves to the guest root filesystem, container
  rootfs, agent sockets, policy/initdata, runtime control state, or another
  UVM-internal trusted path or device;
- correlate sandbox/container IDs in source paths structurally rather than
  replacing them with an unconstrained path regex;
- never accept a user-provided raw regex for a storage or device source; source
  regexes must be emitted from a trusted profile after trust-domain
  classification;
- require exact device identity and trusted runtime/device-manager provenance;
  a container-visible device path alone does not prove which device is exposed;
- fail generation when source provenance or the external-versus-UVM-local
  classification cannot be established.

The current appliance satisfies this invariant by keeping workload
`storages` and `devices` empty and rejecting unsupported bind mounts. Its
versioned sandbox storage is fixed appliance configuration rather than
workload-controlled external storage. Support for CSI, CDI, shared filesystem,
block-device, or other external sources must not be enabled until the
authoritative capture and trust-domain checks above are implemented.

`tests/fixtures/storage-boundary-workload.yaml` exercises `emptyDir`,
ConfigMap, host-directory, and host-character-device volume transformations.
The resulting `raw/*.config.json` files are useful reference artifacts, but
policy generation is expected to fail at the unsupported workload bind mount.
This fixture verifies that capture can observe the transformation without
silently authorizing an unclassified source.

### Draft: end-to-end storage and device source enforcement

This section is a draft for further security review. It separates what the
clean-room appliance can establish from what must be enforced inside the Kata
UVM. The design must not claim that policy generation alone proves the backing
object used by a production Agent.

#### Source-domain contract

Every policy mount, storage, and device should carry an explicit semantic
class:

- `external-shared`: mutable, untrusted host content exposed through a
  runtime-managed shared-filesystem root;
- `guest-local`: storage intentionally created inside the UVM, including local
  or memory-backed `emptyDir`;
- `block-hotplug`: a host-provided block device resolved through the Kata
  device manager and guest transport;
- `device-hotplug`: a non-block device whose guest identity is established by
  runtime hotplug or an equivalent trusted device registry;
- `cdh-trusted`: trusted storage or sealed-secret content established through
  the Confidential Data Hub;
- `forbidden-uvm`: Agent sockets, policy/initdata, guest rootfs, container
  rootfs, runtime control state, and arbitrary pre-existing guest devices.

The policy contract should version these classes, their allowed fields, and the
Agent capabilities needed to enforce them. An Agent must reject an unsupported
contract version rather than ignore a class or silently weaken its checks.

#### Clean-room appliance responsibilities

The appliance can validate declared intent and generate bounded policy:

1. Capture OCI plus the relevant kubelet/containerd CRI mount and device
   inputs. OCI alone does not contain the final Agent `storages` and `devices`.
2. Use an appliance-owned adapter built against the pinned `virtcontainers`
   package to reproduce deterministic Kata normalization for supported classes.
   This adapter is a compatibility predictor, not proof of the production
   backing object.
3. Generate source regexes only from trusted profile rules. An
   `external-shared` regex must be fully anchored within an allowlisted Kata
   shared-filesystem root. Exact matching is unnecessary because the content
   remains mutable and untrusted.
4. Validate settings by class. An external mount must not use a guest-local
   source pattern, and a guest-local mount must not be accepted by an external
   rule.
5. Escape all dynamic path components before inserting them into a regex and
   validate bundle, sandbox, and container IDs with field-specific grammars.
6. Reject `/dev` and `/sys` hostPath inputs unless an authoritative runtime
   device identity is available. A guest-visible device path is not proof of
   the device's origin.
7. Record the source class, generated pattern, trusted rule, required Agent
   capability, and rejection reason in policy provenance.
8. Continue failing closed for CSI, direct volumes, CDI, VFIO, block devices,
   or other classes whose live runtime state cannot be reproduced
   authoritatively.

The clean-room process cannot resolve production-UVM symlinks, mount aliases,
mount IDs, device identities, or races. Those checks belong to the Agent.

#### Required Agent-side enforcement

At the time of this draft, `src/agent/src/policy.rs` returns success without
evaluating or installing policy. `allow_request()` and `do_set_policy()` must
be restored and tested before generated policy can provide enforcement.
Policy should be installed once from trusted initdata, and evaluation errors
must fail closed.

The Agent should maintain a registry of external roots and mount identities
created during sandbox setup, including the virtiofs/9p shared root and
Agent-created watchable mounts. For an `external-shared` source, it should:

1. Resolve the source relative to a registered root using an fd-based API such
   as `openat2()` with `RESOLVE_BENEATH` and `RESOLVE_NO_MAGICLINKS`.
2. Verify that resolution does not cross into an unregistered mount or a
   `forbidden-uvm` object.
3. Bind-mount the resolved fd/object instead of resolving the original path a
   second time. A `canonicalize()` followed by a path-based mount is
   insufficient because it retains a time-of-check/time-of-use race.
4. Enforce class-specific mount-point roots so an untrusted request cannot
   mount storage over Agent or runtime control state.

Guest-local paths must be checked under separate class-specific roots and must
never satisfy an external-source policy rule.

Source-domain enforcement is required at every privileged path consumer, not
only at the initial `CreateContainerRequest` policy check:

| Agent surface | Required enforcement |
| --- | --- |
| Rustjail OCI bind mounts | Resolve `OCI.Mounts[*].source` through the matched source-domain resolver before `mount_from()` mounts it. Canonicalizing an arbitrary guest path without checking its domain still permits exposure of UVM-internal state. |
| Agent `Storage` handling | Validate `source`, `mount_point`, `driver`, filesystem type, options, propagation flags, sharing mode, and ownership settings as one class-specific contract before handler dispatch. A driver name must not authorize arbitrary `mount(2)` parameters. |
| Storage destinations | Resolve or create mount points beneath dedicated class-specific roots with fd-relative, no-escape operations. Validate destinations before adding them to sandbox storage state or invoking a handler. |
| Cross-container `shared_mounts` | Keep denied unless policy explicitly identifies the source container and a registered sharable mount identity. Merely confirming that `src_path` appears in the source namespace's mount table is not authorization to clone that subtree with `open_tree()`. |
| ConfigMap/Secret watchable-copy path | Confine both source and target to registered roots. Recursive scanning, copying, deletion, ownership changes, and fallback bind mounts must use no-escape, symlink-safe traversal rather than lexical prefix operations. |
| Recursive ownership updates | Do not follow symlinks out of the mounted volume while applying `fsGroup`, `chown`, or permission changes. |

The same trusted path-resolution helper should be reused by storage mounting,
OCI bind mounting, shared-mount cloning, watchable-copy handling, and recursive
ownership operations. Parallel path validators with different semantics would
leave gaps between these surfaces.

Block and other devices require identity checks against the Agent's trusted
hotplug/device registry. The Agent must correlate the requested transport,
device identifier, and resolved guest device; it must not authorize a device
from its container-visible `/dev` path alone.

#### Authorize the effective request

The current request gate runs before Agent-side device resolution, CDI edits,
CDH handling, storage mounting, and sealed-secret handling. The creation path
should be split into three stages:

1. **Prepare:** resolve device mappings and compute CDI, CDH, storage, and OCI
   edits without creating mounts or starting the container.
2. **Authorize:** evaluate policy against the effective post-transformation
   OCI, storage, and device plan.
3. **Commit:** perform storage mounts and container creation only after the
   effective plan is authorized.

If an operation cannot be prepared without side effects, it needs a dedicated
policy check before the operation and a final effective-OCI validation before
container creation.

CDI policy must account for every injected mount, environment entry, hook, and
device node and correlate the CDI device kind with a trusted resolved device.
CDH trusted storage and sealed secrets need dedicated resource constraints and
must not be treated as ordinary shared mounts.

The prepare stage must also validate driver semantics. Each supported storage
class needs an allowlist for driver, filesystem type, mount flags, propagation
mode, driver options, and expected source and destination domains. For example,
selecting a virtio-fs handler must not permit the caller to request an
unrelated filesystem type or arbitrary bind/move/shared mount flags.

#### Incremental delivery

Support should be enabled by class:

1. Restore Agent policy enforcement and add the versioned policy contract.
2. Add external-domain resolution and mount-time enforcement for standard
   runtime files and shared ConfigMap, Secret, projected, and downwardAPI
   mounts.
3. Add separate shared, memory, local, and encrypted `emptyDir` classes.
4. Add block, CSI, and direct-volume support only with authoritative
   device-manager provenance.
5. Add CDI, VFIO, and CDH support after post-transformation authorization is
   available.

Unsupported classes remain denied. An audit-only mode may be used to measure
compatibility during rollout, but confidential production mode must enforce.

#### Draft acceptance criteria

- external source strings may vary only within their class's bounded external
  domain;
- an external-classified source cannot resolve to guest rootfs, container
  rootfs, Agent sockets, policy/initdata, runtime control state, or an
  arbitrary existing guest device;
- `..`, symlink, bind-alias, nested-mount, and rename-race attempts cannot
  escape a registered external root;
- an allowed source cannot be mounted onto an arbitrary UVM destination, and a
  driver cannot be used to request a filesystem type or propagation mode
  outside its class contract;
- cross-container shared mounts cannot clone `/`, `/proc`, secret volumes, or
  any mount that was not registered as sharable;
- watchable ConfigMap/Secret synchronization cannot scan, copy, delete, or
  change ownership outside its registered source and target roots;
- CDI, CDH, storage, or device edits performed after receipt of the original
  request cannot bypass policy;
- a volume or device class is not declared supported until both appliance-side
  generation tests and Agent-side runtime-domain tests pass.

Open questions for follow-up analysis include the exact fd-based mount API,
kernel compatibility requirements, the representation of source classes in
policy data, how to prepare CDH operations without side effects, and whether
the Agent should return structured policy-match metadata or enforce source
domains in a separate trusted validator. A further Agent-hardening question is
whether the same fd-relative confinement framework should protect privileged
rootfs setup operations that currently run before `pivot_root` or `chroot`;
that issue is broader than generated mount policy but relies on the same
no-escape filesystem invariant.

### Deliberately excluded legacy code

The compiler does not reuse:

- `AgentPolicy` and YAML resource/controller parsing;
- image registry or containerd image-pull helpers;
- image entrypoint, environment, user, or group derivation;
- YAML-driven mount, storage, device, or container-process derivation.

Those values are either already resolved in captured OCI or are outside OCI and
require a separate authoritative capture. Probe and lifecycle exec requests are
read exactly from workload YAML as described above.

### Validation contract

Automated validation must prove that:

- the appliance image contains and invokes the standalone compiler, not the
  legacy `genpolicy` executable;
- changing a captured OCI field such as `process.cwd` changes the final policy
  without changing workload YAML;
- dynamic markers do not appear in final Rego and become constrained policy
  expressions;
- no uncaptured settings mount is introduced;
- workload exec probes and lifecycle hooks appear as exact command arrays;
- the encoded annotation decodes to the exact emitted `policy.rego`;
- duplicate equivalent captures are deterministic and conflicting duplicates
  fail;
- unsupported non-OCI policy requirements fail with an actionable error.

`policy-oci-diff.json` records the selected capture and the source or
normalization reason for every compiled field.

### TODO: restrict generated regexes to non-security configuration

Before this appliance is used to generate production policy, classify every
dynamic field by security impact. The appliance must generate a restrictive
policy without relying on broad matching behavior.

The generator must follow this rule:

> Generate a regex only for bounded configuration whose accepted values remain
> in the same validated trust domain. Security-relevant identities and
> destinations must use exact values or structured correlation. Guest-visible
> sources for untrusted external storage may use compiler-generated regexes
> confined to an allowlisted external domain.

Until every field is classified, the compiler must remain fail-closed:

- never generate `ExecProcessRequest.regex`; authorize exec only with exact
  argv arrays, or deny it;
- keep executable paths, arguments, UID/GID, capabilities, image identity,
  devices, mount destinations, and mount types/options exact;
- allow mount or storage source regexes only when generated from trusted
  runtime metadata and anchored entirely within a validated external-untrusted
  domain. UVM-local sources must be separately classified and must not match
  those patterns. Runtime IDs must still be validated by structured
  relationships to the sandbox/container ID;
- reject unknown dynamic-marker contexts instead of falling back to `.*`,
  prefix matching, or user-provided raw regex;
- keep workload storages/devices empty until authoritative CRI request capture
  and exact policy generation are implemented.

Candidate regex fields are limited to explicitly reviewed non-secret
configuration values, for example Kubernetes-generated service IP/port
environment variables, DNS-format host names, and similarly bounded metadata.
Even for these fields, the compiler must:

- use a field-specific grammar rather than `.+`;
- escape all static text and anchor the complete expression with `^` and `$`;
- record the tag, authoritative source, field context, grammar, and security
  classification in provenance;
- reject secret-derived environment variables and user-controlled values unless
  they are represented exactly.

Acceptance tests must prove that exact security fields reject executable
prefixes/suffixes, extra or merged argv elements, shell metacharacters, sibling
mount paths, `..` traversal, altered storage definitions, alternate images,
and secret-value substitutions. Regex-approved configuration fields must
reject near-matches outside their bounded grammar.

### Legacy and balanced policy modes

The appliance supports two deployable policy modes from the same OCI captures:

- **legacy** is the default compatibility mode. It preserves inherited
  `allow_env_regex` entries and the legacy service-variable grammars, permits
  any termination-message path, and generalizes generated CNI and kubelet path
  components. A generation-time coverage gate verifies that every captured
  service variable omitted from exact `Env` entries is covered by an inherited
  regex. This mode minimizes migration failures but carries the broadest
  authorization surface;
- **balanced** is enabled with `GENPOLICY_BALANCED=1`. It clears inherited
  environment regexes, keeps Kubernetes
  service endpoints exact and restricts termination messages to the dedicated
  externally backed `/dev/termination-log` mount unless those strings
  already contain an existing generated name/UID marker. It emulates the Kata
  shim by copying the sandbox OCI network namespace path into
  `nerdctl/network-namespace`, then generalizes that generated CNI path with a
  bounded regex. Existing regex-backed relation markers remain explicit
  residual risks.

`policy.rego` contains legacy mode and `policy-balanced.rego` contains balanced
mode. `policy-mode-report.json` records their differences. Balanced policies
require regeneration when a service ClusterIP or port changes, while legacy
policies continue accepting values covered by their service regexes. Both
modes retain bounded generated-identity relationships required for deployable
controller workloads. Raw OCI captures under `raw/` remain the exact reference
for generated values that cannot be predicted safely at deployment time.

A future external-domain mode may wildcard endpoints or storage sources only
inside a structured external-untrusted trust domain. It requires runtime
knowledge to exclude UVM-local, loopback, link-local, agent/control endpoints,
and TCB-internal filesystem paths; the current generic IP/path regexes cannot
provide that guarantee. Balanced mode also does not yet distinguish image/YAML
environment provenance from unknown runtime injection or enforce
required-exactly-once environment keys.

Balanced mode must reject a termination-message path that is not
the dedicated external kubelet bind mount. Exact capture is insufficient:
pinning a malicious path under image code or UVM-internal state would preserve
an overwrite primitive. Detection of the external kubelet mount uses its
normalized `pods/<pod-id>/containers/<container>/<log-id>` role and does not
pin the host's kubelet root directory.
