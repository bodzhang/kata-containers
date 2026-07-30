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

## Goal

Generate the OCI runtime specification that a versioned kubelet and containerd
would produce from Kubernetes YAML without contacting an existing cluster.
The appliance runs as one privileged container inside a disposable Linux VM.
All workload images and referenced Kubernetes objects must be supplied locally.

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

Runtime outbound networking is disabled. The image contains the pinned control
plane binaries and test images. Additional workload images are imported from
OCI archives mounted at `/input/images`.

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

Workload image references must use the profile's local registry prefix
`genpolicy.local:5000`. Imported archives intended for policy generation must
carry that reference so kubelet can resolve the image already imported into
the local containerd content store.

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
and tagging stages. It may read the workload YAML only to place the final
initdata annotation; it must not derive OCI or container execution policy from
the YAML.

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
- explicit Kata normalization for guest root paths, shared-filesystem mount
  sources, guest namespaces, bundle annotations, and container-type
  annotations;
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
- exec command allowlists use request defaults only;
- standard optional runtime annotation patterns are added locally;
- unsupported storage, device, or volume behavior fails explicitly rather than
  being reconstructed from Kubernetes YAML.

A future profile that needs volumes, CDI devices, or other non-OCI request data
must capture the kubelet/containerd CRI request and feed that artifact to the
compiler. It must not restore the legacy YAML derivation path.

### Deliberately excluded legacy code

The compiler does not reuse:

- `AgentPolicy` and YAML resource/controller parsing;
- image registry or containerd image-pull helpers;
- image entrypoint, environment, user, or group derivation;
- YAML-driven mount, storage, device, or exec-command derivation.

Those values are either already resolved in captured OCI or are outside OCI and
require a separate authoritative capture.

### Validation contract

Automated validation must prove that:

- the appliance image contains and invokes the standalone compiler, not the
  legacy `genpolicy` executable;
- changing a captured OCI field such as `process.cwd` changes the final policy
  without changing workload YAML;
- dynamic markers do not appear in final Rego and become constrained policy
  expressions;
- no uncaptured settings mount is introduced;
- the encoded annotation decodes to the exact emitted `policy.rego`;
- duplicate equivalent captures are deterministic and conflicting duplicates
  fail;
- unsupported non-OCI policy requirements fail with an actionable error.

`policy-oci-diff.json` records the selected capture and the source or
normalization reason for every compiled field.

### TODO: restrict generated regexes to non-security configuration

Before this appliance is used to generate production policy, classify every
dynamic field by security impact. The appliance must generate a strict policy
without relying on broad matching behavior.

The generator must follow this rule:

> Generate a regex only for bounded, cluster-generated configuration data whose
> variation does not grant code-execution, filesystem, device, identity, image,
> or secret access. Security-relevant fields must use exact values or a
> structured correlation rule, never a value-matching regex.

Until every field is classified, the compiler must remain fail-closed:

- never generate `ExecProcessRequest.regex`; authorize exec only with exact
  argv arrays, or deny it;
- keep executable paths, arguments, UID/GID, capabilities, image identity,
  devices, mount destinations, mount types/options, and storage fields exact;
- do not generate regexes for mount or storage paths. Runtime IDs in paths must
  be validated by structured relationships to the sandbox/container ID, or the
  feature must remain unsupported;
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
