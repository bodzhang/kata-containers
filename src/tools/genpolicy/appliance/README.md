# GenPolicy OCI conversion appliance

This directory implements the versioned clean-room pipeline described in
[`DESIGN.md`](DESIGN.md).

Run static and unit validation:

```bash
make validate
```

Build the profile image:

```bash
make image
```

Run it inside a disposable Linux VM:

```bash
mkdir -p input/images output
cp tests/fixtures/pod.yaml input/workload.yaml

docker run --rm --privileged --network=none \
  --cgroupns=host \
  -v "$PWD/input:/input:ro" \
  -v "$PWD/output:/output" \
  genpolicy-appliance:k8s-1.33.13-containerd-1.7.29
```

Every `containers`, `initContainers`, and `ephemeralContainers` image in the
input YAML must use an immutable repository
`@sha256:<manifest-digest>` reference. Mutable tags, including version-looking
tags and `latest`, fail before the clean-room cluster starts. A matching image
archive in `input/images` is used when available; otherwise the appliance pulls
the digest-qualified reference from its repository. It then blocks outbound
traffic before starting Kubernetes. Use `--network=none` only when every
requested digest is already available from an input archive or a fixture built
into the appliance. Omit it when repository downloads are required; the
appliance seals its own outbound traffic after those downloads finish.
The image includes local pause and BusyBox fixtures used by `make e2e`.

Successful runs produce the OCI-derived `policy.rego`,
`policy-annotation.txt`, `workload-policy.yaml`, and `policy-oci-diff.json`.
The production appliance contains the standalone Rust OCI compiler and does
not contain or invoke the legacy GenPolicy executable.

## Balanced policy mode

The legacy-compatible policy remains the default. To generate the supported
balanced policy alongside it, set `GENPOLICY_BALANCED=1`:

```bash
docker run --rm --privileged --network=none \
  -e GENPOLICY_BALANCED=1 \
  --cgroupns=host \
  -v "$PWD/input:/input:ro" \
  -v "$PWD/output:/output" \
  genpolicy-appliance:k8s-1.33.13-containerd-1.7.29
```

The run additionally emits:

- `policy-balanced.rego`: pins service endpoints and the special
  termination-message path to the externally backed
  `/dev/termination-log` mount and clears inherited environment regexes.
  It emulates Kata's `nerdctl/network-namespace` injection from the sandbox OCI
  network namespace and generalizes the generated CNI path with a bounded
  regex. It also retains generated name/UID markers wherever those values
  occur, so this mode still has documented correlation risks;
- `policy-mode-report.json`: compares balanced behavior against the
  default legacy-compatible policy. The
  legacy-reference image also compares the original GenPolicy output with the
  OCI-derived legacy-compatible policy, including environment, mount, working
  directory, and exec-probe differences.

Balanced mode reduces regex authorization while preserving deployment-time
generated identities. It requires policy regeneration when an exact service
ClusterIP or port changes. The raw OCI specifications under `raw/` are the
reference for fields that cannot be made portable safely; the appliance does
not emit a knowingly undeployable exact policy.

The report also records unresolved enforcement needs: OCI capture does not yet
retain per-environment-variable provenance or required/duplicate-key
semantics, and a more portable external-endpoint mode needs structured
exclusion of UVM-local/control addresses rather than a generic IP regex.

Balanced generation rejects custom termination-message paths unless
they can be proven equivalent to the dedicated external kubelet bind mount.
This prevents a termination write from being redirected into image code or
other UVM-internal trusted state. The proof matches the kubelet path role and
suffix, not an appliance-specific host installation directory.

`make e2e` additionally builds a test-only `legacy-reference` image. That image
runs both compilers against the same capture so the standalone result can be
checked against legacy behavior without adding the legacy executable to the
production appliance.

## Inspect storage and device transformation

`tests/fixtures/storage-boundary-workload.yaml` contains `emptyDir`,
ConfigMap, host-directory, and host-character-device mounts. Run it with an
output directory preserved on the host:

```bash
cp tests/fixtures/storage-boundary-workload.yaml input/workload.yaml

docker run --rm --privileged --network=none \
  --cgroupns=host \
  -v "$PWD/input:/input:ro" \
  -v "$PWD/output:/output" \
  genpolicy-appliance:k8s-1.33.13-containerd-1.7.29
```

Kubelet and containerd materialize the YAML volumes as bind mounts in
`output/raw/*.config.json`. Policy generation then fails on the first
unsupported workload bind mount. This is intentional: the raw OCI demonstrates
the transformation, but the appliance does not authorize the source until it
can prove whether the resolved backing object is external to the UVM.
