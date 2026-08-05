# GenPolicy OCI conversion appliance

This directory implements the versioned clean-room pipeline described in
[`DESIGN.md`](DESIGN.md).

## Prerequisites

### Host

- Linux host with a container engine (`docker` or `podman`; `CONTAINER_ENGINE`
  selects it for `make image`).
- The appliance is a **container**. It runs `--privileged`, boots a throwaway
  Kubernetes control plane, and seals its own outbound network. It's
  recommended to run it inside a **disposable VM** instead of a bare-metal
  host. The VM (or host, if you skip the VM) must expose a unified cgroup v2
  hierarchy (`stat -fc %T /sys/fs/cgroup` reports `cgroup2fs`) for
  `--cgroupns=host`.
- The base pipeline boots a throwaway Kubernetes control plane and runs each
  workload under **runc/overlayfs** (no guest VM is booted), so it needs no
  special kernel features or hardware virtualization beyond the above.

### EROFS dm-verity rootfs capture (experimental, opt-in)

Set `GENPOLICY_BUILD_EROFS_DMVERITY=1` to have the appliance **generate** the
erofs / dm-verity rootfs storages in-place from the digest-pinned images in the
workload YAML. A bundled containerd (≥ 2.2) erofs snapshotter+differ pulls each
image and produces the real dm-verity root hashes, which feed `--rootfs-mounts`
to the storage predictor and `createreq-capture` (surfaced as
`X-kata.dmverity.roothash`). The guest-pull manifest digest is recorded in
`manifest-digests.json` in both modes (it is the guest-pull analog of the
dm-verity root hash). The userspace tooling (containerd ≥ 2.2, `mkfs.erofs`
≥ 1.8.2, `cryptsetup`) is **bundled in the image**; only the **kernel features**
below must be provided by the host whose kernel the disposable VM shares:

The policy compiler requires one captured `CreateContainerRequest` for every
container. Its final shim-derived OCI, storages, devices, rewritten mounts, and
rootfs integrity pins are authoritative; there is no OCI-config or storage-
predictor fallback. This path currently targets the Kata-CC `shared_fs="none"`
profile; virtio-fs prediction remains diagnostic only.

| Component | Requirement | Verify |
|-----------|-------------|--------|
| Linux kernel | `erofs` filesystem (`CONFIG_EROFS_FS`, ≥ 5.4) | `modprobe erofs && grep -w erofs /proc/filesystems` |
| Device mapper | `dm-verity` target (`CONFIG_DM_VERITY`) | `modprobe dm-verity && dmsetup targets \| grep verity` |
| Loop devices | `losetup` + free `/dev/loopN` | `losetup -f` |

The bundled userspace tooling (for reference; no host install needed):

| Component | Bundled version | Purpose |
|-----------|-----------------|---------|
| erofs-utils | ≥ 1.8.2 (`mkfs.erofs`) | the differ needs the fsmerge `mkfs_options` |
| containerd | ≥ 2.2 (erofs snapshotter + differ) | authoritative dm-verity root-hash generation |
| cryptsetup | `veritysetup` | dm-verity tooling |

Verified working on kernel `6.18` (WSL2): `erofs` present in
`/proc/filesystems` and the `dm-verity` device-mapper target reports `v1.13.0`.
If the kernel lacks `erofs` or `dm-verity`, this capture stage cannot run; the
rest of the pipeline (guest-pull rootfs, ConfigMap/Secret, block volumes) is
unaffected. `GENPOLICY_BUILD_EROFS_DMVERITY` is mutually exclusive with a
guest-pull deployment (`GENPOLICY_GUEST_PULL=1`), which records the manifest
digest only.

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
  -e GENPOLICY_KATA_CONFIG=/input/configuration.toml \
  -v "$PWD/input:/input:ro" \
  -v "$PWD/output:/output" \
  genpolicy-appliance:k8s-1.33.13-containerd-1.7.29-erofs-containerd-2.3.3
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

Successful runs produce the request-derived `policy.rego`,
`policy-annotation.txt`, `workload-policy.yaml`, and `policy-oci-diff.json`.
The production appliance contains the standalone Rust policy compiler and does
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
  genpolicy-appliance:k8s-1.33.13-containerd-1.7.29-erofs-containerd-2.3.3
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
  request-derived legacy-compatible policy, including environment, mount, working
  directory, and exec-probe differences.

Balanced mode reduces regex authorization while preserving deployment-time
generated identities. It requires policy regeneration when an exact service
ClusterIP or port changes. Raw requests under `createcontainer-requests/` are
the reference for fields that cannot be made portable safely; the appliance
does not emit a knowingly undeployable exact policy.

The report also records unresolved enforcement needs: request capture does not yet
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

## Volume handling

The appliance requires a captured `CreateContainerRequest` as the authority for
every container. Missing or incomplete request capture fails generation. The
storage predictor remains an audit artifact and workload YAML supplies only
policy data for operations absent from container creation, such as exec probes.

| Volume form | Legacy GenPolicy | Appliance handling | Policy result |
|---|---|---|---|
| ConfigMap/Secret with `shared_fs = "none"` | Predicts a settings-based `$(sfprefix)` bind mount and, by default, no Agent `Storage`; it does not execute the shim's `CopyFile` path. | Runs the real runtime-rs copy-to-guest path. The recording Agent accepts `CopyFile` calls, and the captured final request contains no `Storage` but has a rewritten bind source matching `<cpath>/<cid>-<16 hex>-<destination basename>`. | Supported. Pins the rewritten mount shape and confines `CopyFile` paths and file types; it does not attest the host-supplied file contents. |
| Raw-block PVC through `volumeDevices` | Emits an `agent::Device` and OCI Linux device from the declared `devicePath`; pins only the container path. | Uses the final captured request devices. | Supported. Bounds the device path, not the device identity, integrity, confidentiality, or mutable contents. |
| Filesystem PVC through shared fs | Emits a generic shared bind mount and no block `Storage`. | The clean-room cluster has no CSI driver, so it cannot materialize an ordinary PVC from YAML. | Fail-closed unless a separately supported authoritative fixture can reproduce the final shim request. |
| Plain block-backed `emptyDir` | Emits the configured plain block-storage template. | Runs the real runtime-rs block-`emptyDir` handler with the dry-run device manager and captures its final `blk`, `scsi`, or platform-equivalent storage and rewritten mount. | Supported. Pins filesystem, options, `fsGroup`, sharing, and the mount-point/device-ID relationship. |
| CDH-managed encrypted block `emptyDir` | Emits the configured encrypted block-storage template. | Runs the real runtime-rs `block-encrypted` handler and captures the final request containing `encryption_key=ephemeral`, `create_filesystem`, the block storage, and rewritten mount. The recording Agent stops at the request boundary; it does not run CDH or create a LUKS mapping. | High-fidelity request capture. Policy pins the CDH trigger and the complete storage/mount relationship. Production CDH/LUKS execution is covered by Kata's confidential Kubernetes integration test, not by this no-VM appliance. |
| CSI direct filesystem-mounted block volume | Has no direct-volume or `mountInfo.json` model; the extra runtime storage and rewritten mount are denied. | `GENPOLICY_DIRECT_VOLUME_MOUNTS` replays operator-supplied `mountInfo.json` data so `createreq-capture` records the real shim storage and mount. The compiler does not yet admit this storage class. | Captured but fail-closed. A dedicated direct-volume path template and Rego clause are required. |
| CDH/KBS-backed persistent encrypted volume | Not represented for persistent PVCs. | Raw CSI direct volumes do not add a CDH key identity or encryption operation to the Agent request. | Unsupported in the production runtime/Agent contract; adding real CSI components to the appliance would not close this gap. |

### Encrypted `emptyDir` fidelity boundary

For `emptydir_mode = "block-encrypted"`, the appliance has high fidelity at the
policy-relevant shim/Agent boundary. `createreq-capture` runs the production
runtime-rs block-`emptyDir` handler, including sparse backing-file creation,
block-device synthesis, storage construction, mount rewriting, and propagation
of `fsGroup`. The captured `CreateContainerRequest` therefore contains the same
`encryption_key=ephemeral` and `create_filesystem` driver options that make the
production Agent call CDH `secure_mount`.

The appliance deliberately does not claim execution fidelity beyond that
boundary. Its recording Agent serializes the request instead of booting a guest,
calling CDH, creating a LUKS2/dm-crypt mapping, formatting ext4, and mounting the
result. That production path is exercised by
`tests/integration/kubernetes/k8s-trusted-ephemeral-data-storage.bats`, which
checks the active dm-crypt cipher and integrity mode and verifies filesystem I/O.
The appliance tests instead verify that the captured CDH trigger and correlated
storage, device, mount, ownership, and sharing fields are admitted exactly and
that altered requests are denied.

### Configure encrypted `emptyDir` capture

Encrypted `emptyDir` capture is selected by the deployment Kata
`configuration.toml`, not by the workload YAML. Mount the configuration into the
appliance and set `GENPOLICY_KATA_CONFIG` to its in-container path. The appliance
loads the file without validating deployment-only hypervisor binary paths, then
uses its active hypervisor, block driver, shared-filesystem mode, and
`emptydir_mode` for both prediction and authoritative request capture.

Use the production node's Kata configuration when generating deployable policy.
For an isolated appliance test, this minimal profile selects the relevant path:

```toml title="input/configuration.toml"
[hypervisor.qemu]
shared_fs = "none"
block_device_driver = "virtio-blk-pci"

[runtime]
hypervisor_name = "qemu"
emptydir_mode = "block-encrypted"
```

The workload must contain a disk-backed `emptyDir` (an omitted or empty
`medium`, not `medium: Memory`) and mount it into a container. Run the appliance
with the configuration already under the read-only `/input` mount:

```bash
docker run --rm --privileged --network=none \
  --cgroupns=host \
  -e GENPOLICY_KATA_CONFIG=/input/configuration.toml \
  -v "$PWD/input:/input:ro" \
  -v "$PWD/output:/output" \
  genpolicy-appliance:k8s-1.33.13-containerd-1.7.29-erofs-containerd-2.3.3
```

The file is required for every policy generation run because request capture
cannot reproduce the deployment shim without it. Its `emptydir_mode`, block
driver, and shared-filesystem mode are authoritative. The corresponding
environment variables affect the audit-only predictor and are not compiler
fallbacks.

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
  genpolicy-appliance:k8s-1.33.13-containerd-1.7.29-erofs-containerd-2.3.3
```

Kubelet and containerd materialize the YAML volumes as bind mounts in
`output/raw/*.config.json`. Policy generation then fails on the first
unsupported workload bind mount. This is intentional: the raw OCI demonstrates
the transformation, but the appliance does not authorize the source until it
can prove whether the resolved backing object is external to the UVM.
