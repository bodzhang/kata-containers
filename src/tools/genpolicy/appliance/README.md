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

Additional workload images must be supplied as archives in `input/images`.
The image includes local pause and BusyBox fixtures used by `make e2e`.

Successful runs produce the OCI-derived `policy.rego`,
`policy-annotation.txt`, `workload-policy.yaml`, and `policy-oci-diff.json`.
The production appliance contains the standalone Rust OCI compiler and does
not contain or invoke the legacy GenPolicy executable.

`make e2e` additionally builds a test-only `legacy-reference` image. That image
runs both compilers against the same capture so the standalone result can be
checked against legacy behavior without adding the legacy executable to the
production appliance.
