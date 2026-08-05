#!/usr/bin/env python3
#
# Copyright (c) 2026 Kata Containers
#
# SPDX-License-Identifier: Apache-2.0
#
# In-appliance generation of the two rootfs integrity pins that policy
# generation consumes, derived from the digest-pinned images in the captured
# OCI specs using a REAL containerd erofs snapshotter (authoritative hashes):
#
#   1. EROFS dm-verity root hashes  -> per-image mount-handler mounts written to
#      the GENPOLICY_ROOTFS_MOUNTS_DIR (<digest-slug>.json), which
#      capture_rootfs_mounts.py converts into raw/<name>.rootfs-mounts.json and
#      createreq-capture surfaces as X-kata.dmverity.roothash storage options.
#      Emitted only in erofs (block dm-verity) mode.
#
#   2. Guest-pull manifest/index digest -> manifest-digests.json (image ref ->
#      digest). This is the guest-pull ANALOG of the dm-verity root hash: when a
#      deployment uses guest-pull instead of a block dm-verity rootfs, the guest
#      (image-rs / CDH) pulls and verifies the image against this digest. Recorded
#      in BOTH modes.
#
# The two rootfs modes are mutually exclusive per deployment. Guest-pull is
# selected by runtime-rs only when share_fs is none AND the rootfs is a Kata
# virtual volume AND no block mounts are present, so rootfs-mounts are emitted
# ONLY in erofs mode (--mode erofs-dmverity); emitting them in guest-pull mode
# would replace the guest-pull VirtualVolume with block storage.
#
# Authoritative layer discovery WITHOUT a shim or boltdb parsing: each image is
# pulled into a FRESH containerd root (isolation removes shared-base dedup), so
# every committed snapshot belongs to that image and the numeric
# snapshots/<N>/ directory order equals containerd's base->top unpack order.
# That order is cross-checked against the authoritative parent chain from
# `ctr snapshot ls` (walking PARENT links); a mismatch fails loud.
#
# Requires (opt-in, documented in README Prerequisites): containerd >= 2.2 with
# the erofs snapshotter+differ, erofs-utils >= 1.8.2, the erofs kernel module,
# dm-verity target, and loop devices.

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Reuse the image-reference/digest extraction the converter already unit-tests.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from capture_rootfs_mounts import image_reference, image_digest, CONFIG_SUFFIX  # noqa: E402

EROFS_SNAPSHOTTER = "erofs"
# Marker file the erofs snapshotter writes alongside each committed erofs layer.
LAYER_BLOB = "layer.erofs"
LAYER_DMVERITY = "layer.erofs.dmverity"


def _run(cmd, **kwargs):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kwargs)


def discover_images(raw_dir: Path) -> list:
    """Unique digest-pinned image references across the captured OCI specs.

    Order is deterministic (sorted) so repeated runs are reproducible.
    """
    refs = {}
    for config in sorted(raw_dir.glob(f"*{CONFIG_SUFFIX}")):
        spec = json.loads(config.read_text(encoding="utf-8"))
        ref = image_reference(spec)
        digest = image_digest(ref)
        if ref and digest:
            refs.setdefault(ref, digest)
    return [(ref, refs[ref]) for ref in sorted(refs)]


def _write_containerd_config(root: Path, sock: Path, default_size: str) -> Path:
    """Minimal version-3 containerd config for authoritative erofs dm-verity.

    fsverity is intentionally disabled: it is orthogonal to dm-verity (the
    block-level hash we capture) and unavailable on many prep filesystems (tmpfs
    lacks it), where enabling it fails snapshotter init. Disabling it does not
    change the dm-verity root hashes.
    """
    config = f"""version = 3
root = "{root / 'root'}"
state = "{root / 'state'}"

[grpc]
  address = "{sock}"

[debug]
  level = "warn"

[plugins.'io.containerd.snapshotter.v1.erofs']
  default_size = '{default_size}'
  max_unmerged_layers = 0
  enable_fsverity = false
  set_immutable = false
  dmverity_mode = 'on'

[plugins.'io.containerd.differ.v1.erofs']
  mkfs_options = ['-T0', '--mkfs-time', '--sort=none']
  enable_tar_index = false
  enable_dmverity = true

[plugins.'io.containerd.service.v1.diff-service']
  default = ['erofs', 'walking']
"""
    config_path = root / "config.toml"
    config_path.write_text(config, encoding="utf-8")
    return config_path


class Containerd:
    """A disposable, per-image containerd instance with a fresh data root."""

    def __init__(self, containerd_bin: str, ctr_bin: str, base_dir: Path,
                 namespace: str, default_size: str):
        self.containerd_bin = containerd_bin
        self.ctr_bin = ctr_bin
        self.namespace = namespace
        self.default_size = default_size
        self.root = Path(tempfile.mkdtemp(prefix="erofs-prep-", dir=str(base_dir)))
        self.sock = self.root / "containerd.sock"
        self.proc = None

    def __enter__(self):
        config = _write_containerd_config(self.root, self.sock, self.default_size)
        log = open(self.root / "containerd.log", "w", encoding="utf-8")
        # /usr/local/bin holds erofs-utils >= 1.8.2 (the differ execs mkfs.erofs).
        env = dict(os.environ, PATH="/usr/local/bin:" + os.environ.get("PATH", ""))
        self.proc = subprocess.Popen(
            [self.containerd_bin, "-c", str(config)],
            stdout=log, stderr=subprocess.STDOUT, env=env,
        )
        self._wait_ready()
        return self

    def __exit__(self, *exc):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        shutil.rmtree(self.root, ignore_errors=True)

    def _wait_ready(self, timeout: float = 30.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.sock.exists():
                try:
                    self.ctr("version")
                    return
                except subprocess.CalledProcessError:
                    pass
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"containerd exited early; see {self.root / 'containerd.log'}"
                )
            time.sleep(0.3)
        raise RuntimeError(f"containerd not ready within {timeout}s")

    def ctr(self, *args, namespaced: bool = False):
        cmd = [self.ctr_bin, "-a", str(self.sock)]
        if namespaced:
            cmd += ["-n", self.namespace]
        cmd += list(args)
        return _run(cmd)

    def snapshotter_root(self) -> Path:
        return self.root / "root" / f"io.containerd.snapshotter.v1.{EROFS_SNAPSHOTTER}"


def pull(cd: Containerd, ref: str) -> str:
    """Pull `ref` with the erofs snapshotter; return the resolved image digest."""
    cd.ctr("images", "pull", "--snapshotter", EROFS_SNAPSHOTTER, ref, namespaced=True)
    listing = cd.ctr("images", "ls", namespaced=True).stdout
    for line in listing.splitlines():
        fields = line.split()
        if fields and fields[0] == ref and len(fields) >= 3:
            return fields[2]
    raise RuntimeError(f"no digest found for {ref} in `ctr images ls`\n{listing}")


def _snapshot_chain(cd: Containerd) -> list:
    """Authoritative ordered chainIDs (base->top) from the committed snapshots.

    Isolation invariant: a fresh root holds exactly one image, so there is a
    single committed leaf; walking PARENT links yields the whole chain.
    """
    listing = cd.ctr("snapshot", "--snapshotter", EROFS_SNAPSHOTTER, "ls",
                     namespaced=True).stdout
    parent_of = {}
    keys = []
    for line in listing.splitlines()[1:]:  # skip header
        fields = line.split()
        # Committed rows are `KEY PARENT Committed` or, for the base layer whose
        # PARENT column is empty, `KEY Committed`.
        if len(fields) < 2 or fields[-1] != "Committed":
            continue
        key = fields[0]
        parent = fields[1] if len(fields) >= 3 else ""
        keys.append(key)
        parent_of[key] = parent
    if not keys:
        return []
    parents = {p for p in parent_of.values() if p}
    leaves = [k for k in keys if k not in parents]
    if len(leaves) != 1:
        raise RuntimeError(
            f"expected exactly one snapshot leaf in isolated root, found {leaves}"
        )
    chain = []
    node = leaves[0]
    seen = set()
    while node and node in parent_of and node not in seen:
        seen.add(node)
        chain.append(node)
        node = parent_of[node]
    chain.reverse()  # base -> top
    if len(chain) != len(keys):
        raise RuntimeError(
            f"snapshot chain length {len(chain)} != committed snapshot count "
            f"{len(keys)} (stray snapshots in isolated root)"
        )
    return chain


def _erofs_layers(cd: Containerd) -> list:
    """On-disk erofs layer blobs in base->top order (numeric snapshot dir order)."""
    snap_dir = cd.snapshotter_root() / "snapshots"
    layers = []
    for entry in sorted(snap_dir.iterdir(), key=lambda p: int(p.name)):
        blob = entry / LAYER_BLOB
        dmverity = entry / LAYER_DMVERITY
        if blob.is_file():
            layers.append((blob.resolve(), dmverity.resolve() if dmverity.is_file() else None))
    return layers


def resolve_layers(cd: Containerd) -> list:
    """Ordered erofs layers, cross-checked against the authoritative chain."""
    chain = _snapshot_chain(cd)
    layers = _erofs_layers(cd)
    # Every erofs blob corresponds to a chain link; empty (whiteout-only) layers
    # produce a chain link but no blob, so blobs <= chain links. More blobs than
    # links is impossible and signals a discovery error.
    if len(layers) > len(chain):
        raise RuntimeError(
            f"discovered {len(layers)} erofs layer blobs but chain has only "
            f"{len(chain)} links; layer discovery is inconsistent"
        )
    if not layers:
        raise RuntimeError("no erofs layer blobs found for image")
    return layers


def persist_layers(layers: list, dest: Path) -> list:
    """Copy erofs blobs + dm-verity metadata to a stable dir, returning new paths.

    The blobs must outlive the disposable per-image containerd root because
    createreq-capture / ErofsMultiLayerRootfs reads them to build the GPT/VMDK.
    """
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    persisted = []
    for idx, (blob, dmverity) in enumerate(layers):
        new_blob = dest / f"{idx:03d}-{LAYER_BLOB}"
        shutil.copyfile(blob, new_blob)
        new_dmverity = None
        if dmverity:
            new_dmverity = dest / f"{idx:03d}-{LAYER_DMVERITY}"
            shutil.copyfile(dmverity, new_dmverity)
        persisted.append((new_blob.resolve(), new_dmverity.resolve() if new_dmverity else None))
    return persisted


def assemble_mounts(layers: list) -> list:
    """Containerd mount dicts matching what the erofs mount-handler hands the shim.

    Single layer -> one erofs+loop block mount (is_block_rootfs / BlockRootfs).
    Multiple layers -> N erofs mounts (GPT mode, one dm-verity root hash each)
    plus an overlay mount (ErofsMultiLayerRootfs).
    """
    def dmverity_opt(dmverity):
        return [f"X-containerd.dmverity={dmverity}"] if dmverity else []

    if len(layers) == 1:
        blob, dmverity = layers[0]
        return [{
            "type": "erofs",
            "source": str(blob),
            "target": "/",
            "options": ["loop", "ro", *dmverity_opt(dmverity)],
        }]

    mounts = []
    for blob, dmverity in layers:
        mounts.append({
            "type": "erofs",
            "source": str(blob),
            "target": "",
            "options": ["ro", *dmverity_opt(dmverity)],
        })
    lowerdirs = ":".join(str(blob) for blob, _ in reversed(layers))
    mounts.append({
        "type": "overlay",
        "source": "overlay",
        "target": "/",
        "options": [f"lowerdir={lowerdirs}"],
    })
    return mounts


def prepare(args) -> dict:
    raw_dir = Path(args.raw_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    base_dir = Path(args.work_root)
    base_dir.mkdir(parents=True, exist_ok=True)

    emit_mounts = args.mode == "erofs-dmverity"
    images = discover_images(raw_dir)
    results = []
    manifest_digests = {}

    for ref, annotated_digest in images:
        status = {"image": ref, "annotated_digest": annotated_digest}
        try:
            with Containerd(args.containerd, args.ctr, base_dir,
                            args.namespace, args.default_size) as cd:
                resolved = pull(cd, ref)
                status["manifest_digest"] = resolved
                manifest_digests[ref] = resolved
                if resolved != annotated_digest:
                    status["digest_mismatch"] = True

                if emit_mounts:
                    slug = annotated_digest.replace(":", "_")
                    layers = resolve_layers(cd)
                    layers = persist_layers(layers, out_dir / "blobs" / slug)
                    mounts = assemble_mounts(layers)
                    artifact = out_dir / f"{slug}.json"
                    artifact.write_text(json.dumps(mounts, indent=2) + "\n",
                                        encoding="utf-8")
                    status["rootfs_mounts"] = artifact.name
                    status["layers"] = len(layers)
        except (subprocess.CalledProcessError, RuntimeError, OSError) as exc:
            detail = exc.stderr if isinstance(exc, subprocess.CalledProcessError) else ""
            status["error"] = (detail or str(exc)).strip()
        results.append(status)

    Path(args.manifest_digests).write_text(
        json.dumps(manifest_digests, indent=2) + "\n", encoding="utf-8")
    return {"schema_version": 1, "mode": args.mode, "captures": results}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", required=True,
                        help="directory of captured OCI specs (raw/<name>.config.json)")
    parser.add_argument("--out-dir", required=True,
                        help="GENPOLICY_ROOTFS_MOUNTS_DIR: per-image <slug>.json output")
    parser.add_argument("--manifest-digests", required=True,
                        help="output JSON mapping image ref -> resolved manifest digest")
    parser.add_argument("--mode", choices=["erofs-dmverity", "guest-pull"],
                        default="erofs-dmverity",
                        help="erofs-dmverity emits rootfs-mounts + records digests; "
                             "guest-pull records digests only")
    parser.add_argument("--containerd", default="containerd",
                        help="path to a containerd >= 2.2 binary with erofs support")
    parser.add_argument("--ctr", default="ctr", help="path to the matching ctr binary")
    parser.add_argument("--namespace", default="genpolicy-erofs-prep")
    parser.add_argument("--default-size", default="10G",
                        help="erofs snapshotter default_size for the writable upper")
    parser.add_argument("--work-root", default="/var/lib/genpolicy-erofs-prep",
                        help="scratch base for per-image containerd data roots")
    parser.add_argument("--report", help="optional path to write the JSON run report")
    args = parser.parse_args()

    report = prepare(args)
    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
