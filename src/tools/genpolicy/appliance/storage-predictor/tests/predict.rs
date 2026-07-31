// Copyright (c) 2026 Kata Containers
//
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::process::Command;

// Drives the predictor binary end-to-end on an OCI config.json whose mounts are
// already Kata-typed, so the run is deterministic without live host tmpfs mounts.
#[test]
fn predicts_storage_classes_without_vm() {
    let base = std::env::temp_dir().join(format!("gp-p2-test-{}", std::process::id()));
    let ephemeral_src = base.join("ephemeral");
    let local_src = base.join("local");
    fs::create_dir_all(&ephemeral_src).unwrap();
    fs::create_dir_all(&local_src).unwrap();

    let config = base.join("config.json");
    let output = base.join("predicted.json");

    let spec = serde_json::json!({
        "ociVersion": "1.0.0",
        "mounts": [
            { "destination": "/dev/shm", "type": "bind", "source": "/dev/shm", "options": ["rbind"] },
            { "destination": "/local", "type": "local", "source": local_src.to_string_lossy(), "options": [] },
            { "destination": "/data", "type": "ephemeral", "source": ephemeral_src.to_string_lossy(), "options": [] }
        ]
    });
    fs::write(&config, serde_json::to_string(&spec).unwrap()).unwrap();

    let bin = env!("CARGO_BIN_EXE_storage-predictor");
    let status = Command::new(bin)
        .args([
            "--config",
            config.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--sid",
            "spike-sandbox",
            "--cid",
            "spike-container",
            "--emptydir-mode",
            "",
        ])
        .status()
        .unwrap();
    assert!(status.success(), "predictor exited with failure");

    let parsed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&output).unwrap()).unwrap();
    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(parsed["volumes"].as_array().unwrap().len(), 3);

    let drivers: Vec<String> = parsed["volumes"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|v| v["storages"].as_array().unwrap().iter())
        .map(|s| s["driver"].as_str().unwrap().to_string())
        .collect();
    // The ephemeral class is produced authoritatively with no VM. (Upstream
    // routes this `local` mount to a shared-fs mount without a `local` Storage,
    // unlike the older cc-branch handler, so only `ephemeral` is asserted here.)
    assert!(drivers.contains(&"ephemeral".to_string()), "drivers={:?}", drivers);

    let _ = fs::remove_dir_all(&base);
}

// A ConfigMap bind mount must be predicted as a watchable-bind storage, via the
// stub ShareFs reproducing the shim's share_volume output.
#[test]
fn predicts_configmap_watchable_bind_storage() {
    let base = std::env::temp_dir().join(format!("gp-p2-cm-{}", std::process::id()));
    let cm_src = base.join("kubernetes.io~configmap").join("my-cm");
    fs::create_dir_all(&cm_src).unwrap();
    fs::write(cm_src.join("key"), "value").unwrap();

    let config = base.join("config.json");
    let output = base.join("predicted.json");
    let spec = serde_json::json!({
        "ociVersion": "1.0.0",
        "mounts": [
            { "destination": "/etc/config", "type": "bind", "source": cm_src.to_string_lossy(), "options": ["ro"] }
        ]
    });
    fs::write(&config, serde_json::to_string(&spec).unwrap()).unwrap();

    let bin = env!("CARGO_BIN_EXE_storage-predictor");
    let status = Command::new(bin)
        .args([
            "--config",
            config.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--sid",
            "sb",
            "--cid",
            "ctr",
            "--emptydir-mode",
            "",
        ])
        .status()
        .unwrap();
    assert!(status.success(), "predictor exited with failure");

    let parsed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&output).unwrap()).unwrap();
    let storages: Vec<&serde_json::Value> = parsed["volumes"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|v| v["storages"].as_array().unwrap().iter())
        .collect();
    assert_eq!(storages.len(), 1, "parsed={parsed}");
    assert_eq!(storages[0]["driver"], "watchable-bind");
    assert_eq!(storages[0]["fs_type"], "bind");

    let _ = fs::remove_dir_all(&base);
}

// A snapshotter-captured multi-layer erofs rootfs_mounts artifact is transformed
// end-to-end by the binary into two block-backed rootfs storages, no VM.
#[test]
fn predicts_erofs_multi_layer_rootfs() {
    let base = std::env::temp_dir().join(format!("gp-p2-erofs-{}", std::process::id()));
    fs::create_dir_all(&base).unwrap();
    let erofs_src = base.join("layer.erofs");
    fs::write(&erofs_src, b"erofs-image-bytes").unwrap();

    let config = base.join("config.json");
    let output = base.join("predicted.json");
    let rootfs_mounts = base.join("rootfs-mounts.json");

    fs::write(
        &config,
        serde_json::to_string(&serde_json::json!({ "ociVersion": "1.0.0", "mounts": [] })).unwrap(),
    )
    .unwrap();

    let mounts = serde_json::json!([
        {
            "source": "/dev/loop0", "destination": "/", "fs_type": "ext4",
            "options": ["rw"], "device_id": null, "host_shared_fs_path": null, "read_only": false
        },
        {
            "source": erofs_src.to_string_lossy(), "destination": "/", "fs_type": "erofs",
            "options": ["ro"], "device_id": null, "host_shared_fs_path": null, "read_only": true
        },
        {
            "source": "overlay", "destination": "/", "fs_type": "overlay",
            "options": [], "device_id": null, "host_shared_fs_path": null, "read_only": false
        }
    ]);
    fs::write(&rootfs_mounts, serde_json::to_string(&mounts).unwrap()).unwrap();

    let bin = env!("CARGO_BIN_EXE_storage-predictor");
    let status = Command::new(bin)
        .args([
            "--config",
            config.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--sid",
            "erofs-sb",
            "--cid",
            "erofs-ctr",
            "--emptydir-mode",
            "",
            "--block-driver",
            "virtio-blk-mmio",
            "--rootfs-mounts",
            rootfs_mounts.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "predictor exited with failure");

    let parsed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&output).unwrap()).unwrap();
    let storages = parsed["rootfs"]["storages"].as_array().unwrap();
    assert_eq!(storages.len(), 2, "parsed={parsed}");
    assert_eq!(storages[0]["fs_type"], "ext4");
    assert_eq!(storages[0]["source"], "/dev/vda");
    assert_eq!(storages[1]["fs_type"], "erofs");
    assert_eq!(storages[1]["source"], "/dev/vdb");

    let _ = fs::remove_dir_all(&base);
}

