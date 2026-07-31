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
    assert!(drivers.contains(&"ephemeral".to_string()), "drivers={:?}", drivers);
    assert!(drivers.contains(&"local".to_string()), "drivers={:?}", drivers);

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
