use agent::types::{
    CreateContainerRequest, Device, ExecProcessRequest, FSGroup, SharedMount, Storage,
};
use oci_spec::runtime as oci;
use serde::{Deserialize, Serialize};
use std::path::Path;

mod runtime_support;
pub use runtime_support::{CaptureSandbox, DryRunHypervisor, RecordingAgent};

#[derive(Deserialize)]
struct DirectVolumeEntry {
    source: String,
    mount_info: kata_types::mount::DirectVolumeMountInfo,
}

pub fn stage_direct_volume_mounts(path: &Path) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(path)?;
    let entries: Vec<DirectVolumeEntry> = serde_json::from_str(&text)?;
    for entry in &entries {
        kata_types::mount::add_volume_mount_info(&entry.source, &entry.mount_info)?;
    }
    Ok(())
}

#[derive(Serialize)]
struct FsGroupDump {
    group_id: u32,
    group_change_policy: String,
}

impl From<&FSGroup> for FsGroupDump {
    fn from(group: &FSGroup) -> Self {
        Self {
            group_id: group.group_id,
            group_change_policy: format!("{:?}", group.group_change_policy),
        }
    }
}

#[derive(Serialize)]
struct StorageDump {
    driver: String,
    driver_options: Vec<String>,
    source: String,
    fs_type: String,
    fs_group: Option<FsGroupDump>,
    options: Vec<String>,
    mount_point: String,
    shared: bool,
}

impl From<&Storage> for StorageDump {
    fn from(storage: &Storage) -> Self {
        Self {
            driver: storage.driver.clone(),
            driver_options: storage.driver_options.clone(),
            source: storage.source.clone(),
            fs_type: storage.fs_type.clone(),
            fs_group: storage.fs_group.as_ref().map(FsGroupDump::from),
            options: storage.options.clone(),
            mount_point: storage.mount_point.clone(),
            shared: storage.shared,
        }
    }
}

#[derive(Serialize)]
struct DeviceDump {
    id: String,
    field_type: String,
    vm_path: String,
    container_path: String,
    options: Vec<String>,
}

impl From<&Device> for DeviceDump {
    fn from(device: &Device) -> Self {
        Self {
            id: device.id.clone(),
            field_type: device.field_type.clone(),
            vm_path: device.vm_path.clone(),
            container_path: device.container_path.clone(),
            options: device.options.clone(),
        }
    }
}

#[derive(Serialize)]
struct SharedMountDump {
    name: String,
    src_ctr: String,
    src_path: String,
    dst_ctr: String,
    dst_path: String,
}

impl From<&SharedMount> for SharedMountDump {
    fn from(mount: &SharedMount) -> Self {
        Self {
            name: mount.name.clone(),
            src_ctr: mount.src_ctr.clone(),
            src_path: mount.src_path.clone(),
            dst_ctr: mount.dst_ctr.clone(),
            dst_path: mount.dst_path.clone(),
        }
    }
}

#[derive(Serialize)]
struct CreateContainerRequestDump {
    container_id: String,
    exec_id: String,
    sandbox_pidns: bool,
    oci: Option<oci::Spec>,
    storages: Vec<StorageDump>,
    devices: Vec<DeviceDump>,
    shared_mounts: Vec<SharedMountDump>,
    stdin_port: Option<u32>,
    stdout_port: Option<u32>,
    stderr_port: Option<u32>,
}

#[derive(Serialize)]
struct ExecProcessRequestDump {
    container_id: String,
    exec_id: String,
    process: Option<oci::Process>,
    stdin_port: u32,
    stdout_port: u32,
    stderr_port: u32,
}

pub fn serialize_create_request(request: &CreateContainerRequest) -> serde_json::Result<String> {
    let dump = CreateContainerRequestDump {
        container_id: request.process_id.container_id.container_id.clone(),
        exec_id: request.process_id.exec_id.clone(),
        sandbox_pidns: request.sandbox_pidns,
        oci: request.oci.clone(),
        storages: request.storages.iter().map(StorageDump::from).collect(),
        devices: request.devices.iter().map(DeviceDump::from).collect(),
        shared_mounts: request
            .shared_mounts
            .iter()
            .map(SharedMountDump::from)
            .collect(),
        stdin_port: request.stdin_port,
        stdout_port: request.stdout_port,
        stderr_port: request.stderr_port,
    };
    serde_json::to_string_pretty(&dump)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_stream_ports_use_protobuf_defaults() {
        let serialized = serialize_exec_request(&ExecProcessRequest::default()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&serialized).unwrap();

        assert_eq!(value["stdin_port"], 0);
        assert_eq!(value["stdout_port"], 0);
        assert_eq!(value["stderr_port"], 0);
    }
}

pub fn serialize_exec_request(request: &ExecProcessRequest) -> serde_json::Result<String> {
    let dump = ExecProcessRequestDump {
        container_id: request.process_id.container_id.container_id.clone(),
        exec_id: request.process_id.exec_id.clone(),
        process: request.process.clone(),
        stdin_port: request.stdin_port.unwrap_or_default(),
        stdout_port: request.stdout_port.unwrap_or_default(),
        stderr_port: request.stderr_port.unwrap_or_default(),
    };
    serde_json::to_string_pretty(&dump)
}