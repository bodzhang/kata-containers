// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Type used to pass optional state between cooperating API calls.
pub type Options = HashMap<String, String>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server_address: String,
    pub bundle_dir: String,
    pub timeout_nano: i64,
    pub hybrid_vsock_port: u64,
    pub interactive: bool,
    pub hybrid_vsock: bool,
    pub ignore_errors: bool,
    pub no_auto_values: bool,
    pub hypervisor_name: String,
    pub shared_fs_host_path: String,
}

// CopyFile input struct
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CopyFileInput {
    pub src: String,
    pub dest: String,
}

// SetPolicy input request
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SetPolicyInput {
    pub policy_file: String,
}

// CreateContainer input
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CreateContainerInput {
    pub image: String,
    pub id: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CapturedFSGroup {
    pub group_id: u32,
    pub group_change_policy: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CapturedStorage {
    pub driver: String,
    pub driver_options: Vec<String>,
    pub source: String,
    pub fs_type: String,
    pub fs_group: Option<CapturedFSGroup>,
    pub options: Vec<String>,
    pub mount_point: String,
    pub shared: bool,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CapturedDevice {
    pub id: String,
    pub field_type: String,
    pub vm_path: String,
    pub container_path: String,
    pub options: Vec<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CapturedSharedMount {
    pub name: String,
    pub src_ctr: String,
    pub src_path: String,
    pub dst_ctr: String,
    pub dst_path: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CapturedCreateContainerRequest {
    pub container_id: String,
    pub exec_id: String,
    pub sandbox_pidns: bool,
    pub oci: Option<oci_spec::runtime::Spec>,
    pub storages: Vec<CapturedStorage>,
    pub devices: Vec<CapturedDevice>,
    pub shared_mounts: Vec<CapturedSharedMount>,
    pub stdin_port: Option<u32>,
    pub stdout_port: Option<u32>,
    pub stderr_port: Option<u32>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CapturedExecProcessRequest {
    pub container_id: String,
    pub exec_id: String,
    pub process: Option<oci_spec::runtime::Process>,
    pub stdin_port: Option<u32>,
    pub stdout_port: Option<u32>,
    pub stderr_port: Option<u32>,
}
