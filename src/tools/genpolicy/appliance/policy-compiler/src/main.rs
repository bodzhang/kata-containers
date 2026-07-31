use anyhow::{anyhow, bail, Context, Result};
use genpolicy::policy::{
    self, KataLinux, KataLinuxCapabilities, KataMount, KataProcess, KataRoot, KataSpec, KataUser,
};
use genpolicy::settings::Settings;
use protocols::agent;
use regex::escape;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const DYNAMIC_PREFIX: &str = "{{GENPOLICY_DYNAMIC:";
const POD_NAME_MARKER: &str = "{{GENPOLICY_DYNAMIC:pod.name}}";
const POD_UID_MARKER: &str = "{{GENPOLICY_DYNAMIC:pod.uid}}";

#[derive(Debug)]
struct Args {
    raw_dir: PathBuf,
    tagged_dir: PathBuf,
    tag_manifest: PathBuf,
    rules: PathBuf,
    settings: PathBuf,
    workload: PathBuf,
    output: PathBuf,
    diff_output: PathBuf,
    annotation_output: PathBuf,
    annotated_yaml_output: PathBuf,
    regex_policy_mode: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
struct CapturedSpec {
    version: String,
    process: CapturedProcess,
    root: CapturedRoot,
    mounts: Vec<CapturedMount>,
    annotations: BTreeMap<String, String>,
    linux: CapturedLinux,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default, rename_all = "camelCase")]
struct CapturedProcess {
    terminal: bool,
    user: CapturedUser,
    args: Vec<String>,
    env: Vec<String>,
    cwd: String,
    capabilities: CapturedCapabilities,
    no_new_privileges: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default, rename_all = "camelCase")]
struct CapturedUser {
    uid: u32,
    gid: u32,
    additional_gids: BTreeSet<u32>,
    username: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
struct CapturedCapabilities {
    ambient: Vec<String>,
    bounding: Vec<String>,
    effective: Vec<String>,
    inheritable: Vec<String>,
    permitted: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
struct CapturedRoot {
    path: String,
    readonly: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
struct CapturedMount {
    destination: String,
    source: String,
    #[serde(rename = "type")]
    type_: String,
    options: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default, rename_all = "camelCase")]
struct CapturedLinux {
    masked_paths: Vec<String>,
    readonly_paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TagManifest {
    tags: Vec<TagDefinition>,
}

#[derive(Debug, Deserialize)]
struct TagDefinition {
    marker: String,
    suggested_regex: String,
}

#[derive(Debug, Serialize)]
#[allow(non_snake_case)]
struct PolicyData {
    containers: Vec<ContainerPolicy>,
    common: policy::CommonData,
    sandbox: policy::SandboxData,
    request_defaults: Value,
    devices: policy::Devices,
    cluster_config: policy::ClusterConfig,
}

#[derive(Debug, Serialize)]
#[allow(non_snake_case)]
struct ContainerPolicy {
    OCI: KataSpec,
    storages: Vec<agent::Storage>,
    devices: Vec<agent::Device>,
    sandbox_pidns: bool,
    exec_commands: Vec<Vec<String>>,
    runtime_anno_patterns: BTreeMap<String, String>,
}

type Identity = (String, String);

#[derive(Clone, Debug, PartialEq)]
struct WorkloadContainerPolicy {
    exec_commands: Vec<Vec<String>>,
    sandbox_name_pattern: Option<String>,
}

#[derive(Debug, Default)]
struct WorkloadPolicy {
    containers: BTreeMap<String, WorkloadContainerPolicy>,
    sandbox_name_patterns: BTreeSet<String>,
}

fn parse_args() -> Result<Args> {
    let mut values = BTreeMap::new();
    let mut iter = env::args().skip(1);
    while let Some(flag) = iter.next() {
        let value = iter
            .next()
            .ok_or_else(|| anyhow!("missing value for {flag}"))?;
        values.insert(flag, PathBuf::from(value));
    }
    let required = |name: &str| {
        values
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow!("{name} is required"))
    };
    Ok(Args {
        raw_dir: required("--raw-dir")?,
        tagged_dir: required("--tagged-dir")?,
        tag_manifest: required("--tag-manifest")?,
        rules: required("--rules")?,
        settings: required("--settings")?,
        workload: required("--workload")?,
        output: required("--output")?,
        diff_output: required("--diff-output")?,
        annotation_output: required("--annotation-output")?,
        annotated_yaml_output: required("--annotated-yaml-output")?,
        regex_policy_mode: values
            .get("--regex-policy-mode")
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_else(|| "legacy".to_string()),
    })
}

fn identity(spec: &CapturedSpec) -> Result<Identity> {
    let container_type = spec
        .annotations
        .get("io.kubernetes.cri.container-type")
        .cloned()
        .ok_or_else(|| anyhow!("capture has no CRI container type"))?;
    let name = spec
        .annotations
        .get("io.kubernetes.cri.container-name")
        .cloned()
        .unwrap_or_default();
    Ok((container_type, name))
}

fn load_captures(
    directory: &Path,
    suffix: &str,
) -> Result<BTreeMap<Identity, (String, CapturedSpec)>> {
    let mut paths: Vec<_> = fs::read_dir(directory)
        .with_context(|| format!("read {}", directory.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with(suffix))
        })
        .collect();
    paths.sort();

    let mut captures = BTreeMap::new();
    let mut canonical = BTreeMap::new();
    for path in paths {
        let mut spec: CapturedSpec = serde_json::from_slice(&fs::read(&path)?)?;
        let key = identity(&spec)?;
        spec.process.env.sort();
        if let Some(previous) = canonical.get(&key) {
            if previous != &spec {
                bail!("inconsistent duplicate OCI captures for {key:?}");
            }
        }
        canonical.insert(key.clone(), spec.clone());
        captures.insert(
            key,
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                spec,
            ),
        );
    }
    if captures.is_empty() {
        bail!("no tagged OCI captures found");
    }
    Ok(captures)
}

fn expand_env_regex(pattern: &str, common: &policy::CommonData) -> String {
    pattern
        .replace("$(ipv4_a)", &common.ipv4_a)
        .replace("$(ip_p)", &common.ip_p)
        .replace(
            "$(svc_name_downward_env)",
            &common.svc_name_downward_env,
        )
        .replace("$(dns_label)", &common.dns_label)
}

fn validate_legacy_service_env_coverage(
    tagged: &CapturedSpec,
    raw: &CapturedSpec,
    request_defaults: &Value,
    common: &policy::CommonData,
) -> Result<usize> {
    let patterns = request_defaults
        .get("CreateContainerRequest")
        .and_then(|value| value.get("allow_env_regex"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            anyhow!("settings have no CreateContainerRequest.allow_env_regex")
        })?;
    let regexes = patterns
        .iter()
        .map(|value| {
            let pattern = value
                .as_str()
                .ok_or_else(|| anyhow!("allow_env_regex entry is not a string"))?;
            regex::Regex::new(&expand_env_regex(pattern, common))
                .with_context(|| format!("compile allow_env_regex {pattern}"))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut checked = 0;
    for tagged_env in &tagged.process.env {
        if !tagged_env.contains("{{GENPOLICY_DYNAMIC:service-env.") {
            continue;
        }
        let (name, _) = tagged_env
            .split_once('=')
            .ok_or_else(|| anyhow!("tagged service environment has no name"))?;
        let prefix = format!("{name}=");
        let actual: Vec<_> = raw
            .process
            .env
            .iter()
            .filter(|value| value.starts_with(&prefix))
            .collect();
        if actual.len() != 1 {
            bail!(
                "container environment has {} values for service variable {name}",
                actual.len()
            );
        }
        if !regexes.iter().any(|regex| regex.is_match(actual[0])) {
            bail!(
                "legacy environment regexes do not cover captured variable {name}"
            );
        }
        checked += 1;
    }
    Ok(checked)
}

fn collect_workload_policy(
    document: &serde_yaml::Value,
    policy: &mut WorkloadPolicy,
) -> Result<()> {
    let kind = document
        .get("kind")
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or_default();
    if kind == "List" {
        let items = document
            .get("items")
            .and_then(serde_yaml::Value::as_sequence)
            .ok_or_else(|| anyhow!("List has no items"))?;
        for item in items {
            collect_workload_policy(item, policy)?;
        }
        return Ok(());
    }

    if !matches!(
        kind,
        "Pod"
            | "Deployment"
            | "DaemonSet"
            | "ReplicaSet"
            | "StatefulSet"
            | "Job"
            | "ReplicationController"
            | "CronJob"
    ) {
        return Ok(());
    }
    let yaml = serde_yaml::to_string(document)?;
    let (resource, _) = genpolicy::yaml::new_k8s_resource(&yaml, true)
        .with_context(|| format!("parse {kind} workload"))?;
    let sandbox_name_pattern = resource.get_sandbox_name();
    if let Some(pattern) = &sandbox_name_pattern {
        policy.sandbox_name_patterns.insert(pattern.clone());
    }
    for container in resource.get_containers() {
        let container_policy = WorkloadContainerPolicy {
            exec_commands: container.get_exec_commands(),
            sandbox_name_pattern: sandbox_name_pattern.clone(),
        };
        if let Some(previous) = policy.containers.get(&container.name) {
            if previous != &container_policy {
                bail!(
                    "conflicting workload policy for container {}",
                    container.name
                );
            }
        } else {
            policy
                .containers
                .insert(container.name.clone(), container_policy);
        }
    }
    Ok(())
}

fn load_workload_policy(path: &Path) -> Result<WorkloadPolicy> {
    let contents = fs::read_to_string(path)?;
    let mut policy = WorkloadPolicy::default();
    for document in serde_yaml::Deserializer::from_str(&contents) {
        let value = serde_yaml::Value::deserialize(document)?;
        if value != serde_yaml::Value::Null {
            collect_workload_policy(&value, &mut policy)?;
        }
    }
    Ok(policy)
}

fn load_regexes(path: &Path) -> Result<BTreeMap<String, String>> {
    let manifest: TagManifest = serde_json::from_slice(&fs::read(path)?)?;
    Ok(manifest
        .tags
        .into_iter()
        .map(|tag| (tag.marker, tag.suggested_regex))
        .collect())
}

fn marker_pattern(value: &str, regexes: &BTreeMap<String, String>) -> Result<String> {
    let mut result = String::new();
    let mut remaining = value;
    while let Some(start) = remaining.find(DYNAMIC_PREFIX) {
        result.push_str(&escape(&remaining[..start]));
        let suffix = &remaining[start..];
        let end = suffix
            .find("}}")
            .ok_or_else(|| anyhow!("unterminated dynamic marker in {value}"))?
            + 2;
        let marker = &suffix[..end];
        result.push_str(
            regexes
                .get(marker)
                .ok_or_else(|| anyhow!("no regex for dynamic marker {marker}"))?,
        );
        remaining = &suffix[end..];
    }
    result.push_str(&escape(remaining));
    Ok(format!("^{result}$"))
}

fn sandbox_log_directory_pattern(
    capture: &CapturedSpec,
    value: &str,
    regexes: &BTreeMap<String, String>,
) -> Result<String> {
    let namespace = capture
        .annotations
        .get("io.kubernetes.cri.sandbox-namespace")
        .ok_or_else(|| anyhow!("sandbox log directory has no sandbox namespace"))?;
    let sandbox_name = capture
        .annotations
        .get("io.kubernetes.cri.sandbox-name")
        .ok_or_else(|| anyhow!("sandbox log directory has no sandbox name"))?;
    let expected =
        format!("/var/log/pods/{namespace}_{sandbox_name}_{POD_UID_MARKER}");
    if value != expected {
        bail!("unexpected sandbox log directory shape: {value}");
    }
    let pod_uid_regex = regexes
        .get(POD_UID_MARKER)
        .ok_or_else(|| anyhow!("no regex for dynamic marker {POD_UID_MARKER}"))?;
    Ok(format!(
        "^/var/log/pods/$(sandbox-namespace)_$(sandbox-name)_{pod_uid_regex}$"
    ))
}

fn compile_env(
    values: &[String],
    regexes: &BTreeMap<String, String>,
    regex_policy_mode: &str,
) -> Result<(Vec<String>, Vec<String>)> {
    let mut env = Vec::new();
    let mut allow_regex = Vec::new();
    for value in values {
        if !value.contains(DYNAMIC_PREFIX) {
            env.push(value.clone());
            continue;
        }
        let (name, marker) = value
            .split_once('=')
            .ok_or_else(|| anyhow!("dynamic environment has no name: {value}"))?;
        let tag = marker
            .strip_prefix(DYNAMIC_PREFIX)
            .and_then(|value| value.strip_suffix("}}"))
            .ok_or_else(|| anyhow!("unsupported partial environment marker: {value}"))?;
        if regex_policy_mode == "legacy" && tag.starts_with("service-env.") {
            continue;
        }
        let replacement = match tag {
            "node.name" => Some("$(node-name)"),
            "pod.uid" => Some("$(pod-uid)"),
            "pod.name" => Some("$(sandbox-name)"),
            _ => None,
        };
        if let Some(replacement) = replacement {
            env.push(format!("{name}={replacement}"));
        } else {
            allow_regex.push(marker_pattern(value, regexes)?);
        }
    }
    Ok((env, allow_regex))
}

fn captured_process(
    process: &CapturedProcess,
    regexes: &BTreeMap<String, String>,
    regex_policy_mode: &str,
) -> Result<(KataProcess, Vec<String>)> {
    let (env, allow_regex) =
        compile_env(&process.env, regexes, regex_policy_mode)?;
    Ok((
        KataProcess {
            Terminal: process.terminal,
            User: KataUser {
                UID: process.user.uid,
                GID: process.user.gid,
                AdditionalGids: process.user.additional_gids.clone(),
                Username: process.user.username.clone(),
            },
            Args: process.args.clone(),
            Env: env,
            Cwd: process.cwd.clone(),
            Capabilities: KataLinuxCapabilities {
                Ambient: process.capabilities.ambient.clone(),
                Bounding: process.capabilities.bounding.clone(),
                Effective: process.capabilities.effective.clone(),
                Inheritable: process.capabilities.inheritable.clone(),
                Permitted: process.capabilities.permitted.clone(),
            },
            NoNewPrivileges: process.no_new_privileges,
        },
        allow_regex,
    ))
}

fn sandbox_process(settings: &Settings, capture: &CapturedSpec) -> KataProcess {
    let mut process = genpolicy::containerd::get_process(false, &settings.common);
    let template = &settings.pause_container.Process;
    process.Terminal = template.Terminal;
    process.User = template.User.clone();
    if process.User.AdditionalGids.is_empty() && process.User.GID != 0 {
        process.User.AdditionalGids.insert(process.User.GID);
    }
    process.Args = if template.Args.is_empty() {
        capture.process.args.clone()
    } else {
        template.Args.clone()
    };
    process.Env = capture
        .process
        .env
        .iter()
        .filter(|value| !value.contains(DYNAMIC_PREFIX))
        .cloned()
        .collect();
    process.Cwd = capture.process.cwd.clone();
    process.NoNewPrivileges = template.NoNewPrivileges;
    process
}

fn normalize_mounts(capture: &CapturedSpec, template: &KataSpec) -> Result<Vec<KataMount>> {
    let templates: BTreeMap<_, _> = template
        .Mounts
        .iter()
        .map(|mount| (mount.destination.as_str(), mount))
        .collect();
    let mut mounts = Vec::new();
    for captured in &capture.mounts {
        if let Some(template) = templates.get(captured.destination.as_str()) {
            let mut mount = (*template).clone();
            if mount.source.is_empty() && mount.type_ == "bind" {
                let name = Path::new(&mount.destination)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| anyhow!("mount has no basename: {}", mount.destination))?;
                mount.source = format!("$(sfprefix){name}$");
            }
            if matches!(
                mount.destination.as_str(),
                "/etc/hostname" | "/etc/resolv.conf"
            ) && !mount.options.iter().any(|value| value == "ro" || value == "rw")
            {
                if let Some(access) = captured
                    .options
                    .iter()
                    .find(|value| value.as_str() == "ro" || value.as_str() == "rw")
                {
                    mount.options.push(access.clone());
                }
            }
            validate_guest_mount_source(&mount)?;
            mounts.push(mount);
        } else if captured.type_ != "bind" {
            mounts.push(KataMount {
                destination: captured.destination.clone(),
                source: captured.source.clone(),
                type_: captured.type_.clone(),
                options: captured.options.clone(),
            });
        } else {
            bail!(
                "captured bind mount has no Kata normalization: {}",
                captured.destination
            );
        }
    }
    Ok(mounts)
}

fn validate_guest_mount_source(mount: &KataMount) -> Result<()> {
    if mount.type_ != "bind" {
        return Ok(());
    }

    if mount.destination == "/dev/shm" {
        if mount.source != "/run/kata-containers/sandbox/shm" {
            bail!(
                "UVM-local /dev/shm mount has unexpected source: {}",
                mount.source
            );
        }
        return Ok(());
    }

    if !mount.source.starts_with("$(sfprefix)") {
        bail!(
            "externally backed mount {} is not confined to the Kata shared-filesystem domain: {}",
            mount.destination,
            mount.source
        );
    }

    Ok(())
}

fn compile_annotations(
    capture: &CapturedSpec,
    template: &KataSpec,
    regexes: &BTreeMap<String, String>,
    sandbox_name_pattern: Option<&str>,
) -> Result<BTreeMap<String, String>> {
    let mut annotations = template.Annotations.clone();
    for key in [
        "io.kubernetes.cri.container-type",
        "io.kubernetes.cri.container-name",
        "io.kubernetes.cri.image-name",
        "io.kubernetes.cri.sandbox-namespace",
    ] {
        if let Some(value) = capture.annotations.get(key) {
            annotations.insert(key.to_string(), value.clone());
        }
    }
    for key in [
        "io.kubernetes.cri.sandbox-id",
        "nerdctl/network-namespace",
    ] {
        if let Some(value) = capture.annotations.get(key) {
            annotations.insert(key.to_string(), marker_pattern(value, regexes)?);
        }
    }
    if let Some(value) = capture
        .annotations
        .get("io.kubernetes.cri.sandbox-log-directory")
    {
        annotations.insert(
            "io.kubernetes.cri.sandbox-log-directory".to_string(),
            sandbox_log_directory_pattern(capture, value, regexes)?,
        );
    }
    if let Some(value) = capture
        .annotations
        .get("io.kubernetes.cri.sandbox-name")
    {
        let pattern = sandbox_name_pattern
            .map(|pattern| format!("^{pattern}$"))
            .unwrap_or(marker_pattern(value, regexes)?);
        annotations.insert(
            "io.kubernetes.cri.sandbox-name".to_string(),
            pattern,
        );
    }
    if capture
        .annotations
        .get("io.kubernetes.cri.container-type")
        .is_some_and(|value| value == "sandbox")
    {
        annotations
            .entry("nerdctl/network-namespace".to_string())
            .or_insert_with(|| {
                "^/var/run/netns/cni-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
                    .to_string()
            });
    }
    Ok(annotations)
}

fn compile_container(
    capture_name: &str,
    capture: &CapturedSpec,
    settings: &Settings,
    regexes: &BTreeMap<String, String>,
    allow_env_regex: &mut Vec<String>,
    regex_policy_mode: &str,
    exec_commands: Vec<Vec<String>>,
    sandbox_name_pattern: Option<&str>,
) -> Result<(ContainerPolicy, Value)> {
    let container_type = capture
        .annotations
        .get("io.kubernetes.cri.container-type")
        .unwrap();
    let sandbox = container_type == "sandbox";
    let template = settings.get_container_settings(sandbox);

    let (process, process_source) = if sandbox {
        (
            sandbox_process(settings, capture),
            "settings-kata-sandbox-normalization",
        )
    } else {
        let (process, dynamic_regex) =
            captured_process(&capture.process, regexes, regex_policy_mode)?;
        for value in dynamic_regex {
            if !allow_env_regex.contains(&value) {
                allow_env_regex.push(value);
            }
        }
        (process, "captured-oci")
    };

    let annotations = compile_annotations(
        capture,
        template,
        regexes,
        sandbox_name_pattern,
    )?;
    let linux = KataLinux {
        Namespaces: policy::get_kata_namespaces(sandbox, false),
        MaskedPaths: capture.linux.masked_paths.clone(),
        ReadonlyPaths: capture.linux.readonly_paths.clone(),
        Devices: template.Linux.Devices.clone(),
        Sysctl: template.Linux.Sysctl.clone(),
    };
    let oci = KataSpec {
        Version: settings.kata_config.oci_version.clone(),
        Process: process,
        Root: KataRoot {
            Path: template.Root.Path.clone(),
            Readonly: capture.root.readonly,
        },
        Mounts: normalize_mounts(capture, template)?,
        Hooks: None,
        Annotations: annotations,
        Linux: linux,
    };
    let mut runtime_anno_patterns = BTreeMap::new();
    if !sandbox {
        let termination_path = if regex_policy_mode == "legacy" {
            "^/.*$".to_string()
        } else {
            safe_termination_message_path(capture, regex_policy_mode)?
        };
        runtime_anno_patterns.insert(
            "^io\\.kubernetes\\.container\\.terminationMessagePath$".to_string(),
            termination_path,
        );
        runtime_anno_patterns.insert(
            "^io\\.kubernetes\\.container\\.terminationMessagePolicy$".to_string(),
            "^(File|FallbackToLogsOnError)$".to_string(),
        );
    }
    let policy = ContainerPolicy {
        OCI: oci,
        storages: Vec::new(),
        devices: Vec::new(),
        sandbox_pidns: false,
        exec_commands,
        runtime_anno_patterns,
    };
    let report = json!({
        "identity": {
            "container_type": container_type,
            "container_name": capture.annotations
                .get("io.kubernetes.cri.container-name")
                .cloned()
                .unwrap_or_default()
        },
        "capture": capture_name,
        "fields": {
            "/OCI/Process": {"source": process_source},
            "/OCI/Root/Readonly": {"source": "captured-oci"},
            "/OCI/Root/Path": {
                "source": "settings-kata-normalization",
                "reason": "Kata supplies the guest rootfs path"
            },
            "/OCI/Mounts": {
                "source": "captured-presence+settings-kata-normalization"
            },
            "/OCI/Linux/MaskedPaths": {"source": "captured-oci"},
            "/OCI/Linux/ReadonlyPaths": {"source": "captured-oci"},
            "/OCI/Linux/Namespaces": {"source": "settings-kata-normalization"},
            "/exec_commands": {"source": "trusted-workload-yaml"}
        }
    });
    Ok((policy, report))
}

fn safe_termination_message_path(
    capture: &CapturedSpec,
    regex_policy_mode: &str,
) -> Result<String> {
    let mount = capture
        .mounts
        .iter()
        .find(|mount| mount.destination == "/dev/termination-log")
        .ok_or_else(|| {
            anyhow!(
                "{regex_policy_mode} mode requires the external /dev/termination-log mount"
            )
        })?;
    let components: Vec<_> = mount.source.split('/').filter(|value| !value.is_empty()).collect();
    let external_kubelet_source = mount.source.starts_with('/')
        && !components.iter().any(|value| *value == "." || *value == "..")
        && components.len() >= 5
        && components[components.len() - 5] == "pods"
        && !components[components.len() - 4].is_empty()
        && components[components.len() - 3] == "containers"
        && !components[components.len() - 2].is_empty()
        && components.last().is_some_and(|value| {
            value.len() == 8 && value.chars().all(|character| character.is_ascii_hexdigit())
        });
    let required_options = ["rbind", "rprivate", "rw"];
    if mount.type_ != "bind"
        || !external_kubelet_source
        || !required_options
            .iter()
            .all(|required| mount.options.iter().any(|option| option == required))
    {
        bail!(
            "{regex_policy_mode} mode requires termination messages to use the dedicated external kubelet bind mount"
        );
    }
    Ok("^/dev/termination\\-log$".to_string())
}

fn append_allow_env_regex(request_defaults: &mut Value, values: &[String]) -> Result<()> {
    let target = request_defaults
        .get_mut("CreateContainerRequest")
        .and_then(|value| value.get_mut("allow_env_regex"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow!("settings have no CreateContainerRequest.allow_env_regex"))?;
    for value in values {
        if !target.iter().any(|existing| existing.as_str() == Some(value)) {
            target.push(Value::String(value.clone()));
        }
    }
    Ok(())
}

fn apply_regex_policy_mode(request_defaults: &mut Value, mode: &str) -> Result<()> {
    match mode {
        "legacy" => return Ok(()),
        "balanced" => {}
        _ => bail!("unknown regex policy mode: {mode}"),
    }
    let target = request_defaults
        .get_mut("CreateContainerRequest")
        .and_then(|value| value.get_mut("allow_env_regex"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| anyhow!("settings have no CreateContainerRequest.allow_env_regex"))?;
    target.clear();
    Ok(())
}

fn annotate_document(document: &mut serde_yaml::Value, annotation: &str) -> Result<bool> {
    let kind = document
        .get("kind")
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or_default();
    let path = match kind {
        "Pod" => Some(""),
        "PodTemplate" => Some("template"),
        "Deployment" | "DaemonSet" | "ReplicaSet" | "StatefulSet" | "Job"
        | "ReplicationController" => Some("spec.template"),
        "CronJob" => Some("spec.jobTemplate.spec.template"),
        _ => None,
    };
    if let Some(path) = path {
        genpolicy::yaml::add_policy_annotation(document, path, annotation);
        return Ok(true);
    }
    if kind == "List" {
        let items = document
            .get_mut("items")
            .and_then(serde_yaml::Value::as_sequence_mut)
            .ok_or_else(|| anyhow!("List has no items"))?;
        let mut changed = false;
        for item in items {
            changed |= annotate_document(item, annotation)?;
        }
        return Ok(changed);
    }
    Ok(false)
}

fn write_annotated_yaml(input: &Path, output: &Path, annotation: &str) -> Result<()> {
    let contents = fs::read_to_string(input)?;
    let mut result = String::new();
    let mut changed = false;
    for document in serde_yaml::Deserializer::from_str(&contents) {
        let mut value = serde_yaml::Value::deserialize(document)?;
        changed |= annotate_document(&mut value, annotation)?;
        if !result.is_empty() {
            result.push_str("---\n");
        }
        result.push_str(&serde_yaml::to_string(&value)?);
    }
    if !changed {
        bail!("workload contains no annotatable Pod template");
    }
    fs::write(output, result)?;
    Ok(())
}

fn run(args: Args) -> Result<()> {
    let settings = Settings::new(args.settings.to_str().unwrap());
    let captures = load_captures(&args.tagged_dir, ".tagged.json")?;
    let raw_captures = load_captures(&args.raw_dir, ".config.json")?;
    let regexes = load_regexes(&args.tag_manifest)?;
    let workload_policy = load_workload_policy(&args.workload)?;
    let sandbox_name_pattern = match workload_policy.sandbox_name_patterns.len()
    {
        0 => None,
        1 => workload_policy.sandbox_name_patterns.iter().next(),
        count => bail!(
            "captured sandbox cannot be mapped to {count} workload name patterns"
        ),
    };
    let mut request_defaults = serde_json::to_value(&settings.request_defaults)?;
    let mut allow_env_regex = Vec::new();
    let mut containers = Vec::new();
    let mut reports = Vec::new();
    for (identity, (name, capture)) in captures {
        let raw_capture = raw_captures
            .get(&identity)
            .map(|(_, capture)| capture)
            .ok_or_else(|| anyhow!("no raw OCI capture for {identity:?}"))?;
        let container_workload_policy = capture
            .annotations
            .get("io.kubernetes.cri.container-name")
            .and_then(|name| workload_policy.containers.get(name));
        let exec_commands = container_workload_policy
            .map(|policy| policy.exec_commands.clone())
            .unwrap_or_default();
        let container_sandbox_name_pattern = container_workload_policy
            .and_then(|policy| policy.sandbox_name_pattern.as_deref())
            .or(sandbox_name_pattern.map(String::as_str));
        let (container, mut report) =
            compile_container(
                &name,
                &capture,
                &settings,
                &regexes,
                &mut allow_env_regex,
                &args.regex_policy_mode,
                exec_commands,
                container_sandbox_name_pattern,
            )?;
        if args.regex_policy_mode == "legacy" {
            let checked = validate_legacy_service_env_coverage(
                &capture,
                raw_capture,
                &request_defaults,
                &settings.common,
            )?;
            report["legacy_service_env_regex_coverage"] = json!({
                "checked": checked,
                "uncovered": 0
            });
        }
        containers.push(container);
        reports.push(report);
    }
    apply_regex_policy_mode(&mut request_defaults, &args.regex_policy_mode)?;
    append_allow_env_regex(&mut request_defaults, &allow_env_regex)?;
    let data = PolicyData {
        containers,
        common: settings.common,
        sandbox: settings.sandbox,
        request_defaults,
        devices: settings.devices,
        cluster_config: settings.cluster_config,
    };
    let rules = fs::read_to_string(&args.rules)?;
    let policy = format!(
        "{}\npolicy_data := {}\n",
        rules.trim_end(),
        serde_json::to_string_pretty(&data)?
    );
    fs::write(&args.output, &policy)?;
    let mut diff = json!({
        "schema_version": 2,
        "containers": reports
    });
    if args.regex_policy_mode != "legacy" {
        diff["regex_policy_mode"] = Value::String(args.regex_policy_mode.clone());
    }
    fs::write(
        &args.diff_output,
        serde_json::to_string_pretty(&diff)? + "\n",
    )?;

    let mut initdata = kata_types::initdata::InitData::new("sha256", "0.1.0");
    initdata.insert_data("policy.rego", policy);
    let annotation = kata_types::initdata::encode_initdata(&initdata);
    fs::write(&args.annotation_output, format!("{annotation}\n"))?;
    write_annotated_yaml(&args.workload, &args.annotated_yaml_output, &annotation)?;
    Ok(())
}

fn main() -> Result<()> {
    run(parse_args()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_environment_uses_macro_or_regex() {
        let regexes = BTreeMap::from([
            (
                "{{GENPOLICY_DYNAMIC:node.name}}".to_string(),
                "[a-z0-9-]+".to_string(),
            ),
            (
                "{{GENPOLICY_DYNAMIC:service-env.TEST_SERVICE_HOST}}".to_string(),
                "(?:[0-9]{1,3}\\.){3}[0-9]{1,3}".to_string(),
            ),
        ]);
        let values = vec![
            "STATIC=value".to_string(),
            "NODE={{GENPOLICY_DYNAMIC:node.name}}".to_string(),
            "TEST_SERVICE_HOST={{GENPOLICY_DYNAMIC:service-env.TEST_SERVICE_HOST}}".to_string(),
        ];

        let (env, allow_regex) =
            compile_env(&values, &regexes, "balanced").unwrap();

        assert_eq!(env, vec!["STATIC=value", "NODE=$(node-name)"]);
        assert_eq!(
            allow_regex,
            vec!["^TEST_SERVICE_HOST=(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$"]
        );
    }

    #[test]
    fn legacy_environment_uses_inherited_service_regexes() {
        let values = vec![
            "STATIC=value".to_string(),
            "TEST_SERVICE_HOST={{GENPOLICY_DYNAMIC:service-env.TEST_SERVICE_HOST}}"
                .to_string(),
        ];
        let regexes = BTreeMap::from([(
            "{{GENPOLICY_DYNAMIC:service-env.TEST_SERVICE_HOST}}".to_string(),
            "(?:[0-9]{1,3}\\.){3}[0-9]{1,3}".to_string(),
        )]);

        let (env, allow_regex) =
            compile_env(&values, &regexes, "legacy").unwrap();

        assert_eq!(env, vec!["STATIC=value"]);
        assert!(allow_regex.is_empty());
    }

    #[test]
    fn legacy_service_regex_coverage_rejects_unknown_variable() {
        let marker =
            "{{GENPOLICY_DYNAMIC:service-env.UNKNOWN_SERVICE_HOST}}";
        let tagged = CapturedSpec {
            process: CapturedProcess {
                env: vec![format!("UNKNOWN_SERVICE_HOST={marker}")],
                ..Default::default()
            },
            ..Default::default()
        };
        let raw = CapturedSpec {
            process: CapturedProcess {
                env: vec!["UNKNOWN_SERVICE_HOST=10.0.0.1".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let defaults = json!({
            "CreateContainerRequest": {
                "allow_env_regex": ["^KNOWN_SERVICE_HOST=$(ipv4_a)$"]
            }
        });
        let common: policy::CommonData = serde_json::from_value(json!({
            "cpath": "",
            "root_path": "",
            "sfprefix": "",
            "spath": "",
            "ipv4_a": "(?:[0-9]{1,3}\\.){3}[0-9]{1,3}",
            "ip_p": "[0-9]{1,5}",
            "svc_name_downward_env": "[A-Z][A-Z0-9_]*",
            "dns_label": "[a-z0-9-]+",
            "default_caps": [],
            "privileged_caps": []
        }))
        .unwrap();

        let error = validate_legacy_service_env_coverage(
            &tagged, &raw, &defaults, &common,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains(
            "legacy environment regexes do not cover captured variable UNKNOWN_SERVICE_HOST"
        ));
    }

    #[test]
    fn marker_pattern_escapes_static_text() {
        let regexes = BTreeMap::from([(
            "{{GENPOLICY_DYNAMIC:pod.uid}}".to_string(),
            "[0-9a-f-]+".to_string(),
        )]);

        let pattern = marker_pattern(
            "/var/log/pods/{{GENPOLICY_DYNAMIC:pod.uid}}",
            &regexes,
        )
        .unwrap();

        assert_eq!(pattern, "^/var/log/pods/[0-9a-f-]+$");
    }

    #[test]
    fn sandbox_log_directory_binds_name_and_namespace() {
        let mut capture = CapturedSpec::default();
        capture.annotations.insert(
            "io.kubernetes.cri.sandbox-namespace".to_string(),
            "default".to_string(),
        );
        capture.annotations.insert(
            "io.kubernetes.cri.sandbox-name".to_string(),
            POD_NAME_MARKER.to_string(),
        );
        let regexes = BTreeMap::from([(
            POD_UID_MARKER.to_string(),
            "[0-9a-f-]+".to_string(),
        )]);
        let value = format!(
            "/var/log/pods/default_{POD_NAME_MARKER}_{POD_UID_MARKER}"
        );

        let pattern =
            sandbox_log_directory_pattern(&capture, &value, &regexes).unwrap();

        assert_eq!(
            pattern,
            "^/var/log/pods/$(sandbox-namespace)_$(sandbox-name)_[0-9a-f-]+$"
        );
    }

    #[test]
    fn sandbox_log_directory_accepts_exact_pod_name() {
        let mut capture = CapturedSpec::default();
        capture.annotations.insert(
            "io.kubernetes.cri.sandbox-namespace".to_string(),
            "default".to_string(),
        );
        capture.annotations.insert(
            "io.kubernetes.cri.sandbox-name".to_string(),
            "exact-pod".to_string(),
        );
        let regexes = BTreeMap::from([(
            POD_UID_MARKER.to_string(),
            "[0-9a-f-]+".to_string(),
        )]);

        let pattern = sandbox_log_directory_pattern(
            &capture,
            &format!("/var/log/pods/default_exact-pod_{POD_UID_MARKER}"),
            &regexes,
        )
        .unwrap();

        assert_eq!(
            pattern,
            "^/var/log/pods/$(sandbox-namespace)_$(sandbox-name)_[0-9a-f-]+$"
        );
    }

    #[test]
    fn sandbox_log_directory_rejects_unrelated_path() {
        let mut capture = CapturedSpec::default();
        capture.annotations.insert(
            "io.kubernetes.cri.sandbox-namespace".to_string(),
            "default".to_string(),
        );
        capture.annotations.insert(
            "io.kubernetes.cri.sandbox-name".to_string(),
            "pod".to_string(),
        );

        let error = sandbox_log_directory_pattern(
            &capture,
            "/var/log/pods/other_pod_uid",
            &BTreeMap::new(),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("unexpected sandbox log directory shape"));
    }

    #[test]
    fn captured_working_directory_is_authoritative() {
        let process = CapturedProcess {
            cwd: "/captured".to_string(),
            ..Default::default()
        };

        let (compiled, _) =
            captured_process(&process, &BTreeMap::new(), "legacy").unwrap();

        assert_eq!(compiled.Cwd, "/captured");
    }

    #[test]
    fn workload_exec_probes_are_exact_policy_commands() {
        let document: serde_yaml::Value = serde_yaml::from_str(
            r#"
apiVersion: v1
kind: Pod
metadata:
  name: workload
spec:
  containers:
    - name: workload
      image: example.invalid/workload
      livenessProbe:
        exec:
          command: ["/bin/check", "live"]
      readinessProbe:
        exec:
          command: ["/bin/check", "ready"]
      startupProbe:
        exec:
          command: ["/bin/check", "startup"]
      lifecycle:
        postStart:
          exec:
            command: ["/bin/hook", "start"]
        preStop:
          exec:
            command: ["/bin/hook", "stop"]
"#,
        )
        .unwrap();
        let mut policy = WorkloadPolicy::default();

        collect_workload_policy(&document, &mut policy).unwrap();

        assert_eq!(
            policy.containers["workload"].exec_commands,
            vec![
                vec!["/bin/check".to_string(), "live".to_string()],
                vec!["/bin/check".to_string(), "ready".to_string()],
                vec!["/bin/check".to_string(), "startup".to_string()],
                vec!["/bin/hook".to_string(), "start".to_string()],
                vec!["/bin/hook".to_string(), "stop".to_string()],
            ]
        );
        assert_eq!(
            policy.containers["workload"].sandbox_name_pattern,
            Some("workload".to_string())
        );
    }

    #[test]
    fn conflicting_workload_exec_commands_fail() {
        let document: serde_yaml::Value = serde_yaml::from_str(
            r#"
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Pod
    metadata:
      name: one
    spec:
      containers:
        - name: workload
          image: example.invalid/one
          readinessProbe:
            exec:
              command: ["/bin/check", "one"]
  - apiVersion: v1
    kind: Pod
    metadata:
      name: two
    spec:
      containers:
        - name: workload
          image: example.invalid/two
          readinessProbe:
            exec:
              command: ["/bin/check", "two"]
"#,
        )
        .unwrap();
        let mut policy = WorkloadPolicy::default();

        let error = collect_workload_policy(&document, &mut policy)
            .unwrap_err()
            .to_string();

        assert!(error.contains("conflicting workload policy for container workload"));
    }

    #[test]
    fn balanced_mode_clears_inherited_environment_regexes() {
        let mut defaults = json!({
            "CreateContainerRequest": {
                "allow_env_regex": [
                    "^KUBERNETES_SERVICE_HOST=.*$",
                    "^AZURE_CLIENT_ID=[A-Fa-f0-9-]*$"
                ]
            }
        });

        apply_regex_policy_mode(&mut defaults, "balanced").unwrap();

        assert_eq!(
            defaults["CreateContainerRequest"]["allow_env_regex"],
            json!([])
        );
    }

    #[test]
    fn legacy_mode_preserves_environment_regexes() {
        let mut defaults = json!({
            "CreateContainerRequest": {
                "allow_env_regex": ["^HOSTNAME=.*$"]
            }
        });

        apply_regex_policy_mode(&mut defaults, "legacy").unwrap();

        assert_eq!(
            defaults["CreateContainerRequest"]["allow_env_regex"],
            json!(["^HOSTNAME=.*$"])
        );
    }

        #[test]
        fn pod_template_is_annotated() {
            let mut document: serde_yaml::Value = serde_yaml::from_str(
                &serde_json::to_string(&json!({
                    "apiVersion": "v1",
                    "kind": "PodTemplate",
                    "metadata": {"name": "worker"},
                    "template": {
                        "spec": {
                            "containers": [{
                                "name": "worker",
                                "image": "example.invalid/worker"
                            }]
                        }
                    }
                }))
                .unwrap(),
            )
            .unwrap();

                assert!(annotate_document(&mut document, "encoded-policy").unwrap());
                assert_eq!(
                        document["template"]["metadata"]["annotations"]
                                ["io.katacontainers.config.hypervisor.cc_init_data"],
                        serde_yaml::Value::String("encoded-policy".to_string())
                );
        }

    #[test]
    fn termination_message_path_requires_external_default_mount() {
        let capture = CapturedSpec {
            mounts: vec![CapturedMount {
                destination: "/dev/termination-log".to_string(),
                source: "/custom/kubelet-root/pods/pod/containers/workload/12ab34cd"
                    .to_string(),
                type_: "bind".to_string(),
                options: vec![
                    "rbind".to_string(),
                    "rprivate".to_string(),
                    "rw".to_string(),
                ],
            }],
            ..Default::default()
        };

        assert_eq!(
            safe_termination_message_path(&capture, "balanced").unwrap(),
            "^/dev/termination\\-log$"
        );
    }

    #[test]
    fn termination_message_path_rejects_internal_code_path() {
        let capture = CapturedSpec {
            mounts: vec![CapturedMount {
                destination: "/app/bin/termination-log".to_string(),
                source: "/app/bin".to_string(),
                type_: "bind".to_string(),
                options: vec!["rbind".to_string(), "rw".to_string()],
            }],
            ..Default::default()
        };

        assert!(safe_termination_message_path(&capture, "balanced").is_err());
    }

    #[test]
    fn external_guest_mount_source_must_use_shared_filesystem_domain() {
        let mount = KataMount {
            destination: "/etc/hosts".to_string(),
            source: "/run/kata-containers/sandbox/shm".to_string(),
            type_: "bind".to_string(),
            options: vec!["rbind".to_string()],
        };

        assert!(validate_guest_mount_source(&mount).is_err());
    }

    #[test]
    fn external_guest_mount_source_accepts_shared_filesystem_regex() {
        let mount = KataMount {
            destination: "/etc/hosts".to_string(),
            source: "$(sfprefix)hosts$".to_string(),
            type_: "bind".to_string(),
            options: vec!["rbind".to_string()],
        };

        validate_guest_mount_source(&mount).unwrap();
    }

    #[test]
    fn uvm_local_shm_source_is_exactly_classified() {
        let mount = KataMount {
            destination: "/dev/shm".to_string(),
            source: "/run/kata-containers/sandbox/shm".to_string(),
            type_: "bind".to_string(),
            options: vec!["rbind".to_string()],
        };

        validate_guest_mount_source(&mount).unwrap();
    }

    #[test]
    fn conflicting_duplicate_captures_fail() {
        let directory = env::temp_dir().join(format!(
            "genpolicy-oci-compiler-duplicates-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();

        for (name, cwd) in [("0001.json", "/one"), ("0002.json", "/two")] {
            let mut spec = CapturedSpec::default();
            spec.process.cwd = cwd.to_string();
            spec.annotations.insert(
                "io.kubernetes.cri.container-type".to_string(),
                "container".to_string(),
            );
            spec.annotations.insert(
                "io.kubernetes.cri.container-name".to_string(),
                "workload".to_string(),
            );
            fs::write(
                directory.join(name.replace(".json", ".tagged.json")),
                serde_json::to_vec(&spec).unwrap(),
            )
            .unwrap();
        }

        let error = load_captures(&directory, ".tagged.json")
            .unwrap_err()
            .to_string();
        fs::remove_dir_all(&directory).unwrap();

        assert!(error.contains("inconsistent duplicate OCI captures"));
    }
}
