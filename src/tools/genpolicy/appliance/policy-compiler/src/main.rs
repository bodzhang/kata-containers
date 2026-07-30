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

#[derive(Debug)]
struct Args {
    tagged_dir: PathBuf,
    tag_manifest: PathBuf,
    rules: PathBuf,
    settings: PathBuf,
    workload: PathBuf,
    output: PathBuf,
    diff_output: PathBuf,
    annotation_output: PathBuf,
    annotated_yaml_output: PathBuf,
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
        tagged_dir: required("--tagged-dir")?,
        tag_manifest: required("--tag-manifest")?,
        rules: required("--rules")?,
        settings: required("--settings")?,
        workload: required("--workload")?,
        output: required("--output")?,
        diff_output: required("--diff-output")?,
        annotation_output: required("--annotation-output")?,
        annotated_yaml_output: required("--annotated-yaml-output")?,
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

fn load_captures(directory: &Path) -> Result<BTreeMap<Identity, (String, CapturedSpec)>> {
    let mut paths: Vec<_> = fs::read_dir(directory)
        .with_context(|| format!("read {}", directory.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "json"))
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

fn compile_env(
    values: &[String],
    regexes: &BTreeMap<String, String>,
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
) -> Result<(KataProcess, Vec<String>)> {
    let (env, allow_regex) = compile_env(&process.env, regexes)?;
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

fn compile_annotations(
    capture: &CapturedSpec,
    template: &KataSpec,
    regexes: &BTreeMap<String, String>,
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
        "io.kubernetes.cri.sandbox-name",
        "io.kubernetes.cri.sandbox-log-directory",
        "nerdctl/network-namespace",
    ] {
        if let Some(value) = capture.annotations.get(key) {
            annotations.insert(key.to_string(), marker_pattern(value, regexes)?);
        }
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
        let (process, dynamic_regex) = captured_process(&capture.process, regexes)?;
        for value in dynamic_regex {
            if !allow_env_regex.contains(&value) {
                allow_env_regex.push(value);
            }
        }
        (process, "captured-oci")
    };

    let annotations = compile_annotations(capture, template, regexes)?;
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
        runtime_anno_patterns.insert(
            "^io\\.kubernetes\\.container\\.terminationMessagePath$".to_string(),
            "^/.*$".to_string(),
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
        exec_commands: Vec::new(),
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
            "/OCI/Linux/Namespaces": {"source": "settings-kata-normalization"}
        }
    });
    Ok((policy, report))
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
    let captures = load_captures(&args.tagged_dir)?;
    let regexes = load_regexes(&args.tag_manifest)?;
    let mut request_defaults = serde_json::to_value(&settings.request_defaults)?;
    let mut allow_env_regex = Vec::new();
    let mut containers = Vec::new();
    let mut reports = Vec::new();
    for (_, (name, capture)) in captures {
        let (container, report) =
            compile_container(&name, &capture, &settings, &regexes, &mut allow_env_regex)?;
        containers.push(container);
        reports.push(report);
    }
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
    fs::write(
        &args.diff_output,
        serde_json::to_string_pretty(&json!({
            "schema_version": 2,
            "containers": reports
        }))? + "\n",
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

        let (env, allow_regex) = compile_env(&values, &regexes).unwrap();

        assert_eq!(env, vec!["STATIC=value", "NODE=$(node-name)"]);
        assert_eq!(
            allow_regex,
            vec!["^TEST_SERVICE_HOST=(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$"]
        );
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
    fn captured_working_directory_is_authoritative() {
        let process = CapturedProcess {
            cwd: "/captured".to_string(),
            ..Default::default()
        };

        let (compiled, _) = captured_process(&process, &BTreeMap::new()).unwrap();

        assert_eq!(compiled.Cwd, "/captured");
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
                directory.join(name),
                serde_json::to_vec(&spec).unwrap(),
            )
            .unwrap();
        }

        let error = load_captures(&directory).unwrap_err().to_string();
        fs::remove_dir_all(&directory).unwrap();

        assert!(error.contains("inconsistent duplicate OCI captures"));
    }
}
