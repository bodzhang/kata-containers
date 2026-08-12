use anyhow::{bail, Context, Result};
use regorus::{Engine, Value};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

const DEFAULT_QUERY: &str = "data.fragment_composer.final_policy";

/// Every loaded module is policy code in one engine, so an unexpected package
/// could add permissive definitions of the composer's own validation rules.
fn package_of(source: &str, name: &str) -> Result<String> {
    for line in source.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(package) = line.strip_prefix("package ") else {
            bail!("{name} does not begin with a package declaration");
        };
        return Ok(package.trim().to_string());
    }
    bail!("{name} has no package declaration")
}

fn require_package(source: &str, name: &str, expected: &str) -> Result<()> {
    let package = package_of(source, name)?;
    if package != expected {
        bail!("{name} declares package {package}, expected {expected}");
    }
    Ok(())
}

fn validate_profile_packages(modules: &[(String, String)]) -> Result<()> {
    for (name, source) in modules {
        let package = package_of(source, name)?;
        if package != "selected_profile_fragments" && !package.starts_with("profile_") {
            bail!("profile module {name} declares disallowed package {package}");
        }
    }
    Ok(())
}

fn evaluate_modules(modules: &[(&str, &str)]) -> Result<Value> {
    evaluate_modules_query(modules, DEFAULT_QUERY)
}

fn evaluate_modules_query(modules: &[(&str, &str)], query: &str) -> Result<Value> {
    let mut engine = Engine::new();
    engine.set_strict_builtin_errors(true);
    for (name, source) in modules {
        engine
            .add_policy((*name).to_string(), (*source).to_string())
            .with_context(|| format!("load Rego module {name}"))?;
    }
    let results = engine.eval_query(query.to_string(), false)?;
    if results.result.len() != 1 || results.result[0].expressions.len() != 1 {
        bail!("composition query is undefined");
    }
    let value = results.result[0].expressions[0].value.clone();
    if value == Value::Undefined || value == Value::Null {
        bail!("composition query returned no final policy");
    }
    Ok(value)
}

#[cfg(test)]
fn evaluate_agent_request(
    modules: &[(&str, &str)],
    endpoint: &str,
    input: &serde_json::Value,
    state: &serde_json::Value,
) -> Result<Value> {
    let mut engine = Engine::new();
    engine.set_strict_builtin_errors(false);
    for (name, source) in modules {
        engine
            .add_policy((*name).to_string(), (*source).to_string())
            .with_context(|| format!("load Agent policy module {name}"))?;
    }
    engine.add_data(Value::from_json_str(&state.to_string())?)?;
    engine.set_input_json(&input.to_string())?;
    let query = format!("data.agent_policy.{endpoint}");
    let results = engine.eval_query(query, false)?;
    if results.result.len() != 1 || results.result[0].expressions.len() != 1 {
        bail!("Agent policy query returned an unexpected result shape");
    }
    let value = results.result[0].expressions[0].value.clone();
    if value == Value::Undefined || value == Value::Null {
        bail!("Agent policy query returned no decision");
    }
    Ok(value)
}

fn load(path: &Path) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("read {}", path.display()))
}

fn load_rego_directory(path: &Path) -> Result<Vec<(String, String)>> {
    let mut paths = fs::read_dir(path)
        .with_context(|| format!("read {}", path.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "rego")
        })
        .collect::<Vec<PathBuf>>();
    paths.sort();
    if paths.is_empty() {
        bail!("no Rego modules in {}", path.display());
    }
    paths
        .into_iter()
        .map(|path| {
            let name = path.to_string_lossy().into_owned();
            Ok((name, load(&path)?))
        })
        .collect()
}

fn validate_rpc_evaluator(evaluator: &str) -> Result<()> {
    require_package(evaluator, "RPC evaluator", "agent_policy")?;
    if evaluator.contains("\npolicy_data := ") {
        bail!("RPC evaluator already contains a policy_data assignment");
    }
    Ok(())
}

fn render_rpc_policy(evaluator: &str, policy_data: &Value) -> Result<String> {
    validate_rpc_evaluator(evaluator)?;
    let policy = format!(
        "{}\npolicy_data := {}\n",
        evaluator.trim_end(),
        serde_json::to_string_pretty(policy_data)?
    );
    evaluate_modules_query(
        &[("policy.rego", policy.as_str())],
        "data.agent_policy.AllowRequestsFailingPolicy",
    )
    .context("validate composed policy with Agent RPC evaluator")?;
    Ok(policy)
}

fn run() -> Result<()> {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    if arguments.len() != 5 && arguments.len() != 7 {
        bail!(
            "usage: fragment-policy-composer <static-ir.rego> <profile-fragments-dir> <materializations.rego> <compose.rego> <output.json> [<rpc-evaluator.rego> <output.rego>]"
        );
    }
    let static_path = Path::new(&arguments[0]);
    let profile_path = Path::new(&arguments[1]);
    let materializations_path = Path::new(&arguments[2]);
    let composer_path = Path::new(&arguments[3]);
    let output_path = Path::new(&arguments[4]);
    let static_source = load(static_path)?;
    let materializations_source = load(materializations_path)?;
    let composer_source = load(composer_path)?;
    let static_name = static_path.to_string_lossy().into_owned();
    let materializations_name = materializations_path.to_string_lossy().into_owned();
    let composer_name = composer_path.to_string_lossy().into_owned();
    let profile_modules = load_rego_directory(profile_path)?;
    require_package(&static_source, &static_name, "static_policy_ir")?;
    require_package(
        &materializations_source,
        &materializations_name,
        "selected_materializations",
    )?;
    require_package(&composer_source, &composer_name, "fragment_composer")?;
    validate_profile_packages(&profile_modules)?;
    let mut modules = vec![
        (static_name.as_str(), static_source.as_str()),
        (
            materializations_name.as_str(),
            materializations_source.as_str(),
        ),
        (composer_name.as_str(), composer_source.as_str()),
    ];
    modules.extend(
        profile_modules
            .iter()
            .map(|(name, source)| (name.as_str(), source.as_str())),
    );
    let final_policy = evaluate_modules(&modules)?;
    fs::write(
        output_path,
        serde_json::to_string_pretty(&final_policy)? + "\n",
    )
    .with_context(|| format!("write {}", output_path.display()))?;
    if arguments.len() == 7 {
        let evaluator_path = Path::new(&arguments[5]);
        let agent_policy_path = Path::new(&arguments[6]);
        let evaluator = load(evaluator_path)?;
        fs::write(
            agent_policy_path,
            render_rpc_policy(&evaluator, &final_policy)?,
        )
        .with_context(|| format!("write {}", agent_policy_path.display()))?;
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("fragment-policy-composer: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATIC: &str = include_str!("../fixtures/static_ir.rego");
    const FRAGMENT: &str = include_str!("../fixtures/composition_test_profile.rego");
    const MATERIALIZATIONS: &str = "package selected_materializations\n\nmaterializations := []\n";
    const GENERATED_KUBELET_PROFILE: &str =
        "package profile_kubelet_resolution\n\nservice_link_claims(_ir) := []\n";
    const GENERATED_KUBELET_CONTAINERD_PROFILE: &str =
        "package profile_kubelet_or_containerd\n\ngenerated_claims(_ir) := []\n";
    const GENERATED_KUBERNETES_CONTROLLER_PROFILE: &str =
        "package profile_kubernetes_controller\n\nsandbox_name_claims(_ir) := []\n";
    const GENERATED_RUNTIME_ENVELOPE_PROFILE: &str = "package profile_runtime_rs_envelope

volume_storage_claims(_ir) := []
copy_file_claims(_ir) := []
device_claims(_ir) := []
runtime_pattern_claims(_ir) := []
exec_command_claims(_ir) := []
";
    const GENERATED_RUNTIME_RS_PROFILE: &str = "package profile_runtime_rs

volume_mount_claims(_ir) := []
device_claims(_ir) := []
oci_normalization_claims(_ir) := []
";
    const RUNTIME_ENVELOPE_PROFILE: &str =
        include_str!("../profiles/k8s-1.33-containerd-2.3-guest-pull/runtime-rs-envelope.rego");
    const RUNTIME_RS_PROFILE: &str =
        include_str!("../profiles/k8s-1.33-containerd-2.3-guest-pull/runtime-rs.rego");
    const POLICY_FRAMEWORK_PROFILE: &str = include_str!(
        "../profiles/k8s-1.33-containerd-2.3-guest-pull/policy-framework-settings.rego"
    );
    const COMPOSER: &str = include_str!("../policies/compose.rego");
    const AGENT_POLICY: &str = include_str!("../fixtures/agent_policy.rego");
    const STATIC_RUNTIME: &str = include_str!("../fixtures/static_runtime.rego");

    fn evaluate(fragment: &str) -> Result<serde_json::Value> {
        let value = evaluate_modules(&[
            ("static_ir.rego", STATIC),
            ("fragment.rego", fragment),
            ("materializations.rego", MATERIALIZATIONS),
            ("generated-kubelet-profile.rego", GENERATED_KUBELET_PROFILE),
            (
                "generated-kubelet-containerd-profile.rego",
                GENERATED_KUBELET_CONTAINERD_PROFILE,
            ),
            (
                "generated-kubernetes-controller-profile.rego",
                GENERATED_KUBERNETES_CONTROLLER_PROFILE,
            ),
            (
                "generated-runtime-envelope-profile.rego",
                GENERATED_RUNTIME_ENVELOPE_PROFILE,
            ),
            (
                "generated-runtime-rs-profile.rego",
                GENERATED_RUNTIME_RS_PROFILE,
            ),
            ("compose.rego", COMPOSER),
        ])?;
        Ok(serde_json::to_value(value)?)
    }

    fn evaluate_agent_endpoint_with_policy(
        endpoint: &str,
        request: &serde_json::Value,
        policy_data: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let value = evaluate_agent_request(
            &[
                ("static-runtime.rego", STATIC_RUNTIME),
                ("agent-policy.rego", AGENT_POLICY),
            ],
            endpoint,
            request,
            &serde_json::json!({"policy_data": policy_data, "pstate": {}}),
        )?;
        Ok(serde_json::to_value(value)?)
    }

    fn evaluate_agent_endpoint(
        endpoint: &str,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        evaluate_agent_endpoint_with_policy(endpoint, request, evaluate(FRAGMENT)?)
    }

    fn evaluate_create_container(request: &serde_json::Value) -> Result<serde_json::Value> {
        evaluate_agent_endpoint("CreateContainerRequest", request)
    }

    #[test]
    fn rejects_injected_composer_package_in_profile_directory() {
        let modules = vec![(
            "zz-injected.rego".to_string(),
            "package fragment_composer\n\ncategory_claim_valid(_c, _x) if true\n".to_string(),
        )];
        assert!(validate_profile_packages(&modules).is_err());
    }

    #[test]
    fn accepts_expected_profile_packages() {
        let modules = vec![
            (
                "selected.rego".to_string(),
                "package selected_profile_fragments\n".to_string(),
            ),
            (
                "runtime-rs.rego".to_string(),
                "# leading comment\n\npackage profile_runtime_rs\n".to_string(),
            ),
        ];
        assert!(validate_profile_packages(&modules).is_ok());
    }

    #[test]
    fn framework_profile_declares_vfio_evaluator_operands() {
        for path in [
            "/devices/vfio/cdi_annotation_prefix",
            "/devices/vfio/device_number_regex",
            "/devices/vfio/device_id_prefix",
            "/devices/vfio/pci_address_regex",
        ] {
            assert!(
                POLICY_FRAMEWORK_PROFILE.contains(path),
                "missing framework profile claim for {path}"
            );
        }
        for value in [
            "cdi.k8s.io/vfio",
            "^[0-9]+$",
            "vfio",
            "^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}",
        ] {
            assert!(
                POLICY_FRAMEWORK_PROFILE.contains(value),
                "missing framework profile value {value}"
            );
        }
    }

    #[test]
    fn framework_profile_declares_mount_compatibility_operands() {
        assert!(POLICY_FRAMEWORK_PROFILE.contains("/cluster_config/mount_compatibility"));
        for field in [
            "sysfs_type",
            "sysfs_policy_read_write_option",
            "sysfs_request_read_only_option",
            "cgroup_type",
        ] {
            assert!(
                POLICY_FRAMEWORK_PROFILE.contains(field),
                "missing mount compatibility field {field}"
            );
        }
    }

    #[test]
    fn framework_profile_declares_rootfs_compatibility_operands() {
        assert!(POLICY_FRAMEWORK_PROFILE.contains("/cluster_config/rootfs_compatibility"));
        for value in [
            "dmverity_roothash_option_prefix",
            "block_transports",
            "rootfs_mount_points",
            "image_guest_pull=",
        ] {
            assert!(POLICY_FRAMEWORK_PROFILE.contains(value));
        }
    }

    #[test]
    fn framework_profile_declares_bundle_id_grammars() {
        for path in [
            "/common/root_bundle_id_regex",
            "/common/copy_file_bundle_id_regex",
        ] {
            assert!(
                POLICY_FRAMEWORK_PROFILE.contains(path),
                "missing framework profile claim for {path}"
            );
        }
        assert!(POLICY_FRAMEWORK_PROFILE.contains("([0-9a-f]{64}|[a-z0-9][a-z0-9.-]*)"));
        assert!(POLICY_FRAMEWORK_PROFILE.contains("[a-z0-9]{64}"));
    }

    #[test]
    fn framework_profile_declares_common_compatibility_operands() {
        for path in [
            "/evaluator_schema_version",
            "/common/namespace_compatibility",
            "/common/capability_compatibility",
            "/common/copy_file_compatibility",
            "/common/substitutions",
            "/common/request_shape",
        ] {
            assert!(POLICY_FRAMEWORK_PROFILE.contains(path));
        }
    }

    #[test]
    fn framework_profile_matches_canonical_evaluator_settings() {
        let fragment: serde_json::Value = serde_json::from_str(
            POLICY_FRAMEWORK_PROFILE
                .split_once("\nfragment := ")
                .unwrap()
                .1,
        )
        .unwrap();
        let settings: serde_json::Value =
            serde_json::from_str(include_str!("../../../genpolicy-settings.json")).unwrap();
        let migrated_paths = [
            "/evaluator_schema_version",
            "/framework",
            "/common/root_bundle_id_regex",
            "/common/copy_file_bundle_id_regex",
            "/common/namespace_compatibility",
            "/common/capability_compatibility",
            "/common/copy_file_compatibility",
            "/common/substitutions",
            "/common/request_shape",
            "/devices/vfio/cdi_annotation_prefix",
            "/devices/vfio/device_number_regex",
            "/devices/vfio/device_id_prefix",
            "/devices/vfio/pci_address_regex",
            "/cluster_config/mount_compatibility",
            "/cluster_config/rootfs_compatibility",
            "/request_defaults/AddARPNeighborsRequest/allowed_flags",
            "/request_defaults/AddARPNeighborsRequest/required_ip_address_mask",
        ];
        for path in migrated_paths {
            let claim = fragment["claims"]
                .as_array()
                .unwrap()
                .iter()
                .find(|claim| claim["target"]["path"] == path)
                .unwrap_or_else(|| panic!("missing profile claim for {path}"));
            assert_eq!(claim["value"], *settings.pointer(path).unwrap(), "{path}");
        }
    }

    #[test]
    fn framework_profile_declares_arp_operands() {
        assert!(POLICY_FRAMEWORK_PROFILE
            .contains("/request_defaults/AddARPNeighborsRequest/allowed_flags"));
        assert!(POLICY_FRAMEWORK_PROFILE.contains("\"allowed_flags\": 136"));
        assert!(POLICY_FRAMEWORK_PROFILE
            .contains("/request_defaults/AddARPNeighborsRequest/required_ip_address_mask"));
        assert!(POLICY_FRAMEWORK_PROFILE.contains("\"required_ip_address_mask\": \"\""));
    }

    #[test]
    fn rejects_module_without_package_declaration() {
        assert!(package_of("allow := true\n", "bad.rego").is_err());
    }

    #[test]
    fn materializes_controller_policy_with_regorus() {
        let result = evaluate(FRAGMENT).unwrap();
        assert_eq!(
            result["containers"][0]["OCI"]["Annotations"]["io.kubernetes.cri.sandbox-name"],
            "^demo$"
        );
        assert_eq!(result["containers"][0]["OCI"]["Version"], "1.1.0");
        assert_eq!(
            result["framework"]["annotations"]["cri_container_type"],
            "io.kubernetes.cri.container-type"
        );
        assert!(result["containers"][0]["OCI"]["Process"]["Env"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("DEMO_SERVICE_HOST=10.0.0.10")));
        assert_eq!(
            result["containers"][0]["OCI"]["Process"]["Args"][0],
            "/usr/bin/app"
        );
        assert!(result.get("subjects").is_none());
    }

    #[test]
    fn parameterized_evaluator_allows_composed_policy_request() {
        let request = serde_json::json!({
            "OCI": {
                "Annotations": {
                    "io.kubernetes.cri.container-type": "container",
                    "io.kubernetes.cri.sandbox-name": "demo",
                },
                "Process": {"Args": ["/usr/bin/app"]},
                "Version": "1.1.0",
            },
        });

        assert_eq!(
            evaluate_create_container(&request).unwrap(),
            serde_json::json!({"allowed": true, "ops": []})
        );
    }

    #[test]
    fn parameterized_evaluator_denies_static_and_profile_mutations() {
        let request = serde_json::json!({
            "OCI": {
                "Annotations": {
                    "io.kubernetes.cri.container-type": "container",
                    "io.kubernetes.cri.sandbox-name": "demo",
                },
                "Process": {"Args": ["/usr/bin/app"]},
                "Version": "1.1.0",
            },
        });
        let mut changed_args = request.clone();
        changed_args["OCI"]["Process"]["Args"][0] = serde_json::json!("/bin/sh");
        let mut changed_version = request.clone();
        changed_version["OCI"]["Version"] = serde_json::json!("1.2.0");
        let mut changed_type = request.clone();
        changed_type["OCI"]["Annotations"]["io.kubernetes.cri.container-type"] =
            serde_json::json!("sandbox");
        let mut changed_name = request;
        changed_name["OCI"]["Annotations"]["io.kubernetes.cri.sandbox-name"] =
            serde_json::json!("other");

        for mutation in [
            &changed_args,
            &changed_version,
            &changed_type,
            &changed_name,
        ] {
            assert_eq!(
                evaluate_create_container(mutation).unwrap(),
                serde_json::json!({"allowed": false, "ops": []})
            );
        }
    }

    #[test]
    fn generic_evaluator_rejects_unanchored_profile_regex() {
        let request = serde_json::json!({
            "OCI": {
                "Annotations": {
                    "io.kubernetes.cri.container-type": "container",
                    "io.kubernetes.cri.sandbox-name": "demo",
                },
                "Process": {"Args": ["/usr/bin/app"]},
                "Version": "1.1.0",
            },
        });
        let unanchored_fragment = FRAGMENT.replace("^demo$", "demo");
        assert_eq!(
            evaluate_agent_endpoint_with_policy(
                "CreateContainerRequest",
                &request,
                evaluate(&unanchored_fragment).unwrap(),
            )
            .unwrap(),
            serde_json::json!({"allowed": false, "ops": []})
        );
    }

    #[test]
    fn generic_evaluator_uses_composed_annotation_keys() {
        let request = serde_json::json!({
            "OCI": {
                "Annotations": {
                    "io.kubernetes.cri.container-type": "container",
                    "io.kubernetes.cri.sandbox-name": "demo",
                },
                "Process": {"Args": ["/usr/bin/app"]},
                "Version": "1.1.0",
            },
        });
        let mut policy_data = evaluate(FRAGMENT).unwrap();
        policy_data["framework"]["annotations"]["cri_container_type"] =
            serde_json::json!("example.invalid/container-role");

        assert_eq!(
            evaluate_agent_endpoint_with_policy("CreateContainerRequest", &request, policy_data,)
                .unwrap(),
            serde_json::json!({"allowed": false, "ops": []})
        );
    }

    #[test]
    fn generic_agent_module_owns_rpc_endpoint_defaults() {
        let empty_request = serde_json::json!({});

        assert_eq!(
            evaluate_agent_endpoint("StatsContainerRequest", &empty_request).unwrap(),
            serde_json::json!(true)
        );
        assert_eq!(
            evaluate_agent_endpoint("CopyFileRequest", &empty_request).unwrap(),
            serde_json::json!(false)
        );
        assert_eq!(
            evaluate_agent_endpoint("AllowRequestsFailingPolicy", &empty_request).unwrap(),
            serde_json::json!(false)
        );
        assert!(evaluate_agent_endpoint("UnknownRequest", &empty_request).is_err());
    }

    #[test]
    fn applies_to_mismatch_fails_closed() {
        let fragment = FRAGMENT.replace(
            "\"containerd\": [\"v2.3.3\"]",
            "\"containerd\": [\"v2.4.0\"]",
        );
        assert!(evaluate(&fragment).is_err());
    }

    #[test]
    fn fragment_replacement_keeps_static_ir_unchanged() {
        let replacement = FRAGMENT.replace("1.1.0", "1.2.0");
        assert_ne!(replacement, FRAGMENT);
        let result = evaluate(&replacement).unwrap();
        assert_eq!(result["containers"][0]["OCI"]["Version"], "1.2.0");
    }

    #[test]
    fn missing_required_category_fails_closed() {
        let static_ir = STATIC.replace(
            "\"categories\": [\"kubelet-resolution\"]",
            "\"categories\": [\"kubelet-resolution\", \"runtime-rs\"]",
        );
        assert!(evaluate_modules(&[
            ("static_ir.rego", &static_ir),
            ("fragment.rego", FRAGMENT),
            ("materializations.rego", MATERIALIZATIONS),
            ("generated-kubelet-profile.rego", GENERATED_KUBELET_PROFILE),
            (
                "generated-kubelet-containerd-profile.rego",
                GENERATED_KUBELET_CONTAINERD_PROFILE,
            ),
            (
                "generated-kubernetes-controller-profile.rego",
                GENERATED_KUBERNETES_CONTROLLER_PROFILE,
            ),
            (
                "generated-runtime-envelope-profile.rego",
                GENERATED_RUNTIME_ENVELOPE_PROFILE,
            ),
            (
                "generated-runtime-rs-profile.rego",
                GENERATED_RUNTIME_RS_PROFILE
            ),
            ("compose.rego", COMPOSER),
        ])
        .is_err());
    }

    #[test]
    fn composition_schema_version_mismatch_fails_closed() {
        let static_ir = STATIC.replace(
            "\"composition_schema_version\": 1",
            "\"composition_schema_version\": 2",
        );
        assert!(evaluate_modules(&[
            ("static_ir.rego", &static_ir),
            ("fragment.rego", FRAGMENT),
            ("materializations.rego", MATERIALIZATIONS),
            ("generated-kubelet-profile.rego", GENERATED_KUBELET_PROFILE),
            (
                "generated-kubelet-containerd-profile.rego",
                GENERATED_KUBELET_CONTAINERD_PROFILE,
            ),
            (
                "generated-kubernetes-controller-profile.rego",
                GENERATED_KUBERNETES_CONTROLLER_PROFILE,
            ),
            (
                "generated-runtime-envelope-profile.rego",
                GENERATED_RUNTIME_ENVELOPE_PROFILE,
            ),
            (
                "generated-runtime-rs-profile.rego",
                GENERATED_RUNTIME_RS_PROFILE
            ),
            ("compose.rego", COMPOSER),
        ])
        .is_err());
    }

    #[test]
    fn replacing_static_field_fails_closed() {
        let fragment = FRAGMENT.replace(
            "/OCI/Annotations/io.kubernetes.cri.sandbox-name",
            "/OCI/Annotations/io.kubernetes.cri.container-name",
        );
        assert!(evaluate(&fragment).is_err());
    }

    #[test]
    fn addition_outside_declared_target_fails_closed() {
        let fragment = FRAGMENT.replace(
            r#""addition": {"OCI": {"Version": "1.1.0"}},"#,
            r#""addition": {"OCI": {"Process": {"Args": ["/bin/sh"]}}},"#,
        );
        assert!(evaluate(&fragment).is_err());
    }

    #[test]
    fn addition_with_extra_branch_fails_closed() {
        let fragment = FRAGMENT.replace(
            r#""addition": {"OCI": {"Version": "1.1.0"}},"#,
            r#""addition": {"OCI": {"Version": "1.1.0", "Hostname": "evil"}},"#,
        );
        assert!(evaluate(&fragment).is_err());
    }

    #[test]
    fn generated_claim_outside_declared_target_fails_closed() {
        let generated = r#"package profile_runtime_rs

volume_mount_claims(_ir) := [{
    "addition": {"OCI": {"Process": {"Args": ["/bin/sh"]}}},
    "category": "runtime-rs",
    "operation": "rewrite",
    "subject": "container/app",
    "target": {"path": "/OCI/Mounts"},
}]
"#;
        assert!(evaluate_modules(&[
            ("static_ir.rego", STATIC),
            ("fragment.rego", FRAGMENT),
            ("materializations.rego", MATERIALIZATIONS),
            ("generated-kubelet-profile.rego", GENERATED_KUBELET_PROFILE),
            (
                "generated-kubelet-containerd-profile.rego",
                GENERATED_KUBELET_CONTAINERD_PROFILE,
            ),
            (
                "generated-kubernetes-controller-profile.rego",
                GENERATED_KUBERNETES_CONTROLLER_PROFILE,
            ),
            (
                "generated-runtime-envelope-profile.rego",
                GENERATED_RUNTIME_ENVELOPE_PROFILE,
            ),
            ("generated-runtime-rs-profile.rego", generated),
            ("compose.rego", COMPOSER),
        ])
        .is_err());
    }

    #[test]
    fn duplicate_claim_ownership_fails_closed() {
        let fragment = FRAGMENT.replace(
            "\"path\": \"/OCI/Process/Env/DEMO_SERVICE_HOST\"",
            "\"path\": \"/OCI/Version\"",
        );
        assert!(evaluate(&fragment).is_err());
    }

    #[test]
    fn unknown_subject_fails_closed() {
        let fragment = FRAGMENT.replace(
            "\"subject\": \"container/app\"",
            "\"subject\": \"container/missing\"",
        );
        assert!(evaluate(&fragment).is_err());
    }

    #[test]
    fn category_contract_violation_fails_closed() {
        let fragment = FRAGMENT.replace(
            "\"category\": \"kubelet-resolution\"",
            "\"category\": \"runtime-rs\"",
        );
        assert!(evaluate(&fragment).is_err());
    }

    #[test]
    fn uncovered_materialization_fails_closed() {
        let profile = r#"package selected_profile_fragments

fragments := [{
    "applies_to": {"kubernetes": ["v1.33.13"]},
    "category": "kubelet-resolution",
    "claims": [],
    "materialization_contracts": [{
        "operations": ["resolve"],
        "path_regex": "^/OCI/Process/Env/ALLOWED$",
    }],
    "schema_version": 1,
    "scope": "profile",
}]
"#;
        let materializations = r#"package selected_materializations

materializations := [{
    "category": "kubelet-resolution",
    "claims": [{
        "addition": {"OCI": {"Process": {"Env": {"DENIED": "value"}}}},
        "operation": "resolve",
        "target": {"path": "/OCI/Process/Env/DENIED", "subject": "container/app"},
    }],
    "schema_version": 1,
    "scope": "static-base-materialization",
    "static_base_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
}]
"#;
        assert!(evaluate_modules(&[
            ("static_ir.rego", STATIC),
            ("profile.rego", profile),
            ("materializations.rego", materializations),
            ("generated-kubelet-profile.rego", GENERATED_KUBELET_PROFILE),
            (
                "generated-kubelet-containerd-profile.rego",
                GENERATED_KUBELET_CONTAINERD_PROFILE,
            ),
            (
                "generated-kubernetes-controller-profile.rego",
                GENERATED_KUBERNETES_CONTROLLER_PROFILE,
            ),
            (
                "generated-runtime-envelope-profile.rego",
                GENERATED_RUNTIME_ENVELOPE_PROFILE,
            ),
            (
                "generated-runtime-rs-profile.rego",
                GENERATED_RUNTIME_RS_PROFILE
            ),
            ("compose.rego", COMPOSER),
        ])
        .is_err());
    }

    #[test]
    fn simulates_agent_installing_composed_data_into_rpc_evaluator() {
        let result = evaluate_modules(&[
            ("static_ir.rego", STATIC),
            ("fragment.rego", FRAGMENT),
            ("materializations.rego", MATERIALIZATIONS),
            ("generated-kubelet-profile.rego", GENERATED_KUBELET_PROFILE),
            (
                "generated-kubelet-containerd-profile.rego",
                GENERATED_KUBELET_CONTAINERD_PROFILE,
            ),
            (
                "generated-kubernetes-controller-profile.rego",
                GENERATED_KUBERNETES_CONTROLLER_PROFILE,
            ),
            (
                "generated-runtime-envelope-profile.rego",
                GENERATED_RUNTIME_ENVELOPE_PROFILE,
            ),
            (
                "generated-runtime-rs-profile.rego",
                GENERATED_RUNTIME_RS_PROFILE,
            ),
            ("compose.rego", COMPOSER),
        ])
        .unwrap();
        let evaluator = "package agent_policy\n\ndefault AllowRequestsFailingPolicy := false\ndefault CreateContainerRequest := false\n";
        let policy = render_rpc_policy(evaluator, &result).unwrap();
        assert!(policy.starts_with("package agent_policy\n"));
        assert!(policy.contains("default CreateContainerRequest := false"));
        assert!(policy.contains("\npolicy_data := {"));
        assert!(policy.contains("\"containers\""));
        let mut engine = Engine::new();
        engine
            .add_policy("policy.rego".to_string(), policy)
            .unwrap();
    }

    #[test]
    fn rejects_rpc_evaluator_outside_agent_policy_package() {
        let result = evaluate_modules(&[
            ("static_ir.rego", STATIC),
            ("fragment.rego", FRAGMENT),
            ("materializations.rego", MATERIALIZATIONS),
            ("generated-kubelet-profile.rego", GENERATED_KUBELET_PROFILE),
            (
                "generated-kubelet-containerd-profile.rego",
                GENERATED_KUBELET_CONTAINERD_PROFILE,
            ),
            (
                "generated-kubernetes-controller-profile.rego",
                GENERATED_KUBERNETES_CONTROLLER_PROFILE,
            ),
            (
                "generated-runtime-envelope-profile.rego",
                GENERATED_RUNTIME_ENVELOPE_PROFILE,
            ),
            (
                "generated-runtime-rs-profile.rego",
                GENERATED_RUNTIME_RS_PROFILE,
            ),
            ("compose.rego", COMPOSER),
        ])
        .unwrap();
        assert!(render_rpc_policy("package other\n", &result).is_err());
    }

    #[test]
    fn rejects_rpc_evaluator_with_embedded_policy_data() {
        let result = evaluate_modules(&[
            ("static_ir.rego", STATIC),
            ("fragment.rego", FRAGMENT),
            ("materializations.rego", MATERIALIZATIONS),
            ("generated-kubelet-profile.rego", GENERATED_KUBELET_PROFILE),
            (
                "generated-kubelet-containerd-profile.rego",
                GENERATED_KUBELET_CONTAINERD_PROFILE,
            ),
            (
                "generated-kubernetes-controller-profile.rego",
                GENERATED_KUBERNETES_CONTROLLER_PROFILE,
            ),
            (
                "generated-runtime-envelope-profile.rego",
                GENERATED_RUNTIME_ENVELOPE_PROFILE,
            ),
            (
                "generated-runtime-rs-profile.rego",
                GENERATED_RUNTIME_RS_PROFILE,
            ),
            ("compose.rego", COMPOSER),
        ])
        .unwrap();
        let evaluator = "package agent_policy\n\npolicy_data := {}\n";
        assert!(render_rpc_policy(evaluator, &result).is_err());
    }

    #[test]
    fn runtime_fragments_lower_typed_volume_intent() {
        let static_ir = r#"package static_policy_ir

ir := {"subjects": [{
    "id": "container/app",
    "role": "application",
    "volumes": [
        {"name": "cache", "role": "empty-dir", "medium": "memory", "destination": "/cache", "read_only": false},
        {"name": "data", "role": "empty-dir", "medium": "node-default", "destination": "/data", "read_only": true},
        {"name": "config", "role": "config-map", "source": {"name": "app-config", "namespace": "default", "content_trust": "untrusted-runtime"}, "destination": "/etc/configuration", "destination_basename": "configuration", "read_only": true},
        {"name": "config-alias", "role": "config-map", "source": {"name": "app-config", "namespace": "default", "content_trust": "untrusted-runtime"}, "destination": "/opt/configuration", "destination_basename": "configuration", "read_only": true},
        {"name": "secret", "role": "secret", "source": {"name": "app-secret", "namespace": "default", "content_trust": "untrusted-runtime"}, "destination": "/etc/credentials", "destination_basename": "credentials", "read_only": true},
    ],
}, {
    "id": "container/optional",
    "role": "application",
    "volumes": [
        {"name": "optional-secret", "role": "secret", "source": {"name": "missing", "namespace": "default", "content_trust": "untrusted-runtime"}, "destination": "/etc/missing", "destination_basename": "missing", "read_only": true},
    ],
}]}
"#;
        let value = evaluate_modules_query(
            &[
                ("static-ir.rego", static_ir),
                ("runtime-envelope.rego", RUNTIME_ENVELOPE_PROFILE),
            ],
            "data.profile_runtime_rs_envelope.volume_storage_claims(data.static_policy_ir.ir)",
        )
        .unwrap();
        let claims = serde_json::to_value(value).unwrap();
        let storages = claims[0]["addition"]["storages"].as_array().unwrap();

        assert_eq!(claims.as_array().unwrap().len(), 2);
        assert_eq!(claims[0]["subject"], "container/app");
        assert_eq!(claims[0]["target"]["path"], "/storages");
        assert_eq!(storages[0]["driver"], "ephemeral");
        assert_eq!(storages[0]["source"], "tmpfs");
        assert_eq!(
            storages[0]["mount_point"],
            "^/run/kata-containers/sandbox/ephemeral/cache$"
        );
        assert_eq!(storages[1]["driver"], "local");
        assert_eq!(storages[1]["source"], "local");
        assert_eq!(storages[1]["options"], serde_json::json!(["mode=0777"]));
        assert_eq!(
            storages[1]["mount_point"],
            "^$(cpath)/$(sandbox-id)/rootfs/local/data$"
        );

        let value = evaluate_modules_query(
            &[
                ("static-ir.rego", static_ir),
                ("runtime-rs.rego", RUNTIME_RS_PROFILE),
            ],
            "data.profile_runtime_rs.volume_mount_claims(data.static_policy_ir.ir)",
        )
        .unwrap();
        let claims = serde_json::to_value(value).unwrap();
        let mounts = claims[0]["addition"]["OCI"]["Mounts"].as_array().unwrap();
        let volume_mounts = &mounts[mounts.len() - 5..];

        assert_eq!(claims[0]["target"]["path"], "/OCI/Mounts");
        assert_eq!(volume_mounts[0]["destination"], "/cache");
        assert_eq!(volume_mounts[0]["source"], "");
        assert_eq!(
            volume_mounts[0]["options"],
            serde_json::json!(["rbind", "rprivate", "rw"])
        );
        assert_eq!(volume_mounts[1]["destination"], "/data");
        assert_eq!(
            volume_mounts[1]["options"],
            serde_json::json!(["rbind", "rprivate", "ro"])
        );
        assert_eq!(volume_mounts[2]["destination"], "/etc/configuration");
        assert_eq!(
            volume_mounts[2]["source"],
            "^$(cpath)/$(bundle-id)-[0-9a-f]{16}-configuration$"
        );
        assert_eq!(
            volume_mounts[2]["options"],
            serde_json::json!(["rbind", "rprivate", "ro"])
        );
        assert_eq!(volume_mounts[4]["destination"], "/etc/credentials");
        assert_eq!(
            volume_mounts[4]["source"],
            "^$(cpath)/$(bundle-id)-[0-9a-f]{16}-credentials$"
        );

        let value = evaluate_modules_query(
            &[
                ("static-ir.rego", static_ir),
                ("runtime-envelope.rego", RUNTIME_ENVELOPE_PROFILE),
            ],
            "data.profile_runtime_rs_envelope.copy_file_claims(data.static_policy_ir.ir)",
        )
        .unwrap();
        let claims = serde_json::to_value(value).unwrap();

        assert_eq!(claims.as_array().unwrap().len(), 1);
        assert_eq!(
            claims[0]["target"]["path"],
            "/request_defaults/CopyFileRequest"
        );
        assert_eq!(
            claims[0]["addition"]["request_defaults"]["CopyFileRequest"],
            serde_json::json!([
                "^$(cpath)/$(bundle-id)-[0-9a-f]{16}-configuration",
                "^$(cpath)/$(bundle-id)-[0-9a-f]{16}-credentials",
                "^$(cpath)/$(bundle-id)-[0-9a-f]{16}-missing"
            ])
        );
    }

    #[test]
    fn runtime_fragments_lower_uvm_only_device_and_direct_volume_intent() {
        let static_ir = r#"package static_policy_ir

ir := {"subjects": [{
    "id": "container/app",
    "role": "application",
    "device_requests": {
        "extended_resources": [{"count": 2, "resource": "nvidia.com/gpu", "resolution": "device-profile"}],
        "volume_devices": [{"device_path": "/dev/data", "name": "claim-block", "resolution": "uvm-device"}],
    },
    "volumes": [{
        "destination": "/external/host",
        "destination_basename": "host",
        "name": "host-data",
        "read_only": true,
        "role": "direct-volume",
        "uvm": {"content_trust": "untrusted-runtime", "transport": "shared-fs"},
    }],
}]}
"#;
        let value = evaluate_modules_query(
            &[
                ("static-ir.rego", static_ir),
                ("runtime-rs.rego", RUNTIME_RS_PROFILE),
            ],
            "{\"mounts\": data.profile_runtime_rs.volume_mount_claims(data.static_policy_ir.ir), \"linux\": data.profile_runtime_rs.device_claims(data.static_policy_ir.ir)}",
        )
        .unwrap();
        let claims = serde_json::to_value(value).unwrap();
        let mounts = claims["mounts"][0]["addition"]["OCI"]["Mounts"]
            .as_array()
            .unwrap();
        let direct_mount = mounts.last().unwrap();
        assert_eq!(direct_mount["destination"], "/external/host");
        assert_eq!(
            direct_mount["source"],
            "^$(cpath)/$(bundle-id)-[0-9a-f]{16}-host$"
        );
        assert_eq!(
            claims["linux"][0]["addition"]["OCI"]["Linux"]["Devices"],
            serde_json::json!([{"Path": "/dev/data", "Type": ""}])
        );

        let value = evaluate_modules_query(
            &[
                ("static-ir.rego", static_ir),
                ("runtime-envelope.rego", RUNTIME_ENVELOPE_PROFILE),
            ],
            "{\"devices\": data.profile_runtime_rs_envelope.device_claims(data.static_policy_ir.ir), \"patterns\": data.profile_runtime_rs_envelope.runtime_pattern_claims(data.static_policy_ir.ir)}",
        )
        .unwrap();
        let claims = serde_json::to_value(value).unwrap();
        let devices = claims["devices"][0]["addition"]["devices"]
            .as_array()
            .unwrap();
        assert_eq!(devices.len(), 3);
        assert_eq!(devices[0]["container_path"], "/dev/data");
        assert!(devices[0]["id"].as_str().unwrap().is_empty());
        assert_eq!(devices[1]["container_path"], "/dev/vfio/devices/vfio");
        assert_eq!(devices[1]["type_"], "vfio-pci-gk");
        assert_eq!(devices[2], devices[1]);
        let serialized = serde_json::to_string(&claims).unwrap();
        assert!(serialized.contains("cdi\\\\.k8s\\\\.io/vfio"));
        assert!(!serialized.contains("/var/lib"));
        assert!(!serialized.contains("0000:"));
        assert!(!serialized.contains("device-test-data"));
    }
}
