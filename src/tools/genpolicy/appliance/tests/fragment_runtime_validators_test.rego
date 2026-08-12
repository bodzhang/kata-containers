package agent_policy

fixture_policy_data := json.unmarshal(`{
    "common": {
        "cpath": "/run/kata-containers/shared/containers",
        "root_path": "/run/kata-containers/$(bundle-id)/rootfs",
        "root_bundle_id_regex": "([0-9a-f]{64}|[a-z0-9][a-z0-9.-]*)",
        "substitutions": {
            "bundle_id": "$(bundle-id)",
            "cpath": "$(cpath)",
            "root_path": "$(root_path)",
            "unresolved_token_regex": "\\$\\([^)]*\\)"
        }
    },
    "framework": {
        "annotations": {
            "container_name": "io.kubernetes.cri.container-name",
            "cri_container_type": "io.kubernetes.cri.container-type",
            "cri_prefix": "io.kubernetes.cri.",
            "kata_container_type": "io.katacontainers.pkg.oci.container_type",
            "network_namespace": "nerdctl/network-namespace",
            "sandbox_id": "io.kubernetes.cri.sandbox-id",
            "sandbox_log_directory": "io.kubernetes.cri.sandbox-log-directory",
            "sandbox_name": "io.kubernetes.cri.sandbox-name",
            "sandbox_namespace": "io.kubernetes.cri.sandbox-namespace",
            "sandbox_uid": "io.kubernetes.cri.sandbox-uid"
        },
        "paths": {"pod_log_directory_format": "/var/log/pods/%s_%s_%s"},
        "roles": {
            "cri_container": "container",
            "cri_sandbox": "sandbox",
            "kata_container": "pod_container",
            "kata_sandbox": "pod_sandbox"
        }
    },
    "request_defaults": {"CreateContainerRequest": {"allow_env_regex": []}}
}`)

policy_data := fixture_policy_data

framework_operand_policy(section, key, value) := object.union(fixture_policy_data, {
    "framework": object.union(fixture_policy_data.framework, {
        section: object.union(fixture_policy_data.framework[section], {key: value}),
    }),
})

common_operand_policy(key, value) := object.union(fixture_policy_data, {
    "common": object.union(fixture_policy_data.common, {key: value}),
})

test_fragment_oci_version_exact_allowed if {
    allow_oci_version({"Version": "1.1.0"}, {"Version": "1.1.0"})
}

test_fragment_oci_version_mismatch_denied if {
    not allow_oci_version({"Version": "1.1.0"}, {"Version": "1.0.2"})
}

test_fragment_container_role_exact_allowed if {
    role := allow_container_role(
        {"Annotations": {"io.kubernetes.cri.container-type": "container"}},
        {"Annotations": {"io.kubernetes.cri.container-type": "container"}},
    )
    role == "container"
}

test_fragment_container_role_mismatch_denied if {
    not allow_container_role(
        {"Annotations": {"io.kubernetes.cri.container-type": "container"}},
        {"Annotations": {"io.kubernetes.cri.container-type": "sandbox"}},
    )
}

test_fragment_pod_log_directory_format_allowed if {
    identity := {
        "pod_name": "demo",
        "pod_namespace": "default",
        "pod_uid": "12345678-1234-1234-9234-123456789abc",
    }
    expected_sandbox_log_directory(identity) == "/var/log/pods/default_demo_12345678-1234-1234-9234-123456789abc"
}

test_fragment_annotation_key_mutation_denied if {
    mutated := framework_operand_policy("annotations", "cri_container_type", "example.invalid/container-role")
    not allow_container_role(
        {"Annotations": {"io.kubernetes.cri.container-type": "container"}},
        {"Annotations": {"io.kubernetes.cri.container-type": "container"}},
    ) with data.agent_policy.policy_data as mutated
}

test_fragment_role_mutation_denied if {
    identity := {
        "pod_name": "demo",
        "pod_namespace": "default",
        "pod_uid": null,
    }
    oci := {"Annotations": {"io.kubernetes.cri.container-type": "sandbox"}}
    mutated := framework_operand_policy("roles", "cri_sandbox", "infra")
    not allow_pod_identity_shape(oci, identity) with data.agent_policy.policy_data as mutated
}

test_fragment_pod_log_format_mutation_denied if {
    identity := {
        "pod_name": "demo",
        "pod_namespace": "default",
        "pod_uid": "12345678-1234-1234-9234-123456789abc",
    }
    oci := {"Annotations": {
        "io.kubernetes.cri.container-type": "sandbox",
        "io.kubernetes.cri.sandbox-log-directory": "/var/log/pods/default_demo_12345678-1234-1234-9234-123456789abc",
    }}
    mutated := framework_operand_policy("paths", "pod_log_directory_format", "/different/%s_%s_%s")
    not allow_pod_identity_shape(oci, identity) with data.agent_policy.policy_data as mutated
}

test_fragment_cpath_exact_allowed if {
    regex.match(
        substitute_cpath("^$(cpath)/bundle/rootfs$"),
        "/run/kata-containers/shared/containers/bundle/rootfs",
    )
}

test_fragment_cpath_mismatch_denied if {
    not regex.match(
        substitute_cpath("^$(cpath)/bundle/rootfs$"),
        "/run/kata-containers/other/bundle/rootfs",
    )
}

test_root_bundle_id_extracted_from_generated_grammar if {
    root_path_bundle_id(
        "$(root_path)",
        "/run/kata-containers/demo-container/rootfs",
    ) == "demo-container"
}

test_root_bundle_id_grammar_mutation_denied if {
    mutated := common_operand_policy("root_bundle_id_regex", "([0-9a-f]{64})")
    not root_path_bundle_id(
        "$(root_path)",
        "/run/kata-containers/demo-container/rootfs",
    ) with data.agent_policy.policy_data as mutated
}