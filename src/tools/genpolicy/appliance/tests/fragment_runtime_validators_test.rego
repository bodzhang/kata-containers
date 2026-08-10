package agent_policy

policy_data := json.unmarshal(`{"common":{"cpath":"/run/kata-containers/shared/containers"},"request_defaults":{"CreateContainerRequest":{"allow_env_regex":[]}}}`)

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