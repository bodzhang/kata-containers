package selected_profile_fragments

capture_provenance := "8b0ae298134cf114935b140f42fc2ca8a8294a674ecbeb58d4727ee2f33f00d2"
static_base_digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

fragments := [
    {
        "applies_to": {"containerd": ["v2.3.3"]},
        "capture_provenance": capture_provenance,
        "category": "containerd-oci",
        "claims": [
            {
                "addition": {"OCI": {"Version": "1.1.0"}},
                "operation": "default",
                "target": {"cardinality": "all", "path": "/OCI/Version", "role": "all", "scope": "container"},
                "value": "1.1.0",
            },
            {
                "addition": {"OCI": {"Annotations": {"io.kubernetes.cri.container-type": "container"}}},
                "operation": "default",
                "target": {"cardinality": "all", "path": "/OCI/Annotations/io.kubernetes.cri.container-type", "role": "application", "scope": "container"},
                "value": "container",
            },
        ],
        "schema_version": 1,
        "scope": "profile",
    },
    {
        "applies_to": {"kubernetes": ["v1.33.13"]},
        "capture_provenance": capture_provenance,
        "category": "policy-framework-settings",
        "claims": [{
            "addition": {"framework": {"annotations": {
                "cri_container_type": "io.kubernetes.cri.container-type",
                "sandbox_name": "io.kubernetes.cri.sandbox-name",
            }}},
            "operation": "default",
            "target": {"path": "/framework", "scope": "policy"},
            "value": {"annotations": {
                "cri_container_type": "io.kubernetes.cri.container-type",
                "sandbox_name": "io.kubernetes.cri.sandbox-name",
            }},
        }],
        "schema_version": 1,
        "scope": "profile",
    },
    {
        "applies_to": {"kubernetes": ["v1.33.13"]},
        "capture_provenance": capture_provenance,
        "category": "kubelet-resolution",
        "claims": [{
            "addition": {"OCI": {"Process": {"Env": {"DEMO_SERVICE_HOST": "10.0.0.10"}}}},
            "operation": "resolve",
            "target": {"cardinality": "all", "path": "/OCI/Process/Env/DEMO_SERVICE_HOST", "role": "application", "scope": "container"},
            "value": "10.0.0.10",
        }],
        "schema_version": 1,
        "scope": "profile",
    },
    {
        "category": "kubernetes-controller",
        "claims": [{
            "addition": {"OCI": {"Annotations": {"io.kubernetes.cri.sandbox-name": "^demo$"}}},
            "operation": "derive",
            "target": {"path": "/OCI/Annotations/io.kubernetes.cri.sandbox-name", "subject": "container/app"},
            "value": "^demo$",
        }],
        "schema_version": 1,
        "scope": "static-base-materialization",
        "static_base_digest": static_base_digest,
    },
]