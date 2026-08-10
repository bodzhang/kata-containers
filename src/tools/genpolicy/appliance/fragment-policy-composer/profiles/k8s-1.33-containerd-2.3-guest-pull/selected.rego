package selected_profile_fragments

# Assembles the independently reviewable fragments that form this runtime,
# Kubernetes, containerd, and guest-pull profile.
fragments := [
    data.profile_containerd_oci.fragment,
    data.profile_kubelet_or_containerd.fragment,
    data.profile_kubelet_resolution.fragment,
    data.profile_policy_framework_settings.fragment,
    data.profile_runtime_rs.fragment,
    data.profile_runtime_rs_envelope.fragment,
]