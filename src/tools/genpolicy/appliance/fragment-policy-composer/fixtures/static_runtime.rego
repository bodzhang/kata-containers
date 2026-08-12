package fragment_static_policy

default validate_create_container(_, _) := false

validate_create_container(request, policy_container) if {
    request.OCI.Process.Args == policy_container.OCI.Process.Args
}