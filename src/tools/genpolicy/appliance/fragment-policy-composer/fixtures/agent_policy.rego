package agent_policy

default AllowRequestsFailingPolicy := false
default GetDiagnosticDataRequest := false
default AddARPNeighborsRequest := false
default AddSwapPathRequest := false
default AddSwapRequest := false
default CloseStdinRequest := false
default CopyFileRequest := false
default CreateContainerRequest := {"allowed": false, "ops": []}
default CreateSandboxRequest := false
default DestroySandboxRequest := true
default ExecProcessRequest := false
default GetIPTablesRequest := false
default GetMetricsRequest := false
default GetOOMEventRequest := true
default GuestDetailsRequest := true
default ListInterfacesRequest := false
default ListRoutesRequest := false
default MemAgentCompactConfig := false
default MemAgentMemcgConfig := false
default MemHotplugByProbeRequest := false
default OnlineCPUMemRequest := true
default PauseContainerRequest := false
default ReadStreamRequest := false
default RemoveContainerRequest := true
default RemoveStaleVirtiofsShareMountsRequest := true
default ReseedRandomDevRequest := false
default ResizeVolumeRequest := false
default ResumeContainerRequest := false
default SetGuestDateTimeRequest := false
default SetIPTablesRequest := false
default SetPolicyRequest := false
default SignalProcessRequest := true
default StartContainerRequest := true
default StartTracingRequest := false
default StatsContainerRequest := true
default StopTracingRequest := false
default TtyWinResizeRequest := true
default UpdateContainerRequest := false
default UpdateEphemeralMountsRequest := false
default UpdateInterfaceRequest := false
default UpdateRoutesRequest := false
default VolumeStatsRequest := false
default WaitProcessRequest := true
default WriteStreamRequest := false

allow_oci_version(policy_oci, request_oci) if {
    policy_oci.Version == request_oci.Version
}

allow_container_role(policy_oci, request_oci) if {
    key := data.policy_data.framework.annotations.cri_container_type
    policy_oci.Annotations[key] == request_oci.Annotations[key]
}

allow_sandbox_name(policy_oci, request_oci) if {
    key := data.policy_data.framework.annotations.sandbox_name
    pattern := policy_oci.Annotations[key]
    startswith(pattern, "^")
    endswith(pattern, "$")
    regex.match(pattern, request_oci.Annotations[key])
}

CreateContainerRequest := {"allowed": true, "ops": []} if {
    some container in data.policy_data.containers
    data.fragment_static_policy.validate_create_container(input, container)
    allow_oci_version(container.OCI, input.OCI)
    allow_container_role(container.OCI, input.OCI)
    allow_sandbox_name(container.OCI, input.OCI)
}