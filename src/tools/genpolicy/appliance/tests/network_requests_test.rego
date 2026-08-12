package agent_policy

fixture_arp_policy_data := json.unmarshal(`{
    "evaluator_schema_version": 1,
    "request_defaults": {
        "AddARPNeighborsRequest": {
            "allowed_flags": 136,
            "allowed_states": [2, 128],
            "forbidden_cidrs_regex": ["^127\\."],
            "forbidden_device_names": ["lo"],
            "required_ip_address_mask": ""
        }
    }
}`)

policy_data := fixture_arp_policy_data

arp_request(flags) := {
    "neighbors": {
        "ARPNeighbors": [{
            "device": "eth0",
            "flags": flags,
            "state": 128,
            "toIPAddress": {
                "address": "10.0.0.1",
                "mask": "",
            },
        }],
    },
}

arp_policy_with_allowed_flags(allowed_flags) := {
    "evaluator_schema_version": 1,
    "request_defaults": {
        "AddARPNeighborsRequest": object.union(
            fixture_arp_policy_data.request_defaults.AddARPNeighborsRequest,
            {"allowed_flags": allowed_flags},
        ),
    },
}

arp_policy_with_required_mask(required_mask) := {
    "evaluator_schema_version": 1,
    "request_defaults": {
        "AddARPNeighborsRequest": object.union(
            fixture_arp_policy_data.request_defaults.AddARPNeighborsRequest,
            {"required_ip_address_mask": required_mask},
        ),
    },
}

test_arp_generated_allowed_flags_accept_proxy if {
    AddARPNeighborsRequest
        with input as arp_request(8)
        with data.agent_policy.policy_data as fixture_arp_policy_data
}

test_arp_allowed_flags_mutation_denied if {
    not AddARPNeighborsRequest
        with input as arp_request(8)
        with data.agent_policy.policy_data as arp_policy_with_allowed_flags(128)
}

test_arp_unknown_flag_denied if {
    not AddARPNeighborsRequest
        with input as arp_request(4)
        with data.agent_policy.policy_data as fixture_arp_policy_data
}

test_arp_required_mask_mutation_denied if {
    not AddARPNeighborsRequest
        with input as arp_request(0)
        with data.agent_policy.policy_data as arp_policy_with_required_mask("255.255.255.0")
}

test_arp_unsupported_schema_denied if {
    mutated := object.union(fixture_arp_policy_data, {"evaluator_schema_version": 2})
    not AddARPNeighborsRequest
        with input as arp_request(0)
        with data.agent_policy.policy_data as mutated
}

test_arp_missing_schema_denied if {
    mutated := object.remove(fixture_arp_policy_data, ["evaluator_schema_version"])
    not AddARPNeighborsRequest
        with input as arp_request(0)
        with data.agent_policy.policy_data as mutated
}