package profile_kubelet_resolution

# Resolves kubelet-owned workload intent into per-container policy values,
# currently Kubernetes Service environment names and constrained value regexes.
ip_address_pattern := "(?:(?:[0-9]{1,3}\\.){3}[0-9]{1,3}|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})"
port_pattern := "[0-9]{1,5}"
protocol_pattern := "(?:tcp|udp|sctp)"

platform_services := [{
  "name": "kubernetes",
  "namespace": "default",
  "ports": [{"name": "https", "port": 443, "protocol": "TCP"}],
}]

service_prefix(service) := upper(replace(service.name, "-", "_"))

common_service_patterns(service) := [
  sprintf("^%s_SERVICE_HOST=%s$", [prefix, ip_address_pattern]),
  sprintf("^%s_SERVICE_PORT=%s$", [prefix, port_pattern]),
  sprintf("^%s_PORT=%s://(?:%s):%s$", [prefix, protocol_pattern, ip_address_pattern, port_pattern]),
] if {
  prefix := service_prefix(service)
  count(service.ports) > 0
}

port_service_patterns(service, port) := [
  sprintf("^%s_PORT_%d_%s=%s://(?:%s):%s$", [prefix, port.port, protocol, protocol_pattern, ip_address_pattern, port_pattern]),
  sprintf("^%s_PORT_%d_%s_ADDR=%s$", [prefix, port.port, protocol, ip_address_pattern]),
  sprintf("^%s_PORT_%d_%s_PORT=%s$", [prefix, port.port, protocol, port_pattern]),
  sprintf("^%s_PORT_%d_%s_PROTO=%s$", [prefix, port.port, protocol, protocol_pattern]),
] if {
  prefix := service_prefix(service)
  protocol := upper(port.protocol)
}

service_patterns(service) := sort(array.concat(common, ports)) if {
  common := common_service_patterns(service)
  ports := [pattern |
    some port in service.ports
    some pattern in port_service_patterns(service, port)
  ]
}

subject_services(ir, subject) := [service |
  some service in array.concat(ir.services, platform_services)
  service.namespace == subject.namespace
]

# Replaces captured Service environment values with per-container EnvRegex
# entries whose names come from declared Services and whose values remain typed.
service_env_regex_claims(ir) := [claim |
  some subject in ir.subjects
  subject.role == "application"
  subject.service_links_enabled
  patterns := sort([pattern |
    some service in subject_services(ir, subject)
    some pattern in service_patterns(service)
  ])
  claim := {
    "addition": {"OCI": {"Process": {"EnvRegex": patterns}}},
    "category": "kubelet-resolution",
    "operation": "resolve",
    "subject": subject.id,
    "target": {"path": "/OCI/Process/EnvRegex"},
  }
]

# Adds exact SERVICE_PORT_<NAME> environment entries because named Service port
# numbers are declared static workload input rather than cluster-assigned data.
named_service_port_claims(ir) := [claim |
  some subject in ir.subjects
  subject.role == "application"
  subject.service_links_enabled
  some service in subject_services(ir, subject)
  prefix := service_prefix(service)
  some port in service.ports
  port.name != ""
  variable := sprintf("%s_SERVICE_PORT_%s", [prefix, upper(replace(port.name, "-", "_"))])
  value := sprintf("%d", [port.port])
  claim := {
    "addition": {"OCI": {"Process": {"Env": {variable: value}}}},
    "category": "kubelet-resolution",
    "operation": "resolve",
    "subject": subject.id,
    "target": {"path": sprintf("/OCI/Process/Env/%s", [variable])},
  }
]

# Resolves typed workload fieldRef declarations into the framework placeholders
# that runtime validation binds to the request's Pod and node identities.
environment_resolution_claims(ir) := [claim |
  some subject in ir.subjects
  some resolution in subject.environment_resolutions
  resolution.owner == "kubelet-resolution"
  resolution.target.collection == "environment"
  resolution.target.path == sprintf("/OCI/Process/Env/%s", [resolution.target.name])
  resolution.source.kind == "field-ref"
  resolution.value_type == "string"
  claim := {
    "addition": {"OCI": {"Process": {"Env": {resolution.target.name: resolution.value}}}},
    "category": "kubelet-resolution",
    "operation": "resolve",
    "subject": subject.id,
    "target": {"path": resolution.target.path},
  }
]

# Combines declared fieldRef values, regex-valued Service variables, and exact
# named-port variables into the complete kubelet-resolution mutation stream.
service_link_claims(ir) := array.concat(
  environment_resolution_claims(ir),
  array.concat(
    service_env_regex_claims(ir),
    named_service_port_claims(ir),
  ),
)

# HOSTNAME is a kubelet default rather than a workload valueFrom declaration.
# It remains an explicit typed-IR gap until hostname policy is modeled.
fragment := {
  "applies_to": {
    "kubernetes": ["v1.33.13"]
  },
  "capture_provenance": "8b0ae298134cf114935b140f42fc2ca8a8294a674ecbeb58d4727ee2f33f00d2",
  "category": "kubelet-resolution",
  "claims": [],
  "materialization_contracts": [
    {
      "operations": ["resolve"],
      "paths": [
        "/OCI/Process/Env/HOSTNAME"
      ]
    }
  ],
  "schema_version": 1,
  "scope": "profile"
}