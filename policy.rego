package api.authz

default allow = false

allowed_ip_range = "10.0.8.0/24"

allow if {
  net.cidr_contains(allowed_ip_range, input.client_ip)
}
