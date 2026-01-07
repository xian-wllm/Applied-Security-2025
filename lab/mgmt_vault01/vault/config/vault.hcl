ui = true

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_disable   = false
  tls_client_ca_file = "/vault/userconfig/tls/ca.crt"
  tls_cert_file = "/vault/userconfig/tls/vault.crt"
  tls_key_file  = "/vault/userconfig/tls/vault.key"
  tls_disable_client_certs  = "true"
}

storage "raft" {
  node_id = "mgmt_vault01"
  path    = "/vault/data"
}

api_addr     = "https://vault.imovies.lan:8200"
cluster_addr = "https://vault.imovies.lan:8201"
disable_mlock = true

telemetry {
  prometheus_retention_time = "24h"
}
