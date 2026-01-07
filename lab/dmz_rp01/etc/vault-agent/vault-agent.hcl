pid_file = "/run/vault-agent/pidfile"

vault {
  address = "https://vault.imovies.lan:8200"
  ca_cert = "/vault/userconfig/tls/ca.crt"
}

auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path   = "/etc/vault-agent/role_id"
      secret_id_file_path = "/etc/vault-agent/secret_id"
    }
  }

  sink "file" {
    config = {
      path = "/run/vault-agent/token"
    }
  }
}

template {
  source      = "/etc/vault-agent/templates/rp_server_cert.tpl"
  destination = "/etc/nginx/tls/rp_server.crt"
  command     = "nginx -s reload || true"
}

template {
  source      = "/etc/vault-agent/templates/rp_server_key.tpl"
  destination = "/etc/nginx/tls/rp_server.key"
  perms       = "0600"
  command     = "nginx -s reload || true"
}

template {
  source      = "/etc/vault-agent/templates/auth.guac_server.tpl"
  destination = "/etc/nginx/tls/auth.guac.crt"
  command     = "nginx -s reload || true"
}

template {
  source      = "/etc/vault-agent/templates/auth.guac_key.tpl"
  destination = "/etc/nginx/tls/auth.guac.key"
  perms       = "0600"
  command     = "nginx -s reload || true"
}

template {
  source      = "/etc/vault-agent/templates/guac_server.tpl"
  destination = "/etc/nginx/tls/guac.crt"
  command     = "nginx -s reload || true"
}

template {
  source      = "/etc/vault-agent/templates/guac_key.tpl"
  destination = "/etc/nginx/tls/guac.key"
  perms       = "0600"
  command     = "nginx -s reload || true"
}

template {
  source      = "/etc/vault-agent/templates/rp_vault_client_cert.tpl"
  destination = "/etc/nginx/tls/rp_vault_client.crt"
  command     = "nginx -s reload || true"
}

template {
  source      = "/etc/vault-agent/templates/rp_vault_client_key.tpl"
  destination = "/etc/nginx/tls/rp_vault_client.key"
  perms       = "0600"
  command     = "nginx -s reload || true"
}

template {
  source      = "/etc/vault-agent/templates/kibana.imovies.lan.key.tpl"
  destination = "/etc/nginx/tls/kibana.imovies.lan.key"
  perms       = "0600"
  command     = "nginx -s reload || true"
}

template {
  source      = "/etc/vault-agent/templates/kibana.imovies.lan.tpl"
  destination = "/etc/nginx/tls/kibana.imovies.lan.crt"
  command     = "nginx -s reload || true"
}

template {
  source      = "/etc/vault-agent/templates/root_ca.tpl"
  destination = "/etc/nginx/tls/root_ca.crt"
  command     = "nginx -s reload || true"
}