# allow login with AppRole
path "auth/approle/login" {
  capabilities = ["update"]
}

# issue HTTPS server cert for the reverse proxy
path "pki/issue/rp_server" {
  capabilities = ["update"]
}

# issue client cert for Nginx -> Vault mTLS
path "pki/issue/rp_agent" {
  capabilities = ["update"]
}

path "pki/cert/ca" {
  capabilities = ["read"]
}