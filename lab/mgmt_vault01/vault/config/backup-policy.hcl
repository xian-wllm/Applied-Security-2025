path "sys/storage/raft/snapshot" {
  capabilities = ["read"]
}

# path "secret/data/*" {
#   capabilities = ["read"]
# }

path "database/creds/mysql-db01-backup" {
  capabilities = ["read"]
}

path "database/creds/mysql-db02-backup" {
  capabilities = ["read"]
}