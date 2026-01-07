#!/usr/bin/env bash

export VAULT_ADDR="https://vault.imovies.lan:8200"
export VAULT_CACERT="/vault/userconfig/tls/ca.crt"
: "${VAULT_TOKEN:?Set VAULT_TOKEN before running this script}"

exec bash -l
