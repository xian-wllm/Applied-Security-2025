path "kv/data/app/portal"              { capabilities = ["read"] }
path "database/creds/imovies_app"      { capabilities = ["read"] }
path "pki/issue/user_cert"             { capabilities = ["update"] }
path "pki/issue/ca_admin_cert"         { capabilities = ["update"] }
path "pki/issue/sys_admin_cert"        { capabilities = ["update"] }
path "pki/revoke"                      { capabilities = ["update"] }
path "transit/encrypt/key-archive"     { capabilities = ["update"] }