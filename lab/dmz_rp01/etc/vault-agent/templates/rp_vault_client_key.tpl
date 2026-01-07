{{- with secret "pki/issue/rp_agent" "common_name=vault-client.imovies.lan" "ttl=720h" -}}
{{ .Data.private_key }}
{{- end }}
