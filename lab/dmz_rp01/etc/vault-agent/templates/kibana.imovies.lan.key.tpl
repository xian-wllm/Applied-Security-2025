{{- with secret "pki/issue/rp_server" "common_name=kibana.imovies.lan" "alt_names=pki.imovies.lan" "ttl=720h" -}}
{{ .Data.private_key }}
{{- end }}
