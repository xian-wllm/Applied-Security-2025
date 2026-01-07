{{- with secret "pki/issue/rp_server" "common_name=portal.imovies.lan" "alt_names=pki.imovies.lan" "ttl=720h" -}}
{{ .Data.certificate }}
{{- end }}
