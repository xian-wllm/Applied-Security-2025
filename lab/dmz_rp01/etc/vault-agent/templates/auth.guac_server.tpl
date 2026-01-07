{{- with secret "pki/issue/rp_server" "common_name=*.auth.guac.imovies.lan" "alt_names=auth.guac.imovies.lan" "ttl=720h" -}}
{{ .Data.certificate }}
{{- end }}
