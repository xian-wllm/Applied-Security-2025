#!/usr/bin/env bash

set -euo pipefail

docker load -i Pre-Built/nginx_prebuilt.tar
docker load -i Pre-Built/portal_prebuilt.tar
docker load -i Pre-Built/mysql_prebuilt.tar
docker load -i Pre-Built/vault_prebuilt.tar
docker load -i Pre-Built/client_prebuilt.tar
docker load -i Pre-Built/guacd_prebuilt.tar
docker load -i Pre-Built/guacamole_prebuilt.tar
docker load -i Pre-Built/wazuh_indexer_prebuilt.tar
docker load -i Pre-Built/wazuh_dashboard_prebuilt.tar
docker load -i Pre-Built/wazuh_manager_prebuilt.tar
docker load -i Pre-Built/backup_prebuilt.tar

mkdir -p {imovies_data,vault_data,backup_local_data,backup_offsite_data}
sudo chown $USER:$(id -gn $USER) mysql_data
sudo chown $USER:$(id -gn $USER) guac_data
sudo chown $USER:$(id -gn $USER) backup_local_data
sudo chown $USER:$(id -gn $USER) backup_offsite_data
sudo sysctl -w vm.max_map_count=262144

# Start lab
# noterminals prevents kathara from spawning a terminal for every container upon startup
# no-shared stops it from mounting the shared directory into the rootfs
# no-hosthome stops it from mounting the hosthome directory into the rootfs 
kathara lrestart --noterminals
kathara lrestart ext_client01 --no-shared --no-hosthome --noterminals